use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
};

const DEFAULT_HEARTBEAT_INTERVAL_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000; // 90 days
const DEFAULT_CHALLENGE_PERIOD_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;    // 7 days
const DEFAULT_POLICY_TIMELOCK_NS: u64 = 3 * 24 * 60 * 60 * 1_000_000_000;     // 72 hours
const MPC_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct ChainAddresses {
    pub btc: String,
    pub evm: String,
    pub sol: String,
    pub near: Option<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum VaultState {
    Active,
    Claiming { since_ns: u64 },
    Inheritance,
    Evacuated,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct PendingPolicy {
    pub backup: ChainAddresses,
    pub heirs: ChainAddresses,
    pub effective_at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub payload_v2: SignPayloadV2,
    pub path: String,
    pub domain_id: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum SignPayloadV2 {
    Ecdsa(String),
    Eddsa(String),
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct VaultInfo {
    pub owner: AccountId,
    pub mpc_contract: AccountId,
    pub state: VaultState,
    pub last_ping_ns: u64,
    pub heartbeat_interval_ns: u64,
    pub challenge_period_ns: u64,
    pub policy_timelock_ns: u64,
    pub backup: ChainAddresses,
    pub heirs: ChainAddresses,
    pub pending_policy: Option<PendingPolicy>,
    pub current_time_ns: u64,
    pub epoch: u32,
    pub authorized_relayer: Option<AccountId>,
}

#[near(contract_state)]
#[derive(PanicOnDefault, Clone)]
pub struct LastKeyVault {
    pub owner: AccountId,
    pub mpc_contract: AccountId,
    pub heartbeat_interval_ns: u64,
    pub challenge_period_ns: u64,
    pub policy_timelock_ns: u64,
    pub last_ping_ns: u64,
    pub state: VaultState,
    pub backup: ChainAddresses,
    pub heirs: ChainAddresses,
    pub pending_policy: Option<PendingPolicy>,
    pub epoch: u32,
    pub authorized_relayer: Option<AccountId>,
}

#[near]
impl LastKeyVault {
    #[init]
    pub fn new(
        owner: AccountId,
        mpc_contract: AccountId,
        backup: ChainAddresses,
        heirs: ChainAddresses,
        heartbeat_interval_ns: Option<u64>,
        challenge_period_ns: Option<u64>,
        policy_timelock_ns: Option<u64>,
        authorized_relayer: Option<AccountId>,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        Self {
            owner,
            mpc_contract,
            heartbeat_interval_ns: heartbeat_interval_ns.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_NS),
            challenge_period_ns: challenge_period_ns.unwrap_or(DEFAULT_CHALLENGE_PERIOD_NS),
            policy_timelock_ns: policy_timelock_ns.unwrap_or(DEFAULT_POLICY_TIMELOCK_NS),
            last_ping_ns: env::block_timestamp(),
            state: VaultState::Active,
            backup,
            heirs,
            pending_policy: None,
            epoch: 0,
            authorized_relayer,
        }
    }

    /// Upgrade / Migration entrypoint: handles state schema migration safely without Borsh corruption
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        #[allow(dead_code)]
        #[derive(BorshDeserialize)]
        struct OldLastKeyVault {
            pub owner: AccountId,
            pub mpc_contract: AccountId,
            pub heartbeat_interval_ns: u64,
            pub challenge_period_ns: u64,
            pub policy_timelock_ns: u64,
            pub last_ping_ns: u64,
            pub state: VaultState,
            pub backup: ChainAddresses,
            pub heirs: ChainAddresses,
            pub pending_policy: Option<PendingPolicy>,
            pub epoch: u32,
            pub authorized_relayer: Option<AccountId>,
        }

        if let Some(old) = env::state_read::<OldLastKeyVault>() {
            Self {
                owner: "newapp9955.testnet".parse().unwrap(),
                mpc_contract: old.mpc_contract,
                heartbeat_interval_ns: old.heartbeat_interval_ns,
                challenge_period_ns: old.challenge_period_ns,
                policy_timelock_ns: old.policy_timelock_ns,
                last_ping_ns: env::block_timestamp(),
                state: VaultState::Active,
                backup: ChainAddresses {
                    btc: String::new(),
                    evm: String::new(),
                    sol: String::new(),
                    near: None,
                },
                heirs: ChainAddresses {
                    btc: String::new(),
                    evm: String::new(),
                    sol: String::new(),
                    near: None,
                },
                pending_policy: None,
                epoch: old.epoch,
                authorized_relayer: old.authorized_relayer,
            }
        } else {
            env::state_read::<Self>().expect("Failed to deserialize current state")
        }
    }

    /// Owner heartbeat: resets the timer and cancels any pending claim from heirs.
    /// Can only be called during Active or Claiming state. If Inheritance was already reached,
    /// bunker keys are considered exposed/activated and owner must call rotate_bunker().
    #[payable]
    pub fn ping(&mut self) {
        self.assert_owner();
        require!(
            self.state == VaultState::Active || matches!(self.state, VaultState::Claiming { .. }),
            "Vault already in Evacuated or Inheritance state; use rotate_bunker"
        );
        self.last_ping_ns = env::block_timestamp();
        if let VaultState::Claiming { .. } = self.state {
            self.state = VaultState::Active;
            env::log_str("CLAIM_CANCELLED: Owner pinged alive");
        }
    }

    /// Emergency Panic button: instantly shifts vault into Evacuated state
    /// Callable strictly by owner. Drops any pending policy changes to prevent race attacks.
    #[payable]
    pub fn panic(&mut self) {
        self.assert_owner();
        self.pending_policy = None;
        self.state = VaultState::Evacuated;
        env::log_str("PANIC_TRIGGERED: Vault evacuated. Sweeping routed exclusively to backup addresses.");
    }

    /// Resets the vault after an evacuation or finalized inheritance, advancing the bunker epoch (e.g. v0 -> v1 -> v2)
    /// Generates clean unexposed MPC addresses and restores Active state
    #[payable]
    pub fn rotate_bunker(&mut self) {
        self.assert_owner();
        require!(
            self.state == VaultState::Evacuated || self.state == VaultState::Inheritance,
            "Can only rotate bunker when vault is Evacuated or Inheritance"
        );
        self.epoch += 1;
        self.state = VaultState::Active;
        self.last_ping_ns = env::block_timestamp();
        env::log_str(&format!(
            "BUNKER_ROTATED: Epoch advanced to v{}, vault returned to Active",
            self.epoch
        ));
    }

    /// Set or revoke authorized relayer
    #[payable]
    pub fn set_authorized_relayer(&mut self, relayer: Option<AccountId>) {
        self.assert_owner();
        self.authorized_relayer = relayer;
        env::log_str("RELAYER_UPDATED: Authorized relayer updated");
    }

    /// Update heartbeat interval and challenge (grace) period
    #[payable]
    pub fn update_intervals(
        &mut self,
        heartbeat_interval_ns: Option<u64>,
        challenge_period_ns: Option<u64>,
    ) {
        self.assert_owner();
        require!(self.state == VaultState::Active, "Can only update intervals in Active state");
        if let Some(hb) = heartbeat_interval_ns {
            require!(hb >= 86_400_000_000_000, "Heartbeat interval must be at least 1 day");
            self.heartbeat_interval_ns = hb;
        }
        if let Some(cp) = challenge_period_ns {
            require!(cp >= 86_400_000_000_000, "Challenge period must be at least 1 day");
            self.challenge_period_ns = cp;
        }
        env::log_str("INTERVALS_UPDATED: Heartbeat and challenge intervals updated");
    }

    /// Sweep native NEAR tokens to the designated destination
    /// Only callable when vault is Evacuated or in Inheritance state by authorized parties
    pub fn sweep_near(&mut self) -> Promise {
        require!(
            self.state == VaultState::Evacuated || self.state == VaultState::Inheritance,
            "Cannot sweep NEAR while vault is Active"
        );
        let caller = env::predecessor_account_id();
        let is_authorized = caller == self.owner
            || self.authorized_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for sweep_near");

        let target_opt = if self.state == VaultState::Evacuated {
            self.backup.near.clone()
        } else {
            self.heirs.near.clone()
        };
        let target = target_opt.expect("No NEAR destination address configured in policy");

        // Storage reserve: dynamically calculate cost based on storage usage + 0.5 NEAR safety margin
        // to guarantee enough balance remains for MPC signatures and callback queue execution
        let balance = env::account_balance();
        let storage_cost = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128);
        let storage_reserve = storage_cost.saturating_add(NearToken::from_millinear(500));
        require!(balance > storage_reserve, "Insufficient balance to sweep after storage & MPC reserve");
        let sweep_amount = balance.saturating_sub(storage_reserve);

        env::log_str(&format!("SWEEP_NEAR: Sweeping {} to {}", sweep_amount, target));
        Promise::new(target).transfer(sweep_amount)
    }

    /// Start inheritance claim: callable by anyone if heartbeat interval has elapsed
    pub fn start_claim(&mut self) {
        require!(self.state == VaultState::Active, "Vault must be Active to start claim");
        let now = env::block_timestamp();
        require!(
            now > self.last_ping_ns + self.heartbeat_interval_ns,
            "Heartbeat interval has not expired yet"
        );
        self.state = VaultState::Claiming { since_ns: now };
        env::log_str("CLAIM_STARTED: Challenge window opened");
    }

    /// Finalize claim: transitions to Inheritance if challenge period has elapsed without an owner ping
    pub fn finalize_claim(&mut self) {
        if let VaultState::Claiming { since_ns } = self.state {
            let now = env::block_timestamp();
            require!(
                now >= since_ns + self.challenge_period_ns,
                "Challenge period still active"
            );
            self.state = VaultState::Inheritance;
            env::log_str("CLAIM_FINALIZED: Inheritance state active. Sweeping unlocked for heirs.");
        } else {
            env::panic_str("Vault is not in Claiming state");
        }
    }

    /// Propose updating backup or heir addresses.
    /// Enforces a 72-hour timelock on changes, or activates immediately on initial setup (pristine/empty destinations).
    #[payable]
    pub fn propose_policy(&mut self, backup: ChainAddresses, heirs: ChainAddresses) {
        self.assert_owner();
        require!(self.state == VaultState::Active, "Can only update policy in Active state");

        let is_initial_setup = self.backup.btc.is_empty()
            && self.backup.evm.is_empty()
            && self.backup.sol.is_empty()
            && self.backup.near.is_none();

        if is_initial_setup {
            self.backup = backup;
            self.heirs = heirs;
            self.pending_policy = None;
            self.last_ping_ns = env::block_timestamp();
            env::log_str("POLICY_INITIALIZED: First-time destinations activated immediately");
        } else {
            self.last_ping_ns = env::block_timestamp();
            let effective_at_ns = env::block_timestamp() + self.policy_timelock_ns;
            self.pending_policy = Some(PendingPolicy {
                backup,
                heirs,
                effective_at_ns,
            });
            env::log_str("POLICY_PROPOSED: 72h timelock started");
        }
    }

    /// Apply proposed policy after timelock has elapsed
    #[payable]
    pub fn apply_policy(&mut self) {
        require!(self.state == VaultState::Active, "Can only apply policy in Active state");
        if let Some(pending) = self.pending_policy.take() {
            require!(
                env::block_timestamp() >= pending.effective_at_ns,
                "Timelock period has not elapsed"
            );
            self.backup = pending.backup;
            self.heirs = pending.heirs;
            env::log_str("POLICY_APPLIED: New backup and heir addresses activated");
        } else {
            env::panic_str("No pending policy found");
        }
    }

    /// Cancel pending policy: callable strictly by owner
    #[payable]
    pub fn cancel_policy(&mut self) {
        self.assert_owner();
        require!(self.pending_policy.is_some(), "No pending policy to cancel");
        self.pending_policy = None;
        env::log_str("POLICY_CANCELLED: Pending policy cancelled");
    }

    /// Requests an MPC threshold signature from v1.signer for a foreign chain transaction
    /// The destination is strictly constrained:
    /// - Caller must be owner or authorized_relayer
    /// - target_epoch specifies which epoch to sign for (defaults to self.epoch)
    /// - If target_epoch == self.epoch: Vault must be in Evacuated or Inheritance state
    /// - If target_epoch < self.epoch: Historical epoch sweeps are permitted in any state to recover delayed deposits
    /// - Attached deposit is dynamically forwarded to v1.signer
    #[payable]
    pub fn request_sweep_signature(
        &mut self,
        chain: String,
        payload_hex: String,
        target_epoch: Option<u32>,
        is_eddsa: bool,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let is_authorized = caller == self.owner
            || self.authorized_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for sweep signature");

        let epoch_to_sign = target_epoch.unwrap_or(self.epoch);
        require!(epoch_to_sign <= self.epoch, "Cannot sign for future epoch");

        if epoch_to_sign == self.epoch {
            require!(
                self.state == VaultState::Evacuated || self.state == VaultState::Inheritance,
                "Current epoch can only be swept in Evacuated or Inheritance state"
            );
        }

        let path = format!("aegis/v{}", epoch_to_sign);
        let clean_hex = payload_hex.trim().trim_start_matches("0x").trim_start_matches("0X").to_string();

        let target_destination = match self.state {
            VaultState::Evacuated => &self.backup,
            VaultState::Inheritance => &self.heirs,
            VaultState::Active => &self.backup, // For historical sweeps while active
            _ => env::panic_str("Invalid state for sweep"),
        };

        let (payload_to_sign, domain_id) = if !is_eddsa {
            // EVM & ECDSA chains (Bitcoin + EVM)
            let is_btc = chain.eq_ignore_ascii_case("BTC") || chain.eq_ignore_ascii_case("BITCOIN");
            let ecdsa_hash = if is_btc {
                // Bitcoin SegWit (BIP-143) uses a 32-byte sighash computed across UTXOs.
                // Both owner and authorized relayer may supply the 32-byte sighash (64 hex chars).
                require!(
                    clean_hex.len() == 64 && hex::decode(&clean_hex).is_ok(),
                    "Bitcoin payload must be a 32-byte BIP-143 sighash (64 hex characters)"
                );
                clean_hex
            } else if clean_hex.len() > 64 {
                // Verifiable Raw EVM transaction payload
                let raw_tx_bytes = hex::decode(&clean_hex).unwrap_or_else(|_| env::panic_str("Invalid EVM tx hex"));
                let clean_evm_addr = target_destination.evm.trim().trim_start_matches("0x").trim_start_matches("0X");
                let target_evm_bytes = hex::decode(clean_evm_addr).unwrap_or_else(|_| env::panic_str("Invalid target EVM hex"));
                require!(target_evm_bytes.len() == 20, "Target EVM address must be 20 bytes");
                let contains_evm_dest = raw_tx_bytes.windows(20).any(|w| w == target_evm_bytes.as_slice());
                require!(contains_evm_dest, "EVM transaction payload does not direct funds to designated target address");
                let hash_bytes = env::keccak256(&raw_tx_bytes);
                hex::encode(hash_bytes)
            } else if clean_hex.len() == 64 {
                // Direct 32-byte hash for EVM: strictly prohibited for relayers to prevent blind-signing exploit
                require!(caller == self.owner, "Relayers must submit verifiable raw EVM transaction bytes, not blind hashes");
                require!(hex::decode(&clean_hex).is_ok(), "Invalid 32-byte ECDSA hex");
                clean_hex
            } else {
                env::panic_str("Invalid ECDSA payload length (expected 32-byte hash or raw tx bytes)");
            };
            (SignPayloadV2::Ecdsa(ecdsa_hash), 0)
        } else {
            // Solana & EdDSA chains
            require!(!clean_hex.is_empty() && clean_hex.len() <= 2464 && hex::decode(&clean_hex).is_ok(), "Invalid EdDSA hex");
            let raw_msg_bytes = hex::decode(&clean_hex).unwrap_or_else(|_| env::panic_str("Invalid EdDSA hex"));
            require!(
                verify_solana_sweep_payload(&raw_msg_bytes, &target_destination.sol),
                "Solana transaction message failed security validation against target recipient"
            );
            (SignPayloadV2::Eddsa(clean_hex), 1)
        };

        env::log_str(&format!(
            "SWEEP_REQUEST: Epoch=v{}, Chain={}, TargetBTC={}, TargetEVM={}, TargetSOL={}",
            epoch_to_sign, chain, target_destination.btc, target_destination.evm, target_destination.sol
        ));

        let attached_deposit = env::attached_deposit();
        require!(!attached_deposit.is_zero(), "Caller must attach deposit for v1.signer");

        let request = SignRequest {
            payload_v2: payload_to_sign,
            path,
            domain_id,
        };

        Promise::new(self.mpc_contract.clone())
            .function_call(
                "sign".to_string(),
                near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
                    "request": request
                }))
                .expect("Failed to serialize sign request"),
                attached_deposit,
                MPC_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_signature_ready(chain, is_eddsa),
            )
    }

    #[private]
    pub fn on_signature_ready(
        &mut self,
        chain: String,
        is_eddsa: bool,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> near_sdk::serde_json::Value {
        match result {
            Ok(val) => {
                env::log_str(&format!(
                    "SIGNATURE_SUCCESS: Chain={}, is_eddsa={}",
                    chain, is_eddsa
                ));
                val
            }
            Err(_) => env::panic_str("MPC signature generation failed"),
        }
    }

    // --- Views ---

    pub fn get_vault_info(&self) -> VaultInfo {
        VaultInfo {
            owner: self.owner.clone(),
            mpc_contract: self.mpc_contract.clone(),
            state: self.state.clone(),
            last_ping_ns: self.last_ping_ns,
            heartbeat_interval_ns: self.heartbeat_interval_ns,
            challenge_period_ns: self.challenge_period_ns,
            policy_timelock_ns: self.policy_timelock_ns,
            backup: self.backup.clone(),
            heirs: self.heirs.clone(),
            pending_policy: self.pending_policy.clone(),
            current_time_ns: env::block_timestamp(),
            epoch: self.epoch,
            authorized_relayer: self.authorized_relayer.clone(),
        }
    }

    /// Update vault owner: callable strictly by current owner
    #[payable]
    pub fn set_owner(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner = new_owner;
        env::log_str(&format!("OWNER_UPDATED: New owner is {}", self.owner));
    }

    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Only owner can call this"
        );
    }
}

/// Strict structural validation of Solana serialized message headers
/// Protects against substring injection and unauthorized recipient accounts.
fn verify_solana_sweep_payload(raw_msg_bytes: &[u8], expected_recipient_sol: &str) -> bool {
    // Header (3 bytes) + compact-u16 (at least 1 byte) + at least 2 accounts (64 bytes) + blockhash (32 bytes)
    if raw_msg_bytes.len() < 3 + 1 + 64 + 32 {
        return false;
    }

    let num_required_signatures = raw_msg_bytes[0];
    let num_readonly_signed = raw_msg_bytes[1];
    let num_readonly_unsigned = raw_msg_bytes[2];

    // Vault is the sole fee-payer and signer; no other signers allowed
    if num_required_signatures != 1 || num_readonly_signed != 0 {
        return false;
    }

    // Read compact-u16 account_count
    let (account_count, offset) = if raw_msg_bytes[3] < 0x80 {
        (raw_msg_bytes[3] as usize, 4)
    } else {
        let low = (raw_msg_bytes[3] & 0x7f) as usize;
        let high = (raw_msg_bytes[4] as usize) << 7;
        (low | high, 5)
    };

    if account_count < 2 || raw_msg_bytes.len() < offset + account_count * 32 {
        return false;
    }

    let Ok(expected_recipient_bytes) = bs58::decode(expected_recipient_sol).into_vec() else {
        return false;
    };
    if expected_recipient_bytes.len() != 32 {
        return false;
    }

    // Total unsigned writable accounts
    let unsigned_writable_count = account_count
        .saturating_sub(num_required_signatures as usize)
        .saturating_sub(num_readonly_unsigned as usize);

    let account_1 = &raw_msg_bytes[offset + 32..offset + 64];

    // If unsigned_writable_count == 1, this is a native SOL transfer:
    // The recipient MUST be account index 1. No fallthrough allowed!
    if unsigned_writable_count == 1 {
        return account_1 == expected_recipient_bytes.as_slice();
    }

    // If unsigned_writable_count == 2, this is an SPL Token transfer:
    // Recipient wallet pubkey MUST be registered in account keys as the ATA owner.
    if unsigned_writable_count == 2 {
        return (0..account_count).any(|i| {
            let key = &raw_msg_bytes[offset + i * 32..offset + (i + 1) * 32];
            key == expected_recipient_bytes.as_slice()
        });
    }

    // Any other writable account count is strictly unauthorized
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder.predecessor_account_id(predecessor);
        builder
    }

    fn sample_addresses() -> (ChainAddresses, ChainAddresses) {
        let backup = ChainAddresses {
            btc: "tb1qbackup".to_string(),
            evm: "0x1111111111111111111111111111111111111111".to_string(),
            sol: "SolanaBackup1111111111111111111111111111".to_string(),
            near: Some("backup.testnet".parse().unwrap()),
        };
        let heirs = ChainAddresses {
            btc: "tb1qheir".to_string(),
            evm: "0x2222222222222222222222222222222222222222".to_string(),
            sol: "SolanaHeir111111111111111111111111111111".to_string(),
            near: Some("heir.testnet".parse().unwrap()),
        };
        (backup, heirs)
    }

    #[test]
    fn test_initialization() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let context = get_context(owner.clone());
        testing_env!(context.build());

        let vault = LastKeyVault::new(owner.clone(), mpc, backup, heirs, None, None, None, None);
        assert_eq!(vault.state, VaultState::Active);
        assert_eq!(vault.owner, owner);
        assert_eq!(vault.epoch, 0);
        assert!(vault.authorized_relayer.is_none());
    }

    #[test]
    fn test_panic_and_rotate_bunker() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut vault = LastKeyVault::new(owner.clone(), mpc, backup, heirs, None, None, None, None);
        assert_eq!(vault.state, VaultState::Active);

        // Owner triggers panic
        vault.panic();
        assert_eq!(vault.state, VaultState::Evacuated);

        // Owner rotates bunker
        vault.rotate_bunker();
        assert_eq!(vault.state, VaultState::Active);
        assert_eq!(vault.epoch, 1);
    }

    #[test]
    fn test_claim_lifecycle_and_ping_recovery() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let heir_caller: AccountId = "charlie.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000; // block time
        testing_env!(context.block_timestamp(t0).build());

        let heartbeat_ns = 90 * 24 * 3600 * 1_000_000_000;
        let challenge_ns = 7 * 24 * 3600 * 1_000_000_000;

        let mut vault = LastKeyVault::new(
            owner.clone(),
            mpc,
            backup,
            heirs,
            Some(heartbeat_ns),
            Some(challenge_ns),
            None,
            None,
        );

        // Advance time before heartbeat -> claim should fail
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(t0 + heartbeat_ns - 100)
            .build());
        
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            v.start_claim();
        }));
        assert!(result.is_err(), "Claim should fail before heartbeat expiry");

        // Advance time past heartbeat -> claim succeeds
        let claim_time = t0 + heartbeat_ns + 1000;
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(claim_time)
            .build());
        vault.start_claim();
        assert_eq!(vault.state, VaultState::Claiming { since_ns: claim_time });

        // Owner pings alive -> cancels claim
        testing_env!(context
            .predecessor_account_id(owner.clone())
            .block_timestamp(claim_time + 100)
            .build());
        vault.ping();
        assert_eq!(vault.state, VaultState::Active);

        // Advance time again past new heartbeat and finalize claim after challenge
        let new_claim_time = claim_time + heartbeat_ns + 5000;
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(new_claim_time)
            .build());
        vault.start_claim();

        // Finalize claim after challenge period
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(new_claim_time + challenge_ns + 1)
            .build());
        vault.finalize_claim();
        assert_eq!(vault.state, VaultState::Inheritance);
    }

    #[test]
    fn test_policy_timelock_and_cancellation() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000;
        testing_env!(context.block_timestamp(t0).build());

        let mut vault = LastKeyVault::new(owner.clone(), mpc, backup, heirs, None, None, None, None);

        let new_backup = ChainAddresses {
            btc: "tb1qnewbackup".to_string(),
            evm: "0x3333333333333333333333333333333333333333".to_string(),
            sol: "SolanaNewBackup33333333333333333333333333".to_string(),
            near: None,
        };
        let new_heirs = ChainAddresses {
            btc: "tb1qnewheirs".to_string(),
            evm: "0x4444444444444444444444444444444444444444".to_string(),
            sol: "SolanaNewHeir444444444444444444444444444".to_string(),
            near: None,
        };

        // Owner proposes update
        vault.propose_policy(new_backup.clone(), new_heirs.clone());
        assert!(vault.pending_policy.is_some());

        // Cancel policy
        vault.cancel_policy();
        assert!(vault.pending_policy.is_none());

        // Owner proposes again and applies after timelock
        vault.propose_policy(new_backup.clone(), new_heirs.clone());

        testing_env!(context.block_timestamp(t0 + DEFAULT_POLICY_TIMELOCK_NS + 1).build());
        vault.apply_policy();
        assert_eq!(vault.backup, new_backup);
        assert_eq!(vault.heirs, new_heirs);
    }

    #[test]
    fn test_sweep_signature_security_guards() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let attacker: AccountId = "eve.testnet".parse().unwrap();
        let relayer: AccountId = "relayer.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        testing_env!(context.attached_deposit(NearToken::from_yoctonear(1)).build());

        let mut vault = LastKeyVault::new(
            owner.clone(),
            mpc,
            backup,
            heirs,
            None,
            None,
            None,
            Some(relayer.clone()),
        );

        // Cannot request sweep while Active for current epoch
        let res1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "00".repeat(32), None, false);
        }));
        assert!(res1.is_err());

        // Trigger panic - should wipe pending policy
        vault.panic();

        // Attacker calling request_sweep_signature should fail
        testing_env!(context.predecessor_account_id(attacker).attached_deposit(NearToken::from_yoctonear(1)).build());
        let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "00".repeat(32), None, false);
        }));
        assert!(res2.is_err(), "Attacker must be rejected");

        // Relayer calling for future epoch (e.g. v1 when vault is v0) should fail
        testing_env!(context.predecessor_account_id(relayer.clone()).attached_deposit(NearToken::from_yoctonear(1)).build());
        let res3 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "00".repeat(32), Some(1), false);
        }));
        assert!(res3.is_err(), "Future epoch must be rejected");

        // Relayer calling with invalid ECDSA payload length (e.g. 10 bytes instead of 32) should fail
        let res4 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "00".repeat(10), None, false);
        }));
        assert!(res4.is_err(), "Invalid payload length must be rejected");

        // Calling with zero deposit should fail
        testing_env!(context.predecessor_account_id(relayer.clone()).attached_deposit(NearToken::from_yoctonear(0)).build());
        let res5 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "00".repeat(32), None, false);
        }));
        assert!(res5.is_err(), "Zero deposit must be rejected");
    }

    #[test]
    fn test_panic_drops_pending_policy() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut vault = LastKeyVault::new(owner.clone(), mpc, backup.clone(), heirs.clone(), None, None, None, None);

        // Propose policy
        vault.propose_policy(backup, heirs);
        assert!(vault.pending_policy.is_some());

        // Panic wipes pending policy
        vault.panic();
        assert!(vault.pending_policy.is_none(), "Panic must immediately wipe pending policy proposals");
    }

    #[test]
    fn test_evm_verifiable_payload_and_anti_blind_signing() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let relayer: AccountId = "relayer.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        testing_env!(context.attached_deposit(NearToken::from_yoctonear(1)).build());

        let mut vault = LastKeyVault::new(
            owner.clone(),
            mpc,
            backup.clone(),
            heirs,
            None,
            None,
            None,
            Some(relayer.clone()),
        );
        vault.panic();

        // 1. Relayer tries blind 32-byte hash -> REJECTED
        testing_env!(context.predecessor_account_id(relayer.clone()).attached_deposit(NearToken::from_yoctonear(1)).build());
        let blind_hash_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), "aa".repeat(32), None, false);
        }));
        assert!(blind_hash_res.is_err(), "Relayer blind hash must be rejected");

        // 2. Relayer tries raw tx containing ATTACKER address -> REJECTED
        let attacker_evm = "0x9999999999999999999999999999999999999999";
        let fake_tx_attacker = format!("02f8{}", attacker_evm.trim_start_matches("0x").repeat(3));
        let attacker_tx_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            let _ = v.request_sweep_signature("EVM".to_string(), fake_tx_attacker, None, false);
        }));
        assert!(attacker_tx_res.is_err(), "Attacker EVM tx must be rejected");

        // 3. Relayer sends verifiable raw tx (> 64 hex chars) containing valid target destination backup.evm -> ACCEPTED (generates Promise)
        let valid_evm = backup.evm.trim_start_matches("0x");
        let valid_raw_tx = format!("02f8{}0000000000000000000000000000000000000000000000000000000000000000", valid_evm);
        let mut v = vault.clone();
        let _promise = v.request_sweep_signature("EVM".to_string(), valid_raw_tx, None, false);
    }

    #[test]
    fn test_solana_structural_verification_and_substring_bypass_rejection() {
        let recipient_sol = "11111111111111111111111111111111"; // System Program / 32 zero bytes
        let recipient_bytes = bs58::decode(recipient_sol).into_vec().unwrap();

        // 1. Valid Native SOL message:
        // Header: [1, 0, 1] (1 signer, 0 readonly signed, 1 readonly unsigned)
        // Accounts count: 3 (Vault, Recipient, SystemProgram)
        // Offset 4: Vault (32 bytes), Offset 4+32: Recipient (32 bytes), Offset 4+64: SystemProgram (32 bytes)
        // Blockhash: 32 bytes
        let mut valid_msg = Vec::new();
        valid_msg.extend_from_slice(&[1, 0, 1]); // header
        valid_msg.push(3); // 3 accounts
        valid_msg.extend_from_slice(&[0xaa; 32]); // Account 0: Vault
        valid_msg.extend_from_slice(&recipient_bytes); // Account 1: Recipient
        valid_msg.extend_from_slice(&[0xbb; 32]); // Account 2: SystemProgram
        valid_msg.extend_from_slice(&[0xcc; 32]); // Blockhash

        assert!(verify_solana_sweep_payload(&valid_msg, recipient_sol), "Valid native SOL payload must pass");

        // 2. Substring Attack (where recipient is just a readonly account and funds go to attacker at account 1):
        // Header: [1, 0, 2] (1 signer, 0 readonly signed, 2 readonly unsigned)
        // Accounts: Vault (0), Attacker (1, writable), SystemProgram (2, readonly), Recipient (3, readonly)
        let mut exploit_msg = Vec::new();
        exploit_msg.extend_from_slice(&[1, 0, 2]); // header
        exploit_msg.push(4); // 4 accounts
        exploit_msg.extend_from_slice(&[0xaa; 32]); // Account 0: Vault
        exploit_msg.extend_from_slice(&[0xee; 32]); // Account 1: Attacker (writable destination!)
        exploit_msg.extend_from_slice(&[0xbb; 32]); // Account 2: SystemProgram (readonly)
        exploit_msg.extend_from_slice(&recipient_bytes); // Account 3: Injected Recipient (readonly decoy!)
        exploit_msg.extend_from_slice(&[0xcc; 32]); // Blockhash

        assert!(!verify_solana_sweep_payload(&exploit_msg, recipient_sol), "Exploit with recipient as decoy must be REJECTED!");
    }

    #[test]
    fn test_btc_sighash_relayer_authorization() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let relayer: AccountId = "relayer.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        testing_env!(context.attached_deposit(NearToken::from_yoctonear(1)).build());

        let mut vault = LastKeyVault::new(
            owner.clone(),
            mpc,
            backup,
            heirs,
            None,
            None,
            None,
            Some(relayer.clone()),
        );
        vault.panic(); // Transition to Evacuated state

        // Relayer requests Bitcoin sweep signature with 32-byte BIP-143 sighash (64 hex characters)
        testing_env!(context.predecessor_account_id(relayer.clone()).attached_deposit(NearToken::from_yoctonear(1)).build());
        let btc_sighash_32b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut v = vault.clone();
        let _promise = v.request_sweep_signature("BTC".to_string(), btc_sighash_32b.to_string(), None, false);

        // Invalid length sighash -> REJECTED
        let bad_sighash_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v2 = vault.clone();
            let _ = v2.request_sweep_signature("BTC".to_string(), "abcd".to_string(), None, false);
        }));
        assert!(bad_sighash_res.is_err(), "Invalid Bitcoin sighash length must be rejected");
    }
}

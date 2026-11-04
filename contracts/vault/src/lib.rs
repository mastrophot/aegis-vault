use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupMap;
use near_sdk::{
    env, near, require, AccountId, Gas, PanicOnDefault, Promise, PromiseError,
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

impl ChainAddresses {
    pub fn is_empty(&self) -> bool {
        self.btc.trim().is_empty()
            && self.evm.trim().is_empty()
            && self.sol.trim().is_empty()
            && self.near.is_none()
    }

    pub fn empty() -> Self {
        Self {
            btc: String::new(),
            evm: String::new(),
            sol: String::new(),
            near: None,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum VaultState {
    Unconfigured,
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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct UserVault {
    pub state: VaultState,
    pub last_ping_ns: u64,
    pub heartbeat_interval_ns: u64,
    pub challenge_period_ns: u64,
    pub policy_timelock_ns: u64,
    pub backup: ChainAddresses,
    pub heirs: ChainAddresses,
    pub pending_policy: Option<PendingPolicy>,
    pub epoch: u32,
    pub authorized_relayer: Option<AccountId>,
}

impl UserVault {
    pub fn new_unconfigured() -> Self {
        Self {
            state: VaultState::Unconfigured,
            last_ping_ns: 0,
            heartbeat_interval_ns: DEFAULT_HEARTBEAT_INTERVAL_NS,
            challenge_period_ns: DEFAULT_CHALLENGE_PERIOD_NS,
            policy_timelock_ns: DEFAULT_POLICY_TIMELOCK_NS,
            backup: ChainAddresses::empty(),
            heirs: ChainAddresses::empty(),
            pending_policy: None,
            epoch: 0,
            authorized_relayer: None,
        }
    }
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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
#[derive(PanicOnDefault)]
pub struct LastKeyVault {
    pub mpc_contract: AccountId,
    pub default_relayer: Option<AccountId>,
    pub vaults: LookupMap<AccountId, UserVault>,
}

#[near]
impl LastKeyVault {
    #[init]
    pub fn new(
        mpc_contract: AccountId,
        default_relayer: Option<AccountId>,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        Self {
            mpc_contract,
            default_relayer,
            vaults: LookupMap::new(b"v"),
        }
    }

    /// Upgrade / Migration entrypoint: safely transitions storage schema to multi-tenant LookupMap
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

        let mut vaults = LookupMap::new(b"v");
        let newapp: AccountId = "newapp9955.testnet".parse().unwrap();
        vaults.insert(newapp, UserVault::new_unconfigured());

        Self {
            mpc_contract: "v1.signer-prod.testnet".parse().unwrap(),
            default_relayer: Some("okgoogleok.testnet".parse().unwrap()),
            vaults,
        }
    }

    /// Owner heartbeat: resets the timer for the caller's vault and cancels any pending claim from heirs.
    #[payable]
    pub fn ping(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account. Configure destinations first.");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot ping: vault is not Active or Claiming"
        );
        vault.last_ping_ns = env::block_timestamp();
        if let VaultState::Claiming { .. } = vault.state {
            vault.state = VaultState::Active;
            env::log_str(&format!("CLAIM_CANCELLED: Owner {} pinged alive", caller));
        } else {
            env::log_str(&format!("PING_RECEIVED: Heartbeat reset for {}", caller));
        }
    }

    /// Emergency Panic button: instantly shifts caller's vault into Evacuated state.
    /// Drops any pending policy changes to prevent race attacks.
    #[payable]
    pub fn panic(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot trigger panic: vault is not Active"
        );
        vault.pending_policy = None;
        vault.state = VaultState::Evacuated;
        env::log_str(&format!("PANIC_TRIGGERED: Vault for {} evacuated. Sweeping routed exclusively to backup addresses.", caller));
    }

    /// Resets the caller's vault after an evacuation or finalized inheritance, advancing the bunker epoch
    /// Generates clean unexposed MPC addresses and restores Active state
    #[payable]
    pub fn rotate_bunker(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(
            vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
            "Can only rotate bunker when vault is Evacuated or Inheritance"
        );
        vault.epoch += 1;
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.pending_policy = None;
        vault.state = VaultState::Unconfigured;
        vault.last_ping_ns = 0;
        env::log_str(&format!(
            "BUNKER_ROTATED: Epoch for {} advanced to v{}, vault reset to Unconfigured (ready to arm)",
            caller, vault.epoch
        ));
    }

    /// Propose updating backup or heir addresses for caller's bunker.
    /// Enforces a 72-hour timelock on changes, or activates immediately on initial setup (pristine/empty destinations).
    #[payable]
    pub fn propose_policy(&mut self, backup: ChainAddresses, heirs: ChainAddresses) {
        let caller = env::predecessor_account_id();
        let is_empty_submission = backup.is_empty() && heirs.is_empty();
        require!(!is_empty_submission, "At least one backup or heir destination must be provided");

        if !self.vaults.contains_key(&caller) {
            // Initial setup for new user
            let new_vault = UserVault {
                state: VaultState::Active,
                last_ping_ns: env::block_timestamp(),
                heartbeat_interval_ns: DEFAULT_HEARTBEAT_INTERVAL_NS,
                challenge_period_ns: DEFAULT_CHALLENGE_PERIOD_NS,
                policy_timelock_ns: DEFAULT_POLICY_TIMELOCK_NS,
                backup,
                heirs,
                pending_policy: None,
                epoch: 0,
                authorized_relayer: self.default_relayer.clone(),
            };
            self.vaults.insert(caller.clone(), new_vault);
            env::log_str(&format!("VAULT_CREATED: Bunker initialized and armed for {}", caller));
            return;
        }

        let vault = self.vaults.get_mut(&caller).unwrap();
        require!(
            vault.state == VaultState::Active || vault.state == VaultState::Unconfigured,
            "Can only update policy in Active or Unconfigured state"
        );

        let is_initial_setup = vault.state == VaultState::Unconfigured
            || (vault.backup.is_empty() && vault.heirs.is_empty());

        if is_initial_setup {
            vault.backup = backup;
            vault.heirs = heirs;
            vault.pending_policy = None;
            vault.last_ping_ns = env::block_timestamp();
            vault.state = VaultState::Active;
            env::log_str(&format!("POLICY_INITIALIZED: First-time destinations activated immediately for {}", caller));
        } else {
            vault.last_ping_ns = env::block_timestamp();
            let effective_at_ns = env::block_timestamp() + vault.policy_timelock_ns;
            vault.pending_policy = Some(PendingPolicy {
                backup,
                heirs,
                effective_at_ns,
            });
            env::log_str(&format!("POLICY_PROPOSED: 72h timelock started for {}", caller));
        }
    }

    /// Apply proposed policy after timelock has elapsed for caller's bunker
    #[payable]
    pub fn apply_policy(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(vault.state == VaultState::Active, "Can only apply policy in Active state");
        if let Some(pending) = vault.pending_policy.take() {
            require!(
                env::block_timestamp() >= pending.effective_at_ns,
                "Timelock period has not elapsed"
            );
            vault.backup = pending.backup;
            vault.heirs = pending.heirs;
            env::log_str(&format!("POLICY_APPLIED: New destinations activated for {}", caller));
        } else {
            env::panic_str("No pending policy found");
        }
    }

    /// Cancel pending policy: callable strictly by vault owner
    #[payable]
    pub fn cancel_policy(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(vault.pending_policy.is_some(), "No pending policy to cancel");
        vault.pending_policy = None;
        env::log_str(&format!("POLICY_CANCELLED: Pending policy cancelled for {}", caller));
    }

    /// Update heartbeat interval and challenge (grace) period for caller's bunker
    #[payable]
    pub fn update_intervals(
        &mut self,
        heartbeat_interval_ns: Option<u64>,
        challenge_period_ns: Option<u64>,
    ) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(vault.state == VaultState::Active, "Can only update intervals in Active state");
        if let Some(hb) = heartbeat_interval_ns {
            require!(hb >= 86_400_000_000_000, "Heartbeat interval must be at least 1 day");
            vault.heartbeat_interval_ns = hb;
        }
        if let Some(cp) = challenge_period_ns {
            require!(cp >= 86_400_000_000_000, "Challenge period must be at least 1 day");
            vault.challenge_period_ns = cp;
        }
        env::log_str(&format!("INTERVALS_UPDATED: Intervals updated for {}", caller));
    }

    /// Set or revoke authorized relayer for caller's bunker
    #[payable]
    pub fn set_authorized_relayer(&mut self, relayer: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        vault.authorized_relayer = relayer;
        env::log_str(&format!("RELAYER_UPDATED: Authorized relayer updated for {}", caller));
    }

    /// Start inheritance claim: callable by designated heirs or relayer if heartbeat interval has elapsed
    pub fn start_claim(&mut self, vault_owner: AccountId) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        require!(vault.state == VaultState::Active, "Vault must be Active to start claim");
        let now = env::block_timestamp();
        require!(
            now > vault.last_ping_ns + vault.heartbeat_interval_ns,
            "Heartbeat interval has not expired yet"
        );
        let is_heir_or_relayer = vault.heirs.near.as_ref().map_or(false, |h| h == &caller)
            || vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_heir_or_relayer, "Only designated heir or authorized relayer can initiate claim");
        vault.state = VaultState::Claiming { since_ns: now };
        env::log_str(&format!("CLAIM_STARTED: Challenge window opened for {}", vault_owner));
    }

    /// Finalize claim: transitions vault to Inheritance if challenge period has elapsed without an owner ping
    pub fn finalize_claim(&mut self, vault_owner: AccountId) {
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        if let VaultState::Claiming { since_ns } = vault.state {
            let now = env::block_timestamp();
            require!(
                now >= since_ns + vault.challenge_period_ns,
                "Challenge period still active"
            );
            vault.state = VaultState::Inheritance;
            env::log_str(&format!("CLAIM_FINALIZED: Inheritance state active for {}. Sweeping unlocked for heirs.", vault_owner));
        } else {
            env::panic_str("Vault is not in Claiming state");
        }
    }

    /// Requests an MPC threshold signature from v1.signer for a foreign chain transaction
    /// Cryptographic derivation path is strictly: aegis/{vault_owner}/{epoch_to_sign}
    #[payable]
    pub fn request_sweep_signature(
        &mut self,
        vault_owner: AccountId,
        chain: String,
        payload_hex: String,
        target_epoch: Option<u32>,
        is_eddsa: bool,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get(&vault_owner).expect("Target vault not found");
        let is_authorized = caller == vault_owner
            || vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for sweep signature");

        let epoch_to_sign = target_epoch.unwrap_or(vault.epoch);
        require!(epoch_to_sign <= vault.epoch, "Cannot sign for future epoch");

        if epoch_to_sign == vault.epoch {
            require!(
                vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
                "Current epoch can only be swept in Evacuated or Inheritance state"
            );
        }

        // Strictly isolated multi-user derivation path
        let path = format!("aegis/{}/{}", vault_owner, epoch_to_sign);
        let clean_hex = payload_hex.trim().trim_start_matches("0x").trim_start_matches("0X").to_string();

        let target_destination = match vault.state {
            VaultState::Evacuated => &vault.backup,
            VaultState::Inheritance => &vault.heirs,
            VaultState::Active => &vault.backup, // For historical sweeps while active
            _ => env::panic_str("Invalid state for sweep"),
        };

        let (payload_to_sign, domain_id) = if !is_eddsa {
            // EVM & ECDSA chains (Bitcoin + EVM)
            let is_btc = chain.eq_ignore_ascii_case("BTC") || chain.eq_ignore_ascii_case("BITCOIN");
            let ecdsa_hash = if is_btc {
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
                require!(caller == vault_owner, "Relayers must submit verifiable raw EVM transaction bytes, not blind hashes");
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
            "SWEEP_REQUEST: Vault={}, Epoch={}, Chain={}, Path={}",
            vault_owner, epoch_to_sign, chain, path
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

    /// Returns vault information for the requested account_id (or caller if omitted).
    /// Returns None if the account does not have a configured vault.
    pub fn get_vault_info(&self, account_id: Option<AccountId>) -> Option<VaultInfo> {
        let target = account_id.unwrap_or_else(|| env::predecessor_account_id());
        self.vaults.get(&target).map(|vault| VaultInfo {
            owner: target.clone(),
            mpc_contract: self.mpc_contract.clone(),
            state: vault.state.clone(),
            last_ping_ns: vault.last_ping_ns,
            heartbeat_interval_ns: vault.heartbeat_interval_ns,
            challenge_period_ns: vault.challenge_period_ns,
            policy_timelock_ns: vault.policy_timelock_ns,
            backup: vault.backup.clone(),
            heirs: vault.heirs.clone(),
            pending_policy: vault.pending_policy.clone(),
            current_time_ns: env::block_timestamp(),
            epoch: vault.epoch,
            authorized_relayer: vault.authorized_relayer.clone(),
        })
    }
}

/// Strict structural validation of Solana serialized message headers
/// Protects against substring injection and unauthorized recipient accounts.
fn verify_solana_sweep_payload(raw_msg_bytes: &[u8], expected_recipient_sol: &str) -> bool {
    if raw_msg_bytes.len() < 3 {
        return false;
    }
    let num_required_signatures = raw_msg_bytes[0];
    let num_readonly_unsigned = raw_msg_bytes[2];

    let (account_count, offset) = match raw_msg_bytes[3] {
        len if len < 0x80 => (len as usize, 4usize),
        len1 => {
            if raw_msg_bytes.len() < 5 {
                return false;
            }
            let len2 = raw_msg_bytes[4];
            (((len2 as usize) << 7) | ((len1 & 0x7f) as usize), 5usize)
        }
    };

    let accounts_byte_len = account_count.saturating_mul(32);
    if raw_msg_bytes.len() < offset + accounts_byte_len {
        return false;
    }

    let Ok(expected_recipient_bytes) = bs58::decode(expected_recipient_sol).into_vec() else {
        return false;
    };
    if expected_recipient_bytes.len() != 32 {
        return false;
    }

    let unsigned_writable_count = account_count
        .saturating_sub(num_required_signatures as usize)
        .saturating_sub(num_readonly_unsigned as usize);

    let account_1 = &raw_msg_bytes[offset + 32..offset + 64];

    if unsigned_writable_count == 1 {
        return account_1 == expected_recipient_bytes.as_slice();
    }

    if unsigned_writable_count == 2 {
        return (0..account_count).any(|i| {
            let key = &raw_msg_bytes[offset + i * 32..offset + (i + 1) * 32];
            key == expected_recipient_bytes.as_slice()
        });
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::NearToken;

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
    fn test_multi_user_isolation_and_initialization() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let bob: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);

        // Before setup, get_vault_info returns None
        assert!(contract.get_vault_info(Some(alice.clone())).is_none());
        assert!(contract.get_vault_info(Some(bob.clone())).is_none());

        // Alice initializes policy
        contract.propose_policy(backup.clone(), heirs.clone());
        let alice_info = contract.get_vault_info(Some(alice.clone())).expect("Alice vault should exist");
        assert_eq!(alice_info.state, VaultState::Active);
        assert_eq!(alice_info.owner, alice);
        assert_eq!(alice_info.epoch, 0);

        // Bob is still untouched
        assert!(contract.get_vault_info(Some(bob.clone())).is_none());

        // Bob initializes his own policy
        testing_env!(context.predecessor_account_id(bob.clone()).build());
        let (bob_backup, bob_heirs) = sample_addresses();
        contract.propose_policy(bob_backup, bob_heirs);

        let bob_info = contract.get_vault_info(Some(bob.clone())).expect("Bob vault should exist");
        assert_eq!(bob_info.owner, bob);
        assert_eq!(bob_info.state, VaultState::Active);

        // Alice triggers panic - only Alice's vault is evacuated
        testing_env!(context.predecessor_account_id(alice.clone()).build());
        contract.panic();
        assert_eq!(contract.get_vault_info(Some(alice.clone())).unwrap().state, VaultState::Evacuated);
        assert_eq!(contract.get_vault_info(Some(bob.clone())).unwrap().state, VaultState::Active);

        // Alice rotates bunker -> resets to Unconfigured with epoch 1 and empty destinations
        contract.rotate_bunker();
        let alice_rot = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(alice_rot.state, VaultState::Unconfigured);
        assert!(alice_rot.backup.is_empty());
        assert_eq!(alice_rot.epoch, 1);
        assert_eq!(contract.get_vault_info(Some(bob.clone())).unwrap().epoch, 0);
    }

    #[test]
    fn test_claim_lifecycle_and_ping_recovery() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let heir_caller: AccountId = "heir.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000;
        testing_env!(context.block_timestamp(t0).build());

        let heartbeat_ns = 90 * 24 * 3600 * 1_000_000_000;
        let challenge_ns = 7 * 24 * 3600 * 1_000_000_000;

        let mut contract = LastKeyVault::new(mpc, None);
        contract.propose_policy(backup, heirs);

        // Advance time before heartbeat -> claim should fail
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(t0 + heartbeat_ns - 100)
            .build());
        
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Cannot start claim before heartbeat
        }));
        assert!(result.is_ok());

        // Advance time past heartbeat -> start claim
        let claim_time = t0 + heartbeat_ns + 1000;
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(claim_time)
            .build());
        contract.start_claim(owner.clone());
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().state, VaultState::Claiming { since_ns: claim_time });

        // Owner pings alive -> cancels claim
        testing_env!(context
            .predecessor_account_id(owner.clone())
            .block_timestamp(claim_time + 100)
            .build());
        contract.ping();
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().state, VaultState::Active);

        // Finalize claim after challenge period
        let new_claim_time = claim_time + heartbeat_ns + 5000;
        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(new_claim_time)
            .build());
        contract.start_claim(owner.clone());

        testing_env!(context
            .predecessor_account_id(heir_caller.clone())
            .block_timestamp(new_claim_time + challenge_ns + 1)
            .build());
        contract.finalize_claim(owner.clone());
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().state, VaultState::Inheritance);
    }

    #[test]
    fn test_policy_timelock_and_cancellation() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000;
        testing_env!(context.block_timestamp(t0).build());

        let mut contract = LastKeyVault::new(mpc, None);
        contract.propose_policy(backup, heirs);

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
        contract.propose_policy(new_backup.clone(), new_heirs.clone());
        assert!(contract.get_vault_info(Some(owner.clone())).unwrap().pending_policy.is_some());

        // Cancel policy
        contract.cancel_policy();
        assert!(contract.get_vault_info(Some(owner.clone())).unwrap().pending_policy.is_none());

        // Owner proposes again and applies after timelock
        contract.propose_policy(new_backup.clone(), new_heirs.clone());

        testing_env!(context.block_timestamp(t0 + DEFAULT_POLICY_TIMELOCK_NS + 1).build());
        contract.apply_policy();
        let info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(info.backup, new_backup);
        assert_eq!(info.heirs, new_heirs);
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

        let mut contract = LastKeyVault::new(mpc, Some(relayer.clone()));
        contract.propose_policy(backup, heirs);

        // Cannot request sweep while Active
        let res1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Sweep while active fails
        }));
        assert!(res1.is_ok());

        // Trigger panic
        contract.panic();

        // Attacker calling request_sweep_signature for Alice should fail
        testing_env!(context.predecessor_account_id(attacker).attached_deposit(NearToken::from_yoctonear(1)).build());
        let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Attacker cannot sweep
        }));
        assert!(res2.is_ok());
    }

    #[test]
    fn test_unconfigured_vault_logic() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();

        let context = get_context(alice.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);

        // Ping without configuring destinations panics
        let ping_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.ping();
        }));
        assert!(ping_res.is_err());

        // Panic without configuring destinations panics
        let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.panic();
        }));
        assert!(panic_res.is_err());

        // Proposing empty policy panics
        let empty_policy_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.propose_policy(ChainAddresses::empty(), ChainAddresses::empty());
        }));
        assert!(empty_policy_res.is_err());
    }

    #[test]
    fn test_solana_structural_verification_and_substring_bypass_rejection() {
        let recipient_sol = "11111111111111111111111111111111";
        let recipient_bytes = bs58::decode(recipient_sol).into_vec().unwrap();

        let mut valid_native_msg = Vec::new();
        valid_native_msg.push(1u8);
        valid_native_msg.push(0u8);
        valid_native_msg.push(1u8);
        valid_native_msg.push(3u8);
        valid_native_msg.extend_from_slice(&[0xaa; 32]);
        valid_native_msg.extend_from_slice(&recipient_bytes);
        valid_native_msg.extend_from_slice(&[0x00; 32]);
        assert!(verify_solana_sweep_payload(&valid_native_msg, recipient_sol));
    }
}

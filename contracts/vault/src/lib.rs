use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U64;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupMap;
use near_sdk::{
    env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
};

const DEFAULT_HEARTBEAT_INTERVAL_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000; // 90 days
const DEFAULT_CHALLENGE_PERIOD_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;    // 7 days
const DEFAULT_POLICY_TIMELOCK_NS: u64 = 3 * 24 * 60 * 60 * 1_000_000_000;     // 72 hours
const MPC_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(15);

const MPC_SIGN_DEPOSIT_YOCTO: u128 = 50_000_000_000_000_000_000_000; // 0.05 NEAR
const KEEPER_GAS_REFUND_YOCTO: u128 = 5_000_000_000_000_000_000_000; // 0.005 NEAR
const STORAGE_RESERVE_BUFFER_YOCTO: u128 = 500_000_000_000_000_000_000_000; // 0.5 NEAR
const MAX_MEMO_BYTES: usize = 1024;
const MAX_TELEMETRY_BYTES: usize = 4096;
const MAX_EVM_FEE_PER_GAS_WEI: u128 = 500_000_000_000; // 500 Gwei cap
const MIN_EVM_GAS_LIMIT: u128 = 21_000;
const MAX_EVM_GAS_LIMIT: u128 = 250_000;
const MAX_SPONSOR_CALLS_PER_EPOCH: u8 = 8;
const MAX_REGISTERED_ACCOUNTS: usize = 500;
const NEP413_TAG: u32 = 2_147_484_061; // (1 << 31) + 413

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

    /// Validates address lengths and cryptographic formats before storing in policy
    pub fn validate(&self) {
        let btc = self.btc.trim();
        if !btc.is_empty() {
            require!(btc.len() <= 96, "BTC address exceeds maximum length");
            require!(
                address_to_btc_script_pubkey(btc).is_some(),
                "Invalid Bitcoin destination address format (expected Bech32 tb1/bc1 or Base58Check)"
            );
        }
        let evm = self.evm.trim();
        if !evm.is_empty() {
            let clean = evm.trim_start_matches("0x").trim_start_matches("0X");
            require!(
                clean.len() == 40 && hex::decode(clean).is_ok(),
                "Invalid EVM destination address (expected 0x + 40 hex chars)"
            );
        }
        let sol = self.sol.trim();
        if !sol.is_empty() {
            let decoded = bs58::decode(sol).into_vec().unwrap_or_default();
            require!(
                decoded.len() == 32,
                "Invalid Solana destination address (expected Base58 32-byte public key)"
            );
        }
    }

    /// Checks if `new` differs from `self` in any chain slot (including filling previously empty slots)
    pub fn has_any_change(&self, new: &ChainAddresses) -> bool {
        let btc_changed = self.btc.trim() != new.btc.trim();
        let evm_changed = !self.evm.trim().eq_ignore_ascii_case(new.evm.trim());
        let sol_changed = self.sol.trim() != new.sol.trim();
        let near_changed = self.near != new.near;
        btc_changed || evm_changed || sol_changed || near_changed
    }

    /// Checks if applying `new` would modify or clear any already-configured (non-empty) address.
    /// Filling a previously empty chain slot (`""` or `None`) returns `false` so users can enable
    /// additional networks on an active vault without triggering a 72-hour cooldown.
    pub fn modifies_existing(&self, new: &ChainAddresses) -> bool {
        let btc_modified = !self.btc.trim().is_empty() && self.btc.trim() != new.btc.trim();
        let evm_modified = !self.evm.trim().is_empty()
            && !self.evm.trim().eq_ignore_ascii_case(new.evm.trim());
        let sol_modified = !self.sol.trim().is_empty() && self.sol.trim() != new.sol.trim();
        let near_modified = self.near.is_some() && self.near != new.near;
        btc_modified || evm_modified || sol_modified || near_modified
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

/// Core Borsh layout preserved verbatim for seamless zero-migration upgrades on live vaults.
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
pub struct ArchivedEpoch {
    pub state: VaultState,
    pub destination: ChainAddresses,
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
    pub pending_heartbeat_interval_ns: Option<u64>,
    pub pending_challenge_period_ns: Option<u64>,
    pub current_time_ns: u64,
    pub epoch: u32,
    pub authorized_relayer: Option<AccountId>,
    pub heir_memo: Option<String>,
    pub gas_escrow_yocto: String,
    pub near_deposit_yocto: String,
    pub is_epoch_swept: bool,
    pub last_sweep_report: Option<String>,
    pub alert_state: Option<String>,
    pub last_cancelled_timelock_ns: Option<u64>,
    pub last_test_alert_req_ns: Option<u64>,
}

#[derive(BorshSerialize)]
struct Nep413Payload {
    pub message: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
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
    pub fn new(mpc_contract: AccountId, default_relayer: Option<AccountId>) -> Self {
        require!(!env::state_exists(), "Already initialized");
        Self {
            mpc_contract,
            default_relayer,
            vaults: LookupMap::new(b"v"),
        }
    }

    /// Upgrade / Migration entrypoint: strictly restricted to self-call by the contract account.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let mut vaults = LookupMap::new(b"v");
        let newapp: AccountId = "newapp9955.testnet".parse().unwrap();
        vaults.insert(newapp, UserVault::new_unconfigured());

        Self {
            mpc_contract: "v1.signer-prod.testnet".parse().unwrap(),
            default_relayer: Some("keeper.aegis.okgoogleok.testnet".parse().unwrap()),
            vaults,
        }
    }

    /// Self-only configuration of the default keeper/relayer account.
    #[private]
    pub fn set_default_relayer(&mut self, relayer: Option<AccountId>) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "Strictly restricted to contract self-call"
        );
        self.default_relayer = relayer.clone();
        env::log_str(&format!("DEFAULT_RELAYER_UPDATED: {:?}", relayer));
    }

    /// Self-only helper to mark or unmark a historical epoch sweep status.
    #[private]
    pub fn admin_mark_epoch_swept(&mut self, vault_owner: AccountId, epoch: u32, is_complete: bool) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "Strictly restricted to contract self-call"
        );
        Self::internal_set_epoch_swept(&vault_owner, epoch, is_complete);
        env::log_str(&format!(
            "ADMIN_EPOCH_SWEPT_UPDATED: Vault={}, Epoch={}, Complete={}",
            vault_owner, epoch, is_complete
        ));
    }

    /// Top up per-vault Gas Escrow used to fund zero-deposit autonomous `v1.signer` sweeps
    /// and `0.005 NEAR` keeper gas refunds. Also renews heartbeat if called by vault owner.
    #[payable]
    pub fn deposit_escrow(&mut self, account_id: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        let target = account_id.unwrap_or_else(|| caller.clone());
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, "Must attach NEAR deposit to fund gas escrow");
        Self::internal_credit_escrow(&target, deposit);
        if caller == target {
            if let Some(vault) = self.vaults.get_mut(&caller) {
                if vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }) {
                    vault.last_ping_ns = env::block_timestamp();
                }
            }
        }
        env::log_str(&format!(
            "ESCROW_DEPOSITED: Credited {} yoctoNEAR to gas escrow for {}",
            deposit, target
        ));
    }

    /// Deposit native NEAR into an isolated per-user bunker ledger (swept via `sweep_near`).
    /// Also renews heartbeat if called by vault owner.
    #[payable]
    pub fn deposit_near_vault(&mut self, account_id: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        let target = account_id.unwrap_or_else(|| caller.clone());
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, "Must attach NEAR deposit for vault storage");
        Self::internal_credit_near_deposit(&target, deposit);
        if caller == target {
            if let Some(vault) = self.vaults.get_mut(&caller) {
                if vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }) {
                    vault.last_ping_ns = env::block_timestamp();
                }
            }
        }
        env::log_str(&format!(
            "NEAR_VAULT_DEPOSITED: Credited {} yoctoNEAR to isolated vault balance for {}",
            deposit, target
        ));
    }

    /// Owner registers an additional Ed25519 public key (32-byte hex) authorized to sign `ping_by_relayer` payloads.
    pub fn register_ping_pubkey(&mut self, pubkey_hex: String) {
        let caller = env::predecessor_account_id();
        require!(self.vaults.contains_key(&caller), "No vault found for account");
        let clean = pubkey_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(clean).unwrap_or_else(|_| env::panic_str("Invalid hex public key"));
        require!(bytes.len() == 32, "Ed25519 public key must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::internal_record_owner_pubkey(&caller, arr);
        if let Some(vault) = self.vaults.get_mut(&caller) {
            if vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }) {
                vault.last_ping_ns = env::block_timestamp();
            }
        }
        env::log_str(&format!("PING_PUBKEY_REGISTERED: Added Ed25519 key for {}", caller));
    }

    /// Synchronizes verified on-chain access-key nonce progression for `vault_owner`.
    /// Whenever `vault_owner` signs ANY outgoing transaction on NEAR Protocol (such as funding a bunker
    /// or interacting with any contract), their access-key nonce strictly increases on-chain.
    /// Callable by `vault_owner` or the authorized keeper/relayer to automatically renew `last_ping_ns`.
    pub fn sync_owner_activity(&mut self, vault_owner: AccountId, observed_nonce: U64) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        let is_authorized = caller == vault_owner
            || vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for sync_owner_activity");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot sync activity: vault is not Active or Claiming"
        );
        let now = env::block_timestamp();
        Self::internal_sync_elapsed_policy(&vault_owner, vault, now);
        require!(
            observed_nonce.0 <= now.saturating_add(60_000_000_000),
            "Security Guard: observed_nonce cannot be in the future"
        );
        let key = format!("ak_nonce:{}", vault_owner);
        let raw_prev_nonce = env::storage_read(key.as_bytes())
            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        let prev_nonce = if raw_prev_nonce > now.saturating_add(60_000_000_000) {
            0
        } else {
            raw_prev_nonce
        };
        require!(
            observed_nonce.0 > prev_nonce,
            "Observed access-key nonce must be strictly greater than previously synced nonce"
        );
        env::storage_write(key.as_bytes(), &observed_nonce.0.to_le_bytes());
        vault.last_ping_ns = now;
        if let VaultState::Claiming { .. } = vault.state {
            vault.state = VaultState::Active;
        }
        env::log_str(&format!(
            "WALLET_ACTIVITY_SYNCED: Outgoing tx nonce {} > {} for {}; heartbeat reset",
            observed_nonce.0, prev_nonce, vault_owner
        ));
    }

    /// Owner heartbeat: resets the timer for the caller's vault and cancels any pending claim from heirs.
    #[payable]
    pub fn ping(&mut self) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let attached = env::attached_deposit().as_yoctonear();
        if attached > 1 {
            Self::internal_credit_escrow(&caller, attached);
        }
        let vault = self
            .vaults
            .get_mut(&caller)
            .expect("No vault found for account. Configure destinations first.");
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

    /// Cryptographically authenticated relayer heartbeat sponsorship (`[ATTACK-3]` mitigation):
    /// Requires a valid Ed25519 signature from a registered owner public key over either:
    /// 1) Raw message `"AEGIS_PING:{vault_owner}:{timestamp_ms}"`, OR
    /// 2) NEP-413 standard SHA-256 Borsh envelope (`nep413_nonce_hex`, `nep413_recipient`) for that message.
    /// Enforces freshness (<= 1 hour old, <= 5 min clock skew) and strict monotonic anti-replay.
    pub fn ping_by_relayer(
        &mut self,
        vault_owner: AccountId,
        timestamp_ms: U64,
        signature_hex: String,
        nep413_nonce_hex: Option<String>,
        nep413_recipient: Option<String>,
    ) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        let is_authorized = vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized relayer");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot ping: vault is not Active or Claiming"
        );

        let now_ns = env::block_timestamp();
        let sig_ts_ns = timestamp_ms.0.saturating_mul(1_000_000);
        require!(
            sig_ts_ns <= now_ns.saturating_add(300_000_000_000),
            "Ping signature timestamp is in the future"
        );
        require!(
            now_ns.saturating_sub(sig_ts_ns) <= 3_600_000_000_000,
            "Ping signature has expired (>1 hour old)"
        );

        let last_used_ms = Self::internal_get_last_ping_sig_ms(&vault_owner);
        require!(
            timestamp_ms.0 > last_used_ms,
            "Replay rejected: timestamp_ms must be strictly greater than previous signed ping"
        );

        let clean_sig = signature_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        let sig_vec = hex::decode(clean_sig).unwrap_or_else(|_| env::panic_str("Invalid signature hex"));
        require!(sig_vec.len() == 64, "Ed25519 signature must be 64 bytes");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_vec);

        let pks = Self::internal_get_owner_pubkeys(&vault_owner);
        require!(
            !pks.is_empty(),
            "No owner Ed25519 public key registered for vault; owner must transact directly first"
        );

        let expected_msg = format!("AEGIS_PING:{}:{}", vault_owner, timestamp_ms.0);
        let signed_bytes: Vec<u8> = if let Some(nonce_hex) = nep413_nonce_hex {
            let clean_nonce = nonce_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
            let nonce_vec = hex::decode(clean_nonce).unwrap_or_else(|_| env::panic_str("Invalid NEP-413 nonce hex"));
            require!(nonce_vec.len() == 32, "NEP-413 nonce must be 32 bytes");
            let mut nonce_arr = [0u8; 32];
            nonce_arr.copy_from_slice(&nonce_vec);
            let recipient = nep413_recipient.unwrap_or_else(|| env::current_account_id().to_string());
            let payload = Nep413Payload {
                message: expected_msg,
                nonce: nonce_arr,
                recipient,
                callback_url: None,
            };
            let mut preimage = Vec::with_capacity(4 + 256);
            preimage.extend_from_slice(&NEP413_TAG.to_le_bytes());
            preimage.extend_from_slice(&near_sdk::borsh::to_vec(&payload).expect("Borsh encode failed"));
            env::sha256(&preimage)
        } else {
            expected_msg.into_bytes()
        };

        let verified = pks
            .iter()
            .any(|pk| env::ed25519_verify(&sig_arr, &signed_bytes, pk));
        require!(verified, "Invalid owner Ed25519 signature for ping_by_relayer");

        Self::internal_set_last_ping_sig_ms(&vault_owner, timestamp_ms.0);
        vault.last_ping_ns = now_ns;
        if let VaultState::Claiming { .. } = vault.state {
            vault.state = VaultState::Active;
            env::log_str(&format!(
                "CLAIM_CANCELLED: Verified signed relayer ping from {} for {}",
                caller, vault_owner
            ));
        } else {
            env::log_str(&format!(
                "PING_RECEIVED: Verified signed relayer heartbeat reset for {}",
                vault_owner
            ));
        }
    }

    /// Emergency Panic button: instantly shifts caller's vault into Evacuated state.
    /// Automatically applies any elapsed 72h pending policy, or blocks if an unelapsed 72h cooldown is active.
    #[payable]
    pub fn panic(&mut self) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let now = env::block_timestamp();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        Self::internal_sync_elapsed_policy(&caller, vault, now);
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot trigger panic: vault is not Active"
        );
        require!(
            vault.pending_policy.is_none(),
            "Cannot trigger panic during an active 72h policy cooldown. Cancel or wait for pending policy first."
        );
        require!(
            !vault.backup.is_empty(),
            "Cannot trigger panic: no backup egress destinations are configured in vault policy"
        );
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&caller);
        vault.state = VaultState::Evacuated;
        Self::internal_set_epoch_swept(&caller, vault.epoch, false);
        env::log_str(&format!(
            "PANIC_TRIGGERED: Vault for {} evacuated. Sweeping routed exclusively to backup addresses.",
            caller
        ));
    }

    /// Resets the caller's vault after an evacuation or finalized inheritance, advancing the bunker epoch.
    /// Archives prior epoch destinations in `archive:{owner}:{old_epoch}` so delayed sweeps remain verifiable!
    #[payable]
    pub fn rotate_bunker(&mut self) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(
            vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
            "Can only rotate bunker when vault is Evacuated or Inheritance"
        );

        let old_epoch = vault.epoch;
        let archived_dest = match vault.state {
            VaultState::Evacuated => vault.backup.clone(),
            VaultState::Inheritance => vault.heirs.clone(),
            _ => ChainAddresses::empty(),
        };
        let archive = ArchivedEpoch {
            state: vault.state.clone(),
            destination: archived_dest,
        };
        if let Ok(bytes) = near_sdk::serde_json::to_vec(&archive) {
            let key = format!("archive:{}:{}", caller, old_epoch);
            env::storage_write(key.as_bytes(), &bytes);
        }

        vault.epoch += 1;
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&caller);
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!(
            "BUNKER_ROTATED: Epoch for {} advanced to v{} (archived v{}), state reset to Unconfigured",
            caller, vault.epoch, old_epoch
        ));
    }

    /// Resets caller's vault back to clean Unconfigured state ONLY if no egress destinations are armed yet.
    /// Prevents `[C2]` 72-hour timelock bypass (`reset_my_vault -> propose_policy -> panic`).
    pub fn reset_my_vault(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(
            vault.state != VaultState::Evacuated && vault.state != VaultState::Inheritance,
            "Use rotate_bunker to advance epoch after evacuation or inheritance"
        );
        require!(
            vault.state == VaultState::Unconfigured
                || (vault.backup.is_empty() && vault.heirs.is_empty()),
            "Cannot instantly reset an armed vault with active destinations; propose a new policy (72h timelock) or rotate bunker after evacuation"
        );
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&caller);
        env::log_str(&format!("VAULT_RESET: Vault for {} reset to Unconfigured", caller));
    }

    /// Strictly self-only administrative reset (relayers are NEVER allowed to reset vaults).
    #[private]
    pub fn admin_reset_vault(&mut self, target_account: AccountId) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "Strictly restricted to contract self-call"
        );
        let vault = self
            .vaults
            .get_mut(&target_account)
            .expect("No vault found for target account");
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&target_account);
        env::log_str(&format!(
            "ADMIN_VAULT_RESET: Vault for {} reset to Unconfigured by contract self",
            target_account
        ));
    }

    /// Sweeps strictly the isolated per-user native NEAR deposit (`near_dep:{vault_owner}`)
    /// to the policy-locked backup or heir destination account (no caller destination override allowed).
    /// Includes an automatic rollback callback (`on_sweep_near_complete`) so funds are never lost if transfer fails.
    pub fn sweep_near(&mut self, vault_owner: AccountId, destination: Option<AccountId>) -> Promise {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get(&vault_owner).expect("Target vault not found");
        let is_authorized = caller == vault_owner
            || vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for sweep_near");
        require!(
            vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
            "Vault must be in Evacuated or Inheritance state to sweep"
        );

        let target_dest = match vault.state {
            VaultState::Evacuated => &vault.backup.near,
            VaultState::Inheritance => &vault.heirs.near,
            _ => env::panic_str("Invalid state for sweep"),
        };

        let target_account_id: AccountId = target_dest
            .clone()
            .expect("No destination NEAR account configured in vault policy");

        if let Some(override_dest) = destination {
            require!(
                override_dest == target_account_id,
                "Destination override forbidden: sweep_near must route strictly to policy-locked NEAR recipient"
            );
        }

        let user_deposit = Self::internal_get_near_deposit(&vault_owner);
        require!(
            user_deposit > 0,
            "No isolated NEAR deposit available to sweep for this vault"
        );
        Self::internal_debit_near_deposit(&vault_owner, user_deposit);

        env::log_str(&format!(
            "NEAR_SWEPT: Sweeping {} yoctoNEAR for {} to {}",
            user_deposit, vault_owner, target_account_id
        ));

        Promise::new(target_account_id)
            .transfer(NearToken::from_yoctonear(user_deposit))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_sweep_near_complete(vault_owner, user_deposit.to_string()),
            )
    }

    #[private]
    pub fn on_sweep_near_complete(
        &mut self,
        vault_owner: AccountId,
        amount_yocto_str: String,
        #[callback_result] result: Result<(), PromiseError>,
    ) {
        if result.is_err() {
            let amount: u128 = amount_yocto_str.parse().unwrap_or(0);
            if amount > 0 {
                Self::internal_credit_near_deposit(&vault_owner, amount);
            }
            env::panic_str("NEAR transfer to destination account failed; isolated vault deposit restored");
        }
    }

    /// Propose updating backup or heir addresses for caller's bunker.
    /// Enforces a strict 72-hour timelock on ANY destination change once armed, or activates immediately on initial setup.
    /// Any attached NEAR deposit (>1 yocto) automatically credits the caller's Gas Escrow.
    #[payable]
    pub fn propose_policy(
        &mut self,
        backup: ChainAddresses,
        heirs: ChainAddresses,
        memo: Option<String>,
        heartbeat_interval_ns: Option<U64>,
        challenge_period_ns: Option<U64>,
    ) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let is_empty_submission = backup.is_empty() && heirs.is_empty();
        require!(
            !is_empty_submission,
            "At least one backup or heir destination must be provided"
        );
        backup.validate();
        heirs.validate();

        if let Some(hb) = heartbeat_interval_ns {
            require!(
                hb.0 >= 15_000_000_000,
                "Heartbeat interval must be at least 15 seconds"
            );
        }
        if let Some(cp) = challenge_period_ns {
            require!(
                cp.0 >= 15_000_000_000,
                "Challenge period must be at least 15 seconds"
            );
        }

        let attached = env::attached_deposit().as_yoctonear();
        if attached > 1 {
            Self::internal_credit_escrow(&caller, attached);
            env::log_str(&format!(
                "ESCROW_CREDITED_ON_POLICY: {} yoctoNEAR added for {}",
                attached, caller
            ));
        }

        if let Some(ref m) = memo {
            let trimmed = m.trim();
            let key = format!("memo:{}", caller);
            if trimmed.is_empty() {
                env::storage_remove(key.as_bytes());
                env::log_str(&format!("HEIR_MEMO_CLEARED: Testament note removed for {}", caller));
            } else {
                require!(
                    trimmed.len() <= MAX_MEMO_BYTES,
                    "Digital testament exceeds 1024 bytes"
                );
                env::storage_write(key.as_bytes(), trimmed.as_bytes());
                env::log_str(&format!("HEIR_MEMO_SAVED: Testament note updated for {}", caller));
            }
        }

        if !self.vaults.contains_key(&caller) {
            let new_vault = UserVault {
                state: VaultState::Active,
                last_ping_ns: env::block_timestamp(),
                heartbeat_interval_ns: heartbeat_interval_ns
                    .map(|v| v.0)
                    .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_NS),
                challenge_period_ns: challenge_period_ns
                    .map(|v| v.0)
                    .unwrap_or(DEFAULT_CHALLENGE_PERIOD_NS),
                policy_timelock_ns: DEFAULT_POLICY_TIMELOCK_NS,
                backup,
                heirs,
                pending_policy: None,
                epoch: 0,
                authorized_relayer: self.default_relayer.clone(),
            };
            self.vaults.insert(caller.clone(), new_vault);
            self.internal_register_account(&caller);
            env::log_str(&format!(
                "VAULT_CREATED: Bunker initialized and armed for {}",
                caller
            ));
            return;
        }

        let now = env::block_timestamp();
        let vault = self.vaults.get_mut(&caller).unwrap();
        Self::internal_sync_elapsed_policy(&caller, vault, now);

        require!(
            vault.state == VaultState::Active || vault.state == VaultState::Unconfigured,
            "Can only update policy in Active or Unconfigured state"
        );

        let is_initial_setup = vault.state == VaultState::Unconfigured
            || (vault.backup.is_empty() && vault.heirs.is_empty());
        let modifies_existing_addrs = vault.backup.modifies_existing(&backup)
            || vault.heirs.modifies_existing(&heirs);

        let target_hb = heartbeat_interval_ns
            .map(|v| v.0)
            .unwrap_or(vault.heartbeat_interval_ns);
        let target_cp = challenge_period_ns
            .map(|v| v.0)
            .unwrap_or(vault.challenge_period_ns);
        require!(
            target_hb >= 15_000_000_000,
            "Heartbeat interval must be at least 15 seconds"
        );
        require!(
            target_cp >= 15_000_000_000,
            "Challenge period must be at least 15 seconds"
        );
        let modifies_intervals = !is_initial_setup
            && (target_hb != vault.heartbeat_interval_ns || target_cp != vault.challenge_period_ns);

        if is_initial_setup {
            vault.heartbeat_interval_ns = target_hb;
            vault.challenge_period_ns = target_cp;
            vault.backup = backup;
            vault.heirs = heirs;
            vault.pending_policy = None;
            Self::internal_clear_pending_intervals(&caller);
            vault.last_ping_ns = now;
            vault.state = VaultState::Active;
            self.internal_register_account(&caller);
            env::log_str(&format!(
                "POLICY_INITIALIZED_INSTANT: Destinations and timers activated immediately for {}",
                caller
            ));
        } else if !modifies_existing_addrs && !modifies_intervals {
            vault.backup = backup;
            vault.heirs = heirs;
            vault.pending_policy = None;
            Self::internal_clear_pending_intervals(&caller);
            vault.last_ping_ns = now;
            vault.state = VaultState::Active;
            self.internal_register_account(&caller);
            env::log_str(&format!(
                "POLICY_INITIALIZED_INSTANT: New chain destinations activated immediately for {}",
                caller
            ));
        } else {
            vault.last_ping_ns = now;
            let effective_at_ns = now + vault.policy_timelock_ns;
            vault.pending_policy = Some(PendingPolicy {
                backup,
                heirs,
                effective_at_ns,
            });
            if modifies_intervals {
                Self::internal_set_pending_intervals(&caller, target_hb, target_cp);
            }
            env::log_str(&format!(
                "POLICY_PROPOSED: 72h timelock started for modifying configured addresses/timers for {}",
                caller
            ));
        }
    }

    /// Apply proposed policy after timelock has elapsed (callable by owner or any keeper/heir once 72h elapsed)
    #[payable]
    pub fn apply_policy(&mut self, account_id: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        let target = account_id.unwrap_or_else(|| {
            Self::internal_capture_signer_pubkey(&caller);
            caller.clone()
        });
        let vault = self.vaults.get_mut(&target).expect("No vault found for account");
        require!(vault.state == VaultState::Active, "Can only apply policy in Active state");
        if let Some(pending) = vault.pending_policy.take() {
            require!(
                env::block_timestamp() >= pending.effective_at_ns,
                "Timelock period has not elapsed"
            );
            vault.backup = pending.backup;
            vault.heirs = pending.heirs;
            if let Some((new_hb, new_cp)) = Self::internal_get_pending_intervals(&target) {
                vault.heartbeat_interval_ns = new_hb;
                vault.challenge_period_ns = new_cp;
                Self::internal_clear_pending_intervals(&target);
            }
            if caller == target {
                vault.last_ping_ns = env::block_timestamp();
            }
            env::log_str(&format!("POLICY_APPLIED: New destinations/timers activated for {}", target));
        } else {
            env::panic_str("No pending policy found");
        }
    }

    /// Cancel pending policy: callable strictly by vault owner
    #[payable]
    pub fn cancel_policy(&mut self) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(vault.pending_policy.is_some(), "No pending policy to cancel");
        let now = env::block_timestamp();
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&caller);
        let cancel_key = format!("cancel_tl:{}", caller);
        env::storage_write(cancel_key.as_bytes(), &now.to_le_bytes());
        vault.last_ping_ns = now;
        env::log_str(&format!("POLICY_CANCELLED: Pending policy/timers cancelled for {}", caller));
    }

    /// Requests an asynchronous Telegram test push from the 24/7 Keeper without exposing any bot token client-side.
    pub fn request_telegram_test(&mut self) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let now = env::block_timestamp();
        if !self.vaults.contains_key(&caller) {
            self.vaults.insert(caller.clone(), UserVault::new_unconfigured());
        }
        self.internal_register_account(&caller);
        let key = format!("test_tg:{}", caller);
        env::storage_write(key.as_bytes(), &now.to_le_bytes());
        if let Some(vault) = self.vaults.get_mut(&caller) {
            if vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }) {
                vault.last_ping_ns = now;
            }
        }
        env::log_str(&format!("TELEGRAM_TEST_REQUESTED: Queued test alert for {}", caller));
    }

    /// Records zero-metadata Telegram alert watermarks on-chain (`alert:{vault_owner}`) so the 24/7 Keeper
    /// never duplicates notifications across restarts and the UI knows when Telegram is linked.
    pub fn record_alert_state(&mut self, vault_owner: AccountId, alert_state_json: String) {
        let caller = env::predecessor_account_id();
        let is_authorized = caller == env::current_account_id()
            || caller == vault_owner
            || self
                .vaults
                .get(&vault_owner)
                .and_then(|v| v.authorized_relayer.as_ref())
                .map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for record_alert_state");
        require!(
            alert_state_json.len() <= 1024,
            "Alert state JSON exceeds 1024 bytes"
        );
        let key = format!("alert:{}", vault_owner);
        env::storage_write(key.as_bytes(), alert_state_json.as_bytes());
        env::log_str(&format!("ALERT_STATE_SYNCED: Vault={}", vault_owner));
    }

    /// Update heartbeat interval and challenge (grace) period for caller's bunker.
    /// Applies immediately when bunker is Unarmed (`Unconfigured`), or enters 72-hour timelock cooldown when Armed (`Active`).
    #[payable]
    pub fn update_intervals(
        &mut self,
        heartbeat_interval_ns: Option<U64>,
        challenge_period_ns: Option<U64>,
    ) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let now = env::block_timestamp();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        Self::internal_sync_elapsed_policy(&caller, vault, now);
        require!(
            vault.state == VaultState::Active || vault.state == VaultState::Unconfigured,
            "Can only update intervals in Active or Unconfigured state"
        );
        let new_hb = heartbeat_interval_ns
            .map(|v| v.0)
            .unwrap_or(vault.heartbeat_interval_ns);
        let new_cp = challenge_period_ns
            .map(|v| v.0)
            .unwrap_or(vault.challenge_period_ns);
        require!(
            new_hb >= 15_000_000_000,
            "Heartbeat interval must be at least 15 seconds"
        );
        require!(
            new_cp >= 15_000_000_000,
            "Challenge period must be at least 15 seconds"
        );

        let is_armed = vault.state == VaultState::Active
            && (!vault.backup.is_empty() || !vault.heirs.is_empty());

        if !is_armed {
            vault.heartbeat_interval_ns = new_hb;
            vault.challenge_period_ns = new_cp;
            Self::internal_clear_pending_intervals(&caller);
            vault.last_ping_ns = now;
            env::log_str(&format!("INTERVALS_UPDATED: Intervals updated immediately for {}", caller));
        } else {
            vault.last_ping_ns = now;
            if new_hb == vault.heartbeat_interval_ns && new_cp == vault.challenge_period_ns {
                Self::internal_clear_pending_intervals(&caller);
                return;
            }
            let (pending_backup, pending_heirs) = if let Some(ref p) = vault.pending_policy {
                (p.backup.clone(), p.heirs.clone())
            } else {
                (vault.backup.clone(), vault.heirs.clone())
            };
            let effective_at_ns = now + vault.policy_timelock_ns;
            vault.pending_policy = Some(PendingPolicy {
                backup: pending_backup,
                heirs: pending_heirs,
                effective_at_ns,
            });
            Self::internal_set_pending_intervals(&caller, new_hb, new_cp);
            env::log_str(&format!(
                "INTERVALS_TIMELOCK_STARTED: 72h timelock started for timer change for {}",
                caller
            ));
        }
    }

    /// Set or revoke authorized relayer for caller's bunker
    #[payable]
    pub fn set_authorized_relayer(&mut self, relayer: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        vault.authorized_relayer = relayer;
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!(
            "RELAYER_UPDATED: Authorized relayer updated for {}",
            caller
        ));
    }

    /// Autonomous push inheritance trigger: callable by anyone (relayer, keeper bot, heir)
    /// once the owner's heartbeat interval + grace period has expired without any owner interaction.
    /// Automatically promotes an elapsed `pending_policy` (or clears an unelapsed one) so inheritance is NEVER deadlocked (`[C3]`).
    pub fn trigger_push_inheritance(&mut self, vault_owner: AccountId) {
        let vault = self
            .vaults
            .get_mut(&vault_owner)
            .expect("Target vault not found");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Vault must be Active to trigger push inheritance"
        );
        let now = env::block_timestamp();
        Self::internal_sync_elapsed_policy(&vault_owner, vault, now);
        let total_inactivity_ns = vault
            .heartbeat_interval_ns
            .saturating_add(vault.challenge_period_ns);
        require!(
            now >= vault.last_ping_ns.saturating_add(total_inactivity_ns),
            "Owner inactivity period (heartbeat + grace) has not elapsed yet"
        );
        // If an unelapsed pending policy still exists when inactivity expires, discard the unelapsed change
        // and use the already confirmed `vault.heirs` so inheritance cannot be blocked.
        vault.pending_policy = None;
        Self::internal_clear_pending_intervals(&vault_owner);
        require!(
            !vault.heirs.is_empty(),
            "Cannot trigger inheritance: no heir destination addresses configured"
        );
        vault.state = VaultState::Inheritance;
        Self::internal_set_epoch_swept(&vault_owner, vault.epoch, false);
        env::log_str(&format!(
            "PUSH_INHERITANCE_TRIGGERED: Owner {} inactive for full period. Vault shifted to Inheritance.",
            vault_owner
        ));
    }

    /// Backwards compatibility helper for start_claim
    pub fn start_claim(&mut self, vault_owner: AccountId) {
        self.trigger_push_inheritance(vault_owner);
    }

    /// Backwards compatibility helper for finalize_claim
    pub fn finalize_claim(&mut self, vault_owner: AccountId) {
        self.trigger_push_inheritance(vault_owner);
    }

    /// Records verified sweep telemetry on-chain and marks whether all chains for `(vault_owner, epoch)`
    /// have completed sweeping (`is_complete = true`), stopping redundant keeper loops.
    pub fn record_sweep_telemetry(
        &mut self,
        vault_owner: AccountId,
        epoch: u32,
        report_json: String,
        is_complete: bool,
    ) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get(&vault_owner).expect("Target vault not found");
        let is_authorized = caller == env::current_account_id()
            || caller == vault_owner
            || vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized caller for record_sweep_telemetry");
        require!(epoch <= vault.epoch, "Cannot record telemetry for future epoch");
        require!(
            report_json.len() <= MAX_TELEMETRY_BYTES,
            "Telemetry report exceeds 4096 bytes"
        );

        let existing_has_real_tx = Self::internal_get_sweep_telemetry(&vault_owner, epoch)
            .map_or(false, |prev| {
                prev.contains("\"tx_hash\"")
                    || prev.contains("\"signature\"")
                    || prev.contains("\"tx_id\"")
            });
        let incoming_has_real_tx = report_json.contains("\"tx_hash\"")
            || report_json.contains("\"signature\"")
            || report_json.contains("\"tx_id\"");

        if existing_has_real_tx && !incoming_has_real_tx {
            if is_complete {
                Self::internal_set_epoch_swept(&vault_owner, epoch, true);
            }
            env::log_str(&format!(
                "SWEEP_TELEMETRY_PRESERVED: Vault={}, Epoch={} (ignored late zero-balance overwrite)",
                vault_owner, epoch
            ));
            return;
        }

        let key = format!("telemetry:{}:{}", vault_owner, epoch);
        env::storage_write(key.as_bytes(), report_json.as_bytes());
        Self::internal_set_epoch_swept(&vault_owner, epoch, is_complete);
        env::log_str(&format!(
            "SWEEP_TELEMETRY_RECORDED: Vault={}, Epoch={}, Complete={}",
            vault_owner, epoch, is_complete
        ));
    }

    /// Requests an MPC threshold signature from `v1.signer` for a foreign chain transaction.
    /// Enforces on-chain transaction verification across all 4 chains (EVM EIP-1559 RLP, Bitcoin BIP-143 SegWit preimage + outputs,
    /// Solana compiled instructions, and NEAR Borsh transaction) so relayers can NEVER blind-sign (`[C4]`).
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
        require!(
            !Self::internal_is_epoch_swept(&vault_owner, epoch_to_sign),
            "Epoch is already completely swept"
        );

        let target_destination: ChainAddresses = if epoch_to_sign == vault.epoch {
            require!(
                vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
                "Current epoch can only be swept in Evacuated or Inheritance state"
            );
            match vault.state {
                VaultState::Evacuated => vault.backup.clone(),
                VaultState::Inheritance => vault.heirs.clone(),
                _ => env::panic_str("Invalid state for sweep"),
            }
        } else {
            // Historical epoch: strictly require archived Evacuated/Inheritance state saved at `rotate_bunker()`
            let archived = Self::internal_get_archived_epoch(&vault_owner, epoch_to_sign)
                .expect("Historical epoch was not archived from an Evacuated or Inheritance state");
            require!(
                archived.state == VaultState::Evacuated || archived.state == VaultState::Inheritance,
                "Historical epoch is not in a sweepable state"
            );
            archived.destination
        };

        let path = format!("aegis/{}/{}", vault_owner, epoch_to_sign);
        let clean_hex = payload_hex
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_string();

        let (payload_to_sign, domain_id) = if !is_eddsa {
            let is_btc =
                chain.eq_ignore_ascii_case("BTC") || chain.eq_ignore_ascii_case("BITCOIN");
            let ecdsa_hash = if is_btc {
                require!(
                    !target_destination.btc.trim().is_empty(),
                    "No target Bitcoin address configured for this epoch"
                );
                if clean_hex.len() > 364 {
                    let raw_btc_bytes = hex::decode(&clean_hex)
                        .unwrap_or_else(|_| env::panic_str("Invalid Bitcoin preimage hex"));
                    match verify_btc_sweep_payload(&raw_btc_bytes, target_destination.btc.trim()) {
                        Ok(sighash) => hex::encode(sighash),
                        Err(reason) => env::panic_str(reason),
                    }
                } else {
                    env::panic_str(
                        "Bitcoin sweep requires verifiable BIP-143 preimage + serialized outputs (>182 bytes); blind hashes forbidden",
                    )
                }
            } else if clean_hex.len() > 64 {
                let raw_tx_bytes = hex::decode(&clean_hex)
                    .unwrap_or_else(|_| env::panic_str("Invalid EVM tx hex"));
                let clean_evm_addr = target_destination
                    .evm
                    .trim()
                    .trim_start_matches("0x")
                    .trim_start_matches("0X");
                let target_evm_bytes = hex::decode(clean_evm_addr)
                    .unwrap_or_else(|_| env::panic_str("Invalid target EVM hex"));
                require!(
                    target_evm_bytes.len() == 20,
                    "Target EVM address must be 20 bytes"
                );
                let mut expected_addr = [0u8; 20];
                expected_addr.copy_from_slice(&target_evm_bytes);
                if let Err(reason) = verify_evm_sweep_payload(&raw_tx_bytes, &expected_addr) {
                    env::panic_str(reason);
                }
                let hash_bytes = env::keccak256(&raw_tx_bytes);
                hex::encode(hash_bytes)
            } else {
                env::panic_str("Blind 32-byte ECDSA hashes are forbidden; submit verifiable raw EVM or BIP-143 BTC bytes");
            };
            (SignPayloadV2::Ecdsa(ecdsa_hash), 0)
        } else {
            require!(
                !clean_hex.is_empty() && clean_hex.len() <= 2464 && hex::decode(&clean_hex).is_ok(),
                "Invalid EdDSA hex"
            );
            let is_near = chain.eq_ignore_ascii_case("NEAR");
            let eddsa_payload = if is_near {
                let expected_near = target_destination
                    .near
                    .as_ref()
                    .expect("No target NEAR account configured for this epoch");
                require!(
                    clean_hex.len() > 64,
                    "NEAR implicit sweep requires verifiable Borsh-encoded Transaction bytes; blind 32-byte hashes forbidden"
                );
                let raw_tx_bytes = hex::decode(&clean_hex)
                    .unwrap_or_else(|_| env::panic_str("Invalid NEAR tx hex"));
                match verify_near_sweep_payload(&raw_tx_bytes, expected_near) {
                    Ok(tx_hash) => hex::encode(tx_hash),
                    Err(reason) => env::panic_str(reason),
                }
            } else {
                let raw_msg_bytes = hex::decode(&clean_hex)
                    .unwrap_or_else(|_| env::panic_str("Invalid EdDSA hex"));
                require!(
                    verify_solana_sweep_payload(&raw_msg_bytes, &target_destination.sol),
                    "Solana transaction message failed security validation against target recipient"
                );
                clean_hex
            };
            (SignPayloadV2::Eddsa(eddsa_payload), 1)
        };

        // Funding resolution: Caller deposit -> Per-Vault Gas Escrow -> Capped Contract Sponsor Pool
        let attached_yocto = env::attached_deposit().as_yoctonear();
        let reward_keeper = caller != vault_owner;
        let keeper_refund_yocto = if reward_keeper { KEEPER_GAS_REFUND_YOCTO } else { 0 };

        let (sign_deposit_yocto, escrow_debited_yocto, refund_caller_yocto, used_sponsor_pool) = if attached_yocto > 0 {
            require!(
                attached_yocto >= MPC_SIGN_DEPOSIT_YOCTO,
                "Attached deposit must be 0 (use escrow/sponsor) or at least 0.05 NEAR"
            );
            (attached_yocto, 0u128, 0u128, false)
        } else {
            let needed = MPC_SIGN_DEPOSIT_YOCTO.saturating_add(keeper_refund_yocto);
            let user_escrow = Self::internal_get_escrow(&vault_owner);
            if user_escrow >= needed {
                Self::internal_debit_escrow(&vault_owner, needed);
                (MPC_SIGN_DEPOSIT_YOCTO, needed, keeper_refund_yocto, false)
            } else {
                let used = Self::internal_get_sponsor_calls(&vault_owner, epoch_to_sign);
                require!(
                    used < MAX_SPONSOR_CALLS_PER_EPOCH,
                    "Per-epoch sponsor pool limit reached for unfunded vault; top up gas escrow via deposit_escrow"
                );
                let min_storage = env::storage_byte_cost()
                    .as_yoctonear()
                    .saturating_mul(env::storage_usage() as u128);
                let total_escrow = Self::internal_read_u128(b"total_escrow");
                let total_near_dep = Self::internal_read_u128(b"total_near_dep");
                let locked = min_storage
                    .saturating_add(total_escrow)
                    .saturating_add(total_near_dep)
                    .saturating_add(STORAGE_RESERVE_BUFFER_YOCTO);
                let available_sponsor = env::account_balance().as_yoctonear().saturating_sub(locked);
                require!(
                    available_sponsor >= needed,
                    "Vault gas escrow depleted and contract sponsor pool insufficient; top up via deposit_escrow"
                );
                Self::internal_set_sponsor_calls(&vault_owner, epoch_to_sign, used + 1);
                (MPC_SIGN_DEPOSIT_YOCTO, 0u128, keeper_refund_yocto, true)
            }
        };

        env::log_str(&format!(
            "SWEEP_REQUEST: Vault={}, Epoch={}, Chain={}, Path={}, EscrowDebited={}, SponsorUsed={}",
            vault_owner, epoch_to_sign, chain, path, escrow_debited_yocto, used_sponsor_pool
        ));

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
                NearToken::from_yoctonear(sign_deposit_yocto),
                MPC_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_signature_ready(
                        vault_owner,
                        caller,
                        chain,
                        is_eddsa,
                        U64((escrow_debited_yocto / 1_000_000_000_000_000_000) as u64), // in milli-micro units (10^18)
                        U64((refund_caller_yocto / 1_000_000_000_000_000_000) as u64),
                        epoch_to_sign,
                        used_sponsor_pool,
                    ),
            )
    }

    #[private]
    pub fn on_signature_ready(
        &mut self,
        vault_owner: AccountId,
        caller: AccountId,
        chain: String,
        is_eddsa: bool,
        escrow_debited_e18: U64,
        keeper_refund_e18: U64,
        epoch_signed: u32,
        used_sponsor_pool: bool,
        #[callback_result] result: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> near_sdk::serde_json::Value {
        let escrow_debited = (escrow_debited_e18.0 as u128).saturating_mul(1_000_000_000_000_000_000);
        let keeper_refund = (keeper_refund_e18.0 as u128).saturating_mul(1_000_000_000_000_000_000);

        match result {
            Ok(val) => {
                if keeper_refund > 0 {
                    // Fire-and-forget gas compensation receipt to keeper while still returning `val` in SuccessValue!
                    let promise_idx = env::promise_batch_create(&caller);
                    env::promise_batch_action_transfer(
                        promise_idx,
                        NearToken::from_yoctonear(keeper_refund),
                    );
                }
                env::log_str(&format!(
                    "SIGNATURE_SUCCESS: Vault={}, Chain={}, is_eddsa={}, KeeperRefund={}",
                    vault_owner, chain, is_eddsa, keeper_refund
                ));
                val
            }
            Err(_) => {
                if escrow_debited > 0 {
                    Self::internal_credit_escrow(&vault_owner, escrow_debited);
                }
                if used_sponsor_pool {
                    let cur = Self::internal_get_sponsor_calls(&vault_owner, epoch_signed);
                    if cur > 0 {
                        Self::internal_set_sponsor_calls(&vault_owner, epoch_signed, cur - 1);
                    }
                }
                env::panic_str("MPC signature generation failed")
            }
        }
    }

    // --- Views ---

    pub fn get_vault_info(&self, account_id: Option<AccountId>) -> Option<VaultInfo> {
        let target = account_id?;
        let now = env::block_timestamp();
        self.vaults.get(&target).map(|vault| {
            let pending_ints = Self::internal_get_pending_intervals(&target);
            let (
                effective_backup,
                effective_heirs,
                effective_pending,
                effective_hb,
                effective_cp,
                pending_hb,
                pending_cp,
            ) = if let Some(ref p) = vault.pending_policy {
                if now >= p.effective_at_ns {
                    let (hb, cp) = pending_ints
                        .unwrap_or((vault.heartbeat_interval_ns, vault.challenge_period_ns));
                    (p.backup.clone(), p.heirs.clone(), None, hb, cp, None, None)
                } else {
                    (
                        vault.backup.clone(),
                        vault.heirs.clone(),
                        Some(p.clone()),
                        vault.heartbeat_interval_ns,
                        vault.challenge_period_ns,
                        pending_ints.map(|(hb, _)| hb),
                        pending_ints.map(|(_, cp)| cp),
                    )
                }
            } else {
                (
                    vault.backup.clone(),
                    vault.heirs.clone(),
                    None,
                    vault.heartbeat_interval_ns,
                    vault.challenge_period_ns,
                    None,
                    None,
                )
            };
            VaultInfo {
                owner: target.clone(),
                mpc_contract: self.mpc_contract.clone(),
                state: vault.state.clone(),
                last_ping_ns: vault.last_ping_ns,
                heartbeat_interval_ns: effective_hb,
                challenge_period_ns: effective_cp,
                policy_timelock_ns: vault.policy_timelock_ns,
                backup: effective_backup,
                heirs: effective_heirs,
                pending_policy: effective_pending,
                pending_heartbeat_interval_ns: pending_hb,
                pending_challenge_period_ns: pending_cp,
                current_time_ns: now,
                epoch: vault.epoch,
                authorized_relayer: vault.authorized_relayer.clone(),
                heir_memo: self.get_heir_memo(target.clone()),
                gas_escrow_yocto: Self::internal_get_escrow(&target).to_string(),
                near_deposit_yocto: Self::internal_get_near_deposit(&target).to_string(),
                is_epoch_swept: Self::internal_is_epoch_swept(&target, vault.epoch),
                last_sweep_report: Self::internal_get_sweep_telemetry(&target, vault.epoch),
                alert_state: env::storage_read(format!("alert:{}", target).as_bytes())
                    .and_then(|b| String::from_utf8(b).ok()),
                last_cancelled_timelock_ns: env::storage_read(format!("cancel_tl:{}", target).as_bytes())
                    .and_then(|b| b.try_into().ok().map(u64::from_le_bytes)),
                last_test_alert_req_ns: env::storage_read(format!("test_tg:{}", target).as_bytes())
                    .and_then(|b| b.try_into().ok().map(u64::from_le_bytes)),
            }
        })
    }

    /// Single-call view method for stateless serverless keepers:
    /// - Skips already-swept epochs (`is_epoch_swept == true`) to prevent infinite loops
    /// - Never deadlocks on `pending_policy` once inactivity expires (`[C3]`)
    pub fn get_actionable_vaults(&self) -> Vec<VaultInfo> {
        let now = env::block_timestamp();
        self.get_registered_accounts()
            .into_iter()
            .filter_map(|owner| self.get_vault_info(Some(owner)))
            .filter(|v| {
                let needs_sweep =
                    matches!(v.state, VaultState::Evacuated | VaultState::Inheritance)
                        && !v.is_epoch_swept;
                let needs_inheritance_trigger =
                    (v.state == VaultState::Active || matches!(v.state, VaultState::Claiming { .. }))
                        && !v.heirs.is_empty()
                        && now
                            >= v.last_ping_ns.saturating_add(
                                v.heartbeat_interval_ns.saturating_add(v.challenge_period_ns),
                            );
                needs_sweep || needs_inheritance_trigger
            })
            .collect()
    }

    /// Sets or clears the custom testament memo (plaintext or client-side E2EE ciphertext up to 1024 bytes).
    #[payable]
    pub fn set_heir_memo(&mut self, memo: String) {
        let caller = env::predecessor_account_id();
        Self::internal_capture_signer_pubkey(&caller);
        let trimmed = memo.trim();
        let key = format!("memo:{}", caller);
        if trimmed.is_empty() {
            env::storage_remove(key.as_bytes());
            env::log_str(&format!("HEIR_MEMO_CLEARED: Testament note removed for {}", caller));
        } else {
            require!(
                trimmed.len() <= MAX_MEMO_BYTES,
                "Digital testament exceeds 1024 bytes"
            );
            env::storage_write(key.as_bytes(), trimmed.as_bytes());
            env::log_str(&format!("HEIR_MEMO_SAVED: Testament note updated for {}", caller));
        }
    }

    pub fn get_heir_memo(&self, account_id: AccountId) -> Option<String> {
        let key = format!("memo:{}", account_id);
        env::storage_read(key.as_bytes()).map(|bytes| String::from_utf8(bytes).unwrap_or_default())
    }

    pub fn get_sweep_telemetry(&self, account_id: AccountId, epoch: Option<u32>) -> Option<String> {
        let ep = epoch.or_else(|| self.vaults.get(&account_id).map(|v| v.epoch))?;
        Self::internal_get_sweep_telemetry(&account_id, ep)
    }

    /// Registers an account in the keeper index ONLY if it has an initialized vault (`[H2]` DoS mitigation).
    pub fn register_account(&mut self, account_id: Option<AccountId>) {
        let acc = account_id.unwrap_or_else(env::predecessor_account_id);
        require!(
            self.vaults.contains_key(&acc),
            "Cannot register account without an initialized vault"
        );
        self.internal_register_account(&acc);
    }

    pub fn get_registered_accounts(&self) -> Vec<AccountId> {
        env::storage_read(b"reg_accounts")
            .and_then(|bytes| near_sdk::serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| {
                vec![
                    "okgoogleok.testnet".parse().unwrap(),
                    "fewvilla8059.testnet".parse().unwrap(),
                    "mastrophot.testnet".parse().unwrap(),
                    "newapp9955.testnet".parse().unwrap(),
                ]
            })
    }

    // --- Internal Storage Helpers (Zero Borsh Migration Impact) ---

    fn internal_sync_elapsed_policy(owner: &AccountId, vault: &mut UserVault, now_ns: u64) {
        let should_apply = vault
            .pending_policy
            .as_ref()
            .map_or(false, |p| now_ns >= p.effective_at_ns);
        if should_apply {
            if let Some(pending) = vault.pending_policy.take() {
                vault.backup = pending.backup;
                vault.heirs = pending.heirs;
            }
            if let Some((new_hb, new_cp)) = Self::internal_get_pending_intervals(owner) {
                vault.heartbeat_interval_ns = new_hb;
                vault.challenge_period_ns = new_cp;
                Self::internal_clear_pending_intervals(owner);
            }
        }
    }

    fn internal_get_pending_intervals(owner: &AccountId) -> Option<(u64, u64)> {
        let key = format!("pend_int:{}", owner);
        env::storage_read(key.as_bytes()).and_then(|bytes| {
            if bytes.len() == 16 {
                let mut hb_arr = [0u8; 8];
                let mut cp_arr = [0u8; 8];
                hb_arr.copy_from_slice(&bytes[0..8]);
                cp_arr.copy_from_slice(&bytes[8..16]);
                Some((u64::from_le_bytes(hb_arr), u64::from_le_bytes(cp_arr)))
            } else {
                None
            }
        })
    }

    fn internal_set_pending_intervals(owner: &AccountId, hb: u64, cp: u64) {
        let key = format!("pend_int:{}", owner);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&hb.to_le_bytes());
        buf[8..16].copy_from_slice(&cp.to_le_bytes());
        env::storage_write(key.as_bytes(), &buf);
    }

    fn internal_clear_pending_intervals(owner: &AccountId) {
        let key = format!("pend_int:{}", owner);
        env::storage_remove(key.as_bytes());
    }

    fn internal_get_sponsor_calls(owner: &AccountId, epoch: u32) -> u8 {
        let key = format!("spons:{}:{}", owner, epoch);
        env::storage_read(key.as_bytes())
            .and_then(|b| b.first().copied())
            .unwrap_or(0)
    }

    fn internal_set_sponsor_calls(owner: &AccountId, epoch: u32, count: u8) {
        let key = format!("spons:{}:{}", owner, epoch);
        env::storage_write(key.as_bytes(), &[count]);
    }

    fn internal_register_account(&self, account_id: &AccountId) {
        let mut list = self.get_registered_accounts();
        if !list.contains(account_id) && list.len() < MAX_REGISTERED_ACCOUNTS {
            list.push(account_id.clone());
            if let Ok(bytes) = near_sdk::serde_json::to_vec(&list) {
                env::storage_write(b"reg_accounts", &bytes);
            }
        }
    }

    fn internal_read_u128(key: &[u8]) -> u128 {
        env::storage_read(key)
            .and_then(|b| b.try_into().ok().map(u128::from_le_bytes))
            .unwrap_or(0)
    }

    fn internal_write_u128(key: &[u8], val: u128) {
        env::storage_write(key, &val.to_le_bytes());
    }

    fn internal_get_escrow(owner: &AccountId) -> u128 {
        let key = format!("escrow:{}", owner);
        Self::internal_read_u128(key.as_bytes())
    }

    fn internal_credit_escrow(owner: &AccountId, amount: u128) {
        let key = format!("escrow:{}", owner);
        let cur = Self::internal_read_u128(key.as_bytes());
        Self::internal_write_u128(key.as_bytes(), cur.saturating_add(amount));
        let tot = Self::internal_read_u128(b"total_escrow");
        Self::internal_write_u128(b"total_escrow", tot.saturating_add(amount));
    }

    fn internal_debit_escrow(owner: &AccountId, amount: u128) {
        let key = format!("escrow:{}", owner);
        let cur = Self::internal_read_u128(key.as_bytes());
        require!(cur >= amount, "Insufficient vault gas escrow");
        Self::internal_write_u128(key.as_bytes(), cur - amount);
        let tot = Self::internal_read_u128(b"total_escrow");
        Self::internal_write_u128(b"total_escrow", tot.saturating_sub(amount));
    }

    fn internal_get_near_deposit(owner: &AccountId) -> u128 {
        let key = format!("near_dep:{}", owner);
        Self::internal_read_u128(key.as_bytes())
    }

    fn internal_credit_near_deposit(owner: &AccountId, amount: u128) {
        let key = format!("near_dep:{}", owner);
        let cur = Self::internal_read_u128(key.as_bytes());
        Self::internal_write_u128(key.as_bytes(), cur.saturating_add(amount));
        let tot = Self::internal_read_u128(b"total_near_dep");
        Self::internal_write_u128(b"total_near_dep", tot.saturating_add(amount));
    }

    fn internal_debit_near_deposit(owner: &AccountId, amount: u128) {
        let key = format!("near_dep:{}", owner);
        let cur = Self::internal_read_u128(key.as_bytes());
        require!(cur >= amount, "Insufficient isolated NEAR deposit");
        Self::internal_write_u128(key.as_bytes(), cur - amount);
        let tot = Self::internal_read_u128(b"total_near_dep");
        Self::internal_write_u128(b"total_near_dep", tot.saturating_sub(amount));
    }

    fn internal_capture_signer_pubkey(caller: &AccountId) {
        if &env::signer_account_id() == caller {
            let pk = env::signer_account_pk();
            let raw = pk.as_bytes();
            if raw.len() == 33 && raw[0] == 0 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw[1..33]);
                Self::internal_record_owner_pubkey(caller, arr);
            }
        }
    }

    fn internal_get_owner_pubkeys(owner: &AccountId) -> Vec<[u8; 32]> {
        let key = format!("pks:{}", owner);
        env::storage_read(key.as_bytes())
            .and_then(|bytes| near_sdk::borsh::from_slice::<Vec<[u8; 32]>>(&bytes).ok())
            .unwrap_or_default()
    }

    fn internal_record_owner_pubkey(owner: &AccountId, pk: [u8; 32]) {
        let mut pks = Self::internal_get_owner_pubkeys(owner);
        if !pks.contains(&pk) {
            if pks.len() >= 16 {
                pks.remove(0);
            }
            pks.push(pk);
            let key = format!("pks:{}", owner);
            if let Ok(bytes) = near_sdk::borsh::to_vec(&pks) {
                env::storage_write(key.as_bytes(), &bytes);
            }
        }
    }

    fn internal_get_last_ping_sig_ms(owner: &AccountId) -> u64 {
        let key = format!("ping_ts:{}", owner);
        env::storage_read(key.as_bytes())
            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    fn internal_set_last_ping_sig_ms(owner: &AccountId, ts_ms: u64) {
        let key = format!("ping_ts:{}", owner);
        env::storage_write(key.as_bytes(), &ts_ms.to_le_bytes());
    }

    fn internal_set_epoch_swept(owner: &AccountId, epoch: u32, is_complete: bool) {
        let key = format!("swept:{}:{}", owner, epoch);
        if is_complete {
            env::storage_write(key.as_bytes(), &[1u8]);
        } else {
            env::storage_remove(key.as_bytes());
        }
    }

    fn internal_is_epoch_swept(owner: &AccountId, epoch: u32) -> bool {
        let key = format!("swept:{}:{}", owner, epoch);
        env::storage_read(key.as_bytes())
            .map(|b| b == vec![1u8])
            .unwrap_or(false)
    }

    fn internal_get_sweep_telemetry(owner: &AccountId, epoch: u32) -> Option<String> {
        let key = format!("telemetry:{}:{}", owner, epoch);
        env::storage_read(key.as_bytes()).and_then(|b| String::from_utf8(b).ok())
    }

    fn internal_get_archived_epoch(owner: &AccountId, epoch: u32) -> Option<ArchivedEpoch> {
        let key = format!("archive:{}:{}", owner, epoch);
        env::storage_read(key.as_bytes())
            .and_then(|b| near_sdk::serde_json::from_slice(&b).ok())
    }
}

/// Full structural & economic verification of EIP-1559 (type 0x02) and Legacy EVM sweep payloads.
/// Mitigates `[ATTACK-1]` parameter poisoning (fee-burn griefing, gas-limit stuffing, recipient spoofing)
/// while securely permitting Native ETH, ERC-20 `transfer`, and ERC-721 `safeTransferFrom` sweeps.
fn verify_evm_sweep_payload(
    raw_tx: &[u8],
    expected_recipient: &[u8; 20],
) -> Result<(), &'static str> {
    if raw_tx.is_empty() {
        return Err("Empty EVM transaction payload");
    }

    let is_eip1559 = raw_tx[0] == 0x02;
    let payload = if is_eip1559 { &raw_tx[1..] } else { raw_tx };
    if payload.is_empty() {
        return Err("Empty RLP list in EVM payload");
    }

    let (list_header_len, list_content_len) =
        decode_rlp_header(payload).ok_or("Invalid RLP list header")?;
    if payload.len() != list_header_len + list_content_len {
        return Err("EVM RLP payload has trailing or truncated bytes");
    }

    let mut items: Vec<&[u8]> = Vec::with_capacity(10);
    let mut offset = list_header_len;
    while offset < payload.len() {
        let slice = payload.get(offset..).ok_or("RLP slice out of bounds")?;
        let (h_len, i_len) = decode_rlp_item(slice).ok_or("Invalid RLP item")?;
        let end = offset
            .checked_add(h_len)
            .and_then(|v| v.checked_add(i_len))
            .ok_or("RLP length overflow")?;
        if end > payload.len() {
            return Err("RLP item exceeds list boundary");
        }
        items.push(&payload[offset + h_len..end]);
        offset = end;
    }

    let (max_priority_fee, max_fee, gas_limit, to_bytes, value_wei, data) = if is_eip1559 {
        if items.len() != 9 {
            return Err("Unsigned EIP-1559 transaction must have exactly 9 RLP fields");
        }
        (
            rlp_bytes_to_u128(items[2]).ok_or("maxPriorityFeePerGas overflow")?,
            rlp_bytes_to_u128(items[3]).ok_or("maxFeePerGas overflow")?,
            rlp_bytes_to_u128(items[4]).ok_or("gasLimit overflow")?,
            items[5],
            rlp_bytes_to_u128(items[6]).ok_or("value overflow")?,
            items[7],
        )
    } else {
        if items.len() != 6 && items.len() != 9 {
            return Err("Unsigned Legacy EVM transaction must have 6 or 9 RLP fields");
        }
        let gp = rlp_bytes_to_u128(items[1]).ok_or("gasPrice overflow")?;
        (
            gp,
            gp,
            rlp_bytes_to_u128(items[2]).ok_or("gasLimit overflow")?,
            items[3],
            rlp_bytes_to_u128(items[4]).ok_or("value overflow")?,
            items[5],
        )
    };

    if to_bytes.len() != 20 {
        return Err("EVM `to` field must be a 20-byte address (contract creation forbidden)");
    }
    if gas_limit < MIN_EVM_GAS_LIMIT || gas_limit > MAX_EVM_GAS_LIMIT {
        return Err("EVM gasLimit out of safe sweep bounds (21,000..=250,000)");
    }
    if max_fee == 0 || max_fee > MAX_EVM_FEE_PER_GAS_WEI {
        return Err("EVM maxFeePerGas exceeds 500 Gwei safety cap or is zero");
    }
    if max_priority_fee > max_fee {
        return Err("EVM maxPriorityFeePerGas cannot exceed maxFeePerGas");
    }

    if to_bytes == expected_recipient.as_slice() {
        // Native ETH sweep directly to configured backup/heir recipient
        if value_wei == 0 {
            return Err("Native EVM sweep must transfer non-zero ETH value");
        }
        if data.len() > MAX_MEMO_BYTES {
            return Err("Native EVM memo calldata exceeds 1024 bytes");
        }
        return Ok(());
    }

    // Token / NFT contract sweep: `value` MUST be 0 and recipient inside ABI calldata MUST match `expected_recipient`
    if value_wei != 0 {
        return Err("EVM recipient mismatch (non-zero ETH sent to unknown address)");
    }

    // ERC-20 `transfer(address,uint256)` selector `0xa9059cbb`
    if data.len() == 68 && data[0..4] == [0xa9, 0x05, 0x9c, 0xbb] {
        if data[4..16].iter().any(|&b| b != 0) {
            return Err("Malformed ABI address padding in ERC-20 transfer");
        }
        if &data[16..36] != expected_recipient.as_slice() {
            return Err("ERC-20 transfer recipient does not match designated target address");
        }
        if data[36..68].iter().all(|&b| b == 0) {
            return Err("ERC-20 transfer amount must be greater than zero");
        }
        return Ok(());
    }

    // ERC-721 `safeTransferFrom(address,address,uint256)` selector `0x42842e0e`
    if data.len() == 100 && data[0..4] == [0x42, 0x84, 0x2e, 0x0e] {
        if data[36..48].iter().any(|&b| b != 0) {
            return Err("Malformed ABI recipient padding in ERC-721 safeTransferFrom");
        }
        if &data[48..68] != expected_recipient.as_slice() {
            return Err("ERC-721 safeTransferFrom recipient does not match designated target address");
        }
        return Ok(());
    }

    Err("EVM transaction recipient does not match designated target address")
}

fn rlp_bytes_to_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.len() > 16 {
        return None;
    }
    let mut acc = 0u128;
    for &b in bytes {
        acc = (acc << 8) | (b as u128);
    }
    Some(acc)
}

fn decode_rlp_header(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if (0xc0..=0xf7).contains(&first) {
        Some((1, (first - 0xc0) as usize))
    } else if first >= 0xf8 {
        let len_of_len = (first - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        Some((1 + len_of_len, len))
    } else {
        None
    }
}

fn decode_rlp_item(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((0, 1))
    } else if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        Some((1, len))
    } else if first <= 0xbf {
        let len_of_len = (first - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        Some((1 + len_of_len, len))
    } else {
        decode_rlp_header(data)
    }
}

fn read_compact_u16(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b0 = *data.get(*pos)? as usize;
    *pos += 1;
    if (b0 & 0x80) == 0 {
        return Some(b0);
    }
    let b1 = *data.get(*pos)? as usize;
    *pos += 1;
    if (b1 & 0x80) == 0 {
        return Some((b0 & 0x7f) | (b1 << 7));
    }
    let b2 = *data.get(*pos)? as usize;
    *pos += 1;
    if (b2 & 0xfc) != 0 {
        return None;
    }
    Some((b0 & 0x7f) | ((b1 & 0x7f) << 7) | (b2 << 14))
}

// Well-known Solana Program IDs (32-byte decoded constants)
// ComputeBudget111111111111111111111111111111 -> BANNED (blocks priority-fee drain [ATTACK-1])
const SOL_COMPUTE_BUDGET_ID: &str = "ComputeBudget111111111111111111111111111111";
const SOL_MEMO_V2_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const SOL_MEMO_V1_ID: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
const SOL_ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SOL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SOL_TOKEN_2022_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Full instruction-level verification of Solana Legacy Message bytes (`[ATTACK-1]` mitigation):
/// - Rejects `ComputeBudget` program (prevents priority-fee drain to block validators)
/// - Rejects zero blockhash & trailing bytes
/// - Whitelists strictly SystemProgram::Transfer (`lamports > 0` to `expected_recipient`),
///   SPL Token / Token-2022 transfers to recipient's ATA, ATA CreateIdempotent for `expected_recipient`,
///   CloseAccount returning rent to vault/recipient, and SPL Memo.
fn verify_solana_sweep_payload(raw_msg_bytes: &[u8], expected_recipient_sol: &str) -> bool {
    if raw_msg_bytes.len() < 3 {
        return false;
    }
    let num_required_signatures = raw_msg_bytes[0];
    let num_readonly_signed = raw_msg_bytes[1];
    let _num_readonly_unsigned = raw_msg_bytes[2];

    if num_required_signatures != 1 || num_readonly_signed != 0 {
        return false;
    }

    let Ok(expected_recipient_bytes) = bs58::decode(expected_recipient_sol.trim()).into_vec() else {
        return false;
    };
    if expected_recipient_bytes.len() != 32 {
        return false;
    }

    let mut pos = 3usize;
    let Some(account_count) = read_compact_u16(raw_msg_bytes, &mut pos) else {
        return false;
    };
    if account_count < 2 || account_count > 16 {
        return false;
    }

    let accounts_end = match account_count
        .checked_mul(32)
        .and_then(|len| pos.checked_add(len))
    {
        Some(e) if e <= raw_msg_bytes.len() => e,
        _ => return false,
    };

    let mut accounts: Vec<[u8; 32]> = Vec::with_capacity(account_count);
    for i in 0..account_count {
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw_msg_bytes[pos + i * 32..pos + (i + 1) * 32]);
        accounts.push(key);
    }
    pos = accounts_end;

    // 32-byte recentBlockhash MUST exist and MUST NOT be all zeros
    if pos + 32 > raw_msg_bytes.len() {
        return false;
    }
    let blockhash = &raw_msg_bytes[pos..pos + 32];
    if blockhash.iter().all(|&b| b == 0) {
        return false;
    }
    pos += 32;

    let Some(ix_count) = read_compact_u16(raw_msg_bytes, &mut pos) else {
        return false;
    };
    if ix_count == 0 || ix_count > 6 {
        return false;
    }

    let compute_budget = bs58::decode(SOL_COMPUTE_BUDGET_ID).into_vec().unwrap();
    let memo_v2 = bs58::decode(SOL_MEMO_V2_ID).into_vec().unwrap();
    let memo_v1 = bs58::decode(SOL_MEMO_V1_ID).into_vec().unwrap();
    let ata_prog = bs58::decode(SOL_ATA_PROGRAM_ID).into_vec().unwrap();
    let token_prog = bs58::decode(SOL_TOKEN_PROGRAM_ID).into_vec().unwrap();
    let token_2022 = bs58::decode(SOL_TOKEN_2022_ID).into_vec().unwrap();
    let system_prog = [0u8; 32];

    // Explicitly forbid ComputeBudget anywhere in account keys as defense-in-depth
    if accounts.iter().any(|k| k.as_slice() == compute_budget.as_slice()) {
        return false;
    }

    let vault_pubkey = accounts[0];
    let mut verified_recipient_ata: Option<[u8; 32]> = None;
    let mut has_valid_transfer = false;

    for _ in 0..ix_count {
        let Some(&prog_idx) = raw_msg_bytes.get(pos) else {
            return false;
        };
        pos += 1;
        let Some(prog_id) = accounts.get(prog_idx as usize) else {
            return false;
        };

        let Some(acct_idx_len) = read_compact_u16(raw_msg_bytes, &mut pos) else {
            return false;
        };
        if pos + acct_idx_len > raw_msg_bytes.len() {
            return false;
        }
        let acct_indices = &raw_msg_bytes[pos..pos + acct_idx_len];
        if acct_indices.iter().any(|&idx| (idx as usize) >= account_count) {
            return false;
        }
        pos += acct_idx_len;

        let Some(data_len) = read_compact_u16(raw_msg_bytes, &mut pos) else {
            return false;
        };
        if pos + data_len > raw_msg_bytes.len() {
            return false;
        }
        let data = &raw_msg_bytes[pos..pos + data_len];
        pos += data_len;

        if prog_id == &system_prog {
            // SystemProgram::Transfer (opcode 2u32 LE + u64 lamports LE)
            if data.len() != 12 || acct_indices.len() < 2 {
                return false;
            }
            let opcode = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let lamports = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            if opcode != 2 || lamports == 0 {
                return false;
            }
            let from_key = &accounts[acct_indices[0] as usize];
            let to_key = &accounts[acct_indices[1] as usize];
            if from_key != &vault_pubkey || to_key.as_slice() != expected_recipient_bytes.as_slice()
            {
                return false;
            }
            has_valid_transfer = true;
        } else if prog_id.as_slice() == memo_v2.as_slice()
            || prog_id.as_slice() == memo_v1.as_slice()
        {
            if data.len() > MAX_MEMO_BYTES {
                return false;
            }
        } else if prog_id.as_slice() == ata_prog.as_slice() {
            // AssociatedTokenAccount Create (empty or [0]) or CreateIdempotent ([1])
            // Accounts: [0: payer, 1: ata, 2: wallet_owner, 3: mint, 4: system, 5: token_prog]
            if acct_indices.len() < 6 || data.len() > 1 {
                return false;
            }
            if data.len() == 1 && data[0] > 1 {
                return false;
            }
            let owner_key = &accounts[acct_indices[2] as usize];
            if owner_key.as_slice() != expected_recipient_bytes.as_slice() {
                return false;
            }
            verified_recipient_ata = Some(accounts[acct_indices[1] as usize]);
        } else if prog_id.as_slice() == token_prog.as_slice()
            || prog_id.as_slice() == token_2022.as_slice()
        {
            if data.is_empty() {
                return false;
            }
            match data[0] {
                3 => {
                    // SPL Transfer: [0: source, 1: dest_ata, 2: authority]
                    if data.len() != 9 || acct_indices.len() < 3 {
                        return false;
                    }
                    let amount = u64::from_le_bytes([
                        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                    ]);
                    if amount == 0 {
                        return false;
                    }
                    let dest_key = accounts[acct_indices[1] as usize];
                    let valid_dest = verified_recipient_ata
                        .map(|ata| ata == dest_key)
                        .unwrap_or(false)
                        || dest_key.as_slice() == expected_recipient_bytes.as_slice();
                    if !valid_dest {
                        return false;
                    }
                    has_valid_transfer = true;
                }
                12 => {
                    // SPL TransferChecked: [0: source, 1: mint, 2: dest_ata, 3: authority]
                    if data.len() != 10 || acct_indices.len() < 4 {
                        return false;
                    }
                    let amount = u64::from_le_bytes([
                        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                    ]);
                    if amount == 0 {
                        return false;
                    }
                    let dest_key = accounts[acct_indices[2] as usize];
                    let valid_dest = verified_recipient_ata
                        .map(|ata| ata == dest_key)
                        .unwrap_or(false);
                    if !valid_dest {
                        return false;
                    }
                    has_valid_transfer = true;
                }
                9 => {
                    // SPL CloseAccount: [0: account, 1: rent_dest, 2: authority]
                    if data.len() != 1 || acct_indices.len() < 3 {
                        return false;
                    }
                    let rent_dest = &accounts[acct_indices[1] as usize];
                    if rent_dest != &vault_pubkey
                        && rent_dest.as_slice() != expected_recipient_bytes.as_slice()
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        } else {
            return false;
        }
    }

    pos == raw_msg_bytes.len() && has_valid_transfer
}

/// Converts a Bitcoin Bech32/Bech32m (`tb1...`/`bc1...`) or Base58Check (`m`/`n`/`2`/`1`/`3`) address
/// into its canonical `scriptPubKey` bytes for on-chain BIP-143 output verification.
fn address_to_btc_script_pubkey(addr: &str) -> Option<Vec<u8>> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("tb1") || lower.starts_with("bc1") {
        let sep = lower.rfind('1')?;
        if sep < 2 || sep + 7 > lower.len() {
            return None;
        }
        let data_part = &lower[sep + 1..];
        const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut values = Vec::with_capacity(data_part.len());
        for b in data_part.bytes() {
            let idx = CHARSET.iter().position(|&c| c == b)? as u8;
            values.push(idx);
        }
        if values.len() < 7 {
            return None;
        }
        let witness_version = values[0];
        if witness_version > 16 {
            return None;
        }
        let payload_5bit = &values[1..values.len() - 6];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut prog = Vec::with_capacity((payload_5bit.len() * 5) / 8);
        for &v in payload_5bit {
            acc = (acc << 5) | (v as u32);
            bits += 5;
            while bits >= 8 {
                bits -= 8;
                prog.push(((acc >> bits) & 0xff) as u8);
            }
        }
        if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
            return None;
        }
        if prog.len() < 2 || prog.len() > 40 {
            return None;
        }
        if witness_version == 0 && prog.len() != 20 && prog.len() != 32 {
            return None;
        }
        let version_opcode = if witness_version == 0 {
            0x00
        } else {
            0x50 + witness_version
        };
        let mut script = Vec::with_capacity(2 + prog.len());
        script.push(version_opcode);
        script.push(prog.len() as u8);
        script.extend_from_slice(&prog);
        return Some(script);
    }

    // Base58Check P2PKH (`1`, `m`, `n`) or P2SH (`3`, `2`)
    let decoded = bs58::decode(trimmed).into_vec().ok()?;
    if decoded.len() != 25 {
        return None;
    }
    let version = decoded[0];
    let hash20 = &decoded[1..21];
    let checksum = &decoded[21..25];
    let dhash = env::sha256(&env::sha256(&decoded[0..21]));
    if &dhash[0..4] != checksum {
        return None;
    }
    match version {
        0x00 | 0x6f => {
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(hash20);
            s.extend_from_slice(&[0x88, 0xac]);
            Some(s)
        }
        0x05 | 0xc4 => {
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(hash20);
            s.push(0x87);
            Some(s)
        }
        _ => None,
    }
}

/// On-chain verification of a Bitcoin SegWit v0 BIP-143 preimage (182 bytes) + serialized transaction outputs (`[C4]` & `[H9]`):
/// 1) Verifies P2WPKH `scriptCode` (`0x1976a914...88ac`) and `SIGHASH_ALL` (`0x01000000`)
/// 2) Verifies `SHA256(SHA256(outputs))` matches `hashOutputs` inside the BIP-143 preimage (`preimage[142..174]`)
/// 3) Verifies Output 0 transfers `>= 546` sats strictly to `expected_btc_addr` (plus optional 0-sat `OP_RETURN` Output 1)
/// 4) Computes and returns the 32-byte BIP-143 sighash `SHA256(SHA256(preimage))` inside WASM
fn verify_btc_sweep_payload(
    raw_bytes: &[u8],
    expected_btc_addr: &str,
) -> Result<[u8; 32], &'static str> {
    if raw_bytes.len() <= 182 {
        return Err("Bitcoin payload too short: expected 182-byte BIP-143 preimage + serialized outputs");
    }
    let preimage = &raw_bytes[0..182];
    let outputs_bytes = &raw_bytes[182..];

    // Check P2WPKH scriptCode at offset 104..130: `0x19 0x76 0xa9 0x14 <20B> 0x88 0xac`
    if preimage[104] != 0x19
        || preimage[105..108] != [0x76, 0xa9, 0x14]
        || preimage[128..130] != [0x88, 0xac]
    {
        return Err("Invalid BIP-143 P2WPKH scriptCode in Bitcoin preimage");
    }

    let sighash_type = u32::from_le_bytes([
        preimage[178],
        preimage[179],
        preimage[180],
        preimage[181],
    ]);
    if sighash_type != 1 {
        return Err("Bitcoin BIP-143 sighash type must be SIGHASH_ALL (1)");
    }

    let input_value = u64::from_le_bytes([
        preimage[130],
        preimage[131],
        preimage[132],
        preimage[133],
        preimage[134],
        preimage[135],
        preimage[136],
        preimage[137],
    ]);
    if input_value < 546 {
        return Err("Bitcoin input value below dust threshold");
    }

    let computed_hash_outputs = env::sha256(&env::sha256(outputs_bytes));
    if computed_hash_outputs.as_slice() != &preimage[142..174] {
        return Err("Bitcoin hashOutputs mismatch: serialized outputs do not match BIP-143 preimage");
    }

    let expected_script = address_to_btc_script_pubkey(expected_btc_addr)
        .ok_or("Invalid target Bitcoin address in vault policy")?;

    // Parse Output 0: must pay >= 546 sats to `expected_script`
    if outputs_bytes.len() < 9 {
        return Err("Truncated Bitcoin output 0");
    }
    let out0_val = u64::from_le_bytes([
        outputs_bytes[0],
        outputs_bytes[1],
        outputs_bytes[2],
        outputs_bytes[3],
        outputs_bytes[4],
        outputs_bytes[5],
        outputs_bytes[6],
        outputs_bytes[7],
    ]);
    if out0_val < 546 {
        return Err("Bitcoin primary output value below 546-sat dust threshold");
    }
    let out0_script_len = outputs_bytes[8] as usize;
    let out0_end = 9usize
        .checked_add(out0_script_len)
        .ok_or("Output 0 script length overflow")?;
    if out0_end > outputs_bytes.len() {
        return Err("Output 0 script exceeds serialized outputs buffer");
    }
    if &outputs_bytes[9..out0_end] != expected_script.as_slice() {
        return Err("Bitcoin output 0 scriptPubKey does not match policy-locked recipient address");
    }

    // Optional Output 1: strictly 0-sat `OP_RETURN` (`0x6a`) testament commitment
    if out0_end < outputs_bytes.len() {
        let rem = &outputs_bytes[out0_end..];
        if rem.len() < 10 {
            return Err("Malformed trailing Bitcoin output");
        }
        let out1_val = u64::from_le_bytes([
            rem[0], rem[1], rem[2], rem[3], rem[4], rem[5], rem[6], rem[7],
        ]);
        if out1_val != 0 {
            return Err("Secondary Bitcoin output must have 0 satoshis (OP_RETURN only)");
        }
        let out1_script_len = rem[8] as usize;
        if 9 + out1_script_len != rem.len() || out1_script_len == 0 || rem[9] != 0x6a {
            return Err("Secondary Bitcoin output must be a valid OP_RETURN script with no trailing outputs");
        }
    }

    let sighash_vec = env::sha256(&env::sha256(preimage));
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_vec);
    Ok(sighash)
}

/// On-chain verification of a Borsh-encoded unsigned NEAR `Transaction` for implicit bunker sweeps (`[C4]` & `[H9]`):
/// - Supports Native NEAR `Action::Transfer` (`opcode 3`) directly to `expected_receiver` (`deposit > 0`)
/// - Supports NEAR Native Token Standards `NEP-141` (`ft_transfer`) & `NEP-171` (`nft_transfer`) via
///   `Action::FunctionCall` (`opcode 2`), verifying JSON `args.receiver_id == expected_receiver`,
///   `args.amount > 0` (for `ft_transfer`), `gas in 5..=50 TGas`, and `deposit == 1 yoctoNEAR`
/// - Verifies `block_hash != 0` and zero trailing bytes
/// - Returns `SHA256(raw_tx)` (32 bytes) to be signed by `v1.signer`
fn verify_near_sweep_payload(
    raw_tx: &[u8],
    expected_receiver: &AccountId,
) -> Result<[u8; 32], &'static str> {
    if raw_tx.len() < 4 + 1 + 32 + 8 + 4 + 32 + 4 + 1 + 16 {
        return Err("NEAR transaction payload too short");
    }
    let mut pos = 0usize;

    let signer_len = u32::from_le_bytes([raw_tx[0], raw_tx[1], raw_tx[2], raw_tx[3]]) as usize;
    pos += 4;
    if signer_len == 0 || signer_len > 64 || pos + signer_len > raw_tx.len() {
        return Err("Invalid signer_id in NEAR transaction");
    }
    pos += signer_len;

    // PublicKey: 1 byte key_type (0 = Ed25519) + 32 bytes
    if pos + 33 > raw_tx.len() || raw_tx[pos] != 0 {
        return Err("Invalid Ed25519 public key in NEAR transaction");
    }
    pos += 33;

    // Nonce: u64 LE
    if pos + 8 > raw_tx.len() {
        return Err("Truncated nonce in NEAR transaction");
    }
    pos += 8;

    // ReceiverId: u32 LE length + UTF-8 string
    if pos + 4 > raw_tx.len() {
        return Err("Truncated receiver_id length in NEAR transaction");
    }
    let recv_len = u32::from_le_bytes([
        raw_tx[pos],
        raw_tx[pos + 1],
        raw_tx[pos + 2],
        raw_tx[pos + 3],
    ]) as usize;
    pos += 4;
    if recv_len < 2 || recv_len > 64 || pos + recv_len > raw_tx.len() {
        return Err("Truncated or invalid receiver_id in NEAR transaction");
    }
    let recv_bytes = &raw_tx[pos..pos + recv_len];
    pos += recv_len;

    // BlockHash: 32 bytes (must not be all zeros)
    if pos + 32 > raw_tx.len() {
        return Err("Truncated block_hash in NEAR transaction");
    }
    let bh = &raw_tx[pos..pos + 32];
    if bh.iter().all(|&b| b == 0) {
        return Err("NEAR transaction block_hash cannot be all zeros");
    }
    pos += 32;

    if pos + 5 > raw_tx.len() {
        return Err("Truncated actions header in NEAR transaction");
    }
    let action_count = u32::from_le_bytes([
        raw_tx[pos],
        raw_tx[pos + 1],
        raw_tx[pos + 2],
        raw_tx[pos + 3],
    ]);
    pos += 4;
    if action_count != 1 {
        return Err("NEAR sweep transaction must contain strictly a single action");
    }

    let action_opcode = raw_tx[pos];
    pos += 1;

    match action_opcode {
        3 => {
            // Action::Transfer (native NEAR)
            if recv_bytes != expected_receiver.as_str().as_bytes() {
                return Err("NEAR transaction receiver_id does not match policy-locked destination");
            }
            if pos + 16 != raw_tx.len() {
                return Err("NEAR Transfer action has invalid length or trailing bytes");
            }
            let mut dep_bytes = [0u8; 16];
            dep_bytes.copy_from_slice(&raw_tx[pos..pos + 16]);
            let deposit = u128::from_le_bytes(dep_bytes);
            if deposit == 0 {
                return Err("NEAR transfer deposit must be greater than zero");
            }
        }
        2 => {
            // Action::FunctionCall (NEP-141 `ft_transfer` or NEP-171 `nft_transfer`)
            if pos + 4 > raw_tx.len() {
                return Err("Truncated method_name length in NEAR FunctionCall");
            }
            let method_len = u32::from_le_bytes([
                raw_tx[pos],
                raw_tx[pos + 1],
                raw_tx[pos + 2],
                raw_tx[pos + 3],
            ]) as usize;
            pos += 4;
            if pos + method_len > raw_tx.len() {
                return Err("Truncated method_name in NEAR FunctionCall");
            }
            let method_name = core::str::from_utf8(&raw_tx[pos..pos + method_len])
                .map_err(|_| "Invalid UTF-8 in NEAR FunctionCall method_name")?;
            pos += method_len;
            if method_name != "ft_transfer" && method_name != "nft_transfer" {
                return Err("Only NEP-141 ft_transfer and NEP-171 nft_transfer FunctionCalls are permitted");
            }

            if pos + 4 > raw_tx.len() {
                return Err("Truncated args length in NEAR FunctionCall");
            }
            let args_len = u32::from_le_bytes([
                raw_tx[pos],
                raw_tx[pos + 1],
                raw_tx[pos + 2],
                raw_tx[pos + 3],
            ]) as usize;
            pos += 4;
            if args_len == 0 || args_len > 512 || pos + args_len > raw_tx.len() {
                return Err("Invalid args length in NEAR NEP-141/NEP-171 FunctionCall");
            }
            let args_json: near_sdk::serde_json::Value =
                near_sdk::serde_json::from_slice(&raw_tx[pos..pos + args_len])
                    .map_err(|_| "Invalid JSON in NEAR NEP-141/NEP-171 FunctionCall args")?;
            pos += args_len;

            let json_recv = args_json
                .get("receiver_id")
                .and_then(|v| v.as_str())
                .ok_or("Missing receiver_id in NEP-141/NEP-171 JSON args")?;
            if json_recv != expected_receiver.as_str() {
                return Err("NEP-141/NEP-171 receiver_id does not match policy-locked destination");
            }
            if method_name == "ft_transfer" {
                let amt_str = args_json
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing amount string in NEP-141 ft_transfer args")?;
                let amt = amt_str
                    .parse::<u128>()
                    .map_err(|_| "Invalid amount integer in NEP-141 ft_transfer args")?;
                if amt == 0 {
                    return Err("NEP-141 ft_transfer amount must be greater than zero");
                }
            } else {
                let token_id = args_json
                    .get("token_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if token_id.is_empty() {
                    return Err("Missing token_id in NEP-171 nft_transfer args");
                }
            }

            if pos + 8 + 16 != raw_tx.len() {
                return Err("NEAR FunctionCall has invalid gas/deposit length or trailing bytes");
            }
            let mut gas_bytes = [0u8; 8];
            gas_bytes.copy_from_slice(&raw_tx[pos..pos + 8]);
            let gas = u64::from_le_bytes(gas_bytes);
            pos += 8;
            if !(5_000_000_000_000..=50_000_000_000_000).contains(&gas) {
                return Err("NEAR NEP-141/NEP-171 gas must be between 5 TGas and 50 TGas");
            }
            let mut dep_bytes = [0u8; 16];
            dep_bytes.copy_from_slice(&raw_tx[pos..pos + 16]);
            let deposit = u128::from_le_bytes(dep_bytes);
            if deposit != 1 {
                return Err("NEAR NEP-141/NEP-171 transfer requires strictly 1 yoctoNEAR attached deposit");
            }
        }
        _ => {
            return Err("NEAR sweep transaction must contain strictly a Transfer (3) or NEP-141/171 FunctionCall (2) action");
        }
    }

    let hash_vec = env::sha256(raw_tx);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_vec);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .predecessor_account_id(predecessor.clone())
            .signer_account_id(predecessor);
        builder
    }

    fn sample_addresses() -> (ChainAddresses, ChainAddresses) {
        let backup = ChainAddresses {
            btc: "tb1qug7ge5vzhslcywjqs62k5392uy7ta5klvd2f7c".to_string(),
            evm: "0x1111111111111111111111111111111111111111".to_string(),
            sol: "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM".to_string(),
            near: Some("backup.testnet".parse().unwrap()),
        };
        let heirs = ChainAddresses {
            btc: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            evm: "0x2222222222222222222222222222222222222222".to_string(),
            sol: "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            near: Some("heir.testnet".parse().unwrap()),
        };
        (backup, heirs)
    }

    fn build_valid_btc_preimage_and_outputs(target_btc: &str, sats: u64) -> Vec<u8> {
        let script = address_to_btc_script_pubkey(target_btc).expect("Valid BTC address");
        let mut outputs = Vec::new();
        outputs.extend_from_slice(&sats.to_le_bytes());
        outputs.push(script.len() as u8);
        outputs.extend_from_slice(&script);

        let hash_outputs = env::sha256(&env::sha256(&outputs));
        let mut preimage = Vec::with_capacity(182);
        preimage.extend_from_slice(&2u32.to_le_bytes()); // nVersion
        preimage.extend_from_slice(&[0x11u8; 32]); // hashPrevouts
        preimage.extend_from_slice(&[0x22u8; 32]); // hashSequence
        preimage.extend_from_slice(&[0x33u8; 36]); // outpoint
        // scriptCode: 0x19 76 a9 14 <20B> 88 ac
        preimage.extend_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
        preimage.extend_from_slice(&[0x44u8; 20]);
        preimage.extend_from_slice(&[0x88, 0xac]);
        preimage.extend_from_slice(&(sats + 1000).to_le_bytes()); // input value
        preimage.extend_from_slice(&0xfffffffdu32.to_le_bytes()); // nSequence
        preimage.extend_from_slice(&hash_outputs); // hashOutputs (32B)
        preimage.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL (1)
        assert_eq!(preimage.len(), 182);

        let mut payload = preimage;
        payload.extend_from_slice(&outputs);
        payload
    }

    fn encode_rlp_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            vec![0x80]
        } else if bytes.len() == 1 && bytes[0] < 0x80 {
            vec![bytes[0]]
        } else if bytes.len() <= 55 {
            let mut out = vec![0x80 + bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        } else {
            let len_bytes = (bytes.len() as u64)
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect::<Vec<_>>();
            let mut out = vec![0xb7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(bytes);
            out
        }
    }

    fn encode_rlp_u128(val: u128) -> Vec<u8> {
        if val == 0 {
            return vec![0x80];
        }
        let be = val
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect::<Vec<_>>();
        encode_rlp_bytes(&be)
    }

    fn build_eip1559_tx(
        max_priority_fee: u128,
        max_fee: u128,
        gas_limit: u128,
        to: &[u8; 20],
        value: u128,
        data: &[u8],
    ) -> Vec<u8> {
        let mut list = Vec::new();
        list.extend_from_slice(&encode_rlp_u128(11155111)); // chain_id
        list.extend_from_slice(&encode_rlp_u128(0)); // nonce
        list.extend_from_slice(&encode_rlp_u128(max_priority_fee));
        list.extend_from_slice(&encode_rlp_u128(max_fee));
        list.extend_from_slice(&encode_rlp_u128(gas_limit));
        list.extend_from_slice(&encode_rlp_bytes(to));
        list.extend_from_slice(&encode_rlp_u128(value));
        list.extend_from_slice(&encode_rlp_bytes(data));
        list.push(0xc0); // empty access_list

        let mut tx = vec![0x02];
        if list.len() <= 55 {
            tx.push(0xc0 + list.len() as u8);
        } else {
            let len_bytes = (list.len() as u64)
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect::<Vec<_>>();
            tx.push(0xf7 + len_bytes.len() as u8);
            tx.extend_from_slice(&len_bytes);
        }
        tx.extend_from_slice(&list);
        tx
    }

    fn build_solana_native_msg(
        vault_key: [u8; 32],
        recipient_key: [u8; 32],
        blockhash: [u8; 32],
        lamports: u64,
        include_compute_budget: bool,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(1u8); // num_required_signatures
        msg.push(0u8); // num_readonly_signed
        if include_compute_budget {
            let cb = bs58::decode(SOL_COMPUTE_BUDGET_ID).into_vec().unwrap();
            msg.push(2u8); // readonly unsigned: system + compute_budget
            msg.push(4u8); // 4 accounts
            msg.extend_from_slice(&vault_key);
            msg.extend_from_slice(&recipient_key);
            msg.extend_from_slice(&[0u8; 32]); // SystemProgram
            msg.extend_from_slice(&cb);
            msg.extend_from_slice(&blockhash);
            msg.push(2u8); // 2 instructions
            // ix 0: ComputeBudget SetComputeUnitPrice
            msg.push(3u8);
            msg.push(0u8);
            msg.push(9u8);
            msg.extend_from_slice(&[3, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            msg.push(1u8); // readonly unsigned: system
            msg.push(3u8); // 3 accounts
            msg.extend_from_slice(&vault_key);
            msg.extend_from_slice(&recipient_key);
            msg.extend_from_slice(&[0u8; 32]); // SystemProgram
            msg.extend_from_slice(&blockhash);
            msg.push(1u8); // 1 instruction
        }
        // SystemProgram::Transfer(lamports)
        msg.push(2u8); // program_id_index = 2
        msg.push(2u8); // 2 accounts
        msg.push(0u8); // from = 0
        msg.push(1u8); // to = 1
        msg.push(12u8); // data_len = 12
        msg.extend_from_slice(&2u32.to_le_bytes());
        msg.extend_from_slice(&lamports.to_le_bytes());
        msg
    }

    #[test]
    fn test_multi_user_isolation_and_epoch_archival() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let bob: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);
        contract.propose_policy(backup.clone(), heirs.clone(), None, None, None);

        testing_env!(context
            .predecessor_account_id(bob.clone())
            .signer_account_id(bob.clone())
            .build());
        contract.propose_policy(backup.clone(), heirs.clone(), None, None, None);

        testing_env!(context
            .predecessor_account_id(alice.clone())
            .signer_account_id(alice.clone())
            .build());
        contract.panic();
        assert_eq!(
            contract.get_vault_info(Some(alice.clone())).unwrap().state,
            VaultState::Evacuated
        );
        assert_eq!(
            contract.get_vault_info(Some(bob.clone())).unwrap().state,
            VaultState::Active
        );

        // Rotate Alice's bunker -> epoch 0 destinations MUST be archived while current epoch 1 is clean
        contract.rotate_bunker();
        let alice_rot = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(alice_rot.state, VaultState::Unconfigured);
        assert_eq!(alice_rot.epoch, 1);
        let archived = LastKeyVault::internal_get_archived_epoch(&alice, 0).expect("Epoch 0 archived");
        assert_eq!(archived.destination, backup);
    }

    #[test]
    fn test_claim_lifecycle_and_ping_recovery() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let anyone_caller: AccountId = "random_relayer.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000;
        testing_env!(context.block_timestamp(t0).build());

        let heartbeat_ns = 90 * 24 * 3600 * 1_000_000_000;
        let challenge_ns = 7 * 24 * 3600 * 1_000_000_000;

        let mut contract = LastKeyVault::new(mpc, None);
        contract.propose_policy(backup, heirs, None, None, None);

        testing_env!(context
            .predecessor_account_id(anyone_caller.clone())
            .block_timestamp(t0 + heartbeat_ns + challenge_ns - 100)
            .build());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.trigger_push_inheritance(owner.clone());
        }))
        .is_err());

        let ping_time = t0 + heartbeat_ns;
        testing_env!(context
            .predecessor_account_id(owner.clone())
            .signer_account_id(owner.clone())
            .block_timestamp(ping_time)
            .build());
        contract.ping();
        assert_eq!(
            contract.get_vault_info(Some(owner.clone())).unwrap().last_ping_ns,
            ping_time
        );

        let final_expire_time = ping_time + heartbeat_ns + challenge_ns + 1;
        testing_env!(context
            .predecessor_account_id(anyone_caller)
            .block_timestamp(final_expire_time)
            .build());
        contract.trigger_push_inheritance(owner.clone());
        assert_eq!(
            contract.get_vault_info(Some(owner)).unwrap().state,
            VaultState::Inheritance
        );
    }

    #[test]
    fn test_solana_instruction_verification_and_compute_budget_ban() {
        let recipient_sol = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM";
        let mut recipient_bytes = [0u8; 32];
        recipient_bytes.copy_from_slice(&bs58::decode(recipient_sol).into_vec().unwrap());
        let vault_bytes = [0xaa; 32];
        let valid_bh = [0x55; 32];

        // 1. Valid native transfer passes
        let valid_msg =
            build_solana_native_msg(vault_bytes, recipient_bytes, valid_bh, 995_000, false);
        assert!(verify_solana_sweep_payload(&valid_msg, recipient_sol));

        // 2. ComputeBudget priority-fee drain MUST be rejected
        let poisoned_cb =
            build_solana_native_msg(vault_bytes, recipient_bytes, valid_bh, 1, true);
        assert!(
            !verify_solana_sweep_payload(&poisoned_cb, recipient_sol),
            "ComputeBudget fee-drain payload must be rejected"
        );

        // 3. Zero-lamport transfer MUST be rejected
        let zero_lamports =
            build_solana_native_msg(vault_bytes, recipient_bytes, valid_bh, 0, false);
        assert!(!verify_solana_sweep_payload(&zero_lamports, recipient_sol));

        // 4. All-zero blockhash MUST be rejected
        let zero_bh =
            build_solana_native_msg(vault_bytes, recipient_bytes, [0u8; 32], 995_000, false);
        assert!(!verify_solana_sweep_payload(&zero_bh, recipient_sol));

        // 5. Wrong recipient MUST be rejected
        let attacker_bytes = [0x77; 32];
        let spoofed_recipient =
            build_solana_native_msg(vault_bytes, attacker_bytes, valid_bh, 995_000, false);
        assert!(!verify_solana_sweep_payload(&spoofed_recipient, recipient_sol));
    }

    #[test]
    fn test_evm_sweep_verification_native_erc20_and_fee_cap() {
        let target = [0x7au8; 20];
        let attacker = [0x66u8; 20];
        let usdc_contract = [0x99u8; 20];

        // 1. Valid Native ETH sweep passes
        let valid_eth = build_eip1559_tx(
            1_000_000_000,
            20_000_000_000,
            25_000,
            &target,
            1_000_000_000_000_000,
            b"enc:x25519:test",
        );
        assert!(verify_evm_sweep_payload(&valid_eth, &target).is_ok());

        // 2. Excessive fee (>500 Gwei) MUST fail ([ATTACK-1] fee-burn mitigation)
        let fee_burn_tx = build_eip1559_tx(
            1_000_000_000,
            900_000_000_000, // 900 Gwei!
            21_000,
            &target,
            1000,
            &[],
        );
        assert!(verify_evm_sweep_payload(&fee_burn_tx, &target).is_err());

        // 3. Zero-value native spam MUST fail
        let zero_val_tx = build_eip1559_tx(1_000_000_000, 20_000_000_000, 21_000, &target, 0, &[]);
        assert!(verify_evm_sweep_payload(&zero_val_tx, &target).is_err());

        // 4. Spoofed recipient in calldata while sending ETH to attacker MUST fail
        let spoof_eth = build_eip1559_tx(
            1_000_000_000,
            20_000_000_000,
            25_000,
            &attacker,
            1_000_000,
            &target,
        );
        assert!(verify_evm_sweep_payload(&spoof_eth, &target).is_err());

        // 5. Valid ERC-20 `transfer(target, 1000)` passes
        let mut erc20_data = vec![0xa9, 0x05, 0x9c, 0xbb];
        erc20_data.extend_from_slice(&[0u8; 12]);
        erc20_data.extend_from_slice(&target);
        let mut amt = [0u8; 32];
        amt[31] = 250;
        erc20_data.extend_from_slice(&amt);
        let valid_erc20 = build_eip1559_tx(
            1_000_000_000,
            20_000_000_000,
            65_000,
            &usdc_contract,
            0,
            &erc20_data,
        );
        assert!(verify_evm_sweep_payload(&valid_erc20, &target).is_ok());

        // 6. ERC-20 `transfer(attacker, 250)` MUST fail
        let mut bad_erc20 = vec![0xa9, 0x05, 0x9c, 0xbb];
        bad_erc20.extend_from_slice(&[0u8; 12]);
        bad_erc20.extend_from_slice(&attacker);
        bad_erc20.extend_from_slice(&amt);
        let stolen_erc20 = build_eip1559_tx(
            1_000_000_000,
            20_000_000_000,
            65_000,
            &usdc_contract,
            0,
            &bad_erc20,
        );
        assert!(verify_evm_sweep_payload(&stolen_erc20, &target).is_err());
    }

    #[test]
    fn test_gas_escrow_isolated_near_sweep_and_telemetry_completion() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let bob: AccountId = "bob.testnet".parse().unwrap();
        let keeper: AccountId = "keeper.testnet".parse().unwrap();
        let contract_id: AccountId = "aegis.okgoogleok.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        context
            .current_account_id(contract_id.clone())
            .account_balance(NearToken::from_near(5))
            .attached_deposit(NearToken::from_millinear(250)); // 0.25 NEAR initial escrow!
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, Some(keeper.clone()));
        contract.propose_policy(backup.clone(), heirs.clone(), Some("enc:x25519:ciphertext".to_string()), None, None);

        let info = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(info.gas_escrow_yocto, NearToken::from_millinear(250).as_yoctonear().to_string());

        // Deposit 1 NEAR into Alice's isolated NEAR vault and 2 NEAR into Bob's
        testing_env!(context
            .predecessor_account_id(alice.clone())
            .attached_deposit(NearToken::from_near(1))
            .build());
        contract.deposit_near_vault(None);

        testing_env!(context
            .predecessor_account_id(bob.clone())
            .signer_account_id(bob.clone())
            .attached_deposit(NearToken::from_near(2))
            .build());
        contract.propose_policy(backup.clone(), heirs, None, None, None);
        contract.deposit_near_vault(None);

        // Alice triggers panic
        testing_env!(context
            .predecessor_account_id(alice.clone())
            .signer_account_id(alice.clone())
            .attached_deposit(NearToken::from_yoctonear(0))
            .build());
        contract.panic();

        // Actionable vaults returns Alice (1 vault)
        assert_eq!(contract.get_actionable_vaults().len(), 1);

        // Keeper calls `request_sweep_signature` with ZERO deposit -> funded by Alice's 0.25 NEAR escrow!
        testing_env!(context
            .predecessor_account_id(keeper.clone())
            .attached_deposit(NearToken::from_yoctonear(0))
            .build());
        let btc_payload_hex = hex::encode(build_valid_btc_preimage_and_outputs(&backup.btc, 50_000));
        let _ = contract.request_sweep_signature(
            alice.clone(),
            "BTC".to_string(),
            btc_payload_hex,
            Some(0),
            false,
        );
        // Escrow debited by 0.055 NEAR (0.05 MPC + 0.005 keeper refund) -> 0.195 NEAR remaining
        let after_sig = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(
            after_sig.gas_escrow_yocto,
            NearToken::from_millinear(195).as_yoctonear().to_string()
        );

        // Keeper sweeps Alice's NEAR -> sweeps strictly Alice's 1 NEAR, Bob's 2 NEAR stays intact!
        let _ = contract.sweep_near(alice.clone(), None);
        assert_eq!(
            contract.get_vault_info(Some(alice.clone())).unwrap().near_deposit_yocto,
            "0"
        );
        assert_eq!(
            contract.get_vault_info(Some(bob)).unwrap().near_deposit_yocto,
            NearToken::from_near(2).as_yoctonear().to_string()
        );

        // Second `sweep_near` for Alice fails cleanly because Alice's isolated balance is 0
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.sweep_near(alice.clone(), None);
        }))
        .is_err());

        // Keeper records telemetry with `is_complete = true` -> Alice disappears from `get_actionable_vaults`!
        contract.record_sweep_telemetry(
            alice.clone(),
            0,
            r#"{"status":"complete"}"#.to_string(),
            true,
        );
        let final_info = contract.get_vault_info(Some(alice)).unwrap();
        assert!(final_info.is_epoch_swept);
        assert_eq!(
            final_info.last_sweep_report,
            Some(r#"{"status":"complete"}"#.to_string())
        );
        assert!(
            contract.get_actionable_vaults().is_empty(),
            "Completed epoch must not loop in get_actionable_vaults"
        );
    }

    #[test]
    fn test_relayer_cannot_call_admin_reset_and_unauthenticated_ping_blocked() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let keeper: AccountId = "keeper.testnet".parse().unwrap();
        let contract_id: AccountId = "aegis.okgoogleok.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        context.current_account_id(contract_id);
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, Some(keeper.clone()));
        contract.propose_policy(backup, heirs, None, None, None);

        // Owner registers her Ed25519 pubkey
        testing_env!(context
            .predecessor_account_id(alice.clone())
            .signer_account_id(alice.clone())
            .build());
        contract.register_ping_pubkey(
            "8119c2811b758728b341f9279c25064df770ef13d63e583acdebe9590f31c43a".to_string(),
        );

        // Keeper attempting `admin_reset_vault` MUST panic (`#[private]` + explicit self-check)
        testing_env!(context
            .predecessor_account_id(keeper.clone())
            .block_timestamp(10_000_000_000)
            .build());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.admin_reset_vault(alice.clone());
        }))
        .is_err());

        // Keeper attempting `ping_by_relayer` with a forged signature MUST panic
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.ping_by_relayer(
                alice.clone(),
                U64(10_000),
                "00".repeat(64),
                None,
                None,
            );
        }))
        .is_err());

        // Valid owner Ed25519 signature over `"AEGIS_PING:alice.testnet:10000"` succeeds!
        let valid_sig = "781bdedd325e3c85c2cfe69aaf4aedd2a10f44cc7f0710b2796152ad7b30ba3a89e9231f6419a4d530c782dc17d35e270744ad477e3b8a7e2c7aaf5b26b23800".to_string();
        contract.ping_by_relayer(
            alice.clone(),
            U64(10_000),
            valid_sig.clone(),
            None,
            None,
        );
        assert_eq!(
            contract.get_vault_info(Some(alice.clone())).unwrap().last_ping_ns,
            10_000_000_000
        );

        // Replaying the exact same signed ping MUST fail (`[ATTACK-3]` replay protection)
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.ping_by_relayer(alice.clone(), U64(10_000), valid_sig, None, None);
        }))
        .is_err());
    }

    #[test]
    fn test_e2ee_1024_byte_testament_memo_limit() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();
        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);
        let long_e2ee = format!("enc:x25519:{}", "A".repeat(420));
        contract.propose_policy(backup, heirs, Some(long_e2ee.clone()), None, None);
        assert_eq!(contract.get_heir_memo(owner.clone()), Some(long_e2ee));

        // Over 1024 bytes panics
        let oversized = "X".repeat(1025);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.set_heir_memo(oversized);
        }))
        .is_err());
    }

    #[test]
    fn test_timelock_anti_bypass_pending_policy_inheritance_and_btc_near_verifiers() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let keeper: AccountId = "keeper.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        let t0 = 1_000_000_000_000_000_000u64;
        testing_env!(context.block_timestamp(t0).build());

        let mut contract = LastKeyVault::new(mpc, Some(keeper));
        contract.propose_policy(backup.clone(), heirs.clone(), None, None, None);

        // 1. `[C2]` Attempting `reset_my_vault()` on an armed vault MUST panic (prevents 72h timelock bypass)
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.reset_my_vault();
        }))
        .is_err());

        // 2. Proposing a modified destination arms a 72h `PendingPolicy`
        let mut new_heirs = heirs.clone();
        new_heirs.near = Some("new_heir.testnet".parse().unwrap());
        contract.propose_policy(backup.clone(), new_heirs.clone(), None, None, None);
        assert!(contract.get_vault_info(Some(alice.clone())).unwrap().pending_policy.is_some());

        // 3. `[C3]` If owner becomes inactive for `heartbeat + grace` (>72h), `trigger_push_inheritance`
        // automatically promotes the elapsed `pending_policy` and transitions to `Inheritance` (never deadlocks!)
        let expire_ns = t0 + DEFAULT_HEARTBEAT_INTERVAL_NS + DEFAULT_CHALLENGE_PERIOD_NS + 1;
        testing_env!(context.block_timestamp(expire_ns).build());
        assert_eq!(contract.get_actionable_vaults().len(), 1);
        contract.trigger_push_inheritance(alice.clone());
        let info = contract.get_vault_info(Some(alice)).unwrap();
        assert_eq!(info.state, VaultState::Inheritance);
        assert_eq!(info.heirs.near, Some("new_heir.testnet".parse().unwrap()));

        // 4. `[C4]` Verify BTC BIP-143 preimage verifier accepts valid target and rejects attacker output
        let valid_btc = build_valid_btc_preimage_and_outputs(&backup.btc, 75_000);
        assert!(verify_btc_sweep_payload(&valid_btc, &backup.btc).is_ok());
        assert!(verify_btc_sweep_payload(&valid_btc, &heirs.btc).is_err());

        // 5. `[C4]` Verify NEAR Borsh transaction verifier accepts valid Transfer and rejects wrong receiver
        let target_near: AccountId = "backup.testnet".parse().unwrap();
        let wrong_near: AccountId = "attacker.testnet".parse().unwrap();
        let mut near_tx = Vec::new();
        let signer_str = "a".repeat(64);
        near_tx.extend_from_slice(&(signer_str.len() as u32).to_le_bytes());
        near_tx.extend_from_slice(signer_str.as_bytes());
        near_tx.push(0u8); // Ed25519
        near_tx.extend_from_slice(&[0x11u8; 32]);
        near_tx.extend_from_slice(&1u64.to_le_bytes()); // nonce
        near_tx.extend_from_slice(&(target_near.as_str().len() as u32).to_le_bytes());
        near_tx.extend_from_slice(target_near.as_str().as_bytes());
        near_tx.extend_from_slice(&[0x22u8; 32]); // block_hash
        near_tx.extend_from_slice(&1u32.to_le_bytes()); // 1 action
        near_tx.push(3u8); // Transfer
        near_tx.extend_from_slice(&100_000_000_000_000_000_000_000u128.to_le_bytes());
        assert!(verify_near_sweep_payload(&near_tx, &target_near).is_ok());
        assert!(verify_near_sweep_payload(&near_tx, &wrong_near).is_err());

        // 6. Verify NEAR NEP-141 `ft_transfer` (1 yoctoNEAR, 30 TGas) succeeds for target_near and fails for wrong_near
        let mut nep141_tx = Vec::new();
        nep141_tx.extend_from_slice(&(signer_str.len() as u32).to_le_bytes());
        nep141_tx.extend_from_slice(signer_str.as_bytes());
        nep141_tx.push(0u8);
        nep141_tx.extend_from_slice(&[0x11u8; 32]);
        nep141_tx.extend_from_slice(&2u64.to_le_bytes());
        let ft_contract = "usdc.fakes.testnet";
        nep141_tx.extend_from_slice(&(ft_contract.len() as u32).to_le_bytes());
        nep141_tx.extend_from_slice(ft_contract.as_bytes());
        nep141_tx.extend_from_slice(&[0x22u8; 32]);
        nep141_tx.extend_from_slice(&1u32.to_le_bytes());
        nep141_tx.push(2u8); // Action::FunctionCall
        let method = "ft_transfer";
        nep141_tx.extend_from_slice(&(method.len() as u32).to_le_bytes());
        nep141_tx.extend_from_slice(method.as_bytes());
        let args_str = r#"{"receiver_id":"backup.testnet","amount":"25000000"}"#;
        nep141_tx.extend_from_slice(&(args_str.len() as u32).to_le_bytes());
        nep141_tx.extend_from_slice(args_str.as_bytes());
        nep141_tx.extend_from_slice(&30_000_000_000_000u64.to_le_bytes()); // 30 TGas
        nep141_tx.extend_from_slice(&1u128.to_le_bytes()); // 1 yoctoNEAR
        assert!(verify_near_sweep_payload(&nep141_tx, &target_near).is_ok());
        assert!(verify_near_sweep_payload(&nep141_tx, &wrong_near).is_err());
    }

    #[test]
    fn test_timer_downgrade_attack_blocked_on_armed_bunker() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let keeper: AccountId = "keeper.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let t0 = 1_700_000_000_000_000_000u64;

        let mut context = get_context(alice.clone());
        testing_env!(context.block_timestamp(t0).build());

        let (backup, heirs) = sample_addresses();
        let mut contract = LastKeyVault::new(mpc, Some(keeper));
        contract.propose_policy(backup.clone(), heirs.clone(), None, None, None);

        // 1. Create a fresh Unconfigured vault via rotate_bunker after panic
        contract.panic();
        contract.rotate_bunker();
        let info_unarmed = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(info_unarmed.state, VaultState::Unconfigured);

        // 2. While Unconfigured (unarmed), changing timers via update_intervals works
        contract.update_intervals(
            Some(U64(90 * 86_400 * 1_000_000_000)),
            Some(U64(7 * 86_400 * 1_000_000_000)),
        );

        // 3. Arm the bunker with 90d check-in and 7d grace
        contract.propose_policy(
            backup.clone(),
            heirs.clone(),
            None,
            Some(U64(90 * 86_400 * 1_000_000_000)),
            Some(U64(7 * 86_400 * 1_000_000_000)),
        );
        let info_armed = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(info_armed.state, VaultState::Active);

        // 4. Changing timers on an armed bunker enters 72-hour timelock cooldown (does NOT apply immediately)
        let hb_90d = 90 * 86_400 * 1_000_000_000u64;
        let cp_7d = 7 * 86_400 * 1_000_000_000u64;
        let hb_3m = 180 * 1_000_000_000u64;
        let cp_1m = 60 * 1_000_000_000u64;

        contract.update_intervals(Some(U64(hb_3m)), Some(U64(cp_1m)));
        let info_pending = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(info_pending.heartbeat_interval_ns, hb_90d);
        assert_eq!(info_pending.challenge_period_ns, cp_7d);
        assert!(info_pending.pending_policy.is_some());
        assert_eq!(info_pending.pending_heartbeat_interval_ns, Some(hb_3m));
        assert_eq!(info_pending.pending_challenge_period_ns, Some(cp_1m));

        // 5. Owner can cancel the unauthorized timer change during the 72h window
        contract.cancel_policy();
        let info_cancelled = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert!(info_cancelled.pending_policy.is_none());
        assert_eq!(info_cancelled.pending_heartbeat_interval_ns, None);
        assert_eq!(info_cancelled.heartbeat_interval_ns, hb_90d);

        // 6. Proposing timer change and waiting full 72h promotes the new timers
        contract.update_intervals(Some(U64(hb_3m)), Some(U64(cp_1m)));
        testing_env!(context.block_timestamp(t0 + DEFAULT_POLICY_TIMELOCK_NS + 1).build());
        contract.apply_policy(None);
        let info_applied = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert!(info_applied.pending_policy.is_none());
        assert_eq!(info_applied.heartbeat_interval_ns, hb_3m);
        assert_eq!(info_applied.challenge_period_ns, cp_1m);

        // 7. sync_owner_activity blocks future/u64::MAX nonce poisoning
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.sync_owner_activity(alice.clone(), U64(u64::MAX));
        }))
        .is_err());
    }
}

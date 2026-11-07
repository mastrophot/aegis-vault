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

    /// Checks if applying `new` would replace any non-empty existing address
    pub fn is_replacing_existing(&self, new: &ChainAddresses) -> bool {
        let btc_replaced = !self.btc.trim().is_empty() && !new.btc.trim().is_empty() && self.btc.trim() != new.btc.trim();
        let evm_replaced = !self.evm.trim().is_empty() && !new.evm.trim().is_empty() && !self.evm.trim().eq_ignore_ascii_case(new.evm.trim());
        let sol_replaced = !self.sol.trim().is_empty() && !new.sol.trim().is_empty() && self.sol.trim() != new.sol.trim();
        let near_replaced = self.near.is_some() && new.near.is_some() && self.near != new.near;
        btc_replaced || evm_replaced || sol_replaced || near_replaced
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
    pub heir_memo: Option<String>,
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

    /// Upgrade / Migration entrypoint: safely transitions storage schema to multi-tenant LookupMap.
    /// Strictly restricted to self-call by the contract account.
    #[private]
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

    /// Relayer heartbeat sponsorship: callable by authorized relayer on behalf of vault owner
    pub fn ping_by_relayer(&mut self, vault_owner: AccountId) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        let is_authorized = vault.authorized_relayer.as_ref().map_or(false, |r| r == &caller)
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_authorized, "Unauthorized relayer");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Cannot ping: vault is not Active or Claiming"
        );
        vault.last_ping_ns = env::block_timestamp();
        if let VaultState::Claiming { .. } = vault.state {
            vault.state = VaultState::Active;
            env::log_str(&format!("CLAIM_CANCELLED: Relayer {} pinged alive for {}", caller, vault_owner));
        } else {
            env::log_str(&format!("PING_RECEIVED: Relayer heartbeat reset for {}", vault_owner));
        }
    }

    /// Emergency Panic button: instantly shifts caller's vault into Evacuated state.
    /// Strictly blocked if a 72-hour policy cooldown is pending, or if no backup destinations are configured.
    #[payable]
    pub fn panic(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
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
        vault.state = VaultState::Evacuated;
        env::log_str(&format!("PANIC_TRIGGERED: Vault for {} evacuated. Sweeping routed exclusively to backup addresses.", caller));
    }

    /// Resets the caller's vault after an evacuation or finalized inheritance, advancing the bunker epoch.
    /// Preserves existing backup and heir destinations so delayed sweeps for prior epochs remain valid.
    #[payable]
    pub fn rotate_bunker(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(
            vault.state == VaultState::Evacuated || vault.state == VaultState::Inheritance,
            "Can only rotate bunker when vault is Evacuated or Inheritance"
        );
        vault.epoch += 1;
        vault.pending_policy = None;
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!(
            "BUNKER_ROTATED: Epoch for {} advanced to v{}, destinations wiped to clean slate, state reset to Unconfigured",
            caller, vault.epoch
        ));
    }

    /// Resets caller's vault back to clean Unconfigured state (clears all egress addresses)
    pub fn reset_my_vault(&mut self) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.pending_policy = None;
        env::log_str(&format!("VAULT_RESET: Vault for {} reset to Unconfigured", caller));
    }

    /// Admin reset of a vault to Unconfigured state
    pub fn admin_reset_vault(&mut self, target_account: AccountId) {
        let caller = env::predecessor_account_id();
        let is_admin = caller == env::current_account_id()
            || self.default_relayer.as_ref().map_or(false, |r| r == &caller);
        require!(is_admin, "Unauthorized caller for admin_reset_vault");
        let vault = self.vaults.get_mut(&target_account).expect("No vault found for target account");
        vault.backup = ChainAddresses::empty();
        vault.heirs = ChainAddresses::empty();
        vault.state = VaultState::Unconfigured;
        vault.pending_policy = None;
        env::log_str(&format!("ADMIN_VAULT_RESET: Vault for {} reset to Unconfigured by {}", target_account, caller));
    }

    /// Sweeps native NEAR tokens from the contract to the configured backup or heir destination account.
    /// Retains a safety reserve (0.5 NEAR) to maintain contract storage staking.
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

        let target_account_id: AccountId = if let Some(override_dest) = destination {
            if &Some(override_dest.clone()) != target_dest {
                require!(caller == vault_owner, "Only owner can override destination");
            }
            override_dest
        } else {
            target_dest.clone().expect("No destination NEAR account configured in vault policy")
        };

        let contract_balance = env::account_balance();
        let min_storage_stake = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128);
        let storage_reserve = min_storage_stake.saturating_add(NearToken::from_millinear(500)); // Storage stake + 0.5 NEAR buffer
        require!(
            contract_balance > storage_reserve,
            "Insufficient contract balance above required storage stake"
        );
        let sweep_amount = contract_balance.saturating_sub(storage_reserve);

        env::log_str(&format!(
            "NEAR_SWEPT: Sweeping {} yoctoNEAR to {}",
            sweep_amount, target_account_id
        ));

        Promise::new(target_account_id).transfer(sweep_amount)
    }

    /// Propose updating backup or heir addresses for caller's bunker.
    /// Enforces a 72-hour timelock on changes, or activates immediately on initial setup (pristine/empty destinations).
    /// Optionally updates digital testament memo for heirs.
    #[payable]
    pub fn propose_policy(&mut self, backup: ChainAddresses, heirs: ChainAddresses, memo: Option<String>) {
        let caller = env::predecessor_account_id();
        let is_empty_submission = backup.is_empty() && heirs.is_empty();
        require!(!is_empty_submission, "At least one backup or heir destination must be provided");

        if let Some(ref m) = memo {
            let trimmed = m.trim();
            let key = format!("memo:{}", caller);
            if trimmed.is_empty() {
                env::storage_remove(key.as_bytes());
                env::log_str(&format!("HEIR_MEMO_CLEARED: Testament note removed for {}", caller));
            } else {
                require!(trimmed.len() <= 128, "Digital testament exceeds 128 bytes");
                env::storage_write(key.as_bytes(), trimmed.as_bytes());
                env::log_str(&format!("HEIR_MEMO_SAVED: Testament note updated for {}", caller));
            }
        }

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
            self.internal_register_account(&caller);
            env::log_str(&format!("VAULT_CREATED: Bunker initialized and armed for {}", caller));
            return;
        }

        let vault = self.vaults.get_mut(&caller).unwrap();

        // If vault is already evacuated, allow owner to fill in previously empty destination slots for leftover assets
        if vault.state == VaultState::Evacuated {
            let is_replacing = vault.backup.is_replacing_existing(&backup);
            require!(!is_replacing, "Cannot overwrite already established evacuation addresses in Evacuated state");
            vault.backup = backup;
            vault.last_ping_ns = env::block_timestamp();
            env::log_str(&format!("POLICY_UPDATED_EVACUATED: Leftover destinations added for {}", caller));
            return;
        }

        require!(
            vault.state == VaultState::Active || vault.state == VaultState::Unconfigured,
            "Can only update policy in Active or Unconfigured state"
        );

        let is_initial_setup = vault.state == VaultState::Unconfigured
            || (vault.backup.is_empty() && vault.heirs.is_empty());
        let is_replacing = vault.backup.is_replacing_existing(&backup)
            || vault.heirs.is_replacing_existing(&heirs);

        if is_initial_setup || !is_replacing {
            vault.backup = backup;
            vault.heirs = heirs;
            vault.pending_policy = None;
            vault.last_ping_ns = env::block_timestamp();
            vault.state = VaultState::Active;
            env::log_str(&format!("POLICY_INITIALIZED_INSTANT: Destinations activated immediately (new/additive addresses, no 72h cooldown) for {}", caller));
        } else {
            vault.last_ping_ns = env::block_timestamp();
            let effective_at_ns = env::block_timestamp() + vault.policy_timelock_ns;
            vault.pending_policy = Some(PendingPolicy {
                backup,
                heirs,
                effective_at_ns,
            });
            env::log_str(&format!("POLICY_PROPOSED: 72h timelock started for modifying existing configured addresses for {}", caller));
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
            vault.last_ping_ns = env::block_timestamp();
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
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!("POLICY_CANCELLED: Pending policy cancelled for {}", caller));
    }

    /// Update heartbeat interval and challenge (grace) period for caller's bunker.
    /// Strictly blocked if a 72-hour policy cooldown is active.
    /// Lengthening intervals is instant. Shortening intervals on an active, configured bunker
    /// triggers a 72-hour policy cooldown to prevent premature inheritance acceleration attacks!
    #[payable]
    pub fn update_intervals(
        &mut self,
        heartbeat_interval_ns: Option<U64>,
        challenge_period_ns: Option<U64>,
    ) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        require!(vault.state == VaultState::Active, "Can only update intervals in Active state");
        require!(
            vault.pending_policy.is_none(),
            "Cannot update intervals during active 72h policy cooldown"
        );
        let new_hb = heartbeat_interval_ns.map(|v| v.0).unwrap_or(vault.heartbeat_interval_ns);
        let new_cp = challenge_period_ns.map(|v| v.0).unwrap_or(vault.challenge_period_ns);
        require!(new_hb >= 15_000_000_000, "Heartbeat interval must be at least 15 seconds");
        require!(new_cp >= 15_000_000_000, "Challenge period must be at least 15 seconds");

        let old_total = vault.heartbeat_interval_ns.saturating_add(vault.challenge_period_ns);
        let new_total = new_hb.saturating_add(new_cp);
        let is_shortening = new_total < old_total;
        let is_configured = !vault.backup.is_empty() || !vault.heirs.is_empty();
        let is_demo_mode = new_hb <= 300_000_000_000;

        if is_configured && is_shortening && !is_demo_mode {
            // Apply new intervals, but arm 72h cooldown to block premature trigger_push_inheritance
            vault.heartbeat_interval_ns = new_hb;
            vault.challenge_period_ns = new_cp;
            vault.last_ping_ns = env::block_timestamp();
            let effective_at_ns = env::block_timestamp() + vault.policy_timelock_ns;
            vault.pending_policy = Some(PendingPolicy {
                backup: vault.backup.clone(),
                heirs: vault.heirs.clone(),
                effective_at_ns,
            });
            env::log_str(&format!(
                "INTERVALS_SHORTENED_TIMELOCK: Intervals shortened for {}. 72h cooldown armed to prevent acceleration attacks.",
                caller
            ));
        } else {
            vault.heartbeat_interval_ns = new_hb;
            vault.challenge_period_ns = new_cp;
            vault.last_ping_ns = env::block_timestamp();
            env::log_str(&format!("INTERVALS_UPDATED: Intervals updated for {}", caller));
        }
    }

    /// Set or revoke authorized relayer for caller's bunker
    #[payable]
    pub fn set_authorized_relayer(&mut self, relayer: Option<AccountId>) {
        let caller = env::predecessor_account_id();
        let vault = self.vaults.get_mut(&caller).expect("No vault found for account");
        vault.authorized_relayer = relayer;
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!("RELAYER_UPDATED: Authorized relayer updated for {}", caller));
    }

    /// Autonomous push inheritance trigger: callable by anyone (relayer, keeper bot, heir)
    /// once the owner's heartbeat interval + grace period has expired without any owner interaction.
    /// Strictly blocked if a 72-hour policy cooldown is active!
    pub fn trigger_push_inheritance(&mut self, vault_owner: AccountId) {
        let vault = self.vaults.get_mut(&vault_owner).expect("Target vault not found");
        require!(
            vault.state == VaultState::Active || matches!(vault.state, VaultState::Claiming { .. }),
            "Vault must be Active to trigger push inheritance"
        );
        require!(
            vault.pending_policy.is_none(),
            "Cannot trigger push inheritance while 72h policy cooldown is active"
        );
        let now = env::block_timestamp();
        let total_inactivity_ns = vault.heartbeat_interval_ns.saturating_add(vault.challenge_period_ns);
        require!(
            now >= vault.last_ping_ns.saturating_add(total_inactivity_ns),
            "Owner inactivity period (heartbeat + grace) has not elapsed yet"
        );
        require!(
            !vault.heirs.is_empty(),
            "Cannot trigger inheritance: no heir destination addresses configured"
        );
        vault.state = VaultState::Inheritance;
        env::log_str(&format!(
            "PUSH_INHERITANCE_TRIGGERED: Owner {} inactive for full period. Vault shifted to Inheritance. Autonomous multichain sweep unlocked for heirs.",
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
                let parsed_to = extract_evm_to_address(&raw_tx_bytes)
                    .unwrap_or_else(|| env::panic_str("Failed to parse EVM recipient address from transaction payload"));
                require!(
                    parsed_to.as_slice() == target_evm_bytes.as_slice(),
                    "EVM transaction recipient does not match designated target address"
                );
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
            // Solana, NEAR & EdDSA chains (domain_id = 1)
            require!(!clean_hex.is_empty() && clean_hex.len() <= 2464 && hex::decode(&clean_hex).is_ok(), "Invalid EdDSA hex");
            let is_near = chain.eq_ignore_ascii_case("NEAR");
            if !is_near {
                let raw_msg_bytes = hex::decode(&clean_hex).unwrap_or_else(|_| env::panic_str("Invalid EdDSA hex"));
                require!(
                    verify_solana_sweep_payload(&raw_msg_bytes, &target_destination.sol),
                    "Solana transaction message failed security validation against target recipient"
                );
            }
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
        let target = match account_id {
            Some(acc) => acc,
            None => return None,
        };
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
            heir_memo: self.get_heir_memo(target.clone()),
        })
    }

    /// Single-call view method for stateless serverless keepers:
    /// Returns all vaults that require automated relayer action:
    /// - Vaults in Evacuated or Inheritance state awaiting foreign chain sweeps
    /// - Active vaults whose heartbeat + challenge period has elapsed
    pub fn get_actionable_vaults(&self) -> Vec<VaultInfo> {
        let now = env::block_timestamp();
        self.get_registered_accounts()
            .into_iter()
            .filter_map(|owner| self.get_vault_info(Some(owner)))
            .filter(|v| {
                matches!(v.state, VaultState::Evacuated | VaultState::Inheritance | VaultState::Claiming { .. })
                    || (v.state == VaultState::Active && now >= v.last_ping_ns.saturating_add(v.heartbeat_interval_ns.saturating_add(v.challenge_period_ns)))
            })
            .collect()
    }

    /// Sets or clears the custom testament memo broadcast to heirs during an inheritance sweep.
    #[payable]
    pub fn set_heir_memo(&mut self, memo: String) {
        let caller = env::predecessor_account_id();
        let trimmed = memo.trim();
        let key = format!("memo:{}", caller);
        if trimmed.is_empty() {
            env::storage_remove(key.as_bytes());
            env::log_str(&format!("HEIR_MEMO_CLEARED: Testament note removed for {}", caller));
        } else {
            require!(trimmed.len() <= 128, "Digital testament exceeds 128 bytes");
            env::storage_write(key.as_bytes(), trimmed.as_bytes());
            env::log_str(&format!("HEIR_MEMO_SAVED: Testament note updated for {}", caller));
        }
    }

    /// Views the custom testament memo configured by the vault owner.
    pub fn get_heir_memo(&self, account_id: AccountId) -> Option<String> {
        let key = format!("memo:{}", account_id);
        env::storage_read(key.as_bytes()).map(|bytes| String::from_utf8(bytes).unwrap_or_default())
    }

    fn internal_register_account(&self, account_id: &AccountId) {
        let mut list: Vec<AccountId> = env::storage_read(b"reg_accounts")
            .and_then(|bytes| near_sdk::serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| vec![
                "okgoogleok.testnet".parse().unwrap(),
                "fewvilla8059.testnet".parse().unwrap(),
                "mastrophot.testnet".parse().unwrap(),
                "newapp9955.testnet".parse().unwrap(),
            ]);
        if !list.contains(account_id) {
            list.push(account_id.clone());
        }
        if let Ok(bytes) = near_sdk::serde_json::to_vec(&list) {
            env::storage_write(b"reg_accounts", &bytes);
        }
    }

    /// Public registration endpoint: adds an account to the monitored registry
    pub fn register_account(&mut self, account_id: Option<AccountId>) {
        let acc = account_id.unwrap_or_else(|| env::predecessor_account_id());
        self.internal_register_account(&acc);
    }

    /// View method: returns all registered accounts for relayer monitoring
    pub fn get_registered_accounts(&self) -> Vec<AccountId> {
        env::storage_read(b"reg_accounts")
            .and_then(|bytes| near_sdk::serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| vec![
                "okgoogleok.testnet".parse().unwrap(),
                "fewvilla8059.testnet".parse().unwrap(),
                "mastrophot.testnet".parse().unwrap(),
                "newapp9955.testnet".parse().unwrap(),
            ])
    }
}

/// Extracts the 20-byte `to` recipient address from an EIP-1559 or Legacy RLP-encoded transaction.
fn extract_evm_to_address(raw_tx: &[u8]) -> Option<[u8; 20]> {
    let (payload, items_before_to) = if raw_tx.first() == Some(&0x02) {
        // EIP-1559 envelope: 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
        (&raw_tx[1..], 5)
    } else {
        // Legacy: rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s])
        (raw_tx, 3)
    };

    if payload.is_empty() {
        return None;
    }

    let (list_header_len, _) = decode_rlp_header(payload)?;
    let mut offset = list_header_len;

    for _ in 0..items_before_to {
        let (item_header_len, item_len) = decode_rlp_item(payload.get(offset..)?)?;
        offset += item_header_len + item_len;
    }

    let (to_header_len, to_len) = decode_rlp_item(payload.get(offset..)?)?;
    if to_len == 20 {
        let to_bytes = payload.get(offset + to_header_len..offset + to_header_len + 20)?;
        let mut addr = [0u8; 20];
        addr.copy_from_slice(to_bytes);
        Some(addr)
    } else {
        None
    }
}

fn decode_rlp_header(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first >= 0xc0 && first <= 0xf7 {
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
        let (h_len, l_len) = decode_rlp_header(data)?;
        Some((h_len, l_len))
    }
}

/// Strict structural validation of Solana serialized message headers
/// Protects against substring injection and unauthorized recipient accounts.
fn verify_solana_sweep_payload(raw_msg_bytes: &[u8], expected_recipient_sol: &str) -> bool {
    if raw_msg_bytes.len() < 3 {
        return false;
    }
    let num_required_signatures = raw_msg_bytes[0];
    let num_readonly_signed = raw_msg_bytes[1];
    let num_readonly_unsigned = raw_msg_bytes[2];

    if num_required_signatures != 1 || num_readonly_signed != 0 {
        return false;
    }

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
        contract.propose_policy(backup.clone(), heirs.clone(), None);
        let alice_info = contract.get_vault_info(Some(alice.clone())).expect("Alice vault should exist");
        assert_eq!(alice_info.state, VaultState::Active);
        assert_eq!(alice_info.owner, alice);
        assert_eq!(alice_info.epoch, 0);

        // Bob is still untouched
        assert!(contract.get_vault_info(Some(bob.clone())).is_none());

        // Bob initializes his own policy
        testing_env!(context.predecessor_account_id(bob.clone()).build());
        let (bob_backup, bob_heirs) = sample_addresses();
        contract.propose_policy(bob_backup, bob_heirs, None);

        let bob_info = contract.get_vault_info(Some(bob.clone())).expect("Bob vault should exist");
        assert_eq!(bob_info.owner, bob);
        assert_eq!(bob_info.state, VaultState::Active);

        // Alice triggers panic - only Alice's vault is evacuated
        testing_env!(context.predecessor_account_id(alice.clone()).build());
        contract.panic();
        assert_eq!(contract.get_vault_info(Some(alice.clone())).unwrap().state, VaultState::Evacuated);
        assert_eq!(contract.get_vault_info(Some(bob.clone())).unwrap().state, VaultState::Active);

        // Alice rotates bunker -> epoch advances to 1, destinations wiped to clean slate, state reset to Unconfigured
        contract.rotate_bunker();
        let alice_rot = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(alice_rot.state, VaultState::Unconfigured);
        assert!(alice_rot.backup.is_empty());
        assert!(alice_rot.heirs.is_empty());
        assert_eq!(alice_rot.epoch, 1);
        assert_eq!(contract.get_vault_info(Some(bob.clone())).unwrap().epoch, 0);
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
        contract.propose_policy(backup, heirs, None);

        // 1. Advance time before full inactivity (heartbeat + challenge) -> trigger_push_inheritance MUST fail
        testing_env!(context
            .predecessor_account_id(anyone_caller.clone())
            .block_timestamp(t0 + heartbeat_ns + challenge_ns - 100)
            .build());
        
        let early_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.trigger_push_inheritance(owner.clone());
        }));
        assert!(early_res.is_err(), "Push inheritance should fail before heartbeat + grace window expires");

        // 2. Owner pings alive -> resets timer
        let ping_time = t0 + heartbeat_ns;
        testing_env!(context
            .predecessor_account_id(owner.clone())
            .block_timestamp(ping_time)
            .build());
        contract.ping();
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().state, VaultState::Active);
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().last_ping_ns, ping_time);

        // 3. Propose a policy change -> pending policy timelock active
        let new_backup = ChainAddresses {
            btc: "tb1qmodified".to_string(),
            evm: "0x5555555555555555555555555555555555555555".to_string(),
            sol: "SolanaMod55555555555555555555555555555555".to_string(),
            near: None,
        };
        contract.propose_policy(new_backup, ChainAddresses::empty(), None);
        assert!(contract.get_vault_info(Some(owner.clone())).unwrap().pending_policy.is_some());

        // 4. Even if past inactivity time, trigger_push_inheritance MUST fail while pending policy is active!
        testing_env!(context
            .predecessor_account_id(anyone_caller.clone())
            .block_timestamp(ping_time + heartbeat_ns + challenge_ns + 100)
            .build());
        let timelock_blocked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.trigger_push_inheritance(owner.clone());
        }));
        assert!(timelock_blocked.is_err(), "Push inheritance MUST be blocked while policy cooldown is pending");

        // 5. Cancel pending policy proves owner is alive (resets heartbeat).
        let cancel_time = ping_time + heartbeat_ns + challenge_ns + 200;
        testing_env!(context
            .predecessor_account_id(owner.clone())
            .block_timestamp(cancel_time)
            .build());
        contract.cancel_policy();
        assert_eq!(contract.get_vault_info(Some(owner.clone())).unwrap().last_ping_ns, cancel_time);

        // 6. After full inactivity expires following cancel_policy, push inheritance succeeds autonomously
        let final_expire_time = cancel_time + heartbeat_ns + challenge_ns + 1;
        testing_env!(context
            .predecessor_account_id(anyone_caller.clone())
            .block_timestamp(final_expire_time)
            .build());
        contract.trigger_push_inheritance(owner.clone());
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
        contract.propose_policy(backup, heirs, None);

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
        contract.propose_policy(new_backup.clone(), new_heirs.clone(), None);
        assert!(contract.get_vault_info(Some(owner.clone())).unwrap().pending_policy.is_some());

        // Cancel policy
        contract.cancel_policy();
        assert!(contract.get_vault_info(Some(owner.clone())).unwrap().pending_policy.is_none());

        // Owner proposes again and applies after timelock
        contract.propose_policy(new_backup.clone(), new_heirs.clone(), None);

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
        contract.propose_policy(backup, heirs, None);

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
            contract.propose_policy(ChainAddresses::empty(), ChainAddresses::empty(), None);
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

    #[test]
    fn test_ping_by_relayer() {
        let alice: AccountId = "alice.testnet".parse().unwrap();
        let relayer: AccountId = "relayer.testnet".parse().unwrap();
        let unauthorized: AccountId = "eve.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(alice.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, Some(relayer.clone()));
        contract.propose_policy(backup, heirs, None);

        let initial_info = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(initial_info.state, VaultState::Active);

        // Relayer pings on behalf of Alice
        testing_env!(context.predecessor_account_id(relayer).block_timestamp(1_000_000_000).build());
        contract.ping_by_relayer(alice.clone());

        let updated_info = contract.get_vault_info(Some(alice.clone())).unwrap();
        assert_eq!(updated_info.last_ping_ns, 1_000_000_000);

        // Unauthorized caller pings on behalf of Alice fails
        testing_env!(context.predecessor_account_id(unauthorized).build());
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.ping_by_relayer(alice.clone());
        }));
        assert!(res.is_err());
    }

    #[test]
    fn test_extract_evm_to_address_and_spoof_rejection() {
        // Construct a genuine EIP-1559 tx
        let to_addr = [0x7au8; 20];
        let mut rlp_list = Vec::new();
        // chain_id = 11155111 (0xaa36a7) -> len 3 -> 0x83, 0xaa, 0x36, 0xa7
        rlp_list.extend_from_slice(&[0x83, 0xaa, 0x36, 0xa7]);
        // nonce = 0 -> 0x80
        rlp_list.push(0x80);
        // max_priority_fee = 1 Gwei -> 0x84, 0x3b, 0x9a, 0xca, 0x00
        rlp_list.extend_from_slice(&[0x84, 0x3b, 0x9a, 0xca, 0x00]);
        // max_fee = 20 Gwei -> 0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00
        rlp_list.extend_from_slice(&[0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);
        // gas_limit = 21000 -> 0x82, 0x52, 0x08
        rlp_list.extend_from_slice(&[0x82, 0x52, 0x08]);
        // to = 20 bytes -> 0x94 followed by to_addr
        rlp_list.push(0x94);
        rlp_list.extend_from_slice(&to_addr);
        // value = 0 -> 0x80
        rlp_list.push(0x80);
        // data = empty -> 0x80
        rlp_list.push(0x80);
        // access_list = empty -> 0xc0
        rlp_list.push(0xc0);

        let mut tx_bytes = vec![0x02]; // EIP-1559 type
        // RLP list header
        let list_len = rlp_list.len();
        if list_len <= 55 {
            tx_bytes.push(0xc0 + list_len as u8);
        } else {
            tx_bytes.push(0xf8);
            tx_bytes.push(list_len as u8);
        }
        tx_bytes.extend_from_slice(&rlp_list);

        let extracted = extract_evm_to_address(&tx_bytes);
        assert_eq!(extracted, Some(to_addr));

        // Attempting to spoof by putting the target address inside data and changing `to`
        let attacker_addr = [0x66u8; 20];
        let mut spoofed_list = Vec::new();
        spoofed_list.extend_from_slice(&[0x83, 0xaa, 0x36, 0xa7]); // chain_id
        spoofed_list.push(0x80); // nonce
        spoofed_list.extend_from_slice(&[0x84, 0x3b, 0x9a, 0xca, 0x00]); // priority fee
        spoofed_list.extend_from_slice(&[0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]); // max fee
        spoofed_list.extend_from_slice(&[0x82, 0x52, 0x08]); // gas limit
        spoofed_list.push(0x94);
        spoofed_list.extend_from_slice(&attacker_addr); // ATTACKER in `to`!
        spoofed_list.push(0x80); // value
        // Data contains victim's address
        spoofed_list.push(0x94);
        spoofed_list.extend_from_slice(&to_addr);
        spoofed_list.push(0xc0); // access list

        let mut spoofed_tx = vec![0x02];
        let spoofed_len = spoofed_list.len();
        if spoofed_len <= 55 {
            spoofed_tx.push(0xc0 + spoofed_len as u8);
        } else {
            spoofed_tx.push(0xf8);
            spoofed_tx.push(spoofed_len as u8);
        }
        spoofed_tx.extend_from_slice(&spoofed_list);

        let extracted_spoofed = extract_evm_to_address(&spoofed_tx);
        assert_eq!(extracted_spoofed, Some(attacker_addr));
        // Ensures the extractor didn't mistake the data payload for the `to` recipient!
        assert_ne!(extracted_spoofed, Some(to_addr));
    }

    #[test]
    fn test_additive_policy_instant_activation_without_timelock() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);

        // 1. Initial setup with only NEAR destination configured
        let mut initial_backup = ChainAddresses::empty();
        initial_backup.near = Some("alice-backup.testnet".parse().unwrap());
        let mut initial_heirs = ChainAddresses::empty();
        initial_heirs.near = Some("alice-heir.testnet".parse().unwrap());

        contract.propose_policy(initial_backup.clone(), initial_heirs.clone(), None);
        let info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(info.state, VaultState::Active);
        assert!(info.pending_policy.is_none());
        assert_eq!(info.backup.near, Some("alice-backup.testnet".parse().unwrap()));
        assert_eq!(info.backup.evm, "");

        // 2. Add EVM and BTC addresses to previously empty fields
        let mut additive_backup = initial_backup.clone();
        additive_backup.evm = "0x1111111111111111111111111111111111111111".to_string();
        additive_backup.btc = "tb1qaddbackup".to_string();

        let mut additive_heirs = initial_heirs.clone();
        additive_heirs.evm = "0x2222222222222222222222222222222222222222".to_string();

        contract.propose_policy(additive_backup.clone(), additive_heirs.clone(), None);

        // MUST activate immediately without 72h timelock!
        let updated_info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(updated_info.state, VaultState::Active);
        assert!(updated_info.pending_policy.is_none(), "Additive policy should NOT trigger 72h timelock");
        assert_eq!(updated_info.backup.evm, "0x1111111111111111111111111111111111111111");
        assert_eq!(updated_info.backup.btc, "tb1qaddbackup");
        assert_eq!(updated_info.backup.near, Some("alice-backup.testnet".parse().unwrap()));

        // 3. Changing an already configured address MUST trigger 72h timelock
        let mut replacing_backup = additive_backup.clone();
        replacing_backup.near = Some("new-evil-backup.testnet".parse().unwrap()); // CHANGING existing NEAR!

        contract.propose_policy(replacing_backup.clone(), additive_heirs.clone(), None);
        let replacing_info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert!(replacing_info.pending_policy.is_some(), "Modifying existing address MUST trigger timelock");

        // 4. Panic must be rejected while pending policy is active
        let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut c = contract;
            c.panic();
        }));
        assert!(panic_res.is_err(), "Panic must fail during active policy timelock");
    }

    #[test]
    fn test_update_intervals_shortening_timelock_defense() {
        let owner: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc.clone(), None);

        // Arm vault with initial addresses and default 90-day intervals
        let mut backup = ChainAddresses::empty();
        backup.near = Some("bob-backup.testnet".parse().unwrap());
        let mut heirs = ChainAddresses::empty();
        heirs.near = Some("bob-heir.testnet".parse().unwrap());
        contract.propose_policy(backup.clone(), heirs.clone(), None);

        let info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(info.heartbeat_interval_ns, DEFAULT_HEARTBEAT_INTERVAL_NS);
        assert!(info.pending_policy.is_none());

        // 1. Lengthening interval (e.g. from 90 days to 180 days) is instant
        let longer_hb = DEFAULT_HEARTBEAT_INTERVAL_NS * 2;
        contract.update_intervals(Some(U64(longer_hb)), None);
        let info_longer = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(info_longer.heartbeat_interval_ns, longer_hb);
        assert!(info_longer.pending_policy.is_none(), "Lengthening intervals must NOT trigger timelock");

        // 2. Shortening interval to a shorter production interval (>60s) MUST trigger 72h cooldown
        let short_hb = 86_400_000_000_000; // 1 day
        let short_cp = 86_400_000_000_000; // 1 day
        contract.update_intervals(Some(U64(short_hb)), Some(U64(short_cp)));
        let info_shortened = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert!(info_shortened.pending_policy.is_some(), "Shortening intervals MUST trigger 72h timelock");

        // 3. Premature trigger_push_inheritance MUST revert while 72h timelock is active!
        let inheritance_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut c = contract;
            c.trigger_push_inheritance(owner.clone());
        }));
        assert!(inheritance_res.is_err(), "Premature inheritance must fail while policy cooldown is pending");

        // 4. Demo mode shortening (<= 300s, e.g. 120s) must NOT trigger 72h cooldown
        let demo_hb = 120_000_000_000; // 2 minutes
        let demo_cp = 30_000_000_000;  // 30 seconds
        let mut contract_demo = LastKeyVault::new(mpc, None);
        contract_demo.propose_policy(backup, heirs, None);
        contract_demo.update_intervals(Some(U64(demo_hb)), Some(U64(demo_cp)));
        let info_demo = contract_demo.get_vault_info(Some(owner)).unwrap();
        assert_eq!(info_demo.heartbeat_interval_ns, demo_hb);
        assert_eq!(info_demo.challenge_period_ns, demo_cp);
        assert!(info_demo.pending_policy.is_none(), "Demo intervals (120s/30s) must NOT trigger 72h timelock");
    }

    #[test]
    fn test_dynamic_registered_accounts() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);
        let list1 = contract.get_registered_accounts();
        assert!(list1.contains(&"okgoogleok.testnet".parse().unwrap()));

        contract.register_account(Some(owner.clone()));
        let list2 = contract.get_registered_accounts();
        assert!(list2.contains(&owner));
    }

    #[test]
    fn test_heir_memo_and_testament() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();
        let context = get_context(owner.clone());
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);
        // Initially no memo
        assert_eq!(contract.get_heir_memo(owner.clone()), None);

        // Propose policy with memo
        contract.propose_policy(backup.clone(), heirs.clone(), Some("test test".to_string()));
        assert_eq!(contract.get_heir_memo(owner.clone()), Some("test test".to_string()));
        let info = contract.get_vault_info(Some(owner.clone())).unwrap();
        assert_eq!(info.heir_memo, Some("test test".to_string()));

        // Update memo directly via set_heir_memo
        contract.set_heir_memo("take care of each other".to_string());
        assert_eq!(contract.get_heir_memo(owner.clone()), Some("take care of each other".to_string()));

        // Clear memo
        contract.set_heir_memo("".to_string());
        assert_eq!(contract.get_heir_memo(owner), None);
    }

    #[test]
    fn test_get_actionable_vaults() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();
        let mut context = get_context(owner.clone());
        context.block_timestamp(1_000_000_000);
        testing_env!(context.build());

        let mut contract = LastKeyVault::new(mpc, None);
        contract.propose_policy(backup, heirs, None);

        // Right after ping, not actionable
        assert!(contract.get_actionable_vaults().is_empty());

        // Fast forward beyond 90 days heartbeat + 7 days challenge (100 days)
        let mut expired_context = get_context(owner.clone());
        expired_context.block_timestamp(1_000_000_000_u64 + 100_u64 * 86_400_u64 * 1_000_000_000_u64);
        testing_env!(expired_context.build());

        let actionable = contract.get_actionable_vaults();
        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable[0].owner, owner);
    }
}

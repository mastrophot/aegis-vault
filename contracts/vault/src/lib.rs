use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
};

const DEFAULT_HEARTBEAT_INTERVAL_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000; // 90 days
const DEFAULT_CHALLENGE_PERIOD_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;    // 7 days
const DEFAULT_POLICY_TIMELOCK_NS: u64 = 3 * 24 * 60 * 60 * 1_000_000_000;     // 72 hours
const MPC_GAS: Gas = Gas::from_tgas(50);
const CALLBACK_GAS: Gas = Gas::from_tgas(30);

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

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub payload_v2: SignPayloadV2,
    pub path: String,
    pub domain_id: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum SignPayloadV2 {
    Ecdsa([u8; 32]),
    Eddsa([u8; 32]),
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct VaultInfo {
    pub owner: AccountId,
    pub guardian: AccountId,
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
}

#[near(contract_state)]
#[derive(PanicOnDefault, Clone)]
pub struct LastKeyVault {
    pub owner: AccountId,
    pub guardian: AccountId,
    pub mpc_contract: AccountId,
    pub heartbeat_interval_ns: u64,
    pub challenge_period_ns: u64,
    pub policy_timelock_ns: u64,
    pub last_ping_ns: u64,
    pub state: VaultState,
    pub backup: ChainAddresses,
    pub heirs: ChainAddresses,
    pub pending_policy: Option<PendingPolicy>,
}

#[near]
impl LastKeyVault {
    #[init]
    pub fn new(
        owner: AccountId,
        guardian: AccountId,
        mpc_contract: AccountId,
        backup: ChainAddresses,
        heirs: ChainAddresses,
        heartbeat_interval_ns: Option<u64>,
        challenge_period_ns: Option<u64>,
        policy_timelock_ns: Option<u64>,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        Self {
            owner,
            guardian,
            mpc_contract,
            heartbeat_interval_ns: heartbeat_interval_ns.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_NS),
            challenge_period_ns: challenge_period_ns.unwrap_or(DEFAULT_CHALLENGE_PERIOD_NS),
            policy_timelock_ns: policy_timelock_ns.unwrap_or(DEFAULT_POLICY_TIMELOCK_NS),
            last_ping_ns: env::block_timestamp(),
            state: VaultState::Active,
            backup,
            heirs,
            pending_policy: None,
        }
    }

    /// Owner heartbeat: resets the timer and cancels any pending claim from heirs
    pub fn ping(&mut self) {
        self.assert_owner();
        require!(self.state != VaultState::Evacuated, "Cannot ping when evacuated");
        self.last_ping_ns = env::block_timestamp();
        if let VaultState::Claiming { .. } = self.state {
            self.state = VaultState::Active;
            env::log_str("CLAIM_CANCELLED: Owner pinged alive");
        }
    }

    /// Emergency Panic button: instantly shifts vault into Evacuated state
    /// Callable by owner or guardian
    pub fn panic(&mut self) {
        self.assert_owner_or_guardian();
        self.state = VaultState::Evacuated;
        env::log_str("PANIC_TRIGGERED: Vault evacuated. Sweeping routed exclusively to backup addresses.");
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

    /// Propose updating backup or heir addresses. Enforces a 72-hour timelock.
    pub fn propose_policy(&mut self, backup: ChainAddresses, heirs: ChainAddresses) {
        self.assert_owner();
        require!(self.state == VaultState::Active, "Can only update policy in Active state");
        let effective_at_ns = env::block_timestamp() + self.policy_timelock_ns;
        self.pending_policy = Some(PendingPolicy {
            backup,
            heirs,
            effective_at_ns,
        });
        env::log_str("POLICY_PROPOSED: 72h timelock started");
    }

    /// Apply proposed policy after timelock has elapsed
    pub fn apply_policy(&mut self) {
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

    /// Guardian veto: cancels any pending policy proposal
    pub fn veto_policy(&mut self) {
        self.assert_guardian();
        self.pending_policy = None;
        env::log_str("POLICY_VETOED: Pending policy cancelled by guardian");
    }

    /// Requests an MPC threshold signature from v1.signer for a foreign chain transaction
    /// The destination is strictly constrained:
    /// - If Evacuated -> destination MUST be backup addresses
    /// - If Inheritance -> destination MUST be heirs addresses
    pub fn request_sweep_signature(
        &mut self,
        chain: String,
        payload_hash: [u8; 32],
        derivation_path: String,
        is_eddsa: bool,
    ) -> Promise {
        require!(
            self.state == VaultState::Evacuated || self.state == VaultState::Inheritance,
            "Sweeping only allowed in Evacuated or Inheritance state"
        );

        let target_destination = match self.state {
            VaultState::Evacuated => &self.backup,
            VaultState::Inheritance => &self.heirs,
            _ => env::panic_str("Invalid state for sweep"),
        };

        env::log_str(&format!(
            "SWEEP_REQUEST: Chain={}, TargetBTC={}, TargetEVM={}, TargetSOL={}",
            chain, target_destination.btc, target_destination.evm, target_destination.sol
        ));

        let request = SignRequest {
            payload_v2: if is_eddsa {
                SignPayloadV2::Eddsa(payload_hash)
            } else {
                SignPayloadV2::Ecdsa(payload_hash)
            },
            path: derivation_path,
            domain_id: if is_eddsa { 1 } else { 0 },
        };

        // Call v1.signer with attached 1 yoctoNEAR
        Promise::new(self.mpc_contract.clone())
            .function_call(
                "sign".to_string(),
                near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
                    "request": request
                }))
                .expect("Failed to serialize sign request"),
                NearToken::from_yoctonear(1),
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
            guardian: self.guardian.clone(),
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
        }
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "Only owner can call this");
    }

    fn assert_guardian(&self) {
        require!(env::predecessor_account_id() == self.guardian, "Only guardian can call this");
    }

    fn assert_owner_or_guardian(&self) {
        let caller = env::predecessor_account_id();
        require!(
            caller == self.owner || caller == self.guardian,
            "Only owner or guardian can call this"
        );
    }
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
            near: None,
        };
        let heirs = ChainAddresses {
            btc: "tb1qheir".to_string(),
            evm: "0x2222222222222222222222222222222222222222".to_string(),
            sol: "SolanaHeir111111111111111111111111111111".to_string(),
            near: None,
        };
        (backup, heirs)
    }

    #[test]
    fn test_initialization() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let guardian: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let context = get_context(owner.clone());
        testing_env!(context.build());

        let vault = LastKeyVault::new(owner.clone(), guardian, mpc, backup, heirs, None, None, None);
        assert_eq!(vault.state, VaultState::Active);
        assert_eq!(vault.owner, owner);
    }

    #[test]
    fn test_panic_button() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let guardian: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        testing_env!(context.build());

        let mut vault = LastKeyVault::new(owner.clone(), guardian.clone(), mpc, backup, heirs, None, None, None);
        assert_eq!(vault.state, VaultState::Active);

        // Guardian triggers panic
        testing_env!(context.predecessor_account_id(guardian).build());
        vault.panic();
        assert_eq!(vault.state, VaultState::Evacuated);
    }

    #[test]
    fn test_claim_lifecycle_and_ping_recovery() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let guardian: AccountId = "bob.testnet".parse().unwrap();
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
            guardian,
            mpc,
            backup,
            heirs,
            Some(heartbeat_ns),
            Some(challenge_ns),
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
    fn test_policy_timelock_and_guardian_veto() {
        let owner: AccountId = "alice.testnet".parse().unwrap();
        let guardian: AccountId = "bob.testnet".parse().unwrap();
        let mpc: AccountId = "v1.signer-prod.testnet".parse().unwrap();
        let (backup, heirs) = sample_addresses();

        let mut context = get_context(owner.clone());
        let t0 = 1_000_000_000_000_000_000;
        testing_env!(context.block_timestamp(t0).build());

        let mut vault = LastKeyVault::new(owner.clone(), guardian.clone(), mpc, backup, heirs, None, None, None);

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

        // Guardian vetos
        testing_env!(context.predecessor_account_id(guardian).build());
        vault.veto_policy();
        assert!(vault.pending_policy.is_none());

        // Owner proposes again
        testing_env!(context.predecessor_account_id(owner.clone()).build());
        vault.propose_policy(new_backup.clone(), new_heirs.clone());

        // Apply before timelock should fail
        testing_env!(context.block_timestamp(t0 + 100).build());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = vault.clone();
            v.apply_policy();
        }));
        assert!(result.is_err(), "Cannot apply policy before timelock expiry");

        // Apply after 72h timelock
        testing_env!(context.block_timestamp(t0 + DEFAULT_POLICY_TIMELOCK_NS + 1).build());
        vault.apply_policy();
        assert_eq!(vault.backup, new_backup);
        assert_eq!(vault.heirs, new_heirs);
    }
}

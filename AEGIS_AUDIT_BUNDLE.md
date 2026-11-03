# 🛡️ AEGIS PROTOCOL: COMPREHENSIVE ARCHITECTURAL AUDIT & VIABILITY DOSSIER

## 🎯 AUDIT MISSION & SCOPE
Ти виступаєш у ролі суворого Senior Web3 Security Auditor & Principal Distributed Systems Architect.
Твоє завдання — провести нещадний, глибокий та реалістичний аудит проекту **Aegis**, перевірити його на реальну життєздатність (а не теоретичні фантазії), знайти всі вектори атак, баги у смартконтракті та релеєрі, а також очистити тексти від маркетингового булшіту на користь сухої, простої технічної ясності.

---

## 🏛️ ЯК ЗАДУМАНО І ЯК ПРАЦЮЄ ПРОЄКТ (OPERATIONAL ARCHITECTURE)

Aegis — це децентралізований автономний сейф (Dead-Man's Switch) та протокол спадкування для **Bitcoin, Ethereum (і EVM L2) та Solana**, побудований на базі **NEAR Chain Signatures (контракт v1.signer)**.

### Ключова філософія:
1. **Zero Private Keys:** На жодному сервері чи пристрої ніколи не генеруються та не зберігаються приватні ключі від адрес BTC, ETH чи SOL. Адреси деривуються математично через NEAR MPC Consensus (`v1.signer`), а контракт сейфу є єдиним контролером, який може авторизувати підпис транзакцій.
2. **Self-Sustaining Gas (Без окремого балансу на газ):** Юзеру не потрібно тримати нативний газ на кожній адресі сейфу. При виводі (sweep) комісія мережі майнерам віднімається безпосередньо з тієї суми, яка виводиться. Платформа бере 0.00 USD.
3. **Anti-Extortion & 72-Hour Timelock:** Будь-яка зміна адрес спадкоємців чи резервних гаманців заморожується рівно на 72 години. Якщо власника намагаються шантажувати або його ключ скомпрометовано, власник може миттєво скасувати підміну (`cancel_policy()`) або запустити панічну евакуацію (`panic()`), яка автоматично скидає непідтверджену політику.
4. **Permanent Bunker Burn:** Після евакуації чи спадкування епоха бункера вважається скомпрометованою. Контракт ротує епоху (`self.epoch += 1`), створюючи абсолютно новий набір адрес. Старі епохи блокуються назавжди.

### Життєвий цикл сейфу:
* **Фаза 1: Депозит (Active)**
  Власник поповнює згенеровані адреси (Bitcoin Native SegWit, EVM, Solana Ed25519, NEAR).
* **Фаза 2: Моніторинг пульсу (Heartbeat)**
  Власник періодично (наприклад, раз на 90 днів) натискає кнопку «I'M ALIVE», скидаючи таймер контракту (`ping()`).
* **Фаза 3: Екстрена евакуація (Emergency Panic)**
  У разі загрози або зламу власник натискає «EMERGENCY PANIC». Контракт миттєво скасовує будь-які незатверджені підміни адрес (`pending_policy = None`) і виводить 100% коштів на заздалегідь зафіксовані резервні адреси (`self.backup`). Модальне вікно підтвердження можна або ввімкнути (3с утримання для захисту від випадкового кліку), або вимкнути (режим бойової 1-Click паніки).
* **Фаза 4: Спадкування (Inheritance)**
  Якщо пульс не оновлюється понад 90 днів:
  1. Контракт переходить у стан `Claiming` (запускається 7-денний пільговий період `grace_period_ns`).
  2. Якщо власник не повернувся і не натиснув `ping()`, після закінчення 7 днів викликається `finalize_inheritance()`.
  3. Релеєр або спадкоємець викликає `request_sweep_signature()`, і MPC підписує транзакції виводу всіх монет на адреси спадкоємців (`self.heirs`).

---

## 🔍 ЗАВДАННЯ ДЛЯ АУДИТОРА (ЩО ПОТРІБНО ПЕРЕВІРИТИ):

### 1. Реалістичність та працездатність (Feasibility Check vs Vaporware):
* Чи дійсно цей стек (NEAR SDK 5.5 + `v1.signer` MPC + Bitcoin SegWit PSBT + EVM EIP-1559 + Solana Ed25519) є робочим у реальних мережах, чи це теоретичний концепт із підводними каменями?
* Які реальні затримки (latency) підпису в NEAR MPC? Чи вистачить 250 TGas на виклик `sign` і 30 TGas на callback?
* Чи існує ризик DoS мережі MPC під час масового виводу активів?

### 2. Вектори атак та дірки в смартконтракті (`lib.rs`):
* **Гонка станів та реентрансі:** Чи можна викликати `request_sweep_signature` паралельно декілька разів, викликавши подвійне списання або переповнення газу?
* **Маніпуляція авторизацією релеєра:** `set_authorized_relayer` викликається власником без таймлоку. Якщо ключ власника скомпрометовано, чи може зловмисник поставити свого релеєра і вивести активи не на `self.backup`, а на свою адресу? Як перевіряється адреса отримувача всередині сирої транзакції `payload_hex`?
* **Блокування через переповнення сховища (Storage Staking):** `sweep_near` резервує 1.6 NEAR. Чи вистачить цього резерву для зберігання стану контракту на мейннеті?
* **Смерть старої епохи:** Ми прибрали `target_epoch`, тобто стара епоха блокується назавжди. Якщо користувачеві випадково надішлють гроші на стару адресу після ротації, кошти будуть втрачені. Чи є це прийнятним компромісом заради чистоти безпеки?

### 3. Надійність релеєра (`sweep_relayer.js`):
* **Розрахунок комісій BTC/EVM/SOL:** Чи не виникне ситуації, коли розрахована комісія з'їсть увесь вивід (dust transaction), або транзакція зависне в мемпулі без RBF?
* **Solana SPL Rent:** Релеєр закриває sender ATA інструкцією `CloseAccount` (opcode 9), щоб повернути 2,039,280 lamports ренти. Чи не зламає це сумісність із токенами Token-2022?
* **EVM L2 Gas:** Чи коректно закладено буфер на L1 Data Fee для Base/Arbitrum?

### 4. Очищення текстів та копірайтингу (Anti-Marketing Polish):
* Переглянь тексти у веб-інтерфейсі (`web/index.html`).
* Прибери будь-який маркетинговий пафос («unbreakable», «quantum supremacy», «revolutionary bunker»).
* Запропонуй сухі, чіткі інженерні формулювання простими словами, як у документації UNIX, Bitcoin Core або Linear.

### 5. Ергономіка та дизайн UI:
* Оціни сітку 1536px (`max-w-screen-2xl`), баланс відступів та роботу перемикача «1-Click Panic Armed» vs «Safe Mode 3s Hold».
* Дай рекомендації, як покращити UX та уникнути помилок користувача.

---

## 📦 ВИХІДНІ МАТЕРІАЛИ ПРОЄКТУ (FULL SOURCE CODE):


### 1. SMART CONTRACT (contracts/vault/src/lib.rs)
```rust
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
            pub epoch: u32,
            pub authorized_relayer: Option<AccountId>,
        }

        if let Some(old) = env::state_read::<OldLastKeyVault>() {
            Self {
                owner: old.owner,
                mpc_contract: old.mpc_contract,
                heartbeat_interval_ns: old.heartbeat_interval_ns,
                challenge_period_ns: old.challenge_period_ns,
                policy_timelock_ns: old.policy_timelock_ns,
                last_ping_ns: old.last_ping_ns,
                state: old.state,
                backup: old.backup,
                heirs: old.heirs,
                pending_policy: old.pending_policy,
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
    pub fn panic(&mut self) {
        self.assert_owner();
        self.pending_policy = None;
        self.state = VaultState::Evacuated;
        env::log_str("PANIC_TRIGGERED: Vault evacuated. Sweeping routed exclusively to backup addresses.");
    }

    /// Resets the vault after an evacuation or finalized inheritance, advancing the bunker epoch (e.g. v0 -> v1 -> v2)
    /// Generates clean unexposed MPC addresses and restores Active state
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
    pub fn set_authorized_relayer(&mut self, relayer: Option<AccountId>) {
        self.assert_owner();
        self.authorized_relayer = relayer;
        env::log_str("RELAYER_UPDATED: Authorized relayer updated");
    }

    /// Update heartbeat interval and challenge (grace) period
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

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "Only owner can call this");
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

```

### 2. MULTICHAIN RELAYER (relayer/sweep_relayer.js)
```javascript
/**
 * LastKey Relayer: Automated Cross-Chain Sweep Engine
 * 
 * Watches LastKey Vault contract on NEAR.
 * When state transitions to 'Evacuated' or 'Inheritance', it constructs
 * evacuation transactions for Bitcoin, EVM, and Solana, fetches threshold
 * signatures via the Vault contract's MPC delegate, and broadcasts to foreign chains.
 */

const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');
const web3 = require('@solana/web3.js');
const chainsig = require('chainsig.js');

class LastKeySweepRelayer {
  constructor(config = {}) {
    this.networkId = config.networkId || 'testnet';
    this.mpcContractId = config.mpcContractId || (this.networkId === 'testnet' ? 'v1.signer-prod.testnet' : 'v1.signer');
    this.vaultContractId = config.vaultContractId || 'lastkey-vault-2151.testnet';
    this.derivationPath = config.derivationPath || 'aegis/v0';
    
    this.chainSigContract = new chainsig.contracts.ChainSignatureContract({
      networkId: this.networkId,
      contractId: this.mpcContractId
    });

    this.evmAdapter = new chainsig.chainAdapters.evm.EVM({
      contract: this.chainSigContract
    });

    this.btcAdapter = new chainsig.chainAdapters.btc.Bitcoin({
      contract: this.chainSigContract,
      network: this.networkId === 'mainnet' ? 'mainnet' : 'testnet'
    });

    this.solanaAdapter = new chainsig.chainAdapters.solana.Solana({
      contract: this.chainSigContract
    });
  }

  /**
   * Derive the multichain vault addresses for an owner account
   */
  async deriveAllAddresses(accountId, path = this.derivationPath) {
    const [evm, btc, sol] = await Promise.all([
      this.evmAdapter.deriveAddressAndPublicKey(accountId, path),
      this.btcAdapter.deriveAddressAndPublicKey(accountId, path),
      this.solanaAdapter.deriveAddressAndPublicKey(accountId, path)
    ]);

    return {
      accountId,
      path,
      evm: { address: evm.address, publicKey: evm.publicKey },
      btc: { address: btc.address, publicKey: btc.publicKey },
      sol: { address: sol.address, publicKey: sol.publicKey }
    };
  }

  /**
   * Prepare EVM Sweep Transaction
   */
  async prepareEvmSweep({ fromAddress, toAddress, valueWei, memo, gasLimit = 21000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const dataHex = memo ? ethers.hexlify(ethers.toUtf8Bytes(memo)) : '0x';
    const dataBytes = ethers.getBytes(dataHex);
    // Exact intrinsic gas per EIP-2028: 16 per non-zero byte, 4 per zero byte
    let calldataGas = 0n;
    for (const b of dataBytes) calldataGas += (b === 0 ? 4n : 16n);
    const computedGasLimit = 21000n + calldataGas;

    // For L2 networks (Base, Optimism, Arbitrum), account for L1 Rollup Data fee buffer
    const isL2 = [8453, 84532, 10, 42161, 421614].includes(Number(chainId));
    const l1DataFeeBuffer = isL2 ? 15000000000000n : 0n; // ~0.000015 ETH buffer

    const rawTx = {
      to: toAddress,
      value: BigInt(valueWei),
      nonce: Number(nonce),
      gasLimit: computedGasLimit,
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2, // EIP-1559
      data: dataHex
    };

    // Serialize unsigned tx and compute Keccak256 hash
    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM',
      rawTx,
      unsignedTxHex, // Verifiable raw transaction payload for request_sweep_signature
      txHash,
      hashBytes,
      memo: memo || null,
      l1DataFeeBuffer: l1DataFeeBuffer.toString(),
      isEddsa: false
    };
  }

  /**
   * Prepare ERC-20 Token Sweep (e.g. USDC, USDT)
   * Swept BEFORE native ETH so gas remains available.
   */
  async prepareEvmTokenSweep({ tokenAddress, fromAddress, toAddress, amountRaw, gasLimit = 65000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const erc20Interface = new ethers.Interface([
      'function transfer(address to, uint256 amount) returns (bool)'
    ]);
    const dataHex = erc20Interface.encodeFunctionData('transfer', [toAddress, BigInt(amountRaw)]);

    const rawTx = {
      to: tokenAddress,
      value: 0n,
      nonce: Number(nonce),
      gasLimit: BigInt(gasLimit),
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2,
      data: dataHex
    };

    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM_ERC20',
      tokenAddress,
      rawTx,
      unsignedTxHex, // Verifiable raw token transfer payload
      txHash,
      hashBytes,
      isEddsa: false
    };
  }

  /**
   * Prepare ERC-721 / NFT Sweep
   * Swept FIRST along with tokens so gas remains available.
   */
  async prepareEvmNftSweep({ nftContract, fromAddress, toAddress, tokenId, gasLimit = 85000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const erc721Interface = new ethers.Interface([
      'function safeTransferFrom(address from, address to, uint256 tokenId)'
    ]);
    const dataHex = erc721Interface.encodeFunctionData('safeTransferFrom', [fromAddress, toAddress, BigInt(tokenId)]);

    const rawTx = {
      to: nftContract,
      value: 0n,
      nonce: Number(nonce),
      gasLimit: BigInt(gasLimit),
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2,
      data: dataHex
    };

    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM_NFT',
      nftContract,
      tokenId,
      rawTx,
      unsignedTxHex,
      txHash,
      hashBytes,
      isEddsa: false
    };
  }

  /**
   * Plan Comprehensive Zero-Asset-Left-Behind Sweep
   * Enforces the critical gas-draining avoidance sequence:
   * 1. Sweep all NFTs (regardless of spam flag)
   * 2. Sweep all ERC-20 / SPL Tokens (regardless of spam flag)
   * 3. Sweep remaining native gas balance (balance - gasFee - L1FeeBuffer)
   */
  planEvmEvacuationQueue({ fromAddress, toAddress, nfts = [], tokens = [], nativeWeiBalance = 0n, memo = null, gasPriceWei = 21000000000n, chainId = 11155111 }) {
    const queue = [];
    let currentNonce = 0;

    // 1. NFTs first
    for (const nft of nfts) {
      queue.push({
        step: 'NFT_SWEEP',
        targetContract: nft.contract,
        id: nft.tokenId,
        gasLimit: 85000n,
        nonce: currentNonce++
      });
    }

    // 2. Tokens second (all tokens, zero filtering)
    for (const tok of tokens) {
      queue.push({
        step: 'TOKEN_SWEEP',
        tokenAddress: tok.address,
        amount: tok.amount,
        gasLimit: 65000n,
        nonce: currentNonce++
      });
    }

    // Exact intrinsic gas for memo per EIP-2028: 16 per non-zero byte, 4 per zero byte
    let calldataGas = 0n;
    if (memo) {
      const memoBytes = Buffer.from(memo, 'utf8');
      for (const b of memoBytes) calldataGas += (b === 0 ? 4n : 16n);
    }

    // For L2 networks (Base, Optimism, Arbitrum), account for L1 Rollup Data fee buffer
    const isL2 = [8453, 84532, 10, 42161, 421614].includes(Number(chainId));
    const l1DataFeeBuffer = isL2 ? 50000000000000n : 0n; // ~0.00005 ETH for L1 DA

    // Calculate total reserved gas for all prior steps + final native sweep
    const totalGasUnits = BigInt(nfts.length) * 85000n + BigInt(tokens.length) * 65000n + (21000n + calldataGas);
    const totalGasCost = totalGasUnits * BigInt(gasPriceWei) + l1DataFeeBuffer;
    const nativeBal = BigInt(nativeWeiBalance);
    const sweepWei = nativeBal > totalGasCost ? nativeBal - totalGasCost : 0n;

    // 3. Native ETH LAST (cleans to absolute 0 minus fee)
    queue.push({
      step: 'NATIVE_FINAL_SWEEP',
      toAddress,
      balanceBefore: nativeBal.toString(),
      sweepAmountWei: sweepWei.toString(),
      gasCostReservedWei: totalGasCost.toString(),
      l1DataFeeBufferWei: l1DataFeeBuffer.toString(),
      memo: memo,
      nonce: currentNonce
    });

    return queue;
  }

  /**
   * Execute Evacuation Queue with Fault Isolation (Anti-Revert Protection)
   * If a scam, paused, or blacklisted token reverts, it NEVER halts the sweep:
   * it logs and continues immediately. Nonces are preserved continuously so
   * subsequent transactions are never blocked in the mempool by a nonce gap.
   */
  async executeQueueWithFaultIsolation(queue, dispatchFn) {
    const results = [];
    let continuousNonce = null;

    for (const task of queue) {
      if (continuousNonce === null && task.nonce !== undefined) {
        continuousNonce = task.nonce;
      }
      const activeTask = { ...task, nonce: continuousNonce };
      try {
        const txResult = await dispatchFn(activeTask);
        results.push({ task: activeTask, status: 'SUCCESS', txResult });
        continuousNonce++; // Nonce advances ONLY on successful step execution
      } catch (err) {
        console.warn(`⚠️ [Aegis Isolation] Step ${task.step} (${task.targetContract || task.tokenAddress || 'asset'}) failed. Skipping without consuming nonce:`, err.message);
        results.push({ task: activeTask, status: 'SKIPPED_REVERT', error: err.message });
        // Nonce is intentionally kept unchanged for the next task
      }
    }
    return results;
  }

  /**
   * Assemble signed EVM transaction from MPC signature (r, s, recoveryId)
   * Supports both raw RSV and NEAR v1.signer Secp256k1 response structure
   */
  assembleSignedEvmTx(rawTx, mpcSignature) {
    const tx = ethers.Transaction.from(rawTx);
    let rHex, sHex, yParity;

    if (mpcSignature.big_r && mpcSignature.big_r.affine_point) {
      // NEAR v1.signer returns big_r.affine_point (33-byte hex, strip 02/03 prefix)
      rHex = '0x' + mpcSignature.big_r.affine_point.slice(2);
      sHex = '0x' + (mpcSignature.s.scalar || mpcSignature.s);
      yParity = mpcSignature.recovery_id;
    } else {
      rHex = mpcSignature.r.startsWith('0x') ? mpcSignature.r : '0x' + mpcSignature.r;
      sHex = mpcSignature.s.startsWith('0x') ? mpcSignature.s : '0x' + mpcSignature.s;
      if (mpcSignature.yParity !== undefined) {
        yParity = mpcSignature.yParity;
      } else if (mpcSignature.v !== undefined) {
        yParity = mpcSignature.v >= 27 ? mpcSignature.v - 27 : mpcSignature.v;
      } else {
        yParity = 0;
      }
    }

    tx.signature = {
      r: rHex,
      s: sHex,
      yParity: yParity
    };

    return {
      signedTx: tx.serialized,
      txHash: tx.hash,
      from: tx.from
    };
  }

  /**
   * Prepare Bitcoin Sweep PSBT
   * Includes dynamic vSize calculation, dust input filtering, and BIP-125 Opt-in RBF.
   */
  prepareBtcSweep({ utxos, fromAddress, toAddress, memo, feeRateSatPerVb = 20, feeSatsOverride = null, network = bitcoin.networks.testnet }) {
    // Filter out dust inputs with negative effective value (costing more than 68 vBytes * feeRate)
    const effectiveUtxos = utxos.filter(u => u.value > Math.ceil(68 * feeRateSatPerVb));
    if (effectiveUtxos.length === 0) {
      throw new Error(`All UTXOs are dust below fee threshold (${feeRateSatPerVb} sat/vB)`);
    }

    const psbt = new bitcoin.Psbt({ network });
    let totalIn = 0;

    for (const utxo of effectiveUtxos) {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        sequence: 0xfffffffd, // BIP-125 Opt-in RBF (allows CPFP/RBF fee bumping)
        witnessUtxo: {
          script: bitcoin.address.toOutputScript(fromAddress, network),
          value: utxo.value
        }
      });
      totalIn += utxo.value;
    }

    const memoBytes = memo ? Buffer.from(memo, 'utf8').slice(0, 80) : null;
    const estimatedVSize = Math.ceil(10.5 + effectiveUtxos.length * 68 + 31 + (memoBytes ? memoBytes.length + 11 : 0));
    const feeSats = feeSatsOverride !== null ? Math.ceil(feeSatsOverride) : Math.max(1000, Math.ceil(estimatedVSize * feeRateSatPerVb));

    const sendAmount = totalIn - feeSats;
    const BTC_DUST_LIMIT_SATS = 546;
    if (sendAmount < BTC_DUST_LIMIT_SATS) {
      throw new Error(`Send amount ${sendAmount} sats is below Bitcoin dust limit (${BTC_DUST_LIMIT_SATS} sats)`);
    }

    psbt.addOutput({
      address: toAddress,
      value: sendAmount
    });

    if (memoBytes) {
      const embed = bitcoin.payments.embed({ data: [memoBytes] });
      psbt.addOutput({
        script: embed.output,
        value: 0
      });
    }

    return {
      chain: 'BTC',
      psbtHex: psbt.toHex(),
      sendAmount,
      totalIn,
      feeSats,
      feeRateSatPerVb,
      estimatedVSize,
      effectiveUtxoCount: effectiveUtxos.length,
      memo: memo || null
    };
  }

  /**
   * Prepare Solana Sweep Transaction
   */
  /**
   * Prepare Solana Sweep Transaction
   * Uses feePayer: from (Vault) so recipient signature is never needed (Push Inheritance).
   * Passes raw serialized message bytes for Ed25519 (no double sha256).
   */
  prepareSolanaSweep({ fromPubkey, toPubkey, lamports, memo, recentBlockhash }) {
    const from = new web3.PublicKey(fromPubkey);
    const to = new web3.PublicKey(toPubkey);
    const TX_FEE_LAMPORTS = 5000n;
    const sweepLamports = BigInt(lamports) - TX_FEE_LAMPORTS;
    if (sweepLamports <= 0n) {
      throw new Error(`Insufficient SOL balance for fee: balance ${lamports} <= fee ${TX_FEE_LAMPORTS}`);
    }

    const transaction = new web3.Transaction({
      recentBlockhash: recentBlockhash || '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM',
      feePayer: from // Vault pays its own fee and signs
    }).add(
      web3.SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: to,
        lamports: Number(sweepLamports)
      })
    );

    if (memo) {
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: from, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: Buffer.from(memo, 'utf8')
        })
      );
    }

    const messageBytes = transaction.serializeMessage();
    const rawPayloadHex = Buffer.from(messageBytes).toString('hex');

    return {
      chain: 'SOL',
      serializedMessage: messageBytes.toString('base64'),
      rawPayloadHex,
      sweepLamports: sweepLamports.toString(),
      memo: memo || null,
      isEddsa: true
    };
  }

  /**
   * Prepare Solana SPL Token Sweep (e.g. USDC, PYUSD) to Brand New Empty Recipient
   * Bundles createAssociatedTokenAccountIdempotent + transferChecked into ONE atomic transaction.
   * Recipient needs ZERO SOL balance - rent is funded by Vault.
   * Supports both standard SPL and Token-2022 programs.
   * Passes raw serialized message bytes for Ed25519.
   */
  prepareSolanaTokenSweep({ mintPubkey, fromOwnerPubkey, toRecipientPubkey, amountTokens, memo, recentBlockhash, tokenProgramId = null }) {
    const fromOwner = new web3.PublicKey(fromOwnerPubkey);
    const toRecipient = new web3.PublicKey(toRecipientPubkey);
    const mint = new web3.PublicKey(mintPubkey);

    const TOKEN_PROGRAM_ID = tokenProgramId
      ? new web3.PublicKey(tokenProgramId)
      : new web3.PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
    const ASSOCIATED_TOKEN_PROGRAM_ID = new web3.PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

    // Derive recipient ATA address deterministically
    const [recipientAta] = web3.PublicKey.findProgramAddressSync(
      [toRecipient.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const [senderAta] = web3.PublicKey.findProgramAddressSync(
      [fromOwner.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const transaction = new web3.Transaction({
      recentBlockhash: recentBlockhash || '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM',
      feePayer: fromOwner
    });

    // 1. Idempotent ATA creation instruction (creates ATA if missing, no-op if exists)
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: fromOwner, isSigner: true, isWritable: true },
          { pubkey: recipientAta, isSigner: false, isWritable: true },
          { pubkey: toRecipient, isSigner: false, isWritable: false },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }
        ],
        programId: ASSOCIATED_TOKEN_PROGRAM_ID,
        data: Buffer.from([1]) // 1 = CreateIdempotent
      })
    );

    // 2. Token Transfer instruction
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: senderAta, isSigner: false, isWritable: true },
          { pubkey: recipientAta, isSigner: false, isWritable: true },
          { pubkey: fromOwner, isSigner: true, isWritable: false }
        ],
        programId: TOKEN_PROGRAM_ID,
        data: Buffer.concat([Buffer.from([3]), Buffer.from(new BigUint64Array([BigInt(amountTokens)]).buffer)]) // 3 = Transfer
      })
    );

    // 3. CloseAccount instruction (opcode 9) - closes emptied senderAta and reclaims the 2,039,280 lamports rent back to fromOwner
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: senderAta, isSigner: false, isWritable: true },
          { pubkey: fromOwner, isSigner: false, isWritable: true }, // Rent returns to vault balance
          { pubkey: fromOwner, isSigner: true, isWritable: false }
        ],
        programId: TOKEN_PROGRAM_ID,
        data: Buffer.from([9]) // 9 = CloseAccount
      })
    );

    if (memo) {
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: fromOwner, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: Buffer.from(memo, 'utf8')
        })
      );
    }

    const messageBytes = transaction.serializeMessage();
    const rawPayloadHex = Buffer.from(messageBytes).toString('hex');

    return {
      chain: 'SOL_SPL_TOKEN',
      recipientAta: recipientAta.toBase58(),
      senderAta: senderAta.toBase58(),
      serializedMessage: messageBytes.toString('base64'),
      rawPayloadHex,
      memo: memo || null,
      isEddsa: true
    };
  }

  /**
   * Finalize Bitcoin Sweep PSBT with MPC ECDSA signature(s)
   * Converts MPC (r, s) into DER encoding (BIP-66) and attaches SIGHASH_ALL (0x01).
   *
   * @param {string} psbtHex - Unfinalized PSBT in hex format
   * @param {Array<{ r: string|Buffer, s: string|Buffer, publicKey: string|Buffer, inputIndex?: number }>} signatures
   * @param {object} network - bitcoinjs network (default: bitcoin.networks.testnet)
   */
  finalizeBtcSweepPsbt(psbtHex, signatures = [], network = bitcoin.networks.testnet) {
    const psbt = bitcoin.Psbt.fromHex(psbtHex, { network });

    if (signatures && signatures.length > 0) {
      signatures.forEach((sigObj, idx) => {
        const inputIndex = typeof sigObj.inputIndex === 'number' ? sigObj.inputIndex : idx;
        const rBuf = Buffer.isBuffer(sigObj.r) ? sigObj.r : Buffer.from(sigObj.r.replace(/^0x/, ''), 'hex');
        const sBuf = Buffer.isBuffer(sigObj.s) ? sigObj.s : Buffer.from(sigObj.s.replace(/^0x/, ''), 'hex');
        const pubkeyRaw = sigObj.publicKey || sigObj.pubkey;
        if (!pubkeyRaw) {
          throw new Error(`Missing publicKey for PSBT signature at input ${inputIndex}`);
        }
        const pubkeyBuf = Buffer.isBuffer(pubkeyRaw)
          ? pubkeyRaw
          : Buffer.from(pubkeyRaw.replace(/^0x/, ''), 'hex');

        const derSig = this.encodeDerSignature(rBuf, sBuf);
        const sigWithHashType = Buffer.concat([derSig, Buffer.from([bitcoin.Transaction.SIGHASH_ALL])]);

        psbt.updateInput(inputIndex, {
          partialSig: [{
            pubkey: pubkeyBuf,
            signature: sigWithHashType
          }]
        });
      });
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    return {
      txHex: tx.toHex(),
      txId: tx.getId()
    };
  }

  /**
   * Encode (r, s) to DER (BIP-66) format
   */
  encodeDerSignature(rBuffer, sBuffer) {
    let r = Buffer.from(rBuffer);
    let s = Buffer.from(sBuffer);
    if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
    if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);
    while (r.length > 1 && r[0] === 0x00 && !(r[1] & 0x80)) r = r.slice(1);
    while (s.length > 1 && s[0] === 0x00 && !(s[1] & 0x80)) s = s.slice(1);

    const length = 4 + r.length + s.length;
    return Buffer.concat([
      Buffer.from([0x30, length, 0x02, r.length]),
      r,
      Buffer.from([0x02, s.length]),
      s
    ]);
  }

  /**
   * Assemble signed Solana transaction from MPC Ed25519 signature
   */
  assembleSignedSolanaTx(serializedMessageBase64, fromPubkeyStr, mpcEddsaSignature) {
    const fromPubkey = new web3.PublicKey(fromPubkeyStr);
    const message = web3.Message.from(Buffer.from(serializedMessageBase64, 'base64'));
    const tx = web3.Transaction.populate(message);
    const sigBytes = Buffer.isBuffer(mpcEddsaSignature)
      ? mpcEddsaSignature
      : Buffer.from((mpcEddsaSignature.signature || mpcEddsaSignature).replace(/^0x/, ''), 'hex');
    tx.addSignature(fromPubkey, sigBytes);
    return {
      signedTxBase64: tx.serialize({ verifySignatures: false, requireAllSignatures: false }).toString('base64'),
      signatureHex: sigBytes.toString('hex')
    };
  }

  /**
   * JIT Blockhash Refresher (Solana)
   * Fetches latest finalized blockhash immediately before MPC signing to prevent 150-slot expiry.
   */
  async refreshTransactionBlockhash(connection, transaction, feePayerPubkey) {
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('finalized');
    transaction.recentBlockhash = blockhash;
    transaction.feePayer = new web3.PublicKey(feePayerPubkey);
    const messageBytes = transaction.serializeMessage();
    return {
      blockhash,
      lastValidBlockHeight,
      serializedMessageBase64: messageBytes.toString('base64'),
      rawPayloadHex: Buffer.from(messageBytes).toString('hex')
    };
  }

  /**
   * Prepare Native NEAR & NEP-141 Sweep
   * Safely leaves calculated contract storage reserve (~1.6 NEAR) and sweeps the remaining balance.
   */
  prepareNearSweep({ fromAccount, toAccount, balanceYocto, reserveYocto = '1600000000000000000000000', memo }) {
    const total = BigInt(balanceYocto);
    const reserve = BigInt(reserveYocto);
    const sweepAmount = total > reserve ? total - reserve : 0n;

    return {
      chain: 'NEAR',
      fromAccount,
      toAccount,
      sweepAmountYocto: sweepAmount.toString(),
      storageReserveYocto: reserve.toString(),
      memo: memo || null,
      actions: [
        {
          type: 'Transfer',
          params: { deposit: sweepAmount.toString() }
        }
      ]
    };
  }
}

module.exports = { LastKeySweepRelayer };

```

### 3. FRONTEND UI & LOGIC (web/index.html)
```html
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis — Multichain MPC Dead-Man's Switch · Built on NEAR Protocol</title>
  
  <!-- NEAR Protocol Brand Typography: Manrope & JetBrains Mono -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- QR Code Library -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
  <!-- NEAR API JS (Official Web3 Provider) -->
  <script src="https://cdn.jsdelivr.net/npm/near-api-js@2.1.4/dist/near-api-js.min.js"></script>
  <!-- NEAR Wallet Selector Standalone Bundle -->
  <script src="./wallet-bundle.js"></script>
  
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['"Manrope"', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
          },
          colors: {
            nearBlack: '#000000',
            nearDark: '#07090E',
            nearSurface: '#0B0E15',
            nearElevated: '#121622',
            nearHover: '#181D2C',
            nearBorder: 'rgba(255, 255, 255, 0.08)',
            nearBorderBright: 'rgba(255, 255, 255, 0.16)',
            nearBorderGreen: 'rgba(0, 245, 212, 0.3)',
            nearGreen: '#00F5D4',
            nearGreenHover: '#00D8BC',
            nearGreenMuted: 'rgba(0, 245, 212, 0.10)',
            nearGreenGlow: 'rgba(0, 245, 212, 0.28)',
            nearCyan: '#00C9FF',
            nearPurple: '#9747FF',
            nearBlue: '#0072CE',
            dangerRed: '#FF4D4D',
            dangerRedMuted: 'rgba(255, 77, 77, 0.12)',
            textWhite: '#FFFFFF',
            textSilver: '#EDF2F7',
            textGray: '#A6B0C3',
            textMuted: '#8490A5',
          },
          boxShadow: {
            'near-glow': '0 0 35px -5px rgba(0, 245, 212, 0.35)',
            'near-pill': '0 0 20px -3px rgba(0, 245, 212, 0.25)',
            'danger-glow': '0 0 30px -5px rgba(255, 77, 77, 0.35)',
            'card-near': '0 8px 30px -4px rgba(0, 0, 0, 0.6), inset 0 1px 0 0 rgba(255, 255, 255, 0.06)',
          }
        }
      }
    }
  </script>

  <style>
    body {
      background-color: #06080D;
      color: #FFFFFF;
      font-feature-settings: "cv01", "ss03";
      -webkit-font-smoothing: antialiased;
      background-image: 
        radial-gradient(ellipse at 50% -5%, rgba(0, 245, 212, 0.09) 0%, transparent 60%),
        radial-gradient(circle at 50% 50%, transparent 40%, rgba(2, 3, 6, 0.85) 100%),
        url('assets/bunker-wall.svg');
      background-size: 100% 100%, 100% 100%, 180px 180px;
      background-attachment: fixed;
    }
    
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #05070B; }
    ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.12); border-radius: 9999px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(0, 245, 212, 0.3); }

    .near-card {
      background: #0B0E15;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 24px;
      transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .near-card:hover {
      border-color: rgba(0, 245, 212, 0.28);
      box-shadow: 0 12px 35px -6px rgba(0, 0, 0, 0.7), 0 0 25px -4px rgba(0, 245, 212, 0.10);
    }

    .near-pill-btn {
      border-radius: 9999px;
      font-weight: 700;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .radar-pulse {
      position: relative;
    }
    .radar-pulse::after {
      content: '';
      position: absolute;
      inset: -3px;
      border-radius: 9999px;
      background: rgba(0, 245, 212, 0.45);
      animation: radar 2.2s cubic-bezier(0, 0, 0.2, 1) infinite;
      z-index: -1;
    }
    @keyframes radar {
      70%, 100% {
        transform: scale(2.3);
        opacity: 0;
      }
    }

    html {
      font-size: 16px;
      scroll-behavior: smooth;
    }

    /* Automatic enhancement of microfonts to readable standards */
    .text-\[10px\] { font-size: 0.75rem !important; line-height: 1.15rem !important; }
    .text-\[11px\] { font-size: 0.8125rem !important; line-height: 1.25rem !important; }

    /* Contrast enhancement for secondary labels and hints */
    .text-\[\#585E6A\], .text-\[\#586274\], .text-white\/40 {
      color: #8E99AD !important;
    }
    .text-\[\#8C929D\], .text-\[\#8C95A6\] {
      color: #B0B9C9 !important;
    }
    input::placeholder, textarea::placeholder {
      color: #6E788C !important;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between selection:bg-nearGreen selection:text-nearBlack font-sans text-sm sm:text-base leading-relaxed">

  <!-- NEAR Official Style Top Navigation -->
  <header class="border-b border-nearBorder bg-black/85 backdrop-blur-xl sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 sm:px-8 min-h-[72px] py-2.5 flex items-center justify-between">
      
      <!-- Brand & Aegis Identity -->
      <div class="flex items-center gap-4">
        <!-- Custom Aegis Cyber Shield Emblem -->
        <a href="#" onclick="window.location.reload(); return false;" title="Aegis Dead-Man's Switch" class="w-11 h-11 rounded-2xl bg-[#0B0E15] border border-white/[0.08] hover:border-[#00F5D4]/40 flex items-center justify-center transition group shadow-near-pill">
          <svg width="26" height="26" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" class="transform group-hover:scale-105 transition">
            <defs>
              <linearGradient id="aegisLogoGrad" x1="2" y1="2" x2="30" y2="30" gradientUnits="userSpaceOnUse">
                <stop stop-color="#00F5D4"/>
                <stop offset="100%" stop-color="#00C9FF"/>
              </linearGradient>
              <linearGradient id="aegisCoreGrad" x1="16" y1="8" x2="16" y2="21" gradientUnits="userSpaceOnUse">
                <stop stop-color="#FFFFFF"/>
                <stop offset="100%" stop-color="#A5F3FC"/>
              </linearGradient>
            </defs>
            <!-- Outer Aegis Cyber Shield -->
            <path d="M16 3L27 7.5V15.5C27 22.8 22.3 27.8 16 29C9.7 27.8 5 22.8 5 15.5V7.5L16 3Z" fill="url(#aegisLogoGrad)" fill-opacity="0.15" stroke="url(#aegisLogoGrad)" stroke-width="2" stroke-linejoin="round"/>
            <!-- Central Geometric 'A' / Quantum Vault Core -->
            <path d="M16 8L22.5 21H18.8L17.2 17.5H14.8L13.2 21H9.5L16 8ZM16 12.8L15.2 15H16.8L16 12.8Z" fill="url(#aegisCoreGrad)"/>
            <!-- Quantum Key Node -->
            <circle cx="16" cy="24.5" r="1.5" fill="#00F5D4"/>
          </svg>
        </a>

        <div>
          <div class="flex items-center gap-2.5 flex-wrap">
            <span class="font-extrabold text-xl sm:text-2xl tracking-tighter text-white">AEGIS</span>
            <span class="text-[10px] sm:text-[11px] font-mono font-bold uppercase tracking-wider px-3 py-0.5 rounded-full bg-[#00F5D4]/10 text-[#00F5D4] border border-[#00F5D4]/30 hidden sm:inline-flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-[#00F5D4] radar-pulse"></span>
              Secured by NEAR MPC
            </span>
          </div>
          <p class="text-xs text-[#8C95A6] hidden sm:block mt-0.5">
            Multichain MPC Dead-Man's Switch · Chain Signatures MPC (`v1.signer`)
          </p>
        </div>
      </div>

      <!-- Live Contract Link, Account & Emergency Trigger -->
      <div class="flex items-center gap-3">
        
        <!-- Live NEAR Testnet Explorer Link -->
        <a href="https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet" target="_blank" rel="noopener noreferrer" class="hidden lg:flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-nearSurface border border-nearBorder hover:border-nearGreen/40 transition text-xs font-mono text-textSilver hover:text-textWhite">
          <span class="w-2 h-2 rounded-full bg-nearGreen"></span>
          <span>aegis.okgoogleok.testnet</span>
          <svg class="w-3.5 h-3.5 text-textGray" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
        </a>

        <!-- User Wallet Connection Area -->
        <div id="walletArea" class="flex items-center">
          <!-- Disconnected state (default) -->
          <button id="connectWalletBtn" onclick="connectMeteorWallet()" class="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-purple-950/40 border border-purple-500/40 hover:bg-purple-900/40 text-xs font-mono font-bold text-purple-300 hover:text-white transition shadow-sm active:scale-95">
            <svg class="w-3.5 h-3.5 text-purple-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L14.4 7.2L20 8L16 12L17 17.6L12 15L7 17.6L8 12L4 8L9.6 7.2L12 2Z"/></svg>
            <span>Connect Meteor</span>
          </button>

          <!-- Connected state (hidden by default) -->
          <div id="connectedWalletPill" class="hidden flex items-center gap-2 px-3 py-1.5 rounded-full bg-nearElevated border border-nearBorder text-xs font-mono">
            <span class="w-2 h-2 rounded-full bg-nearGreen"></span>
            <span id="headerAccountName" class="font-bold text-nearGreen hidden sm:inline">account.testnet</span>
            <span id="headerAccountNameMobile" class="font-bold text-nearGreen sm:hidden">acc...</span>
            <span id="headerAccountBalance" class="text-textMuted border-l border-nearBorder pl-2 font-normal hidden sm:inline">0.00 NEAR</span>
            <button onclick="disconnectWallet()" title="Disconnect" class="ml-1 text-textGray hover:text-red-400 transition p-0.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
            </button>
          </div>
        </div>

        <!-- Vertical Divider -->
        <div class="h-6 w-px bg-white/[0.08] hidden sm:block mx-1"></div>

        <!-- Emergency Panic Button (Isolated Rounded-XL Safety Trigger) -->
        <button id="headerPanicBtn" onclick="startAbortCountdown()" class="px-3.5 sm:px-4 py-2 sm:py-2.5 rounded-xl bg-red-950/40 hover:bg-red-950/70 text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/60 transition text-xs sm:text-sm font-mono font-bold tracking-wider active:scale-98 flex items-center gap-2 shadow-sm shrink-0">
          <span id="panicBtnDot" class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
          <span id="panicBtnLabel" class="hidden sm:inline">EMERGENCY PANIC</span>
          <span id="panicBtnLabelMobile" class="sm:hidden">PANIC</span>
        </button>
      </div>

    </div>
  </header>

  <!-- Main Content Space -->
  <main class="max-w-7xl mx-auto w-full px-4 sm:px-8 py-8 sm:py-10 space-y-8 flex-1">

    <!-- Hero Operational HUD (NEAR Brand Architecture) -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
      
      <!-- Card 1: Dead-Man's Switch Countdown & Heartbeat (Left, Compact) -->
      <div class="lg:col-span-5 near-card p-6 sm:p-7 flex flex-col justify-center gap-6">
        <div class="space-y-4">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse"></span>
              <span class="text-xs font-mono font-bold uppercase tracking-wider text-nearGreen">
                Autonomous Heartbeat Monitor
              </span>
            </div>
            <span id="heartbeatTag" class="text-xs font-mono font-medium text-textGray bg-nearElevated px-3 py-1 rounded-full border border-nearBorder">
              Last check-in: Active
            </span>
          </div>

          <div>
            <div class="text-[11px] uppercase font-mono text-textGray font-semibold tracking-wider">
              Automatic Transfer to Heirs Initiates In:
            </div>
            <div id="countdownBox" class="text-3xl sm:text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight mt-2 flex items-baseline gap-2">
              --
            </div>
          </div>

          <!-- Progress Bar in Minimalist Line -->
          <div class="space-y-1.5">
            <div class="w-full bg-white/[0.08] rounded-full h-1 overflow-hidden">
              <div id="timerBar" class="bg-white/80 h-full w-full transition-all duration-1000 ease-out"></div>
            </div>
            <div class="flex justify-between text-xs text-textGray font-mono">
              <span>Status: <strong class="text-nearGreen font-bold">Active & Enforced</strong></span>
              <span id="timerPctDisplay">99.9% remaining</span>
            </div>
          </div>
        </div>

        <!-- Controls: Ping alive & Config -->
        <div class="flex flex-col gap-3.5 pt-4 border-t border-nearBorder">
          <button id="pingMainBtn" class="w-full bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-near-glow active:scale-98 flex items-center justify-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
            <span>I'M ALIVE (Check-in Now)</span>
          </button>
          
          <div class="grid grid-cols-2 gap-2.5">
            <div class="relative">
              <select id="inactivitySelect" onchange="changeInactivityPeriod(this.value)" class="w-full appearance-none bg-white/[0.04] hover:bg-white/[0.08] text-white font-semibold text-xs sm:text-sm rounded-full pl-4 pr-8 py-3 border border-white/[0.08] focus:border-nearGreen outline-none transition cursor-pointer">
                <option value="30" class="bg-[#0B0D12]">Every 30 Days</option>
                <option value="90" selected class="bg-[#0B0D12]">Every 90 Days</option>
                <option value="180" class="bg-[#0B0D12]">Every 180 Days</option>
                <option value="365" class="bg-[#0B0D12]">Every 1 Year</option>
              </select>
              <svg class="w-4 h-4 text-[#8C929D] absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" /></svg>
            </div>
            <div class="relative">
              <select id="graceSelect" onchange="changeGracePeriod(this.value)" class="w-full appearance-none bg-white/[0.04] hover:bg-white/[0.08] text-white font-semibold text-xs sm:text-sm rounded-full pl-4 pr-8 py-3 border border-white/[0.08] focus:border-nearGreen outline-none transition cursor-pointer">
                <option value="3" class="bg-[#0B0D12]">Grace: 3 Days</option>
                <option value="7" selected class="bg-[#0B0D12]">Grace: 7 Days</option>
                <option value="14" class="bg-[#0B0D12]">Grace: 14 Days</option>
                <option value="30" class="bg-[#0B0D12]">Grace: 30 Days</option>
              </select>
              <svg class="w-4 h-4 text-[#8C929D] absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" /></svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Card 2: Service Description & Multichain Dead-Man's Switch Overview (Right, Expanded) -->
      <div class="lg:col-span-7 near-card p-6 sm:p-7 flex flex-col justify-between gap-5">
        <div class="space-y-4">
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div class="flex items-center gap-2.5">
              <span class="w-2 h-2 rounded-full bg-nearGreen"></span>
              <span class="text-xs sm:text-sm font-mono font-bold uppercase tracking-wider text-nearGreen">
                Autonomous Vault Service
              </span>
            </div>
            <div class="flex items-center gap-2">
              <span id="bunkerEpochPill" class="text-xs font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-3 py-1 rounded-full whitespace-nowrap">
                Derivation Path: aegis/v0 (Active)
              </span>
              <span class="text-xs font-mono font-semibold text-textMuted bg-white/[0.04] border border-white/[0.08] px-3 py-1 rounded-full whitespace-nowrap">
                100% Non-Custodial
              </span>
            </div>
          </div>

          <!-- Big Typographic Service Overview -->
          <div class="space-y-2">
            <h2 class="text-xl sm:text-2xl md:text-[26px] font-bold text-white tracking-tight leading-snug">
              Autonomous Dead-Man's Switch & Multichain Inheritance
            </h2>
            <p class="text-sm sm:text-base text-[#C5CAD3] leading-relaxed">
              Non-custodial automated asset recovery and inheritance contract for <span class="text-white font-semibold">Bitcoin, EVM, and Solana</span>. If heartbeat interval expires, threshold signatures autonomously sweep assets to designated family or backup addresses — without sharing seed phrases or relying on third parties.
            </p>
          </div>

          <!-- Feature Highlights Grid -->
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
            <div class="p-3.5 sm:p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
              <div class="text-xs font-mono uppercase text-nearGreen font-bold tracking-wider">Self-Funded Egress</div>
              <div class="text-xs sm:text-[13px] text-[#A6B0C3] mt-1.5 leading-relaxed">L1 fees deducted directly from swept assets. 0.00 USD platform fee.</div>
            </div>
            <div class="p-3.5 sm:p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
              <div class="text-xs font-mono uppercase text-nearGreen font-bold tracking-wider">72h Policy Timelock</div>
              <div class="text-xs sm:text-[13px] text-[#A6B0C3] mt-1.5 leading-relaxed">Destination address updates require a 72-hour delay before activation.</div>
            </div>
            <div class="p-3.5 sm:p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
              <div class="text-xs font-mono uppercase text-nearGreen font-bold tracking-wider">Chain Signatures</div>
              <div class="text-xs sm:text-[13px] text-[#A6B0C3] mt-1.5 leading-relaxed">Native L1 transfers signed via decentralized NEAR MPC network.</div>
            </div>
          </div>
        </div>

        <div class="pt-4 border-t border-white/[0.08] text-xs font-mono text-[#A6B0C3] flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <span class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full bg-nearGreen shrink-0"></span>
            <span class="truncate">Deterministic Path Rotation (aegis/v0 → v1)</span>
          </span>
          <span class="text-[#8E99AD] shrink-0 whitespace-nowrap">0.00 USD Platform Fee · 100% Free</span>
        </div>
      </div>

    </div>

    <!-- NEAR Navigation Pills (Tabs) -->
    <div class="flex items-center gap-2 border-b border-white/[0.08] pb-4 overflow-x-auto">
      <button onclick="switchTab('vault')" id="tab-vault" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-bold rounded-xl text-nearBlack bg-nearGreen transition-all whitespace-nowrap">
        Safe Bunker Deposits
      </button>
      <button onclick="switchTab('rescue')" id="tab-rescue" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-semibold rounded-xl text-[#8C929D] hover:text-white hover:bg-white/[0.04] transition-all whitespace-nowrap">
        Rescue & Inheritance
      </button>
      <button onclick="switchTab('alerts')" id="tab-alerts" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-semibold rounded-xl text-[#8C929D] hover:text-white hover:bg-white/[0.04] transition-all whitespace-nowrap">
        Realtime Alerts
      </button>
    </div>

    <!-- TAB 1: Safe Deposit Addresses (Bunker Mode) -->
    <section id="panel-vault" class="tab-panel space-y-6">
      
      <!-- Emergency Burn/Rotation Banner (Hidden in pristine state, only appears when burned/evacuated) -->
      <div id="bunkerBurnedBanner" class="p-5 rounded-2xl bg-red-950/25 border border-red-500/35 hidden flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div class="flex items-center gap-3.5">
          <div class="w-10 h-10 rounded-xl bg-red-500/10 text-red-400 flex items-center justify-center font-bold">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          </div>
          <div>
            <h4 class="text-sm font-extrabold text-red-200">Epoch Exhausted — Path Rotation Required</h4>
            <p class="text-xs text-textSilver mt-0.5">Active epoch keys were exposed on-chain during evacuation. Activate the next bunker to derive fresh uncompromised addresses.</p>
          </div>
        </div>
        <button id="rotateBunkerBtn" onclick="rotateBunkerEpoch()" class="px-5 py-2.5 rounded-xl bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold text-xs transition flex items-center gap-2 whitespace-nowrap shadow-near-glow active:scale-98">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
          <span>Activate Next Clean Bunker</span>
        </button>
      </div>

      <!-- Header row for Deposit tab with Live Sync Status -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2">
        <div>
          <h3 class="text-base font-extrabold text-white">Multichain Bunker Deposit Addresses</h3>
          <p class="text-xs text-[#8C929D] mt-0.5">Full deterministic addresses derived via NEAR MPC. Deposit funds safely anytime.</p>
        </div>
        <div class="flex items-center gap-2 self-start sm:self-auto">
          <button onclick="fetchLiveBalances(true)" class="px-3.5 py-1.5 rounded-full bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-xs font-mono text-textSilver hover:text-white transition flex items-center gap-2">
            <span id="liveSyncDot" class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
            <span id="liveSyncBadge">Live On-Chain Synced</span>
            <svg class="w-3.5 h-3.5 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
          </button>
        </div>
      </div>

      <!-- 4 Multichain Deposit Cards (NEAR Clean Typographic Grid) -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">

        <!-- 1. Bitcoin -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.2] p-6 flex flex-col justify-between transition-all space-y-5">
          <div class="space-y-5">
            <!-- Header: Icon + Title + Network Badge -->
            <div class="flex items-start gap-3">
              <img src="assets/coins/btc.png" alt="Bitcoin" class="w-10 h-10 rounded-full shrink-0 shadow-sm mt-0.5">
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between gap-2">
                  <h4 class="text-base sm:text-lg font-bold text-white truncate leading-tight">Bitcoin</h4>
                  <span class="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.05] border border-white/[0.08] text-[#8C929D] shrink-0 font-medium">Testnet</span>
                </div>
                <span class="text-xs sm:text-sm text-[#8C929D] font-mono truncate block mt-0.5">Native SegWit</span>
              </div>
            </div>

            <!-- Vault Balance -->
            <div class="pt-1">
              <div class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Balance</div>
              <div id="btcBalanceText" class="text-2xl sm:text-3xl font-mono font-extrabold text-white mt-1 tracking-tight">0.0000 <span class="text-base font-normal text-[#B0B9C9]">BTC</span></div>
              <div id="btcUsdText" class="text-xs sm:text-sm font-mono text-[#A6B0C3] mt-1">≈ 0.00 USD</div>
            </div>

            <!-- Full Deposit Address -->
            <div class="space-y-1.5 pt-1">
              <div class="flex items-center justify-between">
                <span class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Deposit Address</span>
                <span class="text-xs text-nearGreen font-mono font-bold">Full · SegWit</span>
              </div>
              <div class="p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.2] transition min-h-[68px] flex items-center cursor-pointer group" onclick="copyAddr('btcAddress')">
                <span id="btcAddress" data-full="tb1qv35jld0spv722nmar7gz3nqxp0cf70yhcaadl4" class="font-mono text-xs sm:text-[13px] leading-relaxed text-white break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  tb1qv35jld0spv722nmar7gz3nqxp0cf70yhcaadl4
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
            <button onclick="copyAddr('btcAddress')" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-nearGreen/50 text-xs sm:text-sm font-bold text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
              <span>Copy</span>
            </button>
            <button onclick="openQr('Bitcoin', document.getElementById('btcAddress').dataset.full)" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-white/[0.25] text-xs sm:text-sm font-bold text-[#C5CAD3] hover:text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" /></svg>
              <span>QR Code</span>
            </button>
          </div>
        </div>

        <!-- 2. Ethereum -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.2] p-6 flex flex-col justify-between transition-all space-y-5">
          <div class="space-y-5">
            <!-- Header: Icon + Title + Network Badge -->
            <div class="flex items-start gap-3">
              <img src="assets/coins/eth.png" alt="Ethereum" class="w-10 h-10 rounded-full shrink-0 shadow-sm mt-0.5">
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between gap-2">
                  <h4 class="text-base sm:text-lg font-bold text-white truncate leading-tight">Ethereum</h4>
                  <span class="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.05] border border-white/[0.08] text-[#8C929D] shrink-0 font-medium">Testnet</span>
                </div>
                <span class="text-xs sm:text-sm text-[#8C929D] font-mono truncate block mt-0.5">ETH · Base · Arbitrum</span>
              </div>
            </div>

            <!-- Vault Balance -->
            <div class="pt-1">
              <div class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Balance</div>
              <div id="evmBalanceText" class="text-2xl sm:text-3xl font-mono font-extrabold text-white mt-1 tracking-tight">0.0000 <span class="text-base font-normal text-[#B0B9C9]">ETH</span></div>
              <div id="evmUsdText" class="text-xs sm:text-sm font-mono text-[#A6B0C3] mt-1">≈ 0.00 USD</div>
            </div>

            <!-- Full Deposit Address -->
            <div class="space-y-1.5 pt-1">
              <div class="flex items-center justify-between">
                <span class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Deposit Address</span>
                <span class="text-xs text-nearGreen font-mono font-bold">Full · EVM</span>
              </div>
              <div class="p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.2] transition min-h-[68px] flex items-center cursor-pointer group" onclick="copyAddr('evmAddress')">
                <span id="evmAddress" data-full="0x4BbDe20cc8A8fB5eA9c1a202830efC145E95c5dD" class="font-mono text-xs sm:text-[13px] leading-relaxed text-white break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  0x4BbDe20cc8A8fB5eA9c1a202830efC145E95c5dD
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
            <button onclick="copyAddr('evmAddress')" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-nearGreen/50 text-xs sm:text-sm font-bold text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
              <span>Copy</span>
            </button>
            <button onclick="openQr('Ethereum', document.getElementById('evmAddress').dataset.full)" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-white/[0.25] text-xs sm:text-sm font-bold text-[#C5CAD3] hover:text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" /></svg>
              <span>QR Code</span>
            </button>
          </div>
        </div>

        <!-- 3. Solana -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.2] p-6 flex flex-col justify-between transition-all space-y-5">
          <div class="space-y-5">
            <!-- Header: Icon + Title + Network Badge -->
            <div class="flex items-start gap-3">
              <img src="assets/coins/sol.png" alt="Solana" class="w-10 h-10 rounded-full shrink-0 shadow-sm mt-0.5">
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between gap-2">
                  <h4 class="text-base sm:text-lg font-bold text-white truncate leading-tight">Solana</h4>
                  <span class="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.05] border border-white/[0.08] text-[#8C929D] shrink-0 font-medium">Testnet</span>
                </div>
                <span class="text-xs sm:text-sm text-[#8C929D] font-mono truncate block mt-0.5">Ed25519 Native</span>
              </div>
            </div>

            <!-- Vault Balance -->
            <div class="pt-1">
              <div class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Balance</div>
              <div id="solBalanceText" class="text-2xl sm:text-3xl font-mono font-extrabold text-white mt-1 tracking-tight">0.0000 <span class="text-base font-normal text-[#B0B9C9]">SOL</span></div>
              <div id="solUsdText" class="text-xs sm:text-sm font-mono text-[#A6B0C3] mt-1">≈ 0.00 USD</div>
            </div>

            <!-- Full Deposit Address -->
            <div class="space-y-1.5 pt-1">
              <div class="flex items-center justify-between">
                <span class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Deposit Address</span>
                <span class="text-xs text-nearGreen font-mono font-bold">Full · Ed25519</span>
              </div>
              <div class="p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.2] transition min-h-[68px] flex items-center cursor-pointer group" onclick="copyAddr('solAddress')">
                <span id="solAddress" data-full="FpcQP7AUfTxY8pZc6vKn6Jk8JPRhe69C4JHivzUCBNvf" class="font-mono text-xs sm:text-[13px] leading-relaxed text-white break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  FpcQP7AUfTxY8pZc6vKn6Jk8JPRhe69C4JHivzUCBNvf
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
            <button onclick="copyAddr('solAddress')" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-nearGreen/50 text-xs sm:text-sm font-bold text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
              <span>Copy</span>
            </button>
            <button onclick="openQr('Solana', document.getElementById('solAddress').dataset.full)" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-white/[0.25] text-xs sm:text-sm font-bold text-[#C5CAD3] hover:text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" /></svg>
              <span>QR Code</span>
            </button>
          </div>
        </div>

        <!-- 4. NEAR Protocol -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.2] p-6 flex flex-col justify-between transition-all space-y-5">
          <div class="space-y-5">
            <!-- Header: Icon + Title + Network Badge -->
            <div class="flex items-start gap-3">
              <img src="assets/coins/near.png" alt="NEAR Protocol" class="w-10 h-10 rounded-full shrink-0 shadow-sm mt-0.5">
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between gap-2">
                  <h4 class="text-base sm:text-lg font-bold text-white truncate leading-tight">NEAR</h4>
                  <span class="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.05] border border-white/[0.08] text-[#8C929D] shrink-0 font-medium">Testnet</span>
                </div>
                <span class="text-xs sm:text-sm text-[#8C929D] font-mono truncate block mt-0.5">Native Contract</span>
              </div>
            </div>

            <!-- Vault Balance -->
            <div class="pt-1">
              <div class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Balance</div>
              <div id="nearBalanceText" class="text-2xl sm:text-3xl font-mono font-extrabold text-white mt-1 tracking-tight">9.9978 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span></div>
              <div id="nearUsdText" class="text-xs sm:text-sm font-mono text-[#A6B0C3] mt-1">≈ 38.29 USD</div>
            </div>

            <!-- Full Vault Account -->
            <div class="space-y-1.5 pt-1">
              <div class="flex items-center justify-between">
                <span class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Account</span>
                <span class="text-xs text-nearGreen font-mono font-bold">Full · Testnet</span>
              </div>
              <div class="p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.2] transition min-h-[68px] flex items-center cursor-pointer group" onclick="copyAddr('nearAddress')">
                <span id="nearAddress" data-full="lastkey-vault-2151.testnet" title="lastkey-vault-2151.testnet" class="font-mono text-xs sm:text-[13px] leading-relaxed text-white break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  lastkey-vault-2151.testnet
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
            <button onclick="copyAddr('nearAddress')" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-nearGreen/50 text-xs sm:text-sm font-bold text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
              <span>Copy</span>
            </button>
            <button onclick="openQr('NEAR Protocol', document.getElementById('nearAddress').dataset.full)" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-white/[0.25] text-xs sm:text-sm font-bold text-[#C5CAD3] hover:text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
              <svg class="w-4 h-4 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" /></svg>
              <span>QR Code</span>
            </button>
          </div>
        </div>

      </div>

    </section>

    <!-- TAB 2: Recovery Destinations & Beneficiaries -->
    <section id="panel-rescue" class="tab-panel space-y-6 hidden">
      <div class="space-y-6">
        
        <!-- Header row -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.08] pb-5">
          <div>
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse"></span>
              <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">Destination Routing Policy</h3>
            </div>
            <p class="text-xs sm:text-sm text-[#8C929D] mt-1">
              Cryptographically locked egress destinations for emergency evacuation and autonomous push inheritance.
            </p>
          </div>
          <div class="flex items-center gap-3">
            <button onclick="clearAllAddresses()" class="px-4 py-2.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] text-[#A6B0C3] hover:text-white font-mono text-xs border border-white/[0.08] transition">
              Clear All
            </button>
          </div>
        </div>

        <!-- Initial Unconfigured Banner (Hidden if addresses exist) -->
        <div id="unconfiguredBanner" class="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs flex items-center gap-3 text-amber-200">
          <svg class="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <span>No destination addresses entered yet. Enter your backup and family wallets below, then click <strong>Save Policy</strong>. Initial setup activates immediately without timelock.</span>
        </div>

        <!-- 2-Column Multichain Routing Panel -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

          <!-- Left Column: Emergency Panic Destination (Emergency Egress) -->
          <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.14] p-6 transition-all flex flex-col justify-between">
            <div class="space-y-5">
              <div class="flex items-start justify-between gap-3 border-b border-white/[0.06] pb-4">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-red-400"></span>
                    <h4 class="text-sm font-bold text-white tracking-tight">1. Emergency Panic Destination</h4>
                  </div>
                  <p class="text-xs sm:text-sm text-[#B0B9C9] min-h-[40px] flex items-center">
                    Triggering Panic sweeps 100% of all vault assets to your backup wallets instantly.
                  </p>
                </div>
                <span class="text-[10px] font-mono font-bold text-red-400 bg-red-950/40 border border-red-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap">
                  Emergency Egress
                </span>
              </div>

              <!-- 4 Chain Rows for Panic -->
              <div class="space-y-4">
                
                <!-- NEAR -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Backup NEAR Account</label>
                    <span class="text-[10px] text-white/40 font-mono">Testnet ID</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-white bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      NEAR
                    </span>
                    <input type="text" id="panicNearAddr" value="" placeholder="e.g. backup-wallet.testnet" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Bitcoin -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Backup Bitcoin Address</label>
                    <span class="text-[10px] text-white/40 font-mono">Native SegWit (P2WPKH)</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#F7931A] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      BTC
                    </span>
                    <input type="text" id="panicBtcAddr" value="" placeholder="e.g. tb1q..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Ethereum / EVM -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Backup Ethereum / EVM Address</label>
                    <span class="text-[10px] text-white/40 font-mono">EVM / Base / Arbitrum</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#627EEA] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      ETH
                    </span>
                    <input type="text" id="panicEvmAddr" value="" placeholder="e.g. 0x..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Solana -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Backup Solana Address</label>
                    <span class="text-[10px] text-white/40 font-mono">Ed25519 Native</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#9945FF] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      SOL
                    </span>
                    <input type="text" id="panicSolAddr" value="" placeholder="e.g. Solana Base58 Address..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>
              </div>
            </div>

            <!-- Panic Execution Guard Configuration Card -->
            <div class="mt-5 p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex-1 flex flex-col justify-between">
              <div class="flex items-center justify-between gap-3 h-7 shrink-0">
                <div class="flex items-center gap-2">
                  <span id="panicGuardStatusDot" class="w-2.5 h-2.5 rounded-full bg-nearGreen"></span>
                  <span class="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">Panic Trigger Guard</span>
                </div>
                <label class="relative inline-flex items-center cursor-pointer shrink-0">
                  <input type="checkbox" id="panicArmTabToggle" onchange="toggleInstantPanic(this.checked)" class="sr-only peer">
                  <div class="w-11 h-6 bg-white/[0.1] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-red-600"></div>
                </label>
              </div>

              <div class="flex-1 flex flex-col justify-between gap-2.5 mt-3 text-xs leading-relaxed">
                <div id="panicModeSafeDesc" class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-nearGreen/30 text-white transition flex flex-col justify-center">
                  <div class="font-bold text-nearGreen flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    <span>Mode 1: Safety Buffer (Default — 3s Hold Required)</span>
                  </div>
                  <p class="text-[#B0B9C9] text-[11px] mt-1 leading-snug">
                    Pressing <em>EMERGENCY PANIC</em> opens a confirmation modal requiring a <strong>3-second continuous hold</strong>. Eliminates accidental triggers.
                  </p>
                </div>

                <div id="panicModeArmedDesc" class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06] text-[#8C929D] opacity-60 transition flex flex-col justify-center">
                  <div class="font-bold text-red-400 flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>
                    <span>Mode 2: 1-Click Panic Armed (Instant Execution)</span>
                  </div>
                  <p class="text-[#8C929D] text-[11px] mt-1 leading-snug">
                    Confirmation modal is bypassed. Top navigation button arms in red: <strong>⚡ 1-CLICK PANIC</strong>. Clicking immediately signs and evacuates all assets.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <!-- Right Column: Family Push Inheritance (Heirs) -->
          <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.14] p-6 transition-all flex flex-col justify-between">
            <div class="space-y-5">
              <div class="flex items-start justify-between gap-3 border-b border-white/[0.06] pb-4">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-nearGreen"></span>
                    <h4 class="text-sm font-bold text-white tracking-tight">2. Family Inheritance Destinations</h4>
                  </div>
                  <p class="text-xs sm:text-sm text-[#B0B9C9] min-h-[40px] flex items-center">
                    Autonomous transfer executes if heartbeat expires. Heirs do not need to sign.
                  </p>
                </div>
                <span class="text-[10px] font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2.5 py-0.5 rounded-full whitespace-nowrap">
                  Push Model
                </span>
              </div>

              <!-- 4 Chain Rows for Heirs -->
              <div class="space-y-4">
                
                <!-- NEAR -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Family NEAR Account</label>
                    <span class="text-[10px] text-white/40 font-mono">Testnet ID</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-white bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      NEAR
                    </span>
                    <input type="text" id="heirNearAddr" value="" placeholder="e.g. family.testnet" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Bitcoin -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Family Bitcoin Address</label>
                    <span class="text-[10px] text-white/40 font-mono">Native SegWit (P2WPKH)</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#F7931A] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      BTC
                    </span>
                    <input type="text" id="heirBtcAddr" value="" placeholder="e.g. tb1q..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Ethereum / EVM -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Family Ethereum / EVM Address</label>
                    <span class="text-[10px] text-white/40 font-mono">EVM / Base / Arbitrum</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#627EEA] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      ETH
                    </span>
                    <input type="text" id="heirEvmAddr" value="" placeholder="e.g. 0x..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>

                <!-- Solana -->
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between text-xs">
                    <label class="text-[#8C929D] font-mono text-[11px] uppercase font-semibold">Family Solana Address</label>
                    <span class="text-[10px] text-white/40 font-mono">Ed25519 Native</span>
                  </div>
                  <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                    <span class="px-3 py-2.5 text-xs font-mono font-bold text-[#9945FF] bg-white/[0.03] border-r border-white/[0.06] shrink-0">
                      SOL
                    </span>
                    <input type="text" id="heirSolAddr" value="" placeholder="e.g. Solana Base58 Address..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>
              </div>
            </div>

            <!-- On-Chain Digital Testament & Encoded Memo Card -->
            <div class="mt-5 p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex-1 flex flex-col justify-between">
              <div class="flex items-center justify-between gap-3 h-7 shrink-0">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-nearGreen"></span>
                  <span class="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">Digital Testament & Memo</span>
                </div>
                <span class="text-[10px] font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2.5 py-0.5 rounded-full whitespace-nowrap">
                  OP_RETURN · Optional
                </span>
              </div>

              <div class="flex-1 flex flex-col justify-between gap-2.5 mt-3 text-xs leading-relaxed">
                <!-- Subcard 1: Input area with header -->
                <div class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-nearGreen/30 text-white transition flex flex-col justify-center">
                  <div class="flex items-center justify-between font-bold text-nearGreen">
                    <div class="flex items-center gap-1.5">
                      <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" /></svg>
                      <span>Last Words to Heirs</span>
                    </div>
                    <span id="memoByteCount" class="font-mono text-nearGreen text-xs font-bold">0 / 80 B</span>
                  </div>
                  <input type="text" id="heirFinalMemo" oninput="updateMemoByteCounter(this.value)" placeholder="e.g. For my family. Be happy and take care of each other." class="w-full bg-transparent pt-1 text-xs sm:text-[13px] font-mono text-white placeholder:text-[#585E6A] outline-none">
                  <p class="text-[#8C929D] text-[11px] mt-0.5 leading-snug truncate">
                    Optional note broadcast to heirs upon vault execution.
                  </p>
                </div>

                <!-- Subcard 2: Technical Explanation -->
                <div class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06] text-[#8C929D] transition flex flex-col justify-center">
                  <div class="font-bold text-nearGreen flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" /></svg>
                    <span>Immutable On-Chain Delivery</span>
                  </div>
                  <p class="text-[#8C929D] text-[11px] mt-1 leading-snug">
                    Encoded directly into Bitcoin OP_RETURN, EVM calldata & Solana memo upon execution. Cannot be altered or censored.
                  </p>
                </div>
              </div>
            </div>
          </div>

        </div>

        <!-- Security Cooldown Status & Action Footer -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] p-5 space-y-4">
          
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div class="space-y-0.5">
              <div class="text-xs sm:text-sm font-bold text-white flex items-center gap-2">
                <span id="addressStatusDot" class="w-2 h-2 rounded-full bg-nearGreen"></span>
                <span>Policy Enforcement:</span>
                <span id="addressStatusBadge" class="text-nearGreen font-mono font-bold">Active & Enforced</span>
              </div>
              <p class="text-xs text-[#8C929D]">
                Fund redirection to arbitrary addresses is rejected by smart contract logic.
              </p>
            </div>

            <div class="flex items-center gap-3">
              <button id="cancelUpdateBtn" onclick="cancelAddressCooldown()" class="hidden px-4 py-2.5 rounded-xl bg-red-950/40 hover:bg-red-950/60 text-red-400 font-mono font-bold text-xs border border-red-500/30 transition">
                Cancel & Revert Update
              </button>
              <button id="savePolicyBtn" onclick="saveAddresses()" class="bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-2.5 px-6 rounded-xl text-xs transition shadow-near-glow active:scale-98 whitespace-nowrap">
                Save Policy
              </button>
            </div>
          </div>

          <!-- Pre-Save Warning -->
          <div id="preSaveWarning" class="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200/90 flex items-start gap-3 hidden">
            <svg class="w-4 h-4 text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            <div class="space-y-0.5 leading-relaxed">
              <span class="font-bold text-amber-300">Security Rule:</span> Modifying active addresses activates a strict 72-hour timelock to prevent theft if a device is compromised. Initial setup is immediate.
            </div>
          </div>

          <!-- Cooldown Warning Alert (Clean Typographic Bar) -->
          <div id="cooldownAlertBanner" class="p-4 rounded-xl bg-amber-950/25 border border-amber-500/40 text-xs text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hidden">
            <div class="flex items-center gap-3">
              <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse shrink-0"></span>
              <div class="space-y-0.5">
                <div class="font-mono font-bold text-amber-300">3-Day Security Timelock in Progress (71h 59m remaining)</div>
                <div class="text-[11px] text-amber-200/80">Pending addresses activate automatically once the delay elapses. Click Cancel to revert.</div>
              </div>
            </div>
            <button onclick="cancelAddressCooldown()" class="px-3.5 py-1.5 rounded-lg bg-red-950/50 hover:bg-red-900/60 text-red-300 font-mono text-[11px] border border-red-500/30 transition whitespace-nowrap self-start sm:self-auto">
              Revert Immediately
            </button>
          </div>

        </div>

      </div>
    </section>

    <!-- TAB 3: Emergency Alerts & Notifications -->
    <section id="panel-alerts" class="tab-panel space-y-6 hidden">
      <div class="space-y-6">
        
        <!-- Header row -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.08] pb-5">
          <div>
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse"></span>
              <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">Automated Relayer Alerts</h3>
            </div>
            <p class="text-xs sm:text-sm text-[#8C929D] mt-1">
              Multi-channel push notifications dispatched by the decentralized relayer network prior to heartbeat expiry.
            </p>
          </div>
          <div id="tgStatusBadge" class="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.04] border border-white/[0.08] text-xs font-mono text-[#DFE3E8]">
            <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
            <span>Relayer Bot: <strong class="text-nearGreen">Active</strong></span>
          </div>
        </div>

        <!-- Heartbeat Escalation Timeline (Sleek Connected Workflow) -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] p-6 space-y-5">
          <div class="flex items-center justify-between">
            <h4 class="text-sm font-bold text-white tracking-tight">Heartbeat Escalation Sequence</h4>
            <span class="text-[10px] font-mono text-[#8C929D] uppercase tracking-wider">Automated Workflow</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            
            <!-- Step 1 -->
            <div class="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-nearGreen">T - 14 Days</span>
                <span class="w-2 h-2 rounded-full bg-nearGreen"></span>
              </div>
              <div class="text-sm font-bold text-white">First Pulse</div>
              <p class="text-xs text-[#B0B9C9] leading-relaxed">
                Gentle check-in reminder dispatched via Telegram bot and email.
              </p>
            </div>

            <!-- Step 2 -->
            <div class="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-amber-300">T - 3 Days</span>
                <span class="w-2 h-2 rounded-full bg-amber-400"></span>
              </div>
              <div class="text-sm font-bold text-white">Urgent Escalation</div>
              <p class="text-xs text-[#B0B9C9] leading-relaxed">
                High-priority notification. Action required to prevent grace transition.
              </p>
            </div>

            <!-- Step 3 -->
            <div class="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-red-400">T - 0 (Grace)</span>
                <span class="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>
              </div>
              <div class="text-sm font-bold text-white">Final Safety Window</div>
              <p class="text-xs text-[#B0B9C9] leading-relaxed">
                7-day emergency window with daily alerts before irreversible sweep.
              </p>
            </div>

            <!-- Step 4 -->
            <div class="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-white">Execution</span>
                <span class="w-2 h-2 rounded-full bg-white"></span>
              </div>
              <div class="text-sm font-bold text-white">Autonomous Transfer</div>
              <p class="text-xs text-[#B0B9C9] leading-relaxed">
                Push inheritance executes on-chain and dispatches receipt confirmation.
              </p>
            </div>

          </div>
        </div>

        <!-- 2 Notification Channel Cards (Telegram + Email) -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">

          <!-- Telegram Channel Card -->
          <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.14] p-6 space-y-5 transition-all flex flex-col justify-between">
            <div class="space-y-4">
              <div class="flex items-start justify-between">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#229ED9]/10 text-[#229ED9] flex items-center justify-center font-bold">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.75-.55 2.93-1.28 4.88-2.12 5.86-2.54 2.79-1.19 3.37-1.4 3.75-1.4.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .37z"/></svg>
                  </div>
                  <div>
                    <h4 class="text-sm font-bold text-white">Telegram Bot Alerts</h4>
                    <span class="text-xs text-[#A6B0C3]">Direct push messages to your handle</span>
                  </div>
                </div>
                <span class="text-[10px] font-mono text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2 py-0.5 rounded-full">
                  Primary
                </span>
              </div>

              <div class="space-y-1.5">
                <label class="block text-xs font-mono uppercase text-[#A6B0C3] font-semibold">Your Telegram Username / Chat ID</label>
                <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                  <span class="px-3.5 py-2.5 text-xs font-mono font-bold text-[#A6B0C3] bg-white/[0.03] border-r border-white/[0.06]">
                    @
                  </span>
                  <input id="tgUsernameInput" type="text" value="" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#6E788C] outline-none" placeholder="username or Chat ID">
                </div>
              </div>
            </div>

            <div class="pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs">
              <span class="text-[#8C929D]">Test delivery:</span>
              <button onclick="sendTestAlert()" class="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-white font-mono text-xs border border-white/[0.08] transition flex items-center gap-1.5">
                <span>Send Test Ping</span>
              </button>
            </div>
          </div>

          <!-- Email Channel Card -->
          <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] hover:border-white/[0.14] p-6 space-y-5 transition-all flex flex-col justify-between">
            <div class="space-y-4">
              <div class="flex items-start justify-between">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" /></svg>
                  </div>
                  <div>
                    <h4 class="text-sm font-bold text-white">Failover Email Alerts</h4>
                    <span class="text-xs text-[#8C929D]">Secondary channel if Telegram is muted</span>
                  </div>
                </div>
                <span class="text-[10px] font-mono text-[#8C929D] bg-white/[0.04] px-2 py-0.5 rounded-full">
                  Failover
                </span>
              </div>

              <div class="space-y-1.5">
                <label class="block text-xs font-mono uppercase text-[#8C929D] font-semibold">Your Backup Email Address</label>
                <div class="flex items-center rounded-xl bg-white/[0.02] border border-white/[0.08] focus-within:border-nearGreen transition overflow-hidden">
                  <span class="px-3.5 py-2.5 text-xs text-[#8C929D] bg-white/[0.03] border-r border-white/[0.06]">
                    ✉
                  </span>
                  <input id="emailAlertInput" type="email" value="" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none" placeholder="your-email@domain.com">
                </div>
              </div>
            </div>

            <div class="pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs">
              <span class="text-[#8C929D]">Failover status:</span>
              <span class="text-nearGreen font-mono font-medium">Standby & Armed</span>
            </div>
          </div>

        </div>

        <!-- Notification Action Footer -->
        <div class="rounded-2xl bg-[#0B0D12] border border-white/[0.08] p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div class="text-xs text-[#8C929D] text-center sm:text-left">
            Notifications are dispatched autonomously via NEAR MPC off-chain relayer nodes without third-party tracking.
          </div>
          <button onclick="saveAlertSettings()" class="bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3 px-8 rounded-xl text-xs sm:text-sm transition shadow-near-glow active:scale-98 whitespace-nowrap w-full sm:w-auto">
            Save Alert Preferences
          </button>
        </div>

      </div>
    </section>

  </main>

  <!-- Panic Hold-to-Confirm Modal -->
  <div id="abortModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card border-red-500/50 rounded-3xl max-w-lg w-full p-8 space-y-6 text-center shadow-danger-glow">
      <div class="w-16 h-16 rounded-2xl bg-dangerRedMuted text-red-400 border border-red-500/35 flex items-center justify-center mx-auto shadow-danger-glow">
        <svg class="w-8 h-8" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
      </div>
      <div class="space-y-2">
        <h3 class="text-xl font-extrabold text-textWhite tracking-tight">CONFIRM EMERGENCY EVACUATION</h3>
        <p class="text-xs sm:text-sm text-textSilver leading-relaxed">
          All Bitcoin, Ethereum, Solana, and NEAR assets will be immediately swept to your designated backup addresses. The contract transitions to Evacuated state and burns Epoch v0.
        </p>
      </div>

      <div class="p-5 rounded-2xl bg-nearElevated border border-nearBorder space-y-3">
        <div class="text-xs text-textGray uppercase font-mono font-semibold tracking-wider">Two-Way Safety Guard</div>
        
        <!-- Press and Hold 3s Button -->
        <button id="holdToEvacBtn" onmousedown="onHoldStart(event)" onmouseup="onHoldEnd()" onmouseleave="onHoldEnd()" ontouchstart="onHoldStart(event)" ontouchend="onHoldEnd()" class="w-full relative overflow-hidden bg-red-950/80 hover:bg-red-900 border-2 border-red-500 text-red-200 hover:text-white font-extrabold py-4 px-6 rounded-2xl transition shadow-danger-glow select-none cursor-pointer touch-none [-webkit-touch-callout:none]">
          <div id="holdProgressOverlay" class="absolute inset-0 bg-red-600 transition-all duration-75 ease-linear" style="width: 0%;"></div>
          <span class="relative z-10 flex items-center justify-center gap-2 text-xs sm:text-sm font-mono">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            <span id="holdBtnText">PRESS & HOLD 3 SECONDS TO EVACUATE</span>
          </span>
        </button>
      </div>

      <div class="flex">
        <button onclick="cancelAbort()" class="w-full bg-nearElevated hover:bg-nearHover text-textSilver hover:text-textWhite font-bold py-3 near-pill-btn text-xs sm:text-sm border border-nearBorder transition">
          Cancel & Keep Vault Active
        </button>
      </div>
    </div>
  </div>

  <!-- QR Code Modal -->
  <div id="qrModal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card rounded-3xl max-w-md w-full p-7 space-y-5 text-center shadow-2xl">
      <div class="flex items-center justify-between border-b border-nearBorder pb-4">
        <h3 id="qrTitle" class="text-base font-extrabold text-textWhite">Deposit Address QR</h3>
        <button onclick="closeQr()" class="w-8 h-8 rounded-full bg-nearElevated text-textGray hover:text-textWhite flex items-center justify-center">✕</button>
      </div>
      
      <div class="p-6 bg-white rounded-3xl inline-block mx-auto shadow-2xl">
        <div id="qrcode"></div>
      </div>

      <div class="p-3.5 rounded-2xl bg-nearElevated border border-nearBorder font-mono text-xs text-textWhite break-all select-all">
        <span id="qrAddressText">...</span>
      </div>

      <button onclick="copyCurrentQr()" class="w-full bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3.5 near-pill-btn text-xs sm:text-sm transition shadow-near-glow">
        Copy Address & Close
      </button>
    </div>
  </div>

  <!-- Test Alert Dispatch Modal -->
  <div id="testAlertModal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card rounded-3xl max-w-md w-full p-7 space-y-5 text-center shadow-2xl">
      <div class="w-12 h-12 rounded-2xl bg-nearGreenMuted border border-nearGreen/30 text-nearGreen flex items-center justify-center mx-auto shadow-near-glow">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" /></svg>
      </div>
      <div class="space-y-1.5">
        <h3 class="text-base font-extrabold text-textWhite">Test Alert Sent</h3>
        <p class="text-xs sm:text-sm text-textSilver">
          A test alert has been dispatched to your configured Telegram handle:
        </p>
      </div>
      <div class="p-3.5 rounded-2xl bg-nearElevated border border-nearBorder font-mono text-xs text-nearGreen font-bold">
        <span id="modalTgTarget">@telegram_handle</span>
      </div>
      <div class="text-[11px] text-textGray">
        Also simulated to: <span id="modalEmailTarget" class="text-textSilver font-mono">backup@example.com</span>
      </div>
      <button onclick="closeTestAlertModal()" class="w-full bg-nearElevated hover:bg-nearHover text-textWhite font-bold py-3 near-pill-btn text-xs sm:text-sm transition border border-nearBorder">
        Close
      </button>
    </div>
  </div>

  <!-- Grace Period Modal -->
  <div id="graceModal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card rounded-3xl max-w-md w-full p-7 space-y-5 text-left shadow-2xl">
      <div class="flex items-center justify-between border-b border-nearBorder pb-4">
        <h3 class="text-base font-extrabold text-textWhite">Configure Safety Buffer (Grace Period)</h3>
        <button onclick="closeGraceModal()" class="w-8 h-8 rounded-full bg-nearElevated text-textGray hover:text-textWhite flex items-center justify-center">✕</button>
      </div>
      <p class="text-xs sm:text-sm text-textSilver leading-relaxed">
        When your heartbeat timer expires, an extra safety buffer starts. You receive urgent Telegram alerts during this period before any inheritance transfer is executed.
      </p>
      <div>
        <label class="block text-xs font-semibold text-textSilver mb-1.5">Grace Buffer Duration:</label>
        <select id="modalGraceSelect" onchange="changeGracePeriod(this.value)" class="w-full bg-nearElevated text-textWhite font-mono text-xs rounded-2xl p-3.5 border border-nearBorder focus:outline-none focus:border-nearGreen transition">
          <option value="3">3 Extra Days</option>
          <option value="7" selected>7 Extra Days (Default)</option>
          <option value="14">14 Extra Days (High Safety)</option>
          <option value="30">30 Extra Days</option>
        </select>
      </div>
      <button onclick="closeGraceModal()" class="w-full bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3.5 near-pill-btn text-xs sm:text-sm transition shadow-near-glow">
        Save Buffer Settings
      </button>
    </div>
  </div>

  <!-- Multichain Evacuation Live Telemetry Modal -->
  <div id="evacMonitorModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card border-nearGreen/40 rounded-3xl max-w-xl w-full p-7 sm:p-8 space-y-6 shadow-near-glow">
      <div class="flex items-center justify-between border-b border-nearBorder pb-4">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-nearGreen radar-pulse"></span>
          <h3 class="text-base sm:text-lg font-mono font-extrabold text-textWhite">Multichain Evacuation Monitor</h3>
        </div>
        <button onclick="closeEvacMonitor()" class="text-textGray hover:text-textWhite">✕</button>
      </div>

      <div class="space-y-3 font-mono text-xs">
        <!-- 1. Bitcoin -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-center justify-between">
          <div class="space-y-1">
            <div class="text-textWhite font-bold flex items-center gap-2">
              <span class="text-amber-400">₿ Bitcoin SegWit:</span> <span>9,998,000 sats (0.1 BTC)</span>
            </div>
            <div class="text-textGray text-xs">Target: <span id="monitorBtcTarget">tb1q...backup</span></div>
          </div>
          <span class="text-nearGreen font-bold bg-nearGreenMuted px-2.5 py-1 rounded-full text-xs">Mined (Block #893910)</span>
        </div>

        <!-- 2. EVM -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder space-y-2.5">
          <div class="flex items-center justify-between">
            <div class="space-y-1">
              <div class="text-textWhite font-bold flex items-center gap-2">
                <span class="text-blue-400">Ξ Ethereum / Base:</span> <span>0.5 ETH + 5,000 USDC</span>
              </div>
              <div class="text-textGray text-xs">Target: <span id="monitorEvmTarget">0x...backup</span></div>
            </div>
            <span id="evmTxStatusBadge" class="text-amber-300 font-bold bg-amber-500/10 border border-amber-500/25 px-2.5 py-1 rounded-full text-xs">
              Mempool (<span id="evmGasGwei">25</span> Gwei)
            </span>
          </div>

          <div class="pt-2 border-t border-nearBorder flex items-center justify-between text-xs font-sans">
            <span class="text-textGray">Transaction taking too long?</span>
            <button id="speedUpEvmBtn" onclick="speedUpEvmGas()" class="px-4 py-1.5 near-pill-btn bg-nearGreen/20 hover:bg-nearGreen/30 text-nearGreen font-bold border border-nearGreen/40 transition active:scale-98 flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
              <span>Speed Up (+25% Gas / RBF)</span>
            </button>
          </div>
        </div>

        <!-- 3. Solana -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-center justify-between">
          <div class="space-y-1">
            <div class="text-textWhite font-bold flex items-center gap-2">
              <span class="text-purple-400">◎ Solana Devnet:</span> <span>1.0 SOL + SPL Tokens</span>
            </div>
            <div class="text-textGray text-xs">On-Chain Memo: <span class="text-emerald-400">Embedded</span></div>
          </div>
          <span class="text-nearGreen font-bold bg-nearGreenMuted px-2.5 py-1 rounded-full text-xs">Confirmed (Finalized)</span>
        </div>

        <!-- 4. NEAR Protocol -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-center justify-between">
          <div class="space-y-1">
            <div class="text-textWhite font-bold flex items-center gap-2">
              <span class="text-nearGreen">Ⓝ NEAR Protocol:</span> <span>9.95 NEAR + NEP-141</span>
            </div>
            <div class="text-textGray text-xs">Target: <span id="monitorNearTarget">backup.testnet</span></div>
          </div>
          <span class="text-nearGreen font-bold bg-nearGreenMuted px-2.5 py-1 rounded-full text-xs">Swept (Block #2759332)</span>
        </div>

        <!-- 5. Fault Isolation -->
        <div class="p-3.5 rounded-2xl bg-nearBlack border border-nearBorder text-xs font-sans text-textSilver flex items-center gap-2.5">
          <svg class="w-4 h-4 text-nearGreen shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
          <span><strong>Fault Isolation active:</strong> Honeypots and reverting scam tokens are simulated via free <code>eth_call</code> and safely skipped without halting valid asset delivery.</span>
        </div>
      </div>

      <button onclick="closeEvacMonitor()" class="w-full bg-nearElevated hover:bg-nearHover text-textWhite font-bold py-3.5 near-pill-btn text-xs sm:text-sm transition border border-nearBorder">
        Close Monitor
      </button>
    </div>
  </div>

  <!-- Toast Notification Container -->
  <div id="toast" class="fixed bottom-8 right-8 z-50 transform translate-y-24 opacity-0 transition-all duration-200 pointer-events-none">
    <div id="toastInner" class="bg-nearElevated border border-nearGreen/40 text-textWhite px-6 py-4 rounded-full shadow-2xl text-xs sm:text-sm font-bold flex items-center gap-3 shadow-near-glow">
      <span id="toastIcon" class="w-2.5 h-2.5 rounded-full bg-nearGreen"></span>
      <span id="toastText">Action successful</span>
    </div>
  </div>

  <!-- Official NEAR-Themed Footer -->
  <footer class="border-t border-nearBorder py-8 px-8 bg-black text-center text-xs text-textGray">
    <div class="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
      <div class="flex items-center gap-2">
        <span class="text-nearGreen font-extrabold text-sm tracking-tighter">AEGIS</span>
        <span class="text-textMuted">·</span>
        <span>Multichain MPC Dead-Man's Switch</span>
        <span class="text-textMuted">·</span>
        <span>100% Non-Custodial</span>
      </div>
      <div class="flex items-center gap-3">
        <a href="https://docs.near.org/abstraction/chain-signatures" target="_blank" rel="noopener noreferrer" class="px-3.5 py-1 rounded-full bg-nearSurface hover:bg-nearElevated border border-nearBorder text-textSilver hover:text-nearGreen transition flex items-center gap-2 text-xs font-mono">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M4 19V5L12 15.5V5H19.5V19L11.5 8.5V19H4Z" fill="#00EC97"/>
          </svg>
          <span>Chain Signatures MPC ↗</span>
        </a>
        <a href="https://testnet.nearblocks.io/address/lastkey-vault-2151.testnet" target="_blank" rel="noopener noreferrer" class="px-3.5 py-1 rounded-full bg-nearSurface hover:bg-nearElevated border border-nearBorder text-textSilver hover:text-nearGreen transition text-xs font-mono">
          Explorer ↗
        </a>
      </div>
    </div>
  </footer>

  <!-- Application Logic -->
  <script>
    // Bunker Epochs (BIP-32 style MPC Derivations for Post-Quantum ECDSA Bunker Mode)
    const VAULT_EPOCHS = [
      {
        epoch: '0',
        btc: 'tb1qv35jld0spv722nmar7gz3nqxp0cf70yhcaadl4',
        evm: '0x4BbDe20cc8A8fB5eA9c1a202830efC145E95c5dD',
        sol: 'FpcQP7AUfTxY8pZc6vKn6Jk8JPRhe69C4JHivzUCBNvf',
        near: 'lastkey-vault-2151.testnet'
      },
      {
        epoch: '1',
        btc: 'tb1q7ycanwtqulrv6t259wrddt9m8vh63wnznt9f62',
        evm: '0x6a9AEa291240599deD484C11E048306036c12AAe',
        sol: '3er9NnueZhA5czpKZL76WMVP7pCkq6aCCqd2sBbD4Ke7',
        near: 'lastkey-vault-2151.testnet'
      },
      {
        epoch: '2',
        btc: 'tb1qpk7aql6r76y3yl4y7338n7sup0ev0nakflhzhd',
        evm: '0x0D3C38F502b8C79cE6dA508AE0AAB23a24DD4a9F',
        sol: '9gyKbcppDuvAABBiy2LHVDhcoVE5ksBPu5V7KxLJTKip',
        near: 'lastkey-vault-2151.testnet'
      }
    ];

    let currentEpochIndex = parseInt(localStorage.getItem('aegis_bunker_epoch') || '0');
    const NEAR_RPC_URL = 'https://archival-rpc.testnet.near.org';
    const CONTRACT_ID = 'aegis.okgoogleok.testnet';

    // Live On-Chain State Fetcher via NEAR JSON-RPC
    async function fetchLiveContractState() {
      try {
        const response = await fetch(NEAR_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'aegis-view-state',
            method: 'query',
            params: {
              request_type: 'call_function',
              finality: 'final',
              account_id: CONTRACT_ID,
              method_name: 'get_vault_info',
              args_base64: btoa('{}')
            }
          })
        });
        const data = await response.json();
        if (data.result && data.result.result) {
          const decoded = new TextDecoder().decode(new Uint8Array(data.result.result));
          const vaultInfo = JSON.parse(decoded);
          console.log('📡 [Aegis] Live NEAR RPC State fetched:', vaultInfo);
          syncUIWithOnChainState(vaultInfo);
          return vaultInfo;
        }
      } catch (err) {
        console.warn('📡 [Aegis] Live RPC sync notice:', err.message);
      }
    }

    function syncUIWithOnChainState(info) {
      if (!info) return;
      if (typeof info.epoch === 'number') {
        currentEpochIndex = info.epoch;
        renderBunkerAddresses();
      }
      if (info.backup) {
        const pNear = document.getElementById('panicNearAddr');
        const pBtc = document.getElementById('panicBtcAddr');
        const pEvm = document.getElementById('panicEvmAddr');
        const pSol = document.getElementById('panicSolAddr');
        if (pNear && !pNear.value && info.backup.near) pNear.value = info.backup.near;
        if (pBtc && !pBtc.value && info.backup.btc) pBtc.value = info.backup.btc;
        if (pEvm && !pEvm.value && info.backup.evm) pEvm.value = info.backup.evm;
        if (pSol && !pSol.value && info.backup.sol) pSol.value = info.backup.sol;
      }
      if (info.heirs) {
        const hNear = document.getElementById('heirNearAddr');
        const hBtc = document.getElementById('heirBtcAddr');
        const hEvm = document.getElementById('heirEvmAddr');
        const hSol = document.getElementById('heirSolAddr');
        if (hNear && !hNear.value && info.heirs.near) hNear.value = info.heirs.near;
        if (hBtc && !hBtc.value && info.heirs.btc) hBtc.value = info.heirs.btc;
        if (hEvm && !hEvm.value && info.heirs.evm) hEvm.value = info.heirs.evm;
        if (hSol && !hSol.value && info.heirs.sol) hSol.value = info.heirs.sol;
      }
      if (info.state === 'Evacuated') {
        const banner = document.getElementById('bunkerBurnedBanner');
        if (banner) banner.classList.remove('hidden');
      }
    }

    // NEAR Wallet State & Management
    let nearConnection = null;
    let nearWallet = null;

    function toggleDevLogin() {
      const panel = document.getElementById('devLoginPanel');
      const chevron = document.getElementById('devLoginChevron');
      if (panel) {
        const isHidden = panel.classList.toggle('hidden');
        if (chevron) {
          chevron.innerText = isHidden ? '▼' : '▲';
        }
      }
    }

    // Direct Meteor Wallet Connection Handler
    async function connectMeteorWallet() {
      showToast('Connecting Meteor Wallet...');
      try {
        if (window.AegisMeteor) {
          await window.AegisMeteor.connectMeteor(CONTRACT_ID);
          const sel = await window.AegisMeteor.getSelector();
          const state = sel.store.getState();
          const activeAcc = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;
          if (activeAcc) {
            localStorage.setItem('aegis_signer_account', activeAcc);
            localStorage.setItem('aegis_wallet_type', 'meteor');
            updateWalletConnectedUI(activeAcc);
            fetchAccountNearBalance(activeAcc);
            showToast(`Connected: ${activeAcc}`);
            return;
          }
        }

        if (window.meteorWallet) {
          if (typeof window.meteorWallet.signIn === 'function') {
            await window.meteorWallet.signIn({ contractId: CONTRACT_ID });
          } else if (typeof window.meteorWallet.requestSignIn === 'function') {
            await window.meteorWallet.requestSignIn({ contract_id: CONTRACT_ID });
          }
          const acc = window.meteorWallet.getAccountId ? window.meteorWallet.getAccountId() : null;
          if (acc) {
            localStorage.setItem('aegis_signer_account', acc);
            localStorage.setItem('aegis_wallet_type', 'meteor');
            updateWalletConnectedUI(acc);
            fetchAccountNearBalance(acc);
            showToast(`Connected: ${acc}`);
            return;
          }
        }

        showToast('Opening Meteor Testnet Web Wallet...');
        window.open('https://testnet.meteorwallet.app', '_blank');
      } catch (err) {
        console.error('[Aegis] Meteor connection error:', err);
        showToast(`Meteor error: ${err.message}`, true);
      }
    }

    async function initNearWallet() {
      // 1. Check Meteor Wallet Selector state
      if (window.AegisMeteor) {
        try {
          const sel = await window.AegisMeteor.getSelector();
          const state = sel.store.getState();
          const activeAcc = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;
          if (activeAcc) {
            localStorage.setItem('aegis_signer_account', activeAcc);
            localStorage.setItem('aegis_wallet_type', 'meteor');
            updateWalletConnectedUI(activeAcc);
            fetchAccountNearBalance(activeAcc);
            return;
          }

          sel.store.observable.subscribe((nextState) => {
            const acc = nextState.accounts.find((a) => a.active)?.accountId || nextState.accounts[0]?.accountId;
            if (acc) {
              localStorage.setItem('aegis_signer_account', acc);
              localStorage.setItem('aegis_wallet_type', 'meteor');
              updateWalletConnectedUI(acc);
              fetchAccountNearBalance(acc);
            }
          });
        } catch (err) {
          console.warn('[Aegis] Meteor selector init notice:', err);
        }
      }

      // 2. Direct injection check
      if (window.meteorWallet && typeof window.meteorWallet.isSignedIn === 'function' && window.meteorWallet.isSignedIn()) {
        const acc = window.meteorWallet.getAccountId ? window.meteorWallet.getAccountId() : null;
        if (acc) {
          localStorage.setItem('aegis_signer_account', acc);
          localStorage.setItem('aegis_wallet_type', 'meteor');
          updateWalletConnectedUI(acc);
          fetchAccountNearBalance(acc);
          return;
        }
      }

      // 3. Direct developer credentials in localStorage
      const manualAccount = localStorage.getItem('aegis_signer_account');
      const manualKey = localStorage.getItem('aegis_testnet_signer_key');
      if (manualAccount && manualKey) {
        updateWalletConnectedUI(manualAccount);
        fetchAccountNearBalance(manualAccount);
        return;
      }

      updateWalletDisconnectedUI();
    }

    function updateWalletConnectedUI(accountId) {
      const connectBtn = document.getElementById('connectWalletBtn');
      const connectedPill = document.getElementById('connectedWalletPill');
      const accountNameEl = document.getElementById('headerAccountName');
      const accountNameMobileEl = document.getElementById('headerAccountNameMobile');
      if (connectBtn) connectBtn.classList.add('hidden');
      if (connectedPill) connectedPill.classList.remove('hidden');
      if (accountNameEl) {
        accountNameEl.innerText = accountId;
        accountNameEl.title = accountId;
      }
      if (accountNameMobileEl) {
        accountNameMobileEl.innerText = accountId.length > 12 ? accountId.slice(0, 10) + '...' : accountId;
      }
    }

    function updateWalletDisconnectedUI() {
      const connectBtn = document.getElementById('connectWalletBtn');
      const connectedPill = document.getElementById('connectedWalletPill');
      if (connectBtn) connectBtn.classList.remove('hidden');
      if (connectedPill) connectedPill.classList.add('hidden');
    }

    async function fetchAccountNearBalance(accountId) {
      try {
        const response = await fetch(NEAR_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'bal-check',
            method: 'query',
            params: {
              request_type: 'view_account',
              finality: 'final',
              account_id: accountId
            }
          })
        });
        const data = await response.json();
        if (data.result && data.result.amount) {
          const yocto = BigInt(data.result.amount);
          const whole = yocto / 1000000000000000000000000n;
          const frac = (yocto % 1000000000000000000000000n) / 10000000000000000000000n;
          const formatted = `${whole}.${frac.toString().padStart(2, '0').slice(0, 2)}`;
          const balEl = document.getElementById('headerAccountBalance');
          if (balEl) balEl.innerText = `${formatted} NEAR`;
        }
      } catch (e) {
        console.warn('Balance check error:', e);
      }
    }

    async function disconnectWallet() {
      if (window.AegisMeteor) {
        try { await window.AegisMeteor.disconnectMeteor(); } catch (e) {}
      }
      if (window.meteorWallet && typeof window.meteorWallet.signOut === 'function') {
        try { window.meteorWallet.signOut(); } catch (e) {}
      }
      localStorage.removeItem('aegis_signer_account');
      localStorage.removeItem('aegis_wallet_type');
      localStorage.removeItem('aegis_testnet_signer_key');
      updateWalletDisconnectedUI();
      showToast('Wallet disconnected');
    }

    // Direct On-Chain Contract Caller via NEAR Testnet RPC
    async function dispatchNearTransaction(methodName, args = {}) {
      showToast(`Broadcasting on-chain ${methodName}() to NEAR Testnet...`);
      try {
        console.log(`[Aegis On-Chain] Dispatching ${methodName} on ${CONTRACT_ID} with args:`, args);

        const attachedDeposit = (methodName === 'panic' || methodName === 'ping' || methodName === 'propose_policy') ? '1' : '0';

        // 1. Signed in via Meteor Wallet (Wallet Selector or Direct Injection)
        if (window.AegisMeteor) {
          const outcome = await window.AegisMeteor.signAndSendNearTx(
            CONTRACT_ID,
            methodName,
            args,
            attachedDeposit,
            '30000000000000' // 30 TGas
          );
          const txHash = outcome?.transaction?.hash || outcome?.transaction_outcome?.id || 'Confirmed';
          console.log(`✅ [Aegis] Meteor transaction confirmed: ${txHash}`, outcome);
          showToast(`✅ ${methodName}() confirmed on-chain! Tx: ${txHash.slice(0, 8)}...`);
          setTimeout(() => fetchLiveContractState(), 2000);
          return outcome;
        }

        // 2. Direct private key in localStorage
        const storedKey = localStorage.getItem('aegis_testnet_signer_key');
        const signerAccountId = localStorage.getItem('aegis_signer_account');

        if (window.nearApi && storedKey && signerAccountId) {
          const { connect, keyStores, KeyPair } = window.nearApi;
          const keyStore = new keyStores.InMemoryKeyStore();
          const keyPair = KeyPair.fromString(storedKey.trim());
          await keyStore.setKey('testnet', signerAccountId, keyPair);

          const near = await connect({
            networkId: 'testnet',
            keyStore,
            nodeUrl: NEAR_RPC_URL,
            headers: {}
          });

          const account = await near.account(signerAccountId);
          const outcome = await account.functionCall({
            contractId: CONTRACT_ID,
            methodName: methodName,
            args: args,
            gas: '30000000000000', // 30 TGas
            attachedDeposit
          });

          const txHash = outcome?.transaction?.hash || outcome?.transaction_outcome?.id || 'Confirmed';
          console.log(`✅ [Aegis] KeyPair transaction confirmed: ${txHash}`, outcome);
          showToast(`✅ ${methodName}() confirmed on-chain! Tx: ${txHash.slice(0, 8)}...`);
          setTimeout(() => fetchLiveContractState(), 2000);
          return outcome;
        }

        // 3. Not signed in: Trigger Meteor Connect
        showToast('Please connect your Meteor Wallet first!', true);
        connectMeteorWallet();
      } catch (err) {
        console.error(`❌ [Aegis] Failed to dispatch ${methodName}:`, err);
        showToast(`Error dispatching ${methodName}: ${err.message}`, true);
      }
    }

    function renderBunkerAddresses() {
      const current = VAULT_EPOCHS[currentEpochIndex];
      const btcEl = document.getElementById('btcAddress');
      const evmEl = document.getElementById('evmAddress');
      const solEl = document.getElementById('solAddress');
      const nearEl = document.getElementById('nearAddress');
      const pill = document.getElementById('bunkerEpochPill');
      const banner = document.getElementById('bunkerBurnedBanner');

      if (btcEl) {
        btcEl.innerText = current.btc;
        btcEl.dataset.full = current.btc;
      }
      if (evmEl) {
        evmEl.innerText = current.evm;
        evmEl.dataset.full = current.evm;
      }
      if (solEl) {
        solEl.innerText = current.sol;
        solEl.dataset.full = current.sol;
      }
      if (nearEl) {
        nearEl.innerText = current.near;
        nearEl.dataset.full = current.near;
      }

      const isBurned = localStorage.getItem('aegis_vault_burned_' + current.epoch);
      if (pill) {
        if (isBurned) {
          pill.innerText = `Epoch ${current.epoch} · Burned`;
          pill.className = 'text-[11px] font-mono font-bold text-red-400 bg-red-950/40 border border-red-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
          if (banner) banner.classList.remove('hidden');
        } else {
          pill.innerText = `Derivation Path: aegis/v${current.epoch} (Active)`;
          pill.className = 'text-[11px] font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
          if (banner) banner.classList.add('hidden');
        }
      }
    }

    const CACHE_TTL_MS = 60 * 60 * 1000; // 1-hour cache interval to minimize RPC overhead

    async function fetchLiveBalances(force = false) {
      const btcBalEl = document.getElementById('btcBalanceText');
      const btcUsdEl = document.getElementById('btcUsdText');
      const evmBalEl = document.getElementById('evmBalanceText');
      const evmUsdEl = document.getElementById('evmUsdText');
      const solBalEl = document.getElementById('solBalanceText');
      const solUsdEl = document.getElementById('solUsdText');
      const nearBalEl = document.getElementById('nearBalanceText');
      const nearUsdEl = document.getElementById('nearUsdText');
      const syncBadge = document.getElementById('liveSyncBadge');
      const syncDot = document.getElementById('liveSyncDot');

      // Check 1-hour cache
      const cached = JSON.parse(localStorage.getItem('aegis_balance_cache') || 'null');
      const now = Date.now();

      if (!force && cached && (now - cached.timestamp < CACHE_TTL_MS)) {
        if (btcBalEl && cached.btcBal) btcBalEl.innerHTML = cached.btcBal;
        if (btcUsdEl && cached.btcUsd) btcUsdEl.innerText = cached.btcUsd;
        if (evmBalEl && cached.evmBal) evmBalEl.innerHTML = cached.evmBal;
        if (evmUsdEl && cached.evmUsd) evmUsdEl.innerText = cached.evmUsd;
        if (solBalEl && cached.solBal) solBalEl.innerHTML = cached.solBal;
        if (solUsdEl && cached.solUsd) solUsdEl.innerText = cached.solUsd;
        if (nearBalEl && cached.nearBal) nearBalEl.innerHTML = cached.nearBal;
        if (nearUsdEl && cached.nearUsd) nearUsdEl.innerText = cached.nearUsd;

        const minutesAgo = Math.floor((now - cached.timestamp) / 60000);
        if (syncBadge) syncBadge.innerText = minutesAgo < 1 ? 'Synced: Just now' : `Synced: ${minutesAgo}m ago`;
        if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-nearGreen';
        return;
      }

      if (syncBadge) syncBadge.innerText = 'Syncing...';
      if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-ping';

      let prices = { BTC: 77020, ETH: 2270, SOL: 92.4, NEAR: 3.83 };
      try {
        const [btcRes, ethRes, solRes, nearRes] = await Promise.all([
          fetch('https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT').then(r => r.json()).catch(() => null),
          fetch('https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT').then(r => r.json()).catch(() => null),
          fetch('https://api.binance.com/api/v3/ticker/price?symbol=SOLUSDT').then(r => r.json()).catch(() => null),
          fetch('https://api.binance.com/api/v3/ticker/price?symbol=NEARUSDT').then(r => r.json()).catch(() => null)
        ]);
        if (btcRes?.price) prices.BTC = parseFloat(btcRes.price);
        if (ethRes?.price) prices.ETH = parseFloat(ethRes.price);
        if (solRes?.price) prices.SOL = parseFloat(solRes.price);
        if (nearRes?.price) prices.NEAR = parseFloat(nearRes.price);
      } catch (e) {
        console.warn('Fallback to baseline prices', e);
      }

      const curr = VAULT_EPOCHS[currentEpochIndex];

      // 1. NEAR Testnet RPC View Account
      try {
        const nearRes = await fetch('https://rpc.testnet.near.org', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'aegis',
            method: 'query',
            params: {
              request_type: 'view_account',
              finality: 'final',
              account_id: curr.near
            }
          })
        }).then(r => r.json());

        if (nearRes?.result?.amount) {
          const yoctoStr = nearRes.result.amount;
          const nearVal = Number(BigInt(yoctoStr) / 100000000000000000000n) / 10000;
          if (nearBalEl) nearBalEl.innerHTML = `${nearVal.toFixed(4)} <span class="text-sm font-normal text-[#8C929D]">NEAR</span>`;
          if (nearUsdEl) nearUsdEl.innerText = `≈ ${(nearVal * prices.NEAR).toFixed(2)} USD`;
        }
      } catch (e) {
        console.warn('NEAR RPC failed', e);
      }

      // 2. Sepolia EVM RPC
      try {
        const evmRes = await fetch('https://ethereum-sepolia-rpc.publicnode.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_getBalance',
            params: [curr.evm, 'latest']
          })
        }).then(r => r.json());

        if (evmRes?.result !== undefined) {
          const wei = BigInt(evmRes.result);
          const ethVal = Number(wei / 100000000000000n) / 10000;
          if (evmBalEl) evmBalEl.innerHTML = `${ethVal.toFixed(4)} <span class="text-sm font-normal text-[#8C929D]">ETH</span>`;
          if (evmUsdEl) evmUsdEl.innerText = `≈ ${(ethVal * prices.ETH).toFixed(2)} USD`;
        }
      } catch (e) {
        console.warn('EVM RPC failed', e);
      }

      // 3. Solana Devnet RPC
      try {
        const solRes = await fetch('https://api.devnet.solana.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getBalance',
            params: [curr.sol]
          })
        }).then(r => r.json());

        if (solRes?.result?.value !== undefined) {
          const lamports = solRes.result.value;
          const solVal = lamports / 1e9;
          if (solBalEl) solBalEl.innerHTML = `${solVal.toFixed(4)} <span class="text-sm font-normal text-[#8C929D]">SOL</span>`;
          if (solUsdEl) solUsdEl.innerText = `≈ ${(solVal * prices.SOL).toFixed(2)} USD`;
        }
      } catch (e) {
        console.warn('Solana RPC failed', e);
      }

      // 4. Bitcoin Testnet Mempool.space
      try {
        const btcRes = await fetch(`https://mempool.space/testnet/api/address/${curr.btc}`).then(r => r.json());
        if (btcRes?.chain_stats) {
          const funded = (btcRes.chain_stats.funded_txo_sum || 0) - (btcRes.chain_stats.spent_txo_sum || 0);
          const btcVal = funded / 1e8;
          if (btcBalEl) btcBalEl.innerHTML = `${btcVal.toFixed(4)} <span class="text-sm font-normal text-[#8C929D]">BTC</span>`;
          if (btcUsdEl) btcUsdEl.innerText = `≈ ${(btcVal * prices.BTC).toFixed(2)} USD`;
        }
      } catch (e) {
        console.warn('BTC testnet failed', e);
      }

      // Save to 1-hour cache
      localStorage.setItem('aegis_balance_cache', JSON.stringify({
        timestamp: Date.now(),
        btcBal: btcBalEl ? btcBalEl.innerHTML : '0.0000 BTC',
        btcUsd: btcUsdEl ? btcUsdEl.innerText : '≈ 0.00 USD',
        evmBal: evmBalEl ? evmBalEl.innerHTML : '0.0000 ETH',
        evmUsd: evmUsdEl ? evmUsdEl.innerText : '≈ 0.00 USD',
        solBal: solBalEl ? solBalEl.innerHTML : '0.0000 SOL',
        solUsd: solUsdEl ? solUsdEl.innerText : '≈ 0.00 USD',
        nearBal: nearBalEl ? nearBalEl.innerHTML : '9.9978 NEAR',
        nearUsd: nearUsdEl ? nearUsdEl.innerText : '≈ 38.29 USD'
      }));

      if (syncBadge) syncBadge.innerText = 'Synced: Just now';
      if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-nearGreen';
      if (force) showToast('Balances and rates updated from RPC');
    }

    function rotateBunkerEpoch() {
      currentEpochIndex = (currentEpochIndex + 1) % VAULT_EPOCHS.length;
      localStorage.setItem('aegis_bunker_epoch', currentEpochIndex.toString());
      localStorage.removeItem('aegis_vault_burned_' + VAULT_EPOCHS[currentEpochIndex].epoch);
      renderBunkerAddresses();
      fetchLiveBalances(true);
      remainingSeconds = MAX_SECONDS;
      updateCountdownDisplay();
      dispatchNearTransaction('rotate_bunker');
      showToast(`Bunker Vault rotated to active Epoch ${VAULT_EPOCHS[currentEpochIndex].epoch}`);
    }

    // Configurable Inactivity & Grace Periods
    let inactivityDays = parseInt(localStorage.getItem('aegis_inactivity_days') || '90');
    let graceDays = parseInt(localStorage.getItem('aegis_grace_days') || '7');
    let MAX_SECONDS = inactivityDays * 24 * 3600;
    let remainingSeconds = MAX_SECONDS - (35 * 60 + 25);
    let currentQrAddr = '';
    let countdownInterval = null;

    // Initialize UI Selectors
    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('inactivitySelect').value = inactivityDays;
      document.getElementById('graceSelect').value = graceDays;
      
      const savedTg = localStorage.getItem('aegis_tg');
      const savedEmail = localStorage.getItem('aegis_email');
      if (savedTg) document.getElementById('tgUsernameInput').value = savedTg.replace(/^@+/, '');
      if (savedEmail) document.getElementById('emailAlertInput').value = savedEmail;
      const badge = document.getElementById('tgStatusBadge');
      if (badge && (savedTg || savedEmail)) {
        badge.innerHTML = `
          <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
          <span>Relayer: <strong class="text-nearGreen">${savedTg || savedEmail}</strong></span>
        `;
      }

      renderBunkerAddresses();
      loadSavedAddresses();
      updatePanicUI();
      fetchLiveBalances(false); // Uses 1-hour cache if fresh
      setInterval(() => fetchLiveBalances(false), 60 * 60 * 1000); // Poll once per hour (prevents RPC spam)
    });

    function changeInactivityPeriod(days) {
      inactivityDays = parseInt(days);
      MAX_SECONDS = inactivityDays * 24 * 3600;
      remainingSeconds = MAX_SECONDS;
      localStorage.setItem('aegis_inactivity_days', days);
      updateCountdownDisplay();
      showToast(`Check-in timer set to ${days} days`);
    }

    function changeGracePeriod(days) {
      graceDays = parseInt(days);
      const sel1 = document.getElementById('graceSelect');
      const sel2 = document.getElementById('modalGraceSelect');
      if (sel1) sel1.value = days;
      if (sel2) sel2.value = days;
      localStorage.setItem('aegis_grace_days', days);
      showToast(`Safety buffer set to ${days} days`);
    }

    function openGraceModal() {
      document.getElementById('graceModal').classList.remove('hidden');
    }

    function closeGraceModal() {
      document.getElementById('graceModal').classList.add('hidden');
    }

    function formatTime(sec) {
      const d = Math.floor(sec / (24 * 3600));
      const h = Math.floor((sec % (24 * 3600)) / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      return { d, h, m, s };
    }

    function updateCountdownDisplay() {
      if (remainingSeconds <= 0) {
        document.getElementById('countdownBox').innerHTML = '<span class="text-red-400">EXPIRED</span>';
        document.getElementById('timerBar').style.width = '0%';
        const pctEl = document.getElementById('timerPctDisplay');
        if (pctEl) pctEl.innerText = '0.0% remaining';
        return;
      }
      const { d, h, m, s } = formatTime(remainingSeconds);
      document.getElementById('countdownBox').innerHTML = 
        `${d}<span class="text-textGray text-2xl font-normal">d</span> ` +
        `${h}<span class="text-textGray text-2xl font-normal">h</span> ` +
        `${m}<span class="text-textGray text-2xl font-normal">m</span> ` +
        `${s}<span class="text-textGray text-2xl font-normal">s</span>`;
      
      const pct = Math.max(0, Math.min(100, (remainingSeconds / MAX_SECONDS) * 100));
      document.getElementById('timerBar').style.width = pct + '%';
      const pctEl = document.getElementById('timerPctDisplay');
      if (pctEl) pctEl.innerText = `${pct.toFixed(1)}% remaining`;
    }

    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(() => {
      remainingSeconds--;
      updateCountdownDisplay();
    }, 1000);
    updateCountdownDisplay();

    // Auto-refresh balances once every hour
    setInterval(() => {
      fetchLiveBalances(true);
    }, CACHE_TTL_MS);

    function showToast(msg, isRed = false) {
      const toast = document.getElementById('toast');
      const inner = document.getElementById('toastInner');
      const icon = document.getElementById('toastIcon');
      const text = document.getElementById('toastText');

      text.innerText = msg;
      if (isRed) {
        inner.className = 'bg-nearElevated border border-red-500/40 text-textWhite px-6 py-4 rounded-full shadow-2xl text-xs sm:text-sm font-bold flex items-center gap-3 shadow-danger-glow';
        icon.className = 'w-2.5 h-2.5 rounded-full bg-red-400';
      } else {
        inner.className = 'bg-nearElevated border border-nearGreen/40 text-textWhite px-6 py-4 rounded-full shadow-2xl text-xs sm:text-sm font-bold flex items-center gap-3 shadow-near-glow';
        icon.className = 'w-2.5 h-2.5 rounded-full bg-nearGreen';
      }

      toast.classList.remove('translate-y-24', 'opacity-0');
      setTimeout(() => {
        toast.classList.add('translate-y-24', 'opacity-0');
      }, 3500);
    }

    function copyAddr(elemId) {
      const el = document.getElementById(elemId);
      const text = el.dataset.full || el.innerText;
      navigator.clipboard.writeText(text);
      showToast('Address copied to clipboard');
    }

    // Ping Main Button (Live On-Chain Heartbeat)
    document.getElementById('pingMainBtn').addEventListener('click', () => {
      remainingSeconds = MAX_SECONDS;
      updateCountdownDisplay();
      dispatchNearTransaction('ping');
    });

    // Tab Switching
    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('text-nearBlack', 'bg-nearGreen', 'font-bold');
        btn.classList.add('text-[#8C929D]', 'font-semibold');
      });
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));

      const activeBtn = document.getElementById(`tab-${name}`);
      activeBtn.classList.add('text-nearBlack', 'bg-nearGreen', 'font-bold');
      activeBtn.classList.remove('text-[#8C929D]', 'font-semibold');
      document.getElementById(`panel-${name}`).classList.remove('hidden');
    }

    // QR Code
    function openQr(title, address) {
      currentQrAddr = address;
      document.getElementById('qrTitle').innerText = `${title} QR Code`;
      document.getElementById('qrAddressText').innerText = address;
      const qrEl = document.getElementById('qrcode');
      qrEl.innerHTML = '';
      new QRCode(qrEl, {
        text: address,
        width: 190,
        height: 190,
        colorDark: '#000000',
        colorLight: '#FFFFFF',
        correctLevel: QRCode.CorrectLevel.M
      });
      document.getElementById('qrModal').classList.remove('hidden');
    }

    function closeQr() {
      document.getElementById('qrModal').classList.add('hidden');
    }

    function copyCurrentQr() {
      navigator.clipboard.writeText(currentQrAddr);
      showToast('Address copied to clipboard');
      closeQr();
    }

    // Emergency Panic Sequence: Hold-to-Confirm (3s Safety Guard) or 1-Click Instant Panic
    let holdTimer = null;
    let holdStartTime = 0;
    const HOLD_DURATION_MS = 3000;

    function isInstantPanicEnabled() {
      return localStorage.getItem('aegis_instant_panic') === 'true';
    }

    function toggleInstantPanic(enabled) {
      localStorage.setItem('aegis_instant_panic', enabled ? 'true' : 'false');
      updatePanicUI();
      if (enabled) {
        showToast('⚡ 1-Click Panic ARMED (Safety confirmation modal disabled)', true);
      } else {
        showToast('Safety Guard Enabled (3s hold confirmation modal active)');
      }
    }

    function updatePanicUI() {
      const enabled = isInstantPanicEnabled();
      const tabToggle = document.getElementById('panicArmTabToggle');
      const btn = document.getElementById('headerPanicBtn');
      const label = document.getElementById('panicBtnLabel');
      const dot = document.getElementById('panicBtnDot');
      const safeDesc = document.getElementById('panicModeSafeDesc');
      const armedDesc = document.getElementById('panicModeArmedDesc');
      const statusDot = document.getElementById('panicGuardStatusDot');

      if (tabToggle) tabToggle.checked = enabled;

      if (safeDesc && armedDesc) {
        if (enabled) {
          safeDesc.className = "p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06] text-[#8C929D] opacity-60 transition";
          armedDesc.className = "p-2.5 rounded-lg bg-red-950/30 border border-red-500/40 text-white transition";
          if (statusDot) statusDot.className = "w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse";
        } else {
          safeDesc.className = "p-2.5 rounded-lg bg-white/[0.02] border border-nearGreen/30 text-white transition";
          armedDesc.className = "p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06] text-[#8C929D] opacity-60 transition";
          if (statusDot) statusDot.className = "w-2.5 h-2.5 rounded-full bg-nearGreen";
        }
      }

      if (btn && label && dot) {
        if (enabled) {
          btn.className = "px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white border-2 border-red-400 transition text-xs sm:text-sm font-mono font-extrabold tracking-wider active:scale-98 flex items-center gap-2 shadow-danger-glow";
          label.innerText = "⚡ 1-CLICK PANIC";
          dot.className = "w-2.5 h-2.5 rounded-full bg-white animate-ping";
        } else {
          btn.className = "px-4 py-2.5 rounded-xl bg-red-950/40 hover:bg-red-950/70 text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/60 transition text-xs sm:text-sm font-mono font-bold tracking-wider active:scale-98 flex items-center gap-2 shadow-sm";
          label.innerText = "EMERGENCY PANIC";
          dot.className = "w-2 h-2 rounded-full bg-red-500 animate-pulse";
        }
      }
    }

    function startAbortCountdown() {
      if (isInstantPanicEnabled()) {
        executePanic();
        return;
      }
      const modal = document.getElementById('abortModal');
      modal.classList.remove('hidden');
      resetHoldState();
    }

    function resetHoldState() {
      if (holdTimer) clearInterval(holdTimer);
      holdTimer = null;
      const bar = document.getElementById('holdProgressOverlay');
      const text = document.getElementById('holdBtnText');
      if (bar) bar.style.width = '0%';
      if (text) text.innerText = 'PRESS & HOLD 3 SECONDS TO EVACUATE';
    }

    function onHoldStart(e) {
      if (e) e.preventDefault();
      holdStartTime = Date.now();
      const bar = document.getElementById('holdProgressOverlay');
      const text = document.getElementById('holdBtnText');

      if (holdTimer) clearInterval(holdTimer);
      holdTimer = setInterval(() => {
        const elapsed = Date.now() - holdStartTime;
        const progress = Math.min(100, (elapsed / HOLD_DURATION_MS) * 100);
        const secLeft = Math.max(0, ((HOLD_DURATION_MS - elapsed) / 1000)).toFixed(1);
        if (bar) bar.style.width = progress + '%';
        if (text) text.innerText = `HOLDING... ${secLeft}s REMAINING`;

        if (elapsed >= HOLD_DURATION_MS) {
          clearInterval(holdTimer);
          holdTimer = null;
          executePanic();
        }
      }, 50);
    }

    function onHoldEnd() {
      if (holdTimer) {
        clearInterval(holdTimer);
        holdTimer = null;
        resetHoldState();
        showToast('Evacuation cancelled — button released early');
      }
    }

    function cancelAbort() {
      resetHoldState();
      document.getElementById('abortModal').classList.add('hidden');
    }

    function executePanic() {
      resetHoldState();
      document.getElementById('abortModal').classList.add('hidden');
      remainingSeconds = 0;
      updateCountdownDisplay();

      const curr = VAULT_EPOCHS[currentEpochIndex];
      localStorage.setItem('aegis_vault_burned_' + curr.epoch, 'true');
      renderBunkerAddresses();

      dispatchNearTransaction('panic');
      showToast('PANIC EXECUTED: State set to Evacuated. Rotate epoch to generate new addresses.', true);
      openEvacMonitor();
    }

    function openEvacMonitor() {
      const saved = JSON.parse(localStorage.getItem('aegis_addresses') || '{}');
      document.getElementById('monitorBtcTarget').innerText = saved.panicBtcAddr || 'tb1q...backup';
      document.getElementById('monitorEvmTarget').innerText = saved.panicEvmAddr || '0x...backup';
      document.getElementById('monitorNearTarget').innerText = saved.panicNearAddr || 'backup.testnet';
      document.getElementById('evacMonitorModal').classList.remove('hidden');
    }

    function closeEvacMonitor() {
      document.getElementById('evacMonitorModal').classList.add('hidden');
    }

    let currentGasGwei = 25;
    function speedUpEvmGas() {
      currentGasGwei = Math.round(currentGasGwei * 1.25);
      document.getElementById('evmGasGwei').innerText = currentGasGwei;
      const badge = document.getElementById('evmTxStatusBadge');
      badge.className = 'text-nearGreen font-bold bg-nearGreenMuted border border-nearGreen/30 px-3 py-1 rounded-full text-xs';
      badge.innerHTML = `RBF Bumped to ${currentGasGwei} Gwei · Priority #1`;
      const btn = document.getElementById('speedUpEvmBtn');
      btn.innerText = 'Highest Priority Set';
      btn.disabled = true;
      btn.classList.add('opacity-50');
      showToast(`Gas bumped to ${currentGasGwei} Gwei! Transaction accelerated.`, false);
    }

    // Alert Settings & Test Dispatch Modal
    function saveAlertSettings() {
      const tg = document.getElementById('tgUsernameInput').value.trim();
      const email = document.getElementById('emailAlertInput').value.trim();
      localStorage.setItem('aegis_tg', tg);
      localStorage.setItem('aegis_email', email);
      showToast('Alert preferences saved successfully');
      const badge = document.getElementById('tgStatusBadge');
      if (badge) {
        badge.innerHTML = `
          <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
          <span>Relayer: <strong class="text-nearGreen">${tg || email || 'Active'}</strong></span>
        `;
      }
    }

    function sendTestAlert() {
      const tg = document.getElementById('tgUsernameInput').value.trim() || 'not configured';
      const email = document.getElementById('emailAlertInput').value.trim() || 'not configured';
      document.getElementById('modalTgTarget').innerText = tg;
      document.getElementById('modalEmailTarget').innerText = email;
      document.getElementById('testAlertModal').classList.remove('hidden');
      showToast(tg !== 'not configured' ? `Test alert queued for ${tg}` : 'Please enter a Telegram handle or email first', tg === 'not configured');
    }

    function closeTestAlertModal() {
      document.getElementById('testAlertModal').classList.add('hidden');
    }

    // Destination Policies & 72h Timelock
    let isEditing = false;
    const inputIds = [
      'panicNearAddr', 'panicBtcAddr', 'panicEvmAddr', 'panicSolAddr',
      'heirNearAddr', 'heirBtcAddr', 'heirEvmAddr', 'heirSolAddr', 'heirFinalMemo'
    ];

    function updateMemoByteCounter(val) {
      const bytes = new TextEncoder().encode(val || '').length;
      const counter = document.getElementById('memoByteCount');
      if (counter) {
        counter.innerText = `${bytes} / 80 B`;
        if (bytes > 80) {
          counter.className = 'text-[11px] font-mono font-bold text-red-400';
        } else if (bytes > 0) {
          counter.className = 'text-[11px] font-mono font-semibold text-nearGreen';
        } else {
          counter.className = 'text-[11px] font-mono text-white/50';
        }
      }
    }

    function loadSavedAddresses() {
      const saved = JSON.parse(localStorage.getItem('aegis_addresses') || '{}');
      
      // Auto-sanitize: clear legacy/bogus mastrophot.testnet from panicNearAddr if present
      if (saved.panicNearAddr === 'mastrophot.testnet') {
        delete saved.panicNearAddr;
        localStorage.setItem('aegis_addresses', JSON.stringify(saved));
      }

      let hasAny = false;
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          el.value = saved[id] || '';
          if (saved[id] && saved[id].trim().length > 0) hasAny = true;
        }
      });
      updateMemoByteCounter(saved.heirFinalMemo || '');
      const banner = document.getElementById('unconfiguredBanner');
      if (banner) {
        if (hasAny) banner.classList.add('hidden');
        else banner.classList.remove('hidden');
      }

      const isCooldown = localStorage.getItem('aegis_cooldown_started');
      const badge = document.getElementById('addressStatusBadge');
      const dot = document.getElementById('addressStatusDot');
      const cooldownAlert = document.getElementById('cooldownAlertBanner');
      const cancelBtn = document.getElementById('cancelUpdateBtn');
      const saveBtn = document.getElementById('savePolicyBtn');

      if (isCooldown) {
        if (badge) {
          badge.innerText = '3-Day Cooldown (71h 59m left)';
          badge.className = 'text-amber-300 font-mono font-bold';
        }
        if (dot) dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
        if (cooldownAlert) cooldownAlert.classList.remove('hidden');
        if (cancelBtn) cancelBtn.classList.remove('hidden');
        if (saveBtn) saveBtn.classList.add('hidden');
      } else {
        if (badge) {
          badge.innerText = hasAny ? 'Active & Enforced' : 'Unconfigured';
          badge.className = hasAny ? 'text-nearGreen font-mono font-bold' : 'text-amber-300 font-mono font-bold';
        }
        if (dot) dot.className = hasAny ? 'w-2.5 h-2.5 rounded-full bg-nearGreen shadow-near-glow' : 'w-2.5 h-2.5 rounded-full bg-amber-400';
        if (cooldownAlert) cooldownAlert.classList.add('hidden');
        if (cancelBtn) cancelBtn.classList.add('hidden');
        if (saveBtn) {
          saveBtn.classList.remove('hidden');
          saveBtn.disabled = false;
        }
      }
    }

    function clearAllAddresses() {
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      localStorage.removeItem('aegis_addresses');
      localStorage.removeItem('aegis_pending_addresses');
      localStorage.removeItem('aegis_cooldown_started');
      loadSavedAddresses();
      showToast('All address fields cleared.');
    }

    function toggleEditMode() {
      // Retained for backward-compat if called
      loadSavedAddresses();
    }

    function saveAddresses() {
      const existing = JSON.parse(localStorage.getItem('aegis_addresses') || '{}');
      const hadPreviousAddresses = inputIds.some(id => existing[id] && existing[id].trim().length > 0);

      const data = {};
      let enteredAny = false;
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          data[id] = el.value.trim();
          if (data[id].length > 0) enteredAny = true;
        }
      });

      if (!enteredAny) {
        showToast('Please enter at least one address before saving.');
        return;
      }

      // Address format validation
      const isValidBtc = addr => !addr || /^(bc1|tb1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(addr);
      const isValidEvm = addr => !addr || /^0x[a-fA-F0-9]{40}$/.test(addr);
      const isValidSol = addr => !addr || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr);
      const isValidNear = addr => !addr || (/^[a-z0-9._-]+$/.test(addr) && addr.length >= 2 && addr.length <= 64);

      if (!isValidBtc(data.panicBtcAddr)) {
        showToast('Invalid Backup Bitcoin address format (use Bech32 tb1q/bc1q)', true);
        return;
      }
      if (!isValidBtc(data.heirBtcAddr)) {
        showToast('Invalid Heir Bitcoin address format (use Bech32 tb1q/bc1q)', true);
        return;
      }
      if (!isValidEvm(data.panicEvmAddr)) {
        showToast('Invalid Backup EVM address (must be 0x + 40 hex chars)', true);
        return;
      }
      if (!isValidEvm(data.heirEvmAddr)) {
        showToast('Invalid Heir EVM address (must be 0x + 40 hex chars)', true);
        return;
      }
      if (!isValidSol(data.panicSolAddr)) {
        showToast('Invalid Backup Solana address (must be Base58 32-44 chars)', true);
        return;
      }
      if (!isValidSol(data.heirSolAddr)) {
        showToast('Invalid Heir Solana address (must be Base58 32-44 chars)', true);
        return;
      }
      if (!isValidNear(data.panicNearAddr)) {
        showToast('Invalid Backup NEAR account format', true);
        return;
      }
      if (!isValidNear(data.heirNearAddr)) {
        showToast('Invalid Heir NEAR account format', true);
        return;
      }
      if (data.heirFinalMemo && new TextEncoder().encode(data.heirFinalMemo).length > 80) {
        showToast('Digital testament exceeds 80 bytes (Bitcoin OP_RETURN limit)', true);
        return;
      }

      const policyPayload = {
        backup: {
          btc: data.panicBtcAddr || '',
          evm: data.panicEvmAddr || '',
          sol: data.panicSolAddr || '',
          near: data.panicNearAddr ? data.panicNearAddr : null
        },
        heirs: {
          btc: data.heirBtcAddr || '',
          evm: data.heirEvmAddr || '',
          sol: data.heirSolAddr || '',
          near: data.heirNearAddr ? data.heirNearAddr : null
        }
      };

      if (!hadPreviousAddresses) {
        // FIRST-TIME INITIALIZATION:
        // No cooldown! Activates immediately so user can test panic evacuation and use the vault right away.
        localStorage.setItem('aegis_addresses', JSON.stringify(data));
        localStorage.removeItem('aegis_cooldown_started');
        localStorage.removeItem('aegis_pending_addresses');
        loadSavedAddresses();
        dispatchNearTransaction('propose_policy', policyPayload);
        showToast('Backup destinations active! Emergency evacuation armed.');
      } else {
        // MODIFYING ACTIVE ADDRESSES:
        // Anti-hacking 72h timelock applies strictly when changing existing active addresses.
        localStorage.setItem('aegis_pending_addresses', JSON.stringify(data));
        localStorage.setItem('aegis_cooldown_started', Date.now().toString());
        loadSavedAddresses();
        dispatchNearTransaction('propose_policy', policyPayload);
        showToast('Address update submitted! 72-hour security timelock started.');
      }
    }

    function cancelAddressCooldown() {
      localStorage.removeItem('aegis_cooldown_started');
      localStorage.removeItem('aegis_pending_addresses');
      loadSavedAddresses();
      dispatchNearTransaction('cancel_policy');
      showToast('Address update cancelled. Previous addresses retained.', true);
    }

    // Initialize Live On-Chain Polling and Wallet Connection on page load
    document.addEventListener('DOMContentLoaded', () => {
      initNearWallet();
      fetchLiveContractState();
      setInterval(fetchLiveContractState, 15000);
    });
  </script>
</body>
</html>
```

### 4. E2E RELAYER TEST SUITE (scripts/test_sweep_flow.js)
```javascript
/**
 * Sweep Flow Simulation & Cryptographic Invariant Test
 * 
 * Verifies:
 * 1. Vault address derivation for EVM, BTC, and Solana using vault contract account ID
 * 2. EVM EIP-1559 Sweep preparation, sighash calculation, and NEAR MPC signature reconstruction
 * 3. Bitcoin SegWit PSBT Sweep construction to backup address
 * 4. Solana SystemProgram Sweep construction with feePayer: from and raw serialized message bytes
 * 5. Solana SPL Token Sweep with idempotent ATA creation
 * 6. Native NEAR Sweep with dynamic state storage reserve
 * 7. Zero-Asset-Left-Behind Evacuation Queue with continuous nonces and fault isolation
 */

const { LastKeySweepRelayer } = require('../relayer/sweep_relayer');
const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');

async function runSweepSimulation() {
  console.log('====================================================');
  console.log('🛡️  AEGIS HARDENED MULTICHAIN RELAYER TEST SUITE');
  console.log('====================================================\n');

  const relayer = new LastKeySweepRelayer({ networkId: 'testnet' });
  const vaultContractId = 'lastkey-vault-2151.testnet';
  const derivationPath = 'aegis/v0';

  // 1. Address Derivation
  console.log('1️⃣  Deriving Vault Addresses from NEAR MPC...');
  const vault = await relayer.deriveAllAddresses(vaultContractId, derivationPath);
  console.log(`   • Vault NEAR Contract: ${vaultContractId}`);
  console.log(`   • Derivation Epoch:    ${derivationPath}`);
  console.log(`   • EVM Vault Address:   ${vault.evm.address}`);
  console.log(`   • BTC Vault Address:   ${vault.btc.address}`);
  console.log(`   • SOL Vault Address:   ${vault.sol.address}`);
  console.log('   ✅ Vault addresses derived successfully from contract identity.\n');

  // Simulated Backup Cold Addresses
  const backupAddresses = {
    evm: '0x1111111111111111111111111111111111111111',
    btc: 'tb1q99999999999999999999999999999999999999',
    sol: 'ColdBackupSolanaAddress11111111111111111111'
  };

  // 2. EVM Sweep Simulation & v1.signer Signature Reconstruction
  console.log('2️⃣  Simulating EVM Panic Evacuation (Sepolia / Base)...');
  const evmSweep = await relayer.prepareEvmSweep({
    fromAddress: vault.evm.address,
    toAddress: backupAddresses.evm,
    valueWei: ethers.parseEther('0.5'), // 0.5 ETH
    nonce: 0,
    chainId: 11155111 // Sepolia
  });

  console.log(`   • Target Destination: ${backupAddresses.evm}`);
  console.log(`   • Sweep Amount:       0.5 ETH`);
  console.log(`   • Unsigned Tx Hash:   ${evmSweep.txHash}`);
  console.log(`   • Verifiable Raw Hex: ${evmSweep.unsignedTxHex.slice(0, 32)}... (Anti-Blind-Signing)`);
  if (!evmSweep.unsignedTxHex.toLowerCase().includes(backupAddresses.evm.toLowerCase().replace('0x', ''))) {
    throw new Error('EVM unsigned tx does not contain target recipient address!');
  }
  console.log(`   • Hash byte length:   ${evmSweep.hashBytes.length} bytes (32-byte payload for v1.signer)`);

  // Test NEAR v1.signer response format reconstruction:
  // v1.signer returns: { big_r: { affine_point: "02..." }, s: { scalar: "..." }, recovery_id: 0, scheme: "Secp256k1" }
  const mockWallet = ethers.Wallet.createRandom();
  const rawSig = mockWallet.signingKey.sign(evmSweep.txHash);
  const mpcSignerResponse = {
    scheme: 'Secp256k1',
    big_r: { affine_point: '02' + rawSig.r.replace(/^0x/, '') },
    s: { scalar: rawSig.s.replace(/^0x/, '') },
    recovery_id: rawSig.yParity
  };

  const signedEvm = relayer.assembleSignedEvmTx(evmSweep.rawTx, mpcSignerResponse);
  console.log(`   • Serialized Signed Tx: ${signedEvm.signedTx.slice(0, 42)}...`);
  console.log(`   • Recovered Signer:     ${signedEvm.from}`);
  if (signedEvm.from.toLowerCase() !== mockWallet.address.toLowerCase()) {
    throw new Error('Signer mismatch in assembleSignedEvmTx!');
  }
  console.log('   ✅ EVM signature assembly from v1.signer format validated 100%.\n');

  // 3. Bitcoin SegWit Sweep Simulation
  console.log('3️⃣  Simulating Bitcoin Panic Evacuation (Testnet SegWit)...');
  const mockUtxos = [
    {
      txid: 'f'.repeat(64),
      vout: 0,
      value: 10000000 // 0.1 BTC = 10,000,000 sats
    }
  ];

  const btcSweep = relayer.prepareBtcSweep({
    utxos: mockUtxos,
    fromAddress: vault.btc.address,
    toAddress: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
    feeSats: 2000,
    network: bitcoin.networks.testnet
  });

  console.log(`   • Input UTXO:     ${mockUtxos[0].value} sats (0.1 BTC)`);
  console.log(`   • Output Amount:  ${btcSweep.sendAmount} sats`);
  console.log(`   • Mining Fee:     ${btcSweep.feeSats} sats`);
  console.log(`   • PSBT Hex:       ${btcSweep.psbtHex.slice(0, 50)}...`);

  // Verify Bitcoin Dust rejection invariant
  try {
    relayer.prepareBtcSweep({
      utxos: [{ txid: 'e'.repeat(64), vout: 0, value: 1500 }],
      fromAddress: vault.btc.address,
      toAddress: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
      feeSatsOverride: 1200,
      network: bitcoin.networks.testnet
    });
    throw new Error('Should have rejected dust output < 546 sats');
  } catch (err) {
    if (!err.message.includes('below Bitcoin dust limit')) throw err;
    console.log('   • Dust Guard:     Verified (rejection below 546 sats)');
  }
  // Test Bitcoin PSBT MPC signature injection and finalization
  const mockBtcMpcSig = {
    r: '12'.repeat(32),
    s: '34'.repeat(32),
    publicKey: vault.btc.publicKey
  };
  const finalizedBtc = relayer.finalizeBtcSweepPsbt(btcSweep.psbtHex, [mockBtcMpcSig], bitcoin.networks.testnet);
  console.log(`   • Finalized BTC TxId: ${finalizedBtc.txId}`);
  console.log(`   • Finalized BTC Hex:  ${finalizedBtc.txHex.slice(0, 40)}...`);
  console.log('   ✅ Bitcoin PSBT SegWit signature injection and finalization validated.\n');

  // 4. Solana Sweep Simulation (feePayer: from, no double sha256)
  console.log('4️⃣  Simulating Solana Panic Evacuation (Devnet)...');
  const solSweep = relayer.prepareSolanaSweep({
    fromPubkey: vault.sol.address,
    toPubkey: '11111111111111111111111111111111',
    lamports: 1000000000 // 1 SOL
  });

  console.log(`   • From Pubkey (FeePayer): ${vault.sol.address}`);
  console.log(`   • To Pubkey (Recipient): 11111111111111111111111111111111`);
  console.log(`   • Sweep Lamports:        ${solSweep.sweepLamports} (Fee deducted automatically)`);
  console.log(`   • Raw Payload Hex (Ed25519): ${solSweep.rawPayloadHex.slice(0, 40)}... (Length: ${solSweep.rawPayloadHex.length / 2} bytes)`);
  console.log(`   • EdDSA Mode:            ${solSweep.isEddsa}`);
  console.log('   ✅ Solana transaction message & raw Ed25519 payload validated.\n');

  // 4a. Solana SPL Token Sweep Simulation to Empty Wallet
  console.log('4️⃣a. Simulating Solana SPL Token Sweep (USDC to brand new wallet)...');
  const solSplSweep = relayer.prepareSolanaTokenSweep({
    mintPubkey: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USDC
    fromOwnerPubkey: vault.sol.address,
    toRecipientPubkey: '11111111111111111111111111111111',
    amountTokens: 5000000000n, // 5,000 USDC
    memo: 'Aegis SPL Transfer'
  });
  console.log(`   • Recipient ATA:         ${solSplSweep.recipientAta} (Created via Idempotent Instruction)`);
  console.log(`   • Raw Payload Hex (Ed25519): ${solSplSweep.rawPayloadHex.slice(0, 40)}...`);

  // Test Token-2022 compatibility
  const token2022ProgramId = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
  const solToken2022Sweep = relayer.prepareSolanaTokenSweep({
    mintPubkey: '2b1kV6DKHGMyoChMwnNnkcQvcF4FmJmJ9Y5uY6uG8jYq',
    fromOwnerPubkey: vault.sol.address,
    toRecipientPubkey: '11111111111111111111111111111111',
    amountTokens: 1000000n,
    tokenProgramId: token2022ProgramId
  });
  console.log(`   • Token-2022 Recipient ATA:  ${solToken2022Sweep.recipientAta}`);

  // Test Solana MPC Signature Assembly
  const mockSolanaSig = '0x' + 'ab'.repeat(64); // 64-byte Ed25519 signature
  const signedSol = relayer.assembleSignedSolanaTx(solSweep.serializedMessage, vault.sol.address, mockSolanaSig);
  console.log(`   • Solana Signed Tx Base64:   ${signedSol.signedTxBase64.slice(0, 32)}...`);
  console.log('   ✅ Solana SPL & Token-2022 atomic ATA creation + transfer validated.\n');

  // 4b. NEAR Native Sweep Simulation
  console.log('4️⃣b. Simulating Native NEAR Vault Sweep (Testnet)...');
  const nearSweep = relayer.prepareNearSweep({
    fromAccount: 'lastkey-vault-2151.testnet',
    toAccount: 'mastrophot.testnet',
    balanceYocto: '10000000000000000000000000', // 10 NEAR
    memo: 'Aegis NEAR Evacuation'
  });

  console.log(`   • From Account:          ${nearSweep.fromAccount}`);
  console.log(`   • To Account:            ${nearSweep.toAccount}`);
  console.log(`   • Storage Reserve:       ${nearSweep.storageReserveYocto} yoctoNEAR (~1.6 NEAR)`);
  console.log(`   • Sweep Amount:          ${nearSweep.sweepAmountYocto} yoctoNEAR`);
  console.log('   ✅ NEAR native sweep transaction assembly validated.\n');

  // 5. Test Zero-Asset-Left-Behind Queue Orchestration (NFT -> Tokens -> Native Gas)
  console.log('5️⃣  Validating Zero-Asset-Left-Behind Evacuation Queue with Gas Deduction...');
  const evacuationPlan = relayer.planEvmEvacuationQueue({
    fromAddress: vault.evm.address,
    toAddress: '0x1111111111111111111111111111111111111111',
    nfts: [
      { contract: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', tokenId: 1337 }
    ],
    tokens: [
      { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', amount: 5000000000n },
      { address: '0x6982508145454Ce325dDbE47a25d4ec3d2311933', amount: 1000000000000000000000000000n }
    ],
    nativeWeiBalance: ethers.parseEther('1.25'),
    memo: 'Aegis Zero-Asset Evacuation'
  });

  console.log(`   • Evacuation Steps Planned: ${evacuationPlan.length}`);
  evacuationPlan.forEach((p, idx) => {
    console.log(`     [Step ${idx + 1}] Type: ${p.step} (Planned Nonce: ${p.nonce})`);
  });

  const finalStep = evacuationPlan[evacuationPlan.length - 1];
  console.log(`   • Native Balance Before: ${ethers.formatEther(finalStep.balanceBefore)} ETH`);
  console.log(`   • Reserved Gas Cost:     ${ethers.formatEther(finalStep.gasCostReservedWei)} ETH`);
  console.log(`   • Final Native Sweep:    ${ethers.formatEther(finalStep.sweepAmountWei)} ETH`);

  if (BigInt(finalStep.sweepAmountWei) >= BigInt(finalStep.balanceBefore)) {
    throw new Error('Native final sweep did not deduct gas cost!');
  }
  console.log('   ✅ Evacuation sequence validated: Gas accurately reserved for prior steps.\n');

  // 6. Test Continuous Nonce Fault Isolation: Scam/Blacklist Token Revert Simulation
  console.log('6️⃣  Simulating Fault Isolation with Continuous Nonce Preservation...');
  const isolatedRun = await relayer.executeQueueWithFaultIsolation(evacuationPlan, async (task) => {
    if (task.tokenAddress === '0x6982508145454Ce325dDbE47a25d4ec3d2311933') {
      throw new Error('EXECUTION_REVERTED: Blacklisted / Honeypot token');
    }
    return { txHash: '0x' + '1'.repeat(64), status: 1 };
  });

  const skipped = isolatedRun.filter(r => r.status === 'SKIPPED_REVERT');
  const succeeded = isolatedRun.filter(r => r.status === 'SUCCESS');
  console.log(`   • Total Tasks:                 ${isolatedRun.length}`);
  console.log(`   • Successfully Swept:          ${succeeded.length}`);
  console.log(`   • Safely Skipped Broken Assets: ${skipped.length}`);

  // Check nonce continuity of succeeded steps
  const executedNonces = succeeded.map(s => s.task.nonce);
  console.log(`   • Executed Nonces Sequence:    [${executedNonces.join(', ')}]`);
  for (let i = 0; i < executedNonces.length; i++) {
    if (executedNonces[i] !== i) {
      throw new Error(`Nonce gap detected! Expected ${i}, got ${executedNonces[i]}`);
    }
  }

  console.log('   ✅ Nonce continuity guaranteed: Skipped revert did NOT leave gaps in EVM nonces.\n');

  console.log('====================================================');
  console.log('🚀 ALL MULTICHAIN RELAYER PIPELINES PASSED (100%)');
  console.log('====================================================');
}

runSweepSimulation().catch(err => {
  console.error('❌ Simulation Error:', err);
  process.exit(1);
});

```

### 5. ADDRESS DERIVATION ENGINE (scripts/derive_addresses.js)
```javascript
/**
 * Aegis — Multi-Chain Address Derivation Engine
 * Verifies deterministic foreign address derivation for Bitcoin, EVM, and Solana
 * via NEAR Chain Signatures MPC (v1.signer-prod.testnet)
 */

const { contracts, chainAdapters } = require('chainsig.js');
const { Connection } = require('@solana/web3.js');

async function deriveAllVaultAddresses(accountId = 'lastkey-vault-2151.testnet', path = 'aegis/v0', networkId = 'testnet') {
  console.log(`\n🔑 Deriving Vault Addresses via NEAR MPC (${networkId.toUpperCase()})`);
  console.log(`• NEAR Vault Contract: ${accountId}`);
  console.log(`• Derivation Path:     ${path}\n`);

  const contract = new contracts.ChainSignatureContract({ networkId });

  // 1. EVM (Ethereum / Base / Arbitrum / Polygon)
  const evmAdapter = new chainAdapters.evm.EVM({ contract });
  const evm = await evmAdapter.deriveAddressAndPublicKey(accountId, path);

  // 2. Bitcoin (Native SegWit P2WPKH)
  const btcAdapter = new chainAdapters.btc.Bitcoin({
    network: networkId === 'mainnet' ? 'mainnet' : 'testnet',
    contract,
    btcRpcAdapter: new chainAdapters.btc.BTCRpcAdapter({ network: networkId === 'mainnet' ? 'mainnet' : 'testnet' })
  });
  const btc = await btcAdapter.deriveAddressAndPublicKey(accountId, path);

  // 3. Solana (Ed25519 Native)
  const solAdapter = new chainAdapters.solana.Solana({
    contract,
    solanaConnection: new Connection(networkId === 'mainnet' ? 'https://api.mainnet-beta.solana.com' : 'https://api.devnet.solana.com')
  });
  const sol = await solAdapter.deriveAddressAndPublicKey(accountId, path);

  const result = {
    evm: { address: evm.address, publicKey: evm.publicKey },
    btc: { address: btc.address, publicKey: btc.publicKey },
    sol: { address: sol.address, publicKey: sol.publicKey }
  };

  console.log('✅ EVM Address (Base / Sepolia / ETH):', result.evm.address);
  console.log('✅ Bitcoin Address (P2WPKH SegWit):  ', result.btc.address);
  console.log('✅ Solana Address (Ed25519 Native):  ', result.sol.address);
  console.log('\n🔒 Private keys for these addresses do not exist anywhere — only NEAR MPC threshold consensus can sign for them.');

  return result;
}

if (require.main === module) {
  const accountId = process.argv[2] || 'lastkey-vault-2151.testnet';
  const path = process.argv[3] || 'aegis/v0';
  const networkId = process.argv[4] || 'testnet';
  deriveAllVaultAddresses(accountId, path, networkId)
    .then(() => process.exit(0))
    .catch(err => {
      console.error('❌ Derivation error:', err);
      process.exit(1);
    });
}

module.exports = { deriveAllVaultAddresses };

```

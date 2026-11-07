# 🛡️ AEGIS PROTOCOL: COMPREHENSIVE ARCHITECTURAL AUDIT & CODE DOSSIER

## 🎯 AUDIT MISSION & SCOPE
Ти виступаєш у ролі суворого Senior Web3 Security Auditor & Principal Distributed Systems Architect.
Твоє завдання - провести нещадний, глибокий та реалістичний аудит проєкту **Aegis**, перевірити його на реальну життєздатність у тестовій/основній мережі NEAR (контракт `aegis.okgoogleok.testnet`), знайти потенційні вектори атак, баги у смартконтракті та релеєрі, оцінити коректність мультичейн-виводу через NEAR Chain Signatures (`v1.signer`), а також перевірити ергономіку фронтенду та UX.

---

## 🏛️ АРХІТЕКТУРА ТА ОПЕРАЦІЙНИЙ СТАН ПРОЄКТУ

Aegis - це децентралізований мультичейн Dead-Man's Switch та протокол автономного спадкування для **Bitcoin, EVM (Ethereum / Base / Arbitrum), Solana та NEAR**, побудований на базі **NEAR Chain Signatures (MPC контракт v1.signer)**.

### Ключові принципи та поточна реалізація:
1. **Multi-Tenant LookupMap Сховище:** Контракт зберігає ізольовані сховища для необмеженої кількості користувачів (`LookupMap<AccountId, UserVault>`). Кожен користувач керує виключно своїм сховищем.
2. **Детерміновані адреси бункера:** Адреси для кожної мережі деривуються за шляхом `aegis/{vault_owner}/{epoch}` за допомогою NEAR MPC (`chainsig.js`). Приватні ключі не існують на жодному сервері.
3. **Дворівневий Heartbeat (Пінг):**
   - **Прямий ончейн `ping()`:** без депозиту (0 NEAR deposit) через FunctionCall Access Key користувача з мізерним газом (~0.0003 NEAR).
   - **Спонсорство релеєра `ping_by_relayer(vault_owner, timestamp_ms, signature_hex, ...)`:** авторизований вузькоспеціалізований кіпер (`keeper.aegis.okgoogleok.testnet`, restricted `FunctionCall` key) верифікує підпис власника через `env::ed25519_verify` (сирий або NEP-413) із захистом від replay-атак.
4. **Миттєве озброєння (Instant Arming):** Якщо бункер новий або після ротації (`Unconfigured`), перший виклик `propose_policy` активує політику негайно без 72-годинного таймлоку та поповнює `gas_escrow`. Для вже активного бункера діє 72-годинний захисний таймлок.
5. **Ротація бункера (`rotate_bunker`):** Після евакуації архівує призначення поточної епохи в `archive:{owner}:{old_epoch}`, очищає активні адреси, переводить сховище в `Unconfigured` та переходить на нову епоху (`epoch + 1`).
6. **Мультичейн евакуація активів та E2EE Заповіт:**
   - Клієнтське E2EE шифрування заповіту (`enc:x25519:` на базі Solana-ключа спадкоємця або `enc:aes256:` через `PBKDF2 + AES-256-GCM`) без відкритого тексту ончейн.
   - Смарт-контракт виконує повний структурний парсинг байткоду Solana (бан `ComputeBudget`, перевірка `lamports > 0` та отримувача) та EVM EIP-1559 RLP (ліміт газу `<= 250k`, `max_fee <= 500 Gwei`), фінансує `v1.signer-prod.testnet::sign` із `gas_escrow` / пулу спонсора та повертає `0.005 NEAR` рефанду кіперу.
   - Релеєр транслює реальні транзакції в мережі та зберігає верифіковані хеші ончейн через `record_sweep_telemetry`.
7. **Офіційний NEAR Multi-Wallet Selector:** Інтегровано `@near-wallet-selector/modal-ui` із підтримкою Meteor, HERE, Nightly, Sender та Bitte.

---

## 🔍 ЗАВДАННЯ ДЛЯ АУДИТОРА (СПИСОК ПИТАНЬ НА ВЕРДИКТ):

1. **Безпека смарт-контракту (`lib.rs`):**
   - Чи є ризики викрадення коштів або підміни адрес через `request_sweep_signature`?
   - Чи надійно реалізована Anti-Blind-Signing перевірка для EVM (перевірка входження 20 байт адреси призначення) та Solana (перевірка адреси отримувача у структурі повідомлення)?
   - Чи захищений метод `ping_by_relayer` від зловживань?
   - Чи коректно ізольовані дані користувачів у `LookupMap`?
2. **Логіка ротації епох та деривації адрес:**
   - Чи є ризики втрати коштів при переході на наступні епохи?
   - Чи може користувач або спадкоємець вивести залишки з минулих епох?
3. **Надійність релеєра (`sweep_relayer.js` та `service.js`):**
   - Чи правильно формуються PSBT-транзакції для Bitcoin SegWit та інжектуються DER-підписи (BIP-66)?
   - Чи коректно обчислюється газ для EVM (врахування L1 Data Fee на L2 Base/Arbitrum)?
   - Чи безпечна обробка черги токенів з ізоляцією помилок (Fault Isolation) для запобігання зависанню нонсів?
4. **Фронтенд та UX (`index.html`):**
   - Чи немає прихованих багів у синхронізації стану або розрахунку таймера?
   - Чи повністю усунуто хардкод тестових адрес при відключеному гаманці?
5. **Твій фінальний вердикт:**
   - Що ще критично доробити або виправити перед здачею на хакатон NEAR?

---

## 📦 ПОВНИЙ ВИХІДНИЙ КОД ПРОЄКТУ (SOURCE CODE):

### 1. SMART CONTRACT (contracts/vault/src/lib.rs)
```rust
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

    /// Checks if applying `new` would replace any non-empty existing address
    pub fn is_replacing_existing(&self, new: &ChainAddresses) -> bool {
        let btc_replaced = !self.btc.trim().is_empty()
            && !new.btc.trim().is_empty()
            && self.btc.trim() != new.btc.trim();
        let evm_replaced = !self.evm.trim().is_empty()
            && !new.evm.trim().is_empty()
            && !self.evm.trim().eq_ignore_ascii_case(new.evm.trim());
        let sol_replaced = !self.sol.trim().is_empty()
            && !new.sol.trim().is_empty()
            && self.sol.trim() != new.sol.trim();
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
    pub current_time_ns: u64,
    pub epoch: u32,
    pub authorized_relayer: Option<AccountId>,
    pub heir_memo: Option<String>,
    pub gas_escrow_yocto: String,
    pub near_deposit_yocto: String,
    pub is_epoch_swept: bool,
    pub last_sweep_report: Option<String>,
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
    /// and `0.005 NEAR` keeper gas refunds.
    #[payable]
    pub fn deposit_escrow(&mut self, account_id: Option<AccountId>) {
        let target = account_id.unwrap_or_else(env::predecessor_account_id);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, "Must attach NEAR deposit to fund gas escrow");
        Self::internal_credit_escrow(&target, deposit);
        env::log_str(&format!(
            "ESCROW_DEPOSITED: Credited {} yoctoNEAR to gas escrow for {}",
            deposit, target
        ));
    }

    /// Deposit native NEAR into an isolated per-user bunker ledger (swept via `sweep_near`).
    #[payable]
    pub fn deposit_near_vault(&mut self, account_id: Option<AccountId>) {
        let target = account_id.unwrap_or_else(env::predecessor_account_id);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, "Must attach NEAR deposit for vault storage");
        Self::internal_credit_near_deposit(&target, deposit);
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
        env::log_str(&format!("PING_PUBKEY_REGISTERED: Added Ed25519 key for {}", caller));
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
        Self::internal_sync_elapsed_policy(vault, now);
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
        Self::internal_sync_elapsed_policy(vault, now);

        require!(
            vault.state == VaultState::Active || vault.state == VaultState::Unconfigured,
            "Can only update policy in Active or Unconfigured state"
        );

        if let Some(hb) = heartbeat_interval_ns {
            vault.heartbeat_interval_ns = hb.0;
        }
        if let Some(cp) = challenge_period_ns {
            vault.challenge_period_ns = cp.0;
        }

        let is_initial_setup = vault.state == VaultState::Unconfigured
            || (vault.backup.is_empty() && vault.heirs.is_empty());
        let has_changes = vault.backup.has_any_change(&backup)
            || vault.heirs.has_any_change(&heirs);

        if is_initial_setup || !has_changes {
            vault.backup = backup;
            vault.heirs = heirs;
            vault.pending_policy = None;
            vault.last_ping_ns = now;
            vault.state = VaultState::Active;
            self.internal_register_account(&caller);
            env::log_str(&format!(
                "POLICY_INITIALIZED_INSTANT: Destinations activated immediately for {}",
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
            env::log_str(&format!(
                "POLICY_PROPOSED: 72h timelock started for modifying configured addresses for {}",
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
            if caller == target {
                vault.last_ping_ns = env::block_timestamp();
            }
            env::log_str(&format!("POLICY_APPLIED: New destinations activated for {}", target));
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
        vault.pending_policy = None;
        vault.last_ping_ns = env::block_timestamp();
        env::log_str(&format!("POLICY_CANCELLED: Pending policy cancelled for {}", caller));
    }

    /// Update heartbeat interval and challenge (grace) period for caller's bunker.
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
        Self::internal_sync_elapsed_policy(vault, now);
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

        vault.heartbeat_interval_ns = new_hb;
        vault.challenge_period_ns = new_cp;
        vault.last_ping_ns = now;
        env::log_str(&format!("INTERVALS_UPDATED: Intervals updated for {}", caller));
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
        Self::internal_sync_elapsed_policy(vault, now);
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
            let (effective_backup, effective_heirs, effective_pending) =
                if let Some(ref p) = vault.pending_policy {
                    if now >= p.effective_at_ns {
                        (p.backup.clone(), p.heirs.clone(), None)
                    } else {
                        (vault.backup.clone(), vault.heirs.clone(), Some(p.clone()))
                    }
                } else {
                    (vault.backup.clone(), vault.heirs.clone(), None)
                };
            VaultInfo {
                owner: target.clone(),
                mpc_contract: self.mpc_contract.clone(),
                state: vault.state.clone(),
                last_ping_ns: vault.last_ping_ns,
                heartbeat_interval_ns: vault.heartbeat_interval_ns,
                challenge_period_ns: vault.challenge_period_ns,
                policy_timelock_ns: vault.policy_timelock_ns,
                backup: effective_backup,
                heirs: effective_heirs,
                pending_policy: effective_pending,
                current_time_ns: now,
                epoch: vault.epoch,
                authorized_relayer: vault.authorized_relayer.clone(),
                heir_memo: self.get_heir_memo(target.clone()),
                gas_escrow_yocto: Self::internal_get_escrow(&target).to_string(),
                near_deposit_yocto: Self::internal_get_near_deposit(&target).to_string(),
                is_epoch_swept: Self::internal_is_epoch_swept(&target, vault.epoch),
                last_sweep_report: Self::internal_get_sweep_telemetry(&target, vault.epoch),
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

    fn internal_sync_elapsed_policy(vault: &mut UserVault, now_ns: u64) {
        let should_apply = vault
            .pending_policy
            .as_ref()
            .map_or(false, |p| now_ns >= p.effective_at_ns);
        if should_apply {
            if let Some(pending) = vault.pending_policy.take() {
                vault.backup = pending.backup;
                vault.heirs = pending.heirs;
            }
        }
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
/// - Verifies `receiver_id == expected_receiver`
/// - Verifies `block_hash != 0`
/// - Verifies exactly 1 `Action::Transfer { deposit > 0 }` with zero trailing bytes
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
    if pos + recv_len > raw_tx.len() {
        return Err("Truncated receiver_id in NEAR transaction");
    }
    let recv_bytes = &raw_tx[pos..pos + recv_len];
    if recv_bytes != expected_receiver.as_str().as_bytes() {
        return Err("NEAR transaction receiver_id does not match policy-locked destination");
    }
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

    // Actions: u32 LE count == 1, action variant == 3 (Transfer), deposit u128 > 0
    if pos + 4 + 1 + 16 != raw_tx.len() {
        return Err("NEAR sweep transaction must contain exactly one Transfer action and no trailing bytes");
    }
    let action_count = u32::from_le_bytes([
        raw_tx[pos],
        raw_tx[pos + 1],
        raw_tx[pos + 2],
        raw_tx[pos + 3],
    ]);
    pos += 4;
    if action_count != 1 || raw_tx[pos] != 3 {
        return Err("NEAR sweep transaction must contain strictly a single Transfer action (opcode 3)");
    }
    pos += 1;
    let mut dep_bytes = [0u8; 16];
    dep_bytes.copy_from_slice(&raw_tx[pos..pos + 16]);
    let deposit = u128::from_le_bytes(dep_bytes);
    if deposit == 0 {
        return Err("NEAR transfer deposit must be greater than zero");
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
    }
}
```

### 2. RELAYER SWEEP ENGINE (relayer/sweep_relayer.js)
```javascript
/**
 * LastKey Relayer: Automated Cross-Chain Sweep Engine
 * 
 * Watches LastKey Vault contract on NEAR.
 * When state transitions to 'Evacuated' or 'Inheritance', it constructs
 * evacuation transactions for Bitcoin, EVM, and Solana, fetches threshold
 * signatures via the Vault contract's MPC delegate, and broadcasts to foreign chains.
 */

const crypto = require('crypto');
const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');
const web3 = require('@solana/web3.js');
const chainsig = require('chainsig.js');
const bs58Pkg = require('bs58');
const bs58Encode = bs58Pkg.encode || (bs58Pkg.default && bs58Pkg.default.encode);

class LastKeySweepRelayer {
  constructor(config = {}) {
    this.networkId = config.networkId || 'testnet';
    this.mpcContractId = config.mpcContractId || (this.networkId === 'testnet' ? 'v1.signer-prod.testnet' : 'v1.signer');
    this.vaultContractId = config.vaultContractId || 'aegis.okgoogleok.testnet';
    this.derivationPath = config.derivationPath || 'aegis/v0';
    this.nearRpcUrl =
      config.nearRpcUrl ||
      process.env.NEAR_RPC_URL ||
      (this.networkId === 'testnet' ? 'https://test.rpc.fastnear.com' : 'https://free.rpc.fastnear.com');
    this._derivedCache = new Map();

    this.chainSigContract = new chainsig.contracts.ChainSignatureContract({
      networkId: this.networkId,
      contractId: this.mpcContractId,
      fallbackRpcUrls: [this.nearRpcUrl]
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
    const cacheKey = `${accountId}:${path}`;
    if (this._derivedCache.has(cacheKey)) {
      return this._derivedCache.get(cacheKey);
    }

    const [evm, btc, sol] = await Promise.all([
      this.evmAdapter.deriveAddressAndPublicKey(accountId, path),
      this.btcAdapter.deriveAddressAndPublicKey(accountId, path),
      this.solanaAdapter.deriveAddressAndPublicKey(accountId, path)
    ]);

    const derived = {
      accountId,
      path,
      evm: { address: evm.address, publicKey: evm.publicKey },
      btc: { address: btc.address, publicKey: btc.publicKey },
      sol: { address: sol.address, publicKey: sol.publicKey }
    };
    this._derivedCache.set(cacheKey, derived);
    return derived;
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
    const minIntrinsicGas = 21000n + calldataGas;
    const requestedGas = BigInt(gasLimit || 21000n);
    const rawGasLimit = requestedGas > minIntrinsicGas ? requestedGas : minIntrinsicGas;
    const computedGasLimit = rawGasLimit > 250000n ? 250000n : rawGasLimit;

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

    let memoBytes = null;
    if (memo) {
      const rawMemoBuf = Buffer.from(memo, 'utf8');
      if (rawMemoBuf.length <= 80) {
        memoBytes = rawMemoBuf;
      } else {
        // Bitcoin standardness limits OP_RETURN to 80 bytes: anchor SHA-256 commitment of E2EE ciphertext
        const hexHash = crypto.createHash('sha256').update(String(memo), 'utf8').digest('hex');
        memoBytes = Buffer.from(`aegis-e2ee:${hexHash.slice(0, 36)}`, 'utf8');
      }
    }
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

    const txForHash = psbt.__CACHE.__TX;
    const prevOutScript = bitcoin.address.toOutputScript(fromAddress, network);
    // BIP-143 P2WPKH scriptCode MUST be the 25-byte P2PKH script (0x76a914<20-byte-pkh>88ac)
    const p2pkhScript =
      prevOutScript.length === 22 && prevOutScript[0] === 0x00 && prevOutScript[1] === 0x14
        ? bitcoin.payments.p2pkh({ hash: prevOutScript.subarray(2), network }).output
        : prevOutScript;

    const dsha256 = buf =>
      crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();

    const prevoutsParts = [];
    const sequencesParts = [];
    for (const txIn of txForHash.ins) {
      const idxBuf = Buffer.alloc(4);
      idxBuf.writeUInt32LE(txIn.index, 0);
      prevoutsParts.push(Buffer.from(txIn.hash), idxBuf);
      const seqBuf = Buffer.alloc(4);
      seqBuf.writeUInt32LE(txIn.sequence, 0);
      sequencesParts.push(seqBuf);
    }
    const hashPrevouts = dsha256(Buffer.concat(prevoutsParts));
    const hashSequence = dsha256(Buffer.concat(sequencesParts));

    const outputsParts = [];
    for (const txOut of txForHash.outs) {
      const valBuf = Buffer.alloc(8);
      valBuf.writeBigUInt64LE(BigInt(txOut.value), 0);
      const scriptBuf = Buffer.from(txOut.script);
      outputsParts.push(valBuf, Buffer.from([scriptBuf.length]), scriptBuf);
    }
    const outputsBuffer = Buffer.concat(outputsParts);
    const hashOutputs = dsha256(outputsBuffer);

    const sighashes = effectiveUtxos.map((u, idx) => {
      const hash = txForHash.hashForWitnessV0(
        idx,
        p2pkhScript,
        u.value,
        bitcoin.Transaction.SIGHASH_ALL
      );
      const sighashHex = Buffer.from(hash).toString('hex');

      const verBuf = Buffer.alloc(4);
      verBuf.writeInt32LE(txForHash.version, 0);
      const voutBuf = Buffer.alloc(4);
      voutBuf.writeUInt32LE(txForHash.ins[idx].index, 0);
      const valBuf = Buffer.alloc(8);
      valBuf.writeBigUInt64LE(BigInt(u.value), 0);
      const seqBuf = Buffer.alloc(4);
      seqBuf.writeUInt32LE(txForHash.ins[idx].sequence, 0);
      const lockBuf = Buffer.alloc(4);
      lockBuf.writeUInt32LE(txForHash.locktime, 0);
      const sighashTypeBuf = Buffer.alloc(4);
      sighashTypeBuf.writeUInt32LE(bitcoin.Transaction.SIGHASH_ALL, 0);

      const preimage = Buffer.concat([
        verBuf,
        hashPrevouts,
        hashSequence,
        Buffer.from(txForHash.ins[idx].hash),
        voutBuf,
        Buffer.from([p2pkhScript.length]),
        Buffer.from(p2pkhScript),
        valBuf,
        seqBuf,
        hashOutputs,
        lockBuf,
        sighashTypeBuf
      ]);

      return {
        inputIndex: idx,
        sighashHex,
        verifiablePayloadHex: Buffer.concat([preimage, outputsBuffer]).toString('hex')
      };
    });

    return {
      chain: 'BTC',
      psbtHex: psbt.toHex(),
      sighashes,
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
  prepareSolanaSweep({ fromPubkey, toPubkey, lamports, amountLamports, memo, recentBlockhash }) {
    const from = new web3.PublicKey(fromPubkey);
    const to = new web3.PublicKey(toPubkey);
    const effectiveLamports = lamports !== undefined ? lamports : amountLamports;
    if (effectiveLamports === undefined) {
      throw new Error("Missing required lamports/amountLamports parameter for Solana sweep");
    }
    const TX_FEE_LAMPORTS = 5000n;
    const sweepLamports = BigInt(effectiveLamports) - TX_FEE_LAMPORTS;
    if (sweepLamports <= 0n) {
      throw new Error(`Insufficient SOL balance for fee: balance ${effectiveLamports} <= fee ${TX_FEE_LAMPORTS}`);
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
      const rawMemoBuf = Buffer.from(String(memo), 'utf8');
      // Cap inline Solana memo at 560 bytes so 1 + 64 + message.length never exceeds 1232-byte PACKET_DATA_SIZE
      const solMemoBuf =
        rawMemoBuf.length <= 560
          ? rawMemoBuf
          : Buffer.from(
              `aegis-e2ee:${crypto.createHash('sha256').update(rawMemoBuf).digest('hex')}`,
              'utf8'
            );
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: from, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: solMemoBuf
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
      const rawMemoBuf = Buffer.from(String(memo), 'utf8');
      const solMemoBuf =
        rawMemoBuf.length <= 560
          ? rawMemoBuf
          : Buffer.from(
              `aegis-e2ee:${crypto.createHash('sha256').update(rawMemoBuf).digest('hex')}`,
              'utf8'
            );
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: fromOwner, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: solMemoBuf
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
   * Encode (r, s) to DER (BIP-66) format with BIP-62 Low-S canonical enforcement
   */
  encodeDerSignature(rBuffer, sBuffer) {
    const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const SECP256K1_HALF_N = SECP256K1_N / 2n;

    let sBig = BigInt('0x' + Buffer.from(sBuffer).toString('hex'));
    if (sBig > SECP256K1_HALF_N) {
      sBig = SECP256K1_N - sBig;
      let hex = sBig.toString(16);
      if (hex.length % 2 !== 0) hex = '0' + hex;
      sBuffer = Buffer.from(hex, 'hex');
    }

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
    const rawSig = mpcEddsaSignature?.signature || mpcEddsaSignature;
    const sigBytes = Buffer.isBuffer(rawSig)
      ? rawSig
      : Array.isArray(rawSig)
        ? Buffer.from(rawSig)
        : Buffer.from(String(rawSig).replace(/^0x/, ''), 'hex');
    tx.addSignature(fromPubkey, sigBytes);
    const serialized = tx.serialize({ verifySignatures: false, requireAllSignatures: false });
    const signatureBase58 = bs58Encode ? bs58Encode(Uint8Array.from(sigBytes)) : sigBytes.toString('hex');
    return {
      txHex: Buffer.from(serialized).toString('hex'),
      signedTxBase64: Buffer.from(serialized).toString('base64'),
      signatureBase58,
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

### 3. RELAYER SERVICE & KEEPER (relayer/service.js)
```javascript
/**
 * Aegis Autonomous Relayer & Stateless Keeper Service
 *
 * Security & Architecture Guarantees:
 * - Zero hardcoded private keys; runs with a least-privilege `FunctionCall` key on `keeper.aegis.okgoogleok.testnet`
 * - Zero-deposit `request_sweep_signature` calls funded by Per-Vault Gas Escrow / Sponsor Pool + 0.005 NEAR keeper refund
 * - Multi-UTXO Bitcoin signing + OP_RETURN testament, dynamic EVM nonce/EIP-1559 fee calculation, real Base58 Solana tx signatures
 * - Zero fake fallback hashes; strict broadcast verification with automatic retry if any RPC broadcast fails
 * - On-chain telemetry persistence (`record_sweep_telemetry`) + multi-tenant `web/telemetry.json` mirror
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nearAPI = require('near-api-js');
const { ethers } = require('ethers');
const web3 = require('@solana/web3.js');
const bitcoin = require('bitcoinjs-lib');
const { LastKeySweepRelayer } = require('./sweep_relayer');

class AegisRelayerService {
  constructor(config = {}) {
    this.networkId = config.networkId || process.env.NEAR_NETWORK || 'testnet';
    this.contractId = config.contractId || process.env.CONTRACT_ID || 'aegis.okgoogleok.testnet';
    this.relayerAccountId =
      config.relayerAccountId ||
      process.env.RELAYER_ACCOUNT_ID ||
      'keeper.aegis.okgoogleok.testnet';
    this.privateKey = config.privateKey || '';
    this.disableLocalFileCache = Boolean(config.disableLocalFileCache);
    this.credPath =
      config.credPath ||
      (typeof __dirname !== 'undefined'
        ? path.resolve(__dirname, `../.credentials/${this.relayerAccountId}.json`)
        : '');
    this.telemetryPath =
      config.telemetryPath ||
      (typeof __dirname !== 'undefined' ? path.resolve(__dirname, '../web/telemetry.json') : '');
    this.nearRpcUrl =
      config.nearRpcUrl || process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com';
    this.evmRpcUrl =
      config.evmRpcUrl ||
      process.env.EVM_RPC_URL ||
      'https://ethereum-sepolia-rpc.publicnode.com';
    this.solanaRpcUrl =
      config.solanaRpcUrl ||
      process.env.SOLANA_RPC_URL ||
      'https://api.devnet.solana.com';

    this.engine = new LastKeySweepRelayer({
      networkId: this.networkId,
      vaultContractId: this.contractId,
      nearRpcUrl: this.nearRpcUrl
    });

    this.near = null;
    this.account = null;
    this._signerKeyPair = null;
    this._nextNonce = null;
    this._recentBlockHash = null;
    this._blockFetchedAt = 0;
    this.hasSignerKey = false;
    this.processedSweeps = new Set();
  }

  async init({ requireSigner = false } = {}) {
    if (!this.near) {
      const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
      let privKey = (this.privateKey || process.env.RELAYER_PRIVATE_KEY || '').trim();

      if (
        !privKey &&
        process.env.NODE_ENV !== 'production' &&
        this.credPath &&
        fs &&
        typeof fs.existsSync === 'function' &&
        fs.existsSync(this.credPath)
      ) {
        try {
          const cred = JSON.parse(fs.readFileSync(this.credPath, 'utf8'));
          privKey = (cred.privateKey || cred.private_key || '').trim();
          if (cred.accountId || cred.account_id) {
            this.relayerAccountId = cred.accountId || cred.account_id;
          }
        } catch (e) {
          console.warn(`[Aegis Relayer] Could not parse ${this.credPath}:`, e.message);
        }
      }

      if (privKey) {
        const keyPair = nearAPI.KeyPair.fromString(privKey);
        this._signerKeyPair = keyPair;
        await keyStore.setKey(this.networkId, this.relayerAccountId, keyPair);
        this.hasSignerKey = true;
      }

      this.near = await nearAPI.connect({
        networkId: this.networkId,
        keyStore,
        nodeUrl: this.nearRpcUrl
      });
      this.account = await this.near.account(this.relayerAccountId);

      console.log(
        `🛡️  [Aegis Relayer] Initialized (account: ${this.relayerAccountId}, signerLoaded: ${this.hasSignerKey})`
      );
    }

    if (requireSigner && !this.hasSignerKey) {
      throw new Error(
        `Missing RELAYER_PRIVATE_KEY for ${this.relayerAccountId}. Configure RELAYER_PRIVATE_KEY env secret or ${this.credPath}.`
      );
    }
  }

  async nearRpc(method, params = {}) {
    const candidates = [
      this.nearRpcUrl,
      this.networkId === 'testnet' ? 'https://test.rpc.fastnear.com' : 'https://free.rpc.fastnear.com',
      this.networkId === 'testnet' ? 'https://rpc.testnet.fastnear.com' : 'https://rpc.mainnet.fastnear.com'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'AegisVaultRelayer/1.0'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`NEAR RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          const errData = body.error.data ? JSON.stringify(body.error.data) : body.error.message;
          const rpcErr = new Error(`NEAR RPC ${body.error.name || 'Error'}: ${errData}`);
          rpcErr.rpcError = body.error;
          throw rpcErr;
        }
        return body.result;
      } catch (err) {
        lastErr = err;
        // Do not failover on deterministic NEAR execution/state errors (e.g. InvalidNonce, UNKNOWN_ACCOUNT)
        if (err.rpcError && err.rpcError.name !== 'INTERNAL_ERROR' && !String(err.message).includes('Timeout')) {
          throw err;
        }
      }
    }
    throw lastErr || new Error('All NEAR RPC endpoints failed');
  }

  async ensureSignerNonceAndBlock(forceResync = false) {
    const pubKeyStr = this._signerKeyPair.getPublicKey().toString();
    const blockStale = Date.now() - this._blockFetchedAt > 60_000;
    if (forceResync || this._nextNonce === null || blockStale) {
      const keyInfo = await this.nearRpc('query', {
        request_type: 'view_access_key',
        finality: 'final',
        account_id: this.relayerAccountId,
        public_key: pubKeyStr
      });
      if (keyInfo && keyInfo.error) {
        throw new Error(`Access key query failed for ${this.relayerAccountId}: ${keyInfo.error}`);
      }
      if (forceResync || this._nextNonce === null) {
        this._nextNonce = BigInt(keyInfo.nonce || 0);
      }
      this._recentBlockHash = nearAPI.utils.serialize.base_decode(keyInfo.block_hash);
      this._blockFetchedAt = Date.now();
    }
  }

  async evmRpc(method, params = []) {
    const candidates = [
      this.evmRpcUrl,
      'https://sepolia.drpc.org',
      'https://ethereum-sepolia-rpc.publicnode.com',
      'https://1rpc.io/sepolia',
      'https://rpc.sepolia.org'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'AegisVaultRelayer/1.0'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`EVM RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          throw new Error(body.error.message || JSON.stringify(body.error));
        }
        return body.result;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('All EVM Sepolia RPC endpoints failed');
  }

  async solanaRpc(method, params = []) {
    const candidates = [
      this.solanaRpcUrl,
      'https://solana-devnet.api.onfinality.io/public',
      'https://rpc.magicblock.app/devnet',
      'https://api.devnet.solana.com'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'AegisVaultRelayer/1.0'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`Solana RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          throw new Error(body.error.message || JSON.stringify(body.error));
        }
        return body.result;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('All Solana Devnet RPC endpoints failed');
  }

  async callContractActions(actionsSpec = []) {
    await this.init({ requireSigner: true });
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      let txHashBase58 = '';
      try {
        await this.ensureSignerNonceAndBlock(attempt > 0);
        this._nextNonce += 1n;
        const txNonce = this._nextNonce;
        const pubKey = this._signerKeyPair.getPublicKey();
        const actions = actionsSpec.map(spec =>
          nearAPI.transactions.functionCall(
            spec.methodName,
            spec.args || {},
            BigInt(spec.gas || '100000000000000'),
            BigInt(spec.attachedDeposit || '0')
          )
        );
        const tx = nearAPI.transactions.createTransaction(
          this.relayerAccountId,
          pubKey,
          this.contractId,
          txNonce,
          actions,
          this._recentBlockHash
        );
        const encodedTx = tx.encode();
        const txHashBytes = crypto.createHash('sha256').update(Buffer.from(encodedTx)).digest();
        txHashBase58 = nearAPI.utils.serialize.base_encode(txHashBytes);
        const sig = this._signerKeyPair.sign(txHashBytes);
        const signedTx = new nearAPI.transactions.SignedTransaction({
          transaction: tx,
          signature: new nearAPI.transactions.Signature({
            keyType: pubKey.keyType,
            data: sig.signature
          })
        });
        const signedTxBase64 = Buffer.from(signedTx.encode()).toString('base64');

        let outcome;
        try {
          outcome = await this.nearRpc('send_tx', {
            signed_tx_base64: signedTxBase64,
            wait_until: 'EXECUTED_OPTIMISTIC'
          });
        } catch (sendErr) {
          if (String(sendErr.message || '').includes('Timeout') && txHashBase58) {
            await new Promise(r => setTimeout(r, 2000));
            outcome = await this.nearRpc('tx', {
              tx_hash: txHashBase58,
              sender_account_id: this.relayerAccountId,
              wait_until: 'EXECUTED_OPTIMISTIC'
            });
          } else {
            throw sendErr;
          }
        }

        if (outcome && outcome.status && typeof outcome.status === 'object' && outcome.status.Failure) {
          throw new Error(
            `NEAR transaction ${txHashBase58} failed: ${JSON.stringify(outcome.status.Failure)}`
          );
        }
        return outcome;
      } catch (err) {
        lastErr = err;
        const msg = String(err?.message || err);
        if (
          attempt < 2 &&
          (msg.includes('InvalidNonce') ||
            msg.includes('ak_nonce') ||
            msg.includes('Expired') ||
            msg.includes('Timeout') ||
            msg.includes('502') ||
            msg.includes('503') ||
            msg.includes('429'))
        ) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  }

  async callContract(methodName, args = {}, gas = '100000000000000', attachedDeposit = '0') {
    return this.callContractActions([{ methodName, args, gas, attachedDeposit }]);
  }

  async viewContract(methodName, args = {}) {
    await this.init({ requireSigner: false });
    const raw = await this.nearRpc('query', {
      request_type: 'call_function',
      finality: 'optimistic',
      account_id: this.contractId,
      method_name: methodName,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64')
    });
    if (raw && raw.error) {
      throw new Error(`View ${methodName} error: ${raw.error}`);
    }
    return JSON.parse(Buffer.from(raw.result).toString('utf8'));
  }

  extractMpcSignatureFromOutcome(outcome) {
    for (const out of outcome.receipts_outcome || []) {
      if (out.outcome && out.outcome.status && out.outcome.status.SuccessValue) {
        const raw = Buffer.from(out.outcome.status.SuccessValue, 'base64').toString('utf8');
        try {
          const parsed = JSON.parse(raw);
          if (parsed && (parsed.big_r || parsed.signature || parsed.r)) {
            return parsed;
          }
        } catch (_) {}
      }
    }
    return null;
  }

  /**
   * Sponsor zero-gas heartbeat using cryptographic owner Ed25519 signature (`[ATTACK-3]` compliant)
   */
  async sponsorPing(vaultOwner, { timestampMs, signatureHex, nep413NonceHex = null, nep413Recipient = null } = {}) {
    await this.init({ requireSigner: true });
    if (!vaultOwner || !timestampMs || !signatureHex) {
      return {
        success: false,
        error: 'ping_by_relayer requires vaultOwner, timestampMs, and signatureHex'
      };
    }
    const cleanSig = String(signatureHex).trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{128}$/.test(cleanSig)) {
      return {
        success: false,
        error: 'Invalid signatureHex: must be a 64-byte (128 hex chars) Ed25519 signature'
      };
    }
    if (nep413NonceHex !== null && nep413NonceHex !== undefined) {
      const cleanNonce = String(nep413NonceHex).trim().replace(/^0x/i, '');
      if (!/^[0-9a-fA-F]{64}$/.test(cleanNonce)) {
        return {
          success: false,
          error: 'Invalid nep413NonceHex: must be 32 bytes (64 hex chars)'
        };
      }
    }
    const tsNum = Number(timestampMs);
    const nowMs = Date.now();
    if (!Number.isFinite(tsNum) || Math.abs(nowMs - tsNum) > 10 * 60 * 1000) {
      return {
        success: false,
        error: 'Heartbeat timestamp expired or out of 10-minute window'
      };
    }
    console.log(`⏱️  [Aegis Relayer] Broadcasting verified signed heartbeat for ${vaultOwner}...`);
    try {
      const outcome = await this.callContract(
        'ping_by_relayer',
        {
          vault_owner: vaultOwner,
          timestamp_ms: String(timestampMs),
          signature_hex: cleanSig,
          nep413_nonce_hex: nep413NonceHex ? String(nep413NonceHex).trim().replace(/^0x/i, '') : null,
          nep413_recipient: nep413Recipient
        },
        '30000000000000',
        '0'
      );
      const txHash = outcome.transaction.hash;
      console.log(`✅ [Aegis Relayer] Signed heartbeat confirmed! Tx: ${txHash}`);
      return { success: true, txHash };
    } catch (err) {
      console.error(`❌ [Aegis Relayer] Failed signed heartbeat for ${vaultOwner}:`, err.message);
      return { success: false, error: err.message };
    }
  }

  async getVaultInfo(vaultOwner) {
    try {
      return await this.viewContract('get_vault_info', { account_id: vaultOwner });
    } catch (err) {
      console.warn(`[Aegis Relayer] get_vault_info error for ${vaultOwner}:`, err.message);
      return null;
    }
  }

  async getActionableVaults({ throwOnError = false } = {}) {
    try {
      const vaults = await this.viewContract('get_actionable_vaults', {});
      return Array.isArray(vaults) ? vaults : [];
    } catch (err) {
      console.warn(`[Aegis Relayer] get_actionable_vaults error:`, err.message);
      if (throwOnError) throw err;
      return [];
    }
  }

  /**
   * Persist telemetry to multi-tenant `web/telemetry.json` without clobbering other vaults
   */
  writeLocalTelemetry(telemetryRecord) {
    let store = { vaults: {} };
    if (fs.existsSync(this.telemetryPath)) {
      try {
        const existing = JSON.parse(fs.readFileSync(this.telemetryPath, 'utf8'));
        if (existing && typeof existing === 'object') {
          store.vaults = existing.vaults && typeof existing.vaults === 'object' ? existing.vaults : {};
          if (existing.vault_owner && existing.sweeps) {
            store.vaults[`${existing.vault_owner}:${existing.epoch ?? 0}`] = {
              vault_owner: existing.vault_owner,
              epoch: existing.epoch ?? 0,
              state: existing.state,
              updated_at: existing.updated_at,
              sweeps: existing.sweeps
            };
            store.vaults[existing.vault_owner] = store.vaults[`${existing.vault_owner}:${existing.epoch ?? 0}`];
          }
        }
      } catch (_) {}
    }

    const epochKey = `${telemetryRecord.vault_owner}:${telemetryRecord.epoch}`;
    store.vaults[epochKey] = telemetryRecord;
    store.vaults[telemetryRecord.vault_owner] = telemetryRecord;

    const merged = {
      ...telemetryRecord,
      vaults: store.vaults
    };
    fs.writeFileSync(this.telemetryPath, JSON.stringify(merged, null, 2));
  }

  /**
   * Execute Multichain Panic / Inheritance Sweep
   */
  async sweepVault(vaultOwner, options = {}) {
    await this.init({ requireSigner: true });
    console.log(`\n🚨 [Aegis Relayer] Executing multichain sweep for ${vaultOwner}...`);

    const vault = options.prefetchedVault || (await this.getVaultInfo(vaultOwner));
    if (!vault) {
      console.error(`❌ Vault not found for ${vaultOwner}`);
      return null;
    }

    const state = typeof vault.state === 'string' ? vault.state : Object.keys(vault.state)[0];
    if (state !== 'Evacuated' && state !== 'Inheritance') {
      console.log(`ℹ️  Vault state is '${state}'. No sweep required.`);
      return null;
    }

    if (vault.is_epoch_swept) {
      console.log(`ℹ️  Vault ${vaultOwner} epoch ${vault.epoch} is already marked swept on-chain.`);
      return vault.last_sweep_report ? JSON.parse(vault.last_sweep_report) : null;
    }

    const epoch = vault.epoch;
    const destination = state === 'Evacuated' ? vault.backup : vault.heirs;
    const actionLabel = state === 'Inheritance' ? 'Inheritance' : 'Evacuation';
    let sweepMemo = `Aegis ${actionLabel}: ${vaultOwner} Epoch ${epoch}`;

    if (state === 'Inheritance' && vault.heir_memo && vault.heir_memo.trim()) {
      sweepMemo = vault.heir_memo.trim();
      console.log(
        `   📜 Heir testament loaded (${sweepMemo.startsWith('enc:') ? 'E2EE Ciphertext' : 'Plaintext'}, ${Buffer.byteLength(sweepMemo, 'utf8')} B)`
      );
    }

    const derivationPath = `aegis/${vaultOwner}/${epoch}`;
    console.log(`   • Vault State:       ${state}`);
    console.log(`   • Bunker Epoch:      ${epoch}`);
    console.log(`   • Derivation Path:   ${derivationPath}`);

    const vaultAddrs = await this.engine.deriveAllAddresses(this.contractId, derivationPath);
    console.log(`     - EVM Bunker:  ${vaultAddrs.evm.address}`);
    console.log(`     - BTC Bunker:  ${vaultAddrs.btc.address}`);
    console.log(`     - SOL Bunker:  ${vaultAddrs.sol.address}`);

    const telemetryRecord = {
      vault_owner: vaultOwner,
      epoch,
      state,
      updated_at: new Date().toISOString(),
      sweeps: {}
    };
    let hasRetriableFailure = false;

    // 1. EVM Sweep (Sepolia / Base / Arbitrum)
    if (destination.evm && destination.evm.trim().length === 42) {
      console.log(`\n[EVM Sweep] Checking ${vaultAddrs.evm.address} -> ${destination.evm}...`);
      try {
        const balHex = await this.evmRpc('eth_getBalance', [vaultAddrs.evm.address, 'latest']);
        const liveWei = BigInt(balHex || '0x0');
        console.log(`   • EVM Bunker Balance: ${ethers.formatEther(liveWei)} ETH (${liveWei} wei)`);

        if (liveWei === 0n) {
          telemetryRecord.sweeps.evm = {
            status: 'Skipped (Zero Balance)',
            chain: 'Ethereum / Base (Sepolia)',
            target: destination.evm,
            amount: '0.0000 ETH'
          };
        } else {
          const [nonceHex, gasPriceHex, priorityFeeHex, chainIdHex] = await Promise.all([
            this.evmRpc('eth_getTransactionCount', [vaultAddrs.evm.address, 'pending']),
            this.evmRpc('eth_gasPrice', []),
            this.evmRpc('eth_maxPriorityFeePerGas', []).catch(() => '0x3b9aca00'),
            this.evmRpc('eth_chainId', [])
          ]);
          const nonce = Number(BigInt(nonceHex || '0x0'));
          const chainId = Number(BigInt(chainIdHex || '0xaa36a7'));
          const MIN_FEE = 1_500_000_000n; // 1.5 Gwei floor
          const MAX_SAFE_FEE = 450_000_000_000n; // 450 Gwei (< 500 Gwei contract cap)
          const baseGasPrice = BigInt(gasPriceHex || '0x4a817c800');
          let maxPriorityFeePerGas = BigInt(priorityFeeHex || '0x3b9aca00');
          if (maxPriorityFeePerGas <= 0n) maxPriorityFeePerGas = 1_000_000_000n;
          let maxFeePerGas = baseGasPrice * 2n + maxPriorityFeePerGas;
          if (maxFeePerGas < MIN_FEE) maxFeePerGas = MIN_FEE;
          if (maxFeePerGas > MAX_SAFE_FEE) maxFeePerGas = MAX_SAFE_FEE;
          if (maxPriorityFeePerGas > maxFeePerGas) maxPriorityFeePerGas = maxFeePerGas;

          const memoBytes = sweepMemo ? ethers.toUtf8Bytes(sweepMemo) : new Uint8Array(0);
          let calldataGas = 0n;
          for (const b of memoBytes) calldataGas += b === 0 ? 4n : 16n;
          const minGasLimit = 21000n + calldataGas;
          let gasLimit = minGasLimit;
          try {
            const estHex = await this.evmRpc('eth_estimateGas', [
              {
                from: vaultAddrs.evm.address,
                to: destination.evm.trim(),
                value: '0x1',
                data: sweepMemo ? ethers.hexlify(memoBytes) : '0x'
              }
            ]);
            if (estHex) {
              const est = (BigInt(estHex) * 120n) / 100n; // +20% safety margin for smart contract wallets
              if (est > gasLimit) gasLimit = est;
              if (gasLimit > 250000n) gasLimit = 250000n;
            }
          } catch (_) {}
          const isL2 = [8453, 84532, 10, 42161, 421614].includes(chainId);
          const l1Buffer = isL2 ? 15_000_000_000_000n : 0n;
          const totalGasCost = gasLimit * maxFeePerGas + l1Buffer;

          if (liveWei <= totalGasCost) {
            telemetryRecord.sweeps.evm = {
              status: 'Skipped (Dust Below Gas Fee)',
              chain: 'Ethereum / Base (Sepolia)',
              target: destination.evm,
              amount: `${ethers.formatEther(liveWei)} ETH`
            };
          } else {
            const sweepValueWei = liveWei - totalGasCost;
            const evmSweep = await this.engine.prepareEvmSweep({
              fromAddress: vaultAddrs.evm.address,
              toAddress: destination.evm.trim(),
              valueWei: sweepValueWei,
              gasLimit,
              nonce,
              maxFeePerGas,
              maxPriorityFeePerGas,
              chainId,
              memo: sweepMemo
            });

            const outcome = await this.callContract(
              'request_sweep_signature',
              {
                vault_owner: vaultOwner,
                chain: 'EVM',
                payload_hex: evmSweep.unsignedTxHex,
                target_epoch: epoch,
                is_eddsa: false
              },
              '280000000000000',
              '0'
            );

            const nearTxHash = outcome.transaction.hash;
            const mpcSignature = this.extractMpcSignatureFromOutcome(outcome);
            if (!mpcSignature) {
              throw new Error(`MPC signature missing in NEAR receipt ${nearTxHash}`);
            }

            const signedEvmTx = this.engine.assembleSignedEvmTx(evmSweep.rawTx, mpcSignature);
            const rawSignedHex = signedEvmTx.signedTx.startsWith('0x')
              ? signedEvmTx.signedTx
              : '0x' + signedEvmTx.signedTx;
            let broadcastHash = null;
            try {
              broadcastHash = await this.evmRpc('eth_sendRawTransaction', [rawSignedHex]);
            } catch (bErr) {
              const bMsg = String(bErr?.message || bErr).toLowerCase();
              if (bMsg.includes('already known') || bMsg.includes('known transaction')) {
                broadcastHash = signedEvmTx.txHash;
              } else {
                throw bErr;
              }
            }
            const evmHash = broadcastHash || signedEvmTx.txHash;
            console.log(`   🚀 EVM Sweep Broadcasted! TxHash: ${evmHash}`);

            telemetryRecord.sweeps.evm = {
              status: 'Broadcasted (Sepolia)',
              chain: 'Ethereum / Base (Sepolia)',
              target: destination.evm,
              amount: `${ethers.formatEther(sweepValueWei)} ETH`,
              tx_hash: evmHash,
              explorer: `https://sepolia.etherscan.io/tx/${evmHash}`,
              near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearTxHash}`
            };
          }
        }
      } catch (err) {
        console.error(`   ❌ EVM Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.evm = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Ethereum / Base (Sepolia)',
          target: destination.evm,
          amount: '0.0000 ETH'
        };
      }
    }

    // 2. Bitcoin Sweep (Native SegWit — Multi-UTXO + OP_RETURN)
    if (destination.btc && destination.btc.trim().length > 10) {
      console.log(`\n[Bitcoin Sweep] Checking ${vaultAddrs.btc.address} -> ${destination.btc}...`);
      try {
        const mempoolRes = await fetch(
          `https://mempool.space/testnet/api/address/${vaultAddrs.btc.address}/utxo`
        );
        if (!mempoolRes.ok) {
          throw new Error(`Mempool UTXO HTTP ${mempoolRes.status}`);
        }
        const liveUtxos = await mempoolRes.json();

        if (!Array.isArray(liveUtxos) || liveUtxos.length === 0) {
          telemetryRecord.sweeps.btc = {
            status: 'Skipped (Zero Balance)',
            chain: 'Bitcoin Native SegWit',
            target: destination.btc,
            amount: '0.00000000 BTC'
          };
        } else {
          let feeRateSatPerVb = 10;
          try {
            const feeRes = await fetch('https://mempool.space/testnet/api/v1/fees/recommended');
            if (feeRes.ok) {
              const fees = await feeRes.json();
              feeRateSatPerVb = Math.max(2, Math.min(200, Number(fees.fastestFee || 10)));
            }
          } catch (_) {}

          let btcSweep;
          try {
            btcSweep = this.engine.prepareBtcSweep({
              utxos: liveUtxos,
              fromAddress: vaultAddrs.btc.address,
              toAddress: destination.btc.trim(),
              memo: sweepMemo,
              feeRateSatPerVb,
              network: bitcoin.networks.testnet
            });
          } catch (dustErr) {
            if (dustErr.message.includes('dust')) {
              telemetryRecord.sweeps.btc = {
                status: 'Skipped (Dust UTXOs)',
                chain: 'Bitcoin Native SegWit',
                target: destination.btc,
                amount: '0.00000000 BTC'
              };
              btcSweep = null;
            } else {
              throw dustErr;
            }
          }

          if (btcSweep) {
            const btcSignatures = [];
            let lastNearTxHash = null;

            for (const sh of btcSweep.sighashes) {
              console.log(
                `   • Requesting MPC ECDSA signature for BTC input #${sh.inputIndex}/${btcSweep.sighashes.length - 1}...`
              );
              const outcome = await this.callContract(
                'request_sweep_signature',
                {
                  vault_owner: vaultOwner,
                  chain: 'BTC',
                  payload_hex: sh.verifiablePayloadHex || sh.sighashHex,
                  target_epoch: epoch,
                  is_eddsa: false
                },
                '280000000000000',
                '0'
              );
              lastNearTxHash = outcome.transaction.hash;
              const mpcSig = this.extractMpcSignatureFromOutcome(outcome);
              if (!mpcSig) {
                throw new Error(`MPC signature missing for BTC input #${sh.inputIndex}`);
              }
              const rHex = mpcSig.big_r?.affine_point?.slice(2) || mpcSig.r;
              const sHex = mpcSig.s?.scalar || mpcSig.s;
              btcSignatures.push({
                inputIndex: sh.inputIndex,
                r: Buffer.from(rHex.replace(/^0x/, ''), 'hex'),
                s: Buffer.from(sHex.replace(/^0x/, ''), 'hex'),
                publicKey: Buffer.from(vaultAddrs.btc.publicKey.replace(/^0x/, ''), 'hex')
              });
            }

            const finalized = this.engine.finalizeBtcSweepPsbt(
              btcSweep.psbtHex,
              btcSignatures,
              bitcoin.networks.testnet
            );
            const mempoolBroadcast = await fetch('https://mempool.space/testnet/api/tx', {
              method: 'POST',
              body: finalized.txHex
            });
            if (!mempoolBroadcast.ok) {
              const errBody = await mempoolBroadcast.text();
              throw new Error(`Mempool broadcast rejected (${mempoolBroadcast.status}): ${errBody.slice(0, 80)}`);
            }
            const broadcastedTxId = (await mempoolBroadcast.text()).trim() || finalized.txId;
            console.log(`   🚀 Bitcoin Tx broadcasted to Testnet: ${broadcastedTxId}`);

            telemetryRecord.sweeps.btc = {
              status: 'Broadcasted (Testnet)',
              chain: 'Bitcoin Native SegWit',
              target: destination.btc,
              amount: `${(btcSweep.sendAmount / 1e8).toFixed(8)} BTC`,
              tx_id: broadcastedTxId,
              explorer: `https://mempool.space/testnet/tx/${broadcastedTxId}`,
              near_mpc_tx: `https://testnet.nearblocks.io/txns/${lastNearTxHash}`
            };
          }
        }
      } catch (err) {
        console.error(`   ❌ Bitcoin Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.btc = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Bitcoin Native SegWit',
          target: destination.btc,
          amount: '0.00000000 BTC'
        };
      }
    }

    // 3. Solana Sweep (Devnet — Real Base58 Signature & Verified RPC Broadcast)
    if (destination.sol && destination.sol.trim().length > 20) {
      console.log(`\n[Solana Sweep] Checking ${vaultAddrs.sol.address} -> ${destination.sol}...`);
      try {
        const balResult = await this.solanaRpc('getBalance', [
          vaultAddrs.sol.address,
          { commitment: 'confirmed' }
        ]);
        const liveLamports = BigInt(balResult?.value ?? 0);
        console.log(
          `   • Solana Bunker Balance: ${Number(liveLamports) / 1e9} SOL (${liveLamports} lamports)`
        );

        if (liveLamports <= 5000n) {
          telemetryRecord.sweeps.sol = {
            status: 'Skipped (Zero/Dust Balance)',
            chain: 'Solana Devnet (Ed25519)',
            target: destination.sol,
            amount: `${(Number(liveLamports) / 1e9).toFixed(4)} SOL`
          };
        } else {
          const latestResult = await this.solanaRpc('getLatestBlockhash', [
            { commitment: 'confirmed' }
          ]);
          const blockhash = latestResult?.value?.blockhash;
          if (!blockhash) throw new Error('Missing Solana recentBlockhash');

          const solSweep = this.engine.prepareSolanaSweep({
            fromPubkey: vaultAddrs.sol.address,
            toPubkey: destination.sol.trim(),
            lamports: liveLamports,
            memo: sweepMemo,
            recentBlockhash: blockhash
          });

          const outcome = await this.callContract(
            'request_sweep_signature',
            {
              vault_owner: vaultOwner,
              chain: 'SOL',
              payload_hex: solSweep.rawPayloadHex,
              target_epoch: epoch,
              is_eddsa: true
            },
            '280000000000000',
            '0'
          );

          const nearTxHash = outcome.transaction.hash;
          const mpcSignature = this.extractMpcSignatureFromOutcome(outcome);
          if (!mpcSignature) {
            throw new Error(`MPC signature missing in NEAR receipt ${nearTxHash}`);
          }

          const signedSol = this.engine.assembleSignedSolanaTx(
            solSweep.serializedMessage,
            vaultAddrs.sol.address,
            mpcSignature
          );

          const rpcSig = await this.solanaRpc('sendTransaction', [
            Buffer.from(signedSol.txHex, 'hex').toString('base64'),
            {
              encoding: 'base64',
              skipPreflight: false,
              preflightCommitment: 'confirmed'
            }
          ]);
          const solSig = rpcSig || signedSol.signatureBase58;
          console.log(`   🚀 Solana Tx broadcasted to Devnet: ${solSig}`);

          telemetryRecord.sweeps.sol = {
            status: 'Confirmed (Devnet)',
            chain: 'Solana Devnet (Ed25519)',
            target: destination.sol,
            amount: `${(Number(liveLamports - 5000n) / 1e9).toFixed(4)} SOL`,
            signature: solSig,
            explorer: `https://solscan.io/tx/${solSig}?cluster=devnet`,
            near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearTxHash}`
          };
        }
      } catch (err) {
        console.error(`   ❌ Solana Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.sol = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Solana Devnet (Ed25519)',
          target: destination.sol,
          amount: '0.0000 SOL'
        };
      }
    }

    // 4. NEAR Native Implicit Bunker & Isolated Vault Deposit Sweep (Zero Fake Fallbacks)
    if (destination.near && destination.near.trim().length > 2) {
      const destNear = destination.near.trim();
      console.log(`\n[NEAR Sweep] Checking implicit & isolated NEAR deposits -> ${destNear}...`);
      let totalSweptYocto = options.preSweptNear ? BigInt(options.preSweptNear.amountYocto) : 0n;
      let nearSweepTx = options.preSweptNear ? options.preSweptNear.txHash : null;
      let nearMpcTx = null;

      try {
        // 4a. Sweep isolated per-user contract deposit first
        const isolatedNearDeposit = BigInt(vault.near_deposit_yocto || '0');
        if (isolatedNearDeposit > 0n) {
          const sweepOutcome = await this.callContract('sweep_near', { vault_owner: vaultOwner }, '100000000000000', '0');
          if (!nearSweepTx) nearSweepTx = sweepOutcome.transaction.hash;
          totalSweptYocto += isolatedNearDeposit;
          console.log(`   🚀 NEAR Isolated Vault Deposit Swept! Tx: ${sweepOutcome.transaction.hash}`);
        }

        // 4b. Check NEAR implicit bunker account
        const nearPubKeyObj = nearAPI.utils.PublicKey.from('ed25519:' + vaultAddrs.sol.address);
        const implicitAccountId = Buffer.from(nearPubKeyObj.data).toString('hex');
        const nearPubKeyStr = 'ed25519:' + vaultAddrs.sol.address;

        const accInfo = await this.nearRpc('query', {
          request_type: 'view_account',
          finality: 'final',
          account_id: implicitAccountId
        }).catch(() => null);

        if (accInfo && accInfo.amount && BigInt(accInfo.amount) > 10_000_000_000_000_000_000_000n) {
          const keyInfo = await this.nearRpc('query', {
            request_type: 'view_access_key',
            finality: 'final',
            account_id: implicitAccountId,
            public_key: nearPubKeyStr
          });
          const blockHash = nearAPI.utils.serialize.base_decode(keyInfo.block_hash);

          const totalBal = BigInt(accInfo.amount);
          const feeReserve = 5_000_000_000_000_000_000_000n; // 0.005 NEAR transfer fee buffer
          const sweepYocto = totalBal > feeReserve ? totalBal - feeReserve : 0n;

          if (sweepYocto > 0n) {
            const nonce = BigInt(keyInfo.nonce || 0) + 1n;
            const actions = [nearAPI.transactions.transfer(BigInt(sweepYocto.toString()))];
            const transaction = nearAPI.transactions.createTransaction(
              implicitAccountId,
              nearPubKeyObj,
              destNear,
              nonce,
              actions,
              blockHash
            );
            const serializedTx = transaction.encode();
            const rawBorshHex = Buffer.from(serializedTx).toString('hex');

            const sigRes = await this.callContract(
              'request_sweep_signature',
              {
                vault_owner: vaultOwner,
                chain: 'NEAR',
                payload_hex: rawBorshHex,
                target_epoch: epoch,
                is_eddsa: true
              },
              '280000000000000',
              '0'
            );
            nearMpcTx = sigRes.transaction.hash;
            const parsedSig = this.extractMpcSignatureFromOutcome(sigRes);
            const rawSigBytes = parsedSig?.signature || parsedSig;
            if (!rawSigBytes) {
              throw new Error('Missing Ed25519 signature for NEAR implicit transfer');
            }
            const sigUint8 = Array.isArray(rawSigBytes)
              ? new Uint8Array(rawSigBytes)
              : new Uint8Array(Buffer.from(String(rawSigBytes).replace(/^0x/, ''), 'hex'));

            const signature = new nearAPI.transactions.Signature({
              keyType: 0,
              data: sigUint8
            });
            const signedTx = new nearAPI.transactions.SignedTransaction({
              transaction,
              signature
            });
            const broadcast = await this.nearRpc('send_tx', {
              signed_tx_base64: Buffer.from(signedTx.encode()).toString('base64'),
              wait_until: 'EXECUTED_OPTIMISTIC'
            });
            nearSweepTx = broadcast.transaction.hash;
            totalSweptYocto += sweepYocto;
            console.log(`   🚀 NEAR Implicit Bunker Swept! Tx: ${nearSweepTx}`);
          }
        }

        if (nearSweepTx && totalSweptYocto > 0n) {
          const formattedNear = nearAPI.utils.format.formatNearAmount(totalSweptYocto.toString(), 4);
          telemetryRecord.sweeps.near = {
            status: 'Confirmed (NEAR Testnet)',
            chain: 'NEAR Protocol Testnet (Ed25519)',
            target: destNear,
            amount: `${formattedNear} NEAR`,
            tx_hash: nearSweepTx,
            explorer: `https://testnet.nearblocks.io/txns/${nearSweepTx}`,
            ...(nearMpcTx ? { near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearMpcTx}` } : {})
          };
        } else {
          telemetryRecord.sweeps.near = {
            status: 'Skipped (Zero Balance)',
            chain: 'NEAR Protocol Testnet (Ed25519)',
            target: destNear,
            amount: '0.0000 NEAR'
          };
        }
      } catch (nearErr) {
        console.error(`   ❌ NEAR Sweep Error:`, nearErr.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.near = {
          status: `Error (${nearErr.message.slice(0, 60)})`,
          chain: 'NEAR Protocol Testnet (Ed25519)',
          target: destNear,
          amount: '0.0000 NEAR'
        };
      }
    }

    const isComplete = !hasRetriableFailure;
    telemetryRecord.is_complete = isComplete;

    // Persist verified telemetry directly on-chain (`aegis.okgoogleok.testnet`)
    try {
      const recOut = await this.callContract(
        'record_sweep_telemetry',
        {
          vault_owner: vaultOwner,
          epoch,
          report_json: JSON.stringify(telemetryRecord),
          is_complete: isComplete
        },
        '50000000000000',
        '0'
      );
      console.log(
        `📡 [Aegis Relayer] Telemetry stored on-chain (is_complete=${isComplete})! Tx: ${recOut.transaction.hash}`
      );
    } catch (recErr) {
      console.warn(`⚠️ [Aegis Relayer] Could not record telemetry on-chain:`, recErr.message);
      telemetryRecord.telemetry_write_error = recErr.message;
    }

    if (!this.disableLocalFileCache && this.telemetryPath) {
      try {
        this.writeLocalTelemetry(telemetryRecord);
        console.log(`📁 [Aegis Relayer] Local telemetry cache updated at ${this.telemetryPath}`);
      } catch (fsErr) {
        console.warn(`⚠️ [Aegis Relayer] Local telemetry write skipped:`, fsErr.message);
      }
    }

    if (isComplete) {
      this.processedSweeps.add(`${vaultOwner}:${epoch}:${state}`);
    }
    return telemetryRecord;
  }

  async getRegisteredAccounts() {
    try {
      const list = await this.viewContract('get_registered_accounts', {});
      if (Array.isArray(list) && list.length > 0) return list;
    } catch (_) {}
    return [];
  }

  startHttpServer(port = process.env.PORT || 8080) {
    if (this._httpServerRunning) return;
    this._httpServerRunning = true;
    const http = require('http');
    const server = http.createServer((req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Private-Network', 'true');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

      if (url.pathname === '/' || url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'online',
            service: 'Aegis Stateless Autonomous Keeper',
            network: this.networkId,
            contract: this.contractId,
            relayer: this.relayerAccountId,
            uptime_seconds: Math.floor(process.uptime()),
            timestamp: new Date().toISOString()
          })
        );
        return;
      }

      if (url.pathname === '/telemetry') {
        try {
          if (fs.existsSync(this.telemetryPath)) {
            const data = fs.readFileSync(this.telemetryPath, 'utf8');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(data);
            return;
          }
        } catch (_) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'No local telemetry cached; query get_vault_info on-chain' }));
        return;
      }

      if (url.pathname === '/ping' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          if (body.length < 8192) body += chunk;
        });
        req.on('end', async () => {
          try {
            const payload = JSON.parse(body || '{}');
            const result = await this.sponsorPing(payload.vault_owner, {
              timestampMs: payload.timestamp_ms,
              signatureHex: payload.signature_hex,
              nep413NonceHex: payload.nep413_nonce_hex || null,
              nep413Recipient: payload.nep413_recipient || null
            });
            res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
          }
        });
        return;
      }

      if ((url.pathname === '/trigger' || url.pathname === '/sweep') && req.method === 'POST') {
        this.sweepAllActionable()
          .then(summary => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, ...summary }));
          })
          .catch(err => {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
          });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    server.listen(port, '0.0.0.0', () => {
      console.log(`🌐 [Aegis Relayer] HTTP Keeper Server listening on port ${port}`);
    });
  }

  async startMonitoring(_initialAccounts = [], intervalMs = 15000) {
    await this.init({ requireSigner: false });
    if (process.env.PORT || process.env.ENABLE_HTTP === 'true') {
      this.startHttpServer();
    }
    console.log(`🔍 [Aegis Relayer] Starting stateless get_actionable_vaults monitor on ${this.contractId}...`);
    const check = async () => {
      try {
        await this.sweepAllActionable();
      } catch (err) {
        console.warn('[Aegis Keeper Cycle] Notice:', err.message);
      }
    };
    await check();
    setInterval(check, intervalMs);
  }

  async runSinglePass() {
    return await this.sweepAllActionable();
  }

  /**
   * Production stateless sweep cycle using `get_actionable_vaults`:
   * - Single RPC view call when healthy (0 gas burned, 0 private key needed if 0 actionable vaults)
   * - Triggers push inheritance & executes verified multichain sweeps for expired/evacuated vaults
   */
  async sweepAllActionable() {
    if (this._activeSweepPromise) {
      console.log('⏳ [Aegis Relayer] Sweep cycle already in progress; coalescing concurrent request.');
      return this._activeSweepPromise;
    }
    this._activeSweepPromise = this._executeSweepAllActionable().finally(() => {
      this._activeSweepPromise = null;
    });
    return this._activeSweepPromise;
  }

  async _executeSweepAllActionable() {
    await this.init({ requireSigner: false });
    console.log(`🔍 [Aegis Relayer] Querying get_actionable_vaults on ${this.contractId}...`);
    const actionable = await this.getActionableVaults({ throwOnError: true });

    if (!actionable || actionable.length === 0) {
      console.log('✅ 0 actionable vaults found. All bunkers healthy or already swept. 0 gas burned.');
      return { actionable: 0, processed: [] };
    }

    await this.init({ requireSigner: true });
    console.log(
      `🚨 Found ${actionable.length} actionable vault(s): ${actionable.map(v => `${v.owner}[v${v.epoch}]`).join(', ')}`
    );

    const processed = [];
    for (const v of actionable) {
      const state = typeof v.state === 'string' ? v.state : Object.keys(v.state)[0];
      const acc = v.owner;
      const prefetchedVault = await this.getVaultInfo(acc);
      if (!prefetchedVault) continue;
      let transitionedInSamePass = false;

      if (state === 'Active' || state === 'Claiming') {
        console.log(`⏱️  [Autonomous Inheritance] Triggering trigger_push_inheritance for ${acc}...`);
        try {
          const pushOut = await this.callContract(
            'trigger_push_inheritance',
            { vault_owner: acc },
            '80000000000000',
            '0'
          );
          console.log(`✅ Push inheritance triggered on-chain for ${acc}! Tx: ${pushOut.transaction.hash}`);
          prefetchedVault.state = 'Inheritance';
          prefetchedVault.is_epoch_swept = false;
          transitionedInSamePass = true;
        } catch (err) {
          console.warn(`[trigger_push_inheritance] error for ${acc}:`, err.message);
          continue;
        }
      }
      const report = await this.sweepVault(acc, { prefetchedVault, transitionedInSamePass });
      processed.push({
        owner: acc,
        epoch: v.epoch,
        complete: Boolean(report?.is_complete),
        sweeps: report?.sweeps || null
      });
    }
    console.log('✅ [Aegis Relayer] sweep-all execution cycle finished.');
    return { actionable: actionable.length, processed };
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const service = new AegisRelayerService();

  if (args.includes('--sweep-all') || args.includes('--once')) {
    service
      .sweepAllActionable()
      .then(() => process.exit(0))
      .catch(err => {
        console.error('Sweep-all failed:', err.message);
        process.exit(1);
      });
  } else if (args.includes('--sweep')) {
    const idx = args.indexOf('--sweep');
    const target = args[idx + 1];
    if (!target) {
      console.error('Usage: node relayer/service.js --sweep <account.testnet>');
      process.exit(1);
    }
    service
      .sweepVault(target)
      .then(() => process.exit(0))
      .catch(err => {
        console.error(err.message);
        process.exit(1);
      });
  } else if (args.includes('--watch') || args.includes('--server')) {
    if (args.includes('--port')) {
      const pIdx = args.indexOf('--port');
      process.env.PORT = args[pIdx + 1];
    }
    service.startMonitoring();
  } else {
    console.log('Usage:');
    console.log('  node relayer/service.js --sweep-all');
    console.log('  node relayer/service.js --sweep <account>');
    console.log('  node relayer/service.js --server [--port 8080]');
  }
}

module.exports = { AegisRelayerService };
```

### 4. FRONTEND APPLICATION (web/index.html)
```html
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis — Multichain MPC Dead-Man's Switch · Built on NEAR Protocol</title>
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  
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
  <!-- Browser Buffer & Process Polyfills for Web3 / Wallet Selector -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/buffer/6.0.3/buffer.min.js"></script>
  <script>
    window.Buffer = window.Buffer || (window.buffer && window.buffer.Buffer);
    window.process = window.process || { env: { NODE_ENV: 'production' }, browser: true };
    window.global = window;
  </script>
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
    <div class="max-w-7xl mx-auto px-4 sm:px-8 min-h-[72px] py-2.5 flex items-center justify-between gap-3">
      
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
            Multichain MPC Dead-Man's Switch · Chain Signatures MPC (v1.signer-prod.testnet)
          </p>
        </div>
      </div>

      <!-- Live Contract Link, Account & Emergency Trigger -->
      <div class="flex items-center gap-3">
        
        <!-- Live NEAR Testnet Explorer Link -->
        <a href="https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet" target="_blank" rel="noopener noreferrer" class="hidden xl:flex items-center gap-2 h-9 px-3.5 rounded-full bg-nearSurface border border-nearBorder hover:border-nearGreen/40 transition text-xs font-mono text-textSilver hover:text-textWhite shrink-0">
          <span class="text-[#8E99AD] font-semibold">Contract:</span>
          <span class="text-white font-mono">aegis.okgoogleok.testnet</span>
          <svg class="w-3.5 h-3.5 text-textGray" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
        </a>

        <!-- User Wallet Connection Area -->
        <div id="walletArea" class="flex items-center gap-2 shrink-0">
          <!-- Disconnected state (default) -->
          <button id="connectWalletBtn" onclick="openMultichainWalletModal()" class="flex items-center gap-2 h-9 px-4 rounded-full bg-purple-950/40 border border-purple-500/40 hover:bg-purple-900/40 text-xs font-mono font-bold text-purple-300 hover:text-white transition shadow-sm active:scale-95 whitespace-nowrap shrink-0 cursor-pointer">
            <svg class="w-3.5 h-3.5 text-purple-400 shrink-0" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L14.4 7.2L20 8L16 12L17 17.6L12 15L7 17.6L8 12L4 8L9.6 7.2L12 2Z"/></svg>
            <span>Connect Wallet</span>
          </button>

          <!-- Connected state (hidden by default) -->
          <div id="connectedWalletPill" class="hidden flex items-center gap-2 h-9 px-3.5 rounded-full bg-nearElevated border border-nearBorder text-xs font-mono whitespace-nowrap shrink-0">
            <span class="w-2 h-2 rounded-full bg-nearGreen shrink-0"></span>
            <span id="headerAccountName" class="font-bold text-nearGreen hidden sm:inline whitespace-nowrap">account.testnet</span>
            <span id="headerAccountNameMobile" class="font-bold text-nearGreen sm:hidden whitespace-nowrap">acc...</span>
            <span id="headerAccountBalance" class="text-[#A6B0C3] border-l border-white/10 pl-2 font-normal hidden sm:inline whitespace-nowrap">0.00 NEAR</span>
            
            <!-- Secondary linked chains (ETH / SOL / BTC) -->
            <div id="headerMultichainBadges" class="hidden items-center gap-1.5 border-l border-white/10 pl-2"></div>

            <button onclick="openMultichainWalletModal()" title="Link More Wallets" class="ml-1 text-[#00F5D4] hover:text-white transition p-0.5 shrink-0 flex items-center cursor-pointer">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" /></svg>
            </button>
            <button onclick="disconnectAllWallets()" title="Disconnect All" class="ml-1 text-textGray hover:text-red-400 transition p-0.5 shrink-0 flex items-center cursor-pointer">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
            </button>
          </div>
        </div>

        <!-- Vertical Divider -->
        <div class="h-6 w-px bg-white/[0.08] hidden sm:block mx-0.5 shrink-0"></div>

        <!-- Emergency Panic Button (Isolated Rounded-XL Safety Trigger) -->
        <button id="headerPanicBtn" onclick="startAbortCountdown()" class="h-9 px-3.5 sm:px-4 rounded-xl bg-red-950/40 hover:bg-red-950/70 text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/60 transition text-xs sm:text-sm font-mono font-bold tracking-wider active:scale-98 flex items-center gap-2 shadow-sm shrink-0 whitespace-nowrap">
          <span id="panicBtnDot" class="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0"></span>
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
              <span id="heartbeatPulseDot" class="w-2.5 h-2.5 rounded-full bg-yellow-400"></span>
              <span id="heartbeatCardTitle" class="text-xs font-mono font-bold uppercase tracking-wider text-[#A6B0C3]">
                Dead-Man's Switch Heartbeat
              </span>
            </div>
            <span id="heartbeatTag" class="text-xs font-mono font-medium text-yellow-400/90 bg-yellow-950/30 px-3 py-1 rounded-full border border-yellow-500/30">
              Vault Inactive · Connect Wallet
            </span>
          </div>

          <div>
            <div id="countdownTitle" class="text-[11px] uppercase font-mono text-textGray font-semibold tracking-wider">
              Automatic Transfer to Heirs Initiates In:
            </div>
            <div id="countdownBox" class="text-3xl sm:text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight mt-2 flex items-baseline gap-2">
              Ready to Arm
            </div>
          </div>

          <!-- Progress Bar in Minimalist Line -->
          <div class="space-y-1.5">
            <div class="w-full bg-white/[0.08] rounded-full h-1 overflow-hidden">
              <div id="timerBar" class="bg-white/40 h-full w-full transition-all duration-1000 ease-out"></div>
            </div>
            <div class="flex justify-between text-xs text-textGray font-mono">
              <span id="statusDisplay">Status: <strong class="text-yellow-400/90 font-bold">Connect Wallet to Arm</strong></span>
              <span id="timerPctDisplay">100.0% remaining</span>
            </div>
          </div>

          <!-- Top Heartbeat 72h Timelock Notice -->
          <div id="heartbeatTimelockNotice" class="hidden mt-2 p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-300 font-mono text-xs flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0"></span>
              <span id="heartbeatTimelockText" class="font-bold">72h Policy Timelock Active</span>
            </div>
            <button onclick="document.getElementById('cooldownAlertBanner')?.scrollIntoView({ behavior: 'smooth' })" class="text-[11px] text-amber-400 hover:text-white underline font-semibold cursor-pointer">
              Review / Revert ↓
            </button>
          </div>
        </div>

        <!-- Controls: Ping alive & Config -->
        <div class="flex flex-col gap-3.5 pt-4 border-t border-nearBorder">
          <button id="pingMainBtn" onclick="handlePingMainBtnClick()" class="w-full bg-purple-600 hover:bg-purple-500 text-white font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-sm active:scale-98 flex items-center justify-center gap-2">
            <svg id="pingMainBtnIcon" class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L14.4 7.2L20 8L16 12L17 17.6L12 15L7 17.6L8 12L4 8L9.6 7.2L12 2Z"/></svg>
            <span id="pingMainBtnText">Connect Wallet to Arm Vault</span>
          </button>
          <div id="onchainPingOption" class="hidden"></div>
          
          <!-- Heartbeat & Grace Policy Schedule Configuration Block -->
          <div class="mt-3 p-3.5 rounded-2xl bg-white/[0.03] border border-white/[0.08] space-y-3">
            <div class="flex items-center justify-between text-xs">
              <div class="flex items-center gap-1.5 text-white font-bold">
                <svg class="w-3.5 h-3.5 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                <span>Trigger Schedule & Safety Buffer</span>
              </div>
              <span class="text-[10px] font-mono text-[#8C929D] bg-white/[0.04] px-2 py-0.5 rounded-full border border-white/[0.06]">Autonomous Policy</span>
            </div>

            <!-- Two Selectors with Labels -->
            <div class="grid grid-cols-2 gap-2.5">
              <div class="space-y-1">
                <label class="block text-[10px] font-semibold text-[#8C929D] uppercase tracking-wider pl-1">1. Check-in Timer</label>
                <div class="relative">
                  <select id="inactivitySelect" onchange="changeInactivityPeriod(this.value)" class="w-full appearance-none bg-[#0B0D12] hover:bg-white/[0.06] text-white font-semibold text-xs rounded-xl pl-3 pr-7 py-2.5 border border-white/[0.08] focus:border-nearGreen outline-none transition cursor-pointer">
                    <option value="demo_120s" class="bg-[#0B0D12] text-amber-300 font-bold">⚡ 2m (Judge Demo)</option>
                    <option value="30" class="bg-[#0B0D12]">Every 30 Days</option>
                    <option value="90" selected class="bg-[#0B0D12]">Every 90 Days</option>
                    <option value="180" class="bg-[#0B0D12]">Every 180 Days</option>
                    <option value="365" class="bg-[#0B0D12]">Every 1 Year</option>
                  </select>
                  <svg class="w-3.5 h-3.5 text-[#8C929D] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" /></svg>
                </div>
              </div>
              <div class="space-y-1">
                <label class="block text-[10px] font-semibold text-[#8C929D] uppercase tracking-wider pl-1">2. Grace Buffer</label>
                <div class="relative">
                  <select id="graceSelect" onchange="changeGracePeriod(this.value)" class="w-full appearance-none bg-[#0B0D12] hover:bg-white/[0.06] text-white font-semibold text-xs rounded-xl pl-3 pr-7 py-2.5 border border-white/[0.08] focus:border-nearGreen outline-none transition cursor-pointer">
                    <option value="demo_30s" class="bg-[#0B0D12] text-amber-300 font-bold">⚡ 30s (Judge Demo)</option>
                    <option value="3" class="bg-[#0B0D12]">Grace: 3 Days</option>
                    <option value="7" selected class="bg-[#0B0D12]">Grace: 7 Days</option>
                    <option value="14" class="bg-[#0B0D12]">Grace: 14 Days</option>
                    <option value="30" class="bg-[#0B0D12]">Grace: 30 Days</option>
                  </select>
                  <svg class="w-3.5 h-3.5 text-[#8C929D] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" /></svg>
                </div>
              </div>
            </div>

            <!-- Clear Explanations -->
            <div class="p-2.5 rounded-xl bg-black/40 border border-white/[0.05] space-y-1.5 text-[11px] leading-relaxed text-[#8C929D]">
              <div class="flex items-start gap-1.5">
                <span class="text-nearGreen font-bold shrink-0">•</span>
                <span><strong class="text-white">Check-in:</strong> Inactivity interval before heartbeat expires. Owner pings or sends any on-chain tx to renew.</span>
              </div>
              <div class="flex items-start gap-1.5">
                <span class="text-amber-400 font-bold shrink-0">•</span>
                <span><strong class="text-white">Grace Window:</strong> Emergency buffer after expiration. Fires urgent Telegram/Email alerts before assets are autonomously swept to heirs.</span>
              </div>
              <div class="flex items-start gap-1.5">
                <span class="text-sky-400 font-bold shrink-0">•</span>
                <span><strong class="text-white">72h Cooldown:</strong> Shortening intervals or changing destinations triggers an on-chain delay to block acceleration attacks.</span>
              </div>
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
            <div class="flex items-center gap-2 min-w-0 max-w-full">
              <span id="bunkerEpochPill" class="text-xs font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-3 py-1 rounded-full whitespace-nowrap max-w-full truncate">
                Derivation Path: aegis/v0 (Active)
              </span>
              <span class="text-xs font-mono font-semibold text-textMuted bg-white/[0.04] border border-white/[0.08] px-3 py-1 rounded-full whitespace-nowrap shrink-0">
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
      <button onclick="switchTab('rescue')" id="tab-rescue" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-bold rounded-xl text-nearBlack bg-nearGreen transition-all whitespace-nowrap">
        1. Rescue & Inheritance (Destinations)
      </button>
      <button onclick="switchTab('vault')" id="tab-vault" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-semibold rounded-xl text-[#8C929D] hover:text-white hover:bg-white/[0.04] transition-all whitespace-nowrap">
        2. Safe Bunker Deposits (Fund Vault)
      </button>
      <button onclick="switchTab('alerts')" id="tab-alerts" class="tab-btn px-5 py-2.5 text-xs sm:text-sm font-semibold rounded-xl text-[#8C929D] hover:text-white hover:bg-white/[0.04] transition-all whitespace-nowrap">
        3. Realtime Alerts
      </button>
    </div>

    <!-- TAB 1: Safe Deposit Addresses (Bunker Mode) -->
    <section id="panel-vault" class="tab-panel space-y-6 hidden">
      
      <!-- Emergency Burn/Rotation Banner (Hidden in pristine state, only appears when burned/evacuated) -->
      <div id="bunkerBurnedBanner" class="p-5 rounded-2xl bg-red-950/25 border border-red-500/35 hidden space-y-3.5">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div class="flex items-start gap-3.5">
            <div class="w-10 h-10 rounded-xl bg-red-500/10 text-red-400 flex items-center justify-center font-bold shrink-0 mt-0.5">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div>
              <h4 class="text-sm font-extrabold text-red-200">Epoch Exhausted — Path Rotation Required</h4>
              <p class="text-xs text-textSilver mt-0.5">Active epoch keys were exposed on-chain during evacuation. Activate the next bunker to derive fresh uncompromised addresses.</p>
            </div>
          </div>
          <div class="flex items-center gap-2 shrink-0 self-start sm:self-center">
            <button type="button" onclick="openEvacMonitor()" class="px-4 py-2.5 rounded-xl bg-white/[0.06] hover:bg-white/[0.1] border border-white/[0.12] text-white font-mono font-bold text-xs transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
              <span>View Sweeps Monitor</span>
            </button>
            <button id="rotateBunkerBtn" onclick="rotateBunkerEpoch()" class="px-5 py-2.5 rounded-xl bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold text-xs transition flex items-center gap-2 whitespace-nowrap shadow-near-glow active:scale-98 cursor-pointer">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
              <span>Activate Next Clean Bunker</span>
            </button>
          </div>
        </div>
        <div class="text-[11px] font-mono font-bold text-red-300 bg-red-900/40 border border-red-500/50 rounded-xl px-3 py-2 flex items-center gap-2">
          <span class="shrink-0 text-base leading-none">🛑</span>
          <span>DO NOT DEPOSIT TO THIS ADDRESS: Active epoch keys are burned. If this address is saved in your exchange whitelists (Binance/OKX/Bybit) or wallet contacts, delete it immediately!</span>
        </div>
      </div>

      <!-- Unarmed Bunker Notice Banner (Appears when vault is connected but unconfigured) -->
      <div id="bunkerUnarmedBanner" class="p-4 rounded-2xl bg-amber-950/25 border border-amber-500/35 hidden flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          </div>
          <div>
            <h4 class="text-xs sm:text-sm font-extrabold text-amber-200">Bunker Inactive — Arm Vault Before Depositing</h4>
            <p class="text-xs text-[#C5CAD3] mt-0.5">Deposit addresses are disabled for security until you configure and save emergency backup or inheritance destinations in Tab 1.</p>
          </div>
        </div>
        <button onclick="switchTab('rescue')" class="px-4 py-2 rounded-xl bg-amber-400 hover:bg-amber-300 text-black font-extrabold text-xs transition whitespace-nowrap shrink-0">
          Configure Policy in Tab 1 ↗
        </button>
      </div>

      <!-- Unallocated Bunker Funds Warning Banner (Appears when deposit exists without backup egress) -->
      <div id="unallocatedDepositAlert" class="p-4 rounded-2xl bg-amber-950/30 border border-amber-500/40 hidden flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          </div>
          <div>
            <h4 class="text-xs sm:text-sm font-extrabold text-amber-200">Unallocated Funds Detected — No Egress Destination Configured</h4>
            <p id="unallocatedDepositText" class="text-xs text-[#C5CAD3] mt-0.5 font-mono"></p>
          </div>
        </div>
        <button onclick="switchTab('rescue')" class="px-4 py-2 rounded-xl bg-amber-400 hover:bg-amber-300 text-black font-extrabold text-xs transition whitespace-nowrap shrink-0">
          Set Egress Addresses ↗
        </button>
      </div>

      <!-- Header row for Deposit tab with Live Sync Status -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2">
        <div>
          <h3 class="text-base font-extrabold text-white">Multichain Bunker Deposit Addresses</h3>
          <p class="text-xs text-[#8C929D] mt-0.5">Full deterministic addresses derived via NEAR MPC. <span class="text-amber-400/90 font-medium">⚠️ One-Epoch Addresses: do not save permanently in exchange whitelists.</span></p>
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
                <span id="btcAddress" data-full="" class="font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  Connect wallet to reveal address
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div id="btcActions" class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
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
                <span id="evmAddress" data-full="" class="font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  Connect wallet to reveal address
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div id="evmActions" class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
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
                <span id="solAddress" data-full="" class="font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  Connect wallet to reveal address
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div id="solActions" class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
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
                <span class="text-xs sm:text-sm text-[#8C929D] font-mono truncate block mt-0.5">Native Implicit (Ed25519)</span>
              </div>
            </div>

            <!-- Vault Balance -->
            <div class="pt-1">
              <div class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Vault Balance</div>
              <div id="nearBalanceText" class="text-2xl sm:text-3xl font-mono font-extrabold text-white mt-1 tracking-tight">0.0000 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span></div>
              <div id="nearUsdText" class="text-xs sm:text-sm font-mono text-[#A6B0C3] mt-1">≈ 0.00 USD</div>
            </div>

            <!-- Full Vault Account -->
            <div class="space-y-1.5 pt-1">
              <div class="flex items-center justify-between">
                <span class="text-xs font-sans font-semibold text-[#A6B0C3] uppercase tracking-wider">Deposit Address</span>
                <span class="text-xs text-nearGreen font-mono font-bold">Full · Ed25519</span>
              </div>
              <div class="p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-white/[0.2] transition min-h-[68px] flex items-center cursor-pointer group" onclick="copyAddr('nearAddress')">
                <span id="nearAddress" data-full="" title="Connect wallet to reveal address" class="font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-all select-all font-medium group-hover:text-nearGreen transition-colors">
                  Connect wallet to reveal address
                </span>
              </div>
            </div>
          </div>

          <!-- Action Row -->
          <div id="nearActions" class="grid grid-cols-2 gap-2.5 pt-4 border-t border-white/[0.08]">
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
    <section id="panel-rescue" class="tab-panel space-y-6">
      <div class="space-y-6">
        
        <!-- Header row -->
        <div class="border-b border-white/[0.08] pb-5">
          <div>
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse"></span>
              <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">Destination Routing Policy</h3>
            </div>
            <p class="text-xs sm:text-sm text-[#8C929D] mt-1">
              Cryptographically locked egress destinations for emergency evacuation and autonomous push inheritance.
            </p>
          </div>
        </div>

        <!-- Unallocated Funds Alert in Rescue Policy Tab -->
        <div id="unallocatedPolicyAlert" class="p-4 rounded-xl bg-amber-950/30 border border-amber-500/40 hidden items-center gap-3 text-amber-200">
          <div class="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold shrink-0">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          </div>
          <div>
            <div class="font-bold text-amber-200 text-xs">Action Required: Unallocated Deposit Funds</div>
            <div id="unallocatedPolicyText" class="text-xs text-[#C5CAD3] mt-0.5 font-mono"></div>
          </div>
        </div>

        <!-- Initial Unconfigured Banner (Hidden if addresses exist) -->
        <div id="unconfiguredBanner" class="hidden p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs items-center gap-3 text-amber-200">
          <svg class="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <span>No destination addresses entered yet. Enter your backup and family wallets below, then click <strong>Save Policy</strong>. Initial setup activates immediately without timelock.</span>
        </div>

        <!-- Armed & Synchronized Banner (Shown when destinations are saved on-chain) -->
        <div id="activePolicyBanner" class="hidden p-4 rounded-xl bg-nearGreen/10 border border-nearGreen/35 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-white">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-nearGreen/20 flex items-center justify-center text-nearGreen shrink-0 font-bold">
              <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
            </div>
            <div>
              <div class="font-bold text-nearGreen flex items-center gap-2">
                <span>Bunker Egress Armed & Active On-Chain</span>
                <span class="text-[10px] font-mono bg-nearGreen/20 text-nearGreen border border-nearGreen/40 px-2 py-0.5 rounded-full font-bold">BLOCKCHAIN ENFORCED</span>
              </div>
              <div id="activePolicySummary" class="text-white/80 text-[11px] mt-0.5 font-mono">
                <!-- Dynamically populated: e.g. Backup: okgoogleok.testnet · Heirs: mastrophot.testnet -->
              </div>
            </div>
          </div>
          <div class="flex items-center gap-2 text-xs font-mono text-nearGreen self-start sm:self-auto">
            <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
            <span class="font-bold">Live Synchronized</span>
          </div>
        </div>

        <!-- Evacuated / Inherited / Expired Policy Banner -->
        <div id="evacuatedPolicyBanner" class="hidden p-4 rounded-xl bg-red-950/25 border border-red-500/35 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-white">
          <div class="flex items-center gap-3">
            <div id="evacuatedBannerIconBox" class="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center text-red-400 shrink-0 font-bold">
              <svg id="evacuatedBannerIcon" class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div>
              <div id="evacuatedBannerHeader" class="font-bold text-red-400 flex flex-wrap items-center gap-2">
                <span id="evacuatedBannerTitle">Bunker Evacuated · Protection Inactive</span>
                <span id="evacuatedBannerBadge" class="text-[10px] font-mono bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 rounded-full font-bold">KEYS BURNED</span>
              </div>
              <div id="evacuatedPolicySummary" class="text-white/80 text-[11px] mt-0.5 font-mono">
                <!-- Egress status summary -->
              </div>
            </div>
          </div>
          <div id="evacuatedBannerRight" class="flex items-center gap-2 text-xs font-mono text-red-400 self-start sm:self-auto shrink-0">
            <span id="evacuatedBannerDot" class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
            <span id="evacuatedBannerRightText" class="font-bold">Vault Burned</span>
          </div>
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
                    <input type="text" id="panicNearAddr" value="" name="aegis_panicNearAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. backup-wallet.testnet" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="panicBtcAddr" value="" name="aegis_panicBtcAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. tb1q..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="panicEvmAddr" value="" name="aegis_panicEvmAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. 0x..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="panicSolAddr" value="" name="aegis_panicSolAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. Solana Base58 Address..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="heirNearAddr" value="" name="aegis_heirNearAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. family.testnet" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="heirBtcAddr" value="" name="aegis_heirBtcAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. tb1q..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="heirEvmAddr" value="" name="aegis_heirEvmAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. 0x..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
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
                    <input type="text" id="heirSolAddr" value="" name="aegis_heirSolAddr_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" placeholder="e.g. Solana Base58 Address..." class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none">
                  </div>
                </div>
              </div>
            </div>

            <!-- On-Chain E2EE Digital Testament & Sealed Box Card -->
            <div class="mt-5 p-4 rounded-xl bg-white/[0.03] border border-white/[0.08] flex-1 flex flex-col justify-between">
              <div class="flex items-center justify-between gap-2 h-7 shrink-0">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-nearGreen"></span>
                  <span class="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">E2EE Digital Testament</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <button type="button" onclick="openDecryptModal()" class="text-[10px] font-mono font-bold text-white bg-white/[0.06] hover:bg-white/[0.12] border border-white/15 px-2.5 py-0.5 rounded-full transition cursor-pointer">
                    🔓 Decrypt
                  </button>
                  <span class="text-[10px] font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2.5 py-0.5 rounded-full whitespace-nowrap">
                    🔒 X25519 / AES-256
                  </span>
                </div>
              </div>

              <div class="flex-1 flex flex-col justify-between gap-2.5 mt-3 text-xs leading-relaxed">
                <!-- Subcard 1: Plaintext Input + Optional Passphrase (Encrypted Client-Side Before RPC) -->
                <div class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-nearGreen/30 text-white transition flex flex-col justify-center space-y-1.5">
                  <div class="flex items-center justify-between font-bold text-nearGreen">
                    <div class="flex items-center gap-1.5">
                      <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" /></svg>
                      <span>Private Note to Heirs (Zero Plaintext On-Chain)</span>
                    </div>
                    <span id="memoByteCount" class="font-mono text-nearGreen text-xs font-bold">0 / 240 B</span>
                  </div>
                  <input type="text" id="heirFinalMemo" name="aegis_heirFinalMemo_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" oninput="updateMemoByteCounter(this.value)" placeholder="e.g. Hardware wallet PIN & family vault instructions..." class="w-full bg-transparent pt-0.5 text-xs sm:text-[13px] font-mono text-white placeholder:text-[#585E6A] outline-none">
                  <div class="flex items-center gap-2 pt-1 border-t border-white/[0.06]">
                    <input type="password" id="heirMemoPassphrase" name="aegis_memo_pass_noautofill" autocomplete="new-password" data-lpignore="true" data-1p-ignore="true" placeholder="Optional AES-256 passphrase (blank = auto-seal to Heir SOL key)" class="w-full bg-transparent text-[11px] font-mono text-white placeholder:text-[#585E6A] outline-none">
                    <span id="e2eeArmedStatus" class="hidden text-[10px] font-mono text-nearGreen whitespace-nowrap font-bold">🔒 Sealed</span>
                  </div>
                </div>

                <!-- Subcard 2: Cryptographic Guarantee -->
                <div class="flex-1 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06] text-[#8C929D] transition flex flex-col justify-center">
                  <div class="font-bold text-nearGreen flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>
                    <span>Client-Side X25519 / AES-256-GCM Sealed Box</span>
                  </div>
                  <p class="text-[#8C929D] text-[11px] mt-1 leading-snug">
                    Encrypted locally in your browser before touching NEAR RPC. Stored as <code>enc:x25519:...</code> or <code>enc:aes256:...</code> — unreadable on NearBlocks/Solscan; decryptable offline only by your heir.
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
              <div class="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono">
                <span class="text-[#8C929D]">Keeper Gas Escrow:</span>
                <span id="gasEscrowBalanceText" class="text-nearGreen font-bold">Sponsor Pool Ready</span>
                <button type="button" onclick="topUpGasEscrow()" class="px-2 py-0.5 rounded-md bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-nearGreen text-[10px] font-bold transition cursor-pointer">
                  +0.25 NEAR Escrow
                </button>
              </div>
            </div>

            <div class="flex items-center gap-3">
              <button id="cancelUpdateBtn" onclick="cancelAddressCooldown()" class="cancel-policy-btn hidden px-4 py-2.5 rounded-xl bg-red-950/40 hover:bg-red-950/60 text-red-400 font-mono font-bold text-xs border border-red-500/30 transition">
                Cancel & Revert Update
              </button>
              <button id="applyPolicyBtn" onclick="applyAddressPolicy()" class="apply-policy-btn hidden px-4 py-2.5 rounded-xl bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-mono font-bold text-xs transition shadow-near-glow whitespace-nowrap cursor-pointer">
                Apply Policy
              </button>
              <button id="savePolicyBtn" onclick="saveAddresses()" class="save-policy-btn bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-2.5 px-6 rounded-xl text-xs sm:text-sm transition shadow-near-glow active:scale-98 whitespace-nowrap cursor-pointer">
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
            <div class="flex items-center gap-2.5 flex-wrap">
              <span class="w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse"></span>
              <h3 class="text-base sm:text-lg font-bold text-white tracking-tight">Automated Relayer Alerts</h3>
              <span class="text-[10px] font-mono font-bold text-amber-300 bg-amber-950/40 border border-amber-500/30 px-2.5 py-0.5 rounded-full">Optional Off-Chain Webhook Preview</span>
            </div>
            <p class="text-xs sm:text-sm text-[#8C929D] mt-1">
              Optional off-chain notification targets prior to heartbeat expiry. Core Dead-Man's Switch & MPC sweeps execute 100% autonomously on-chain without relying on Telegram or email delivery.
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
                  <input id="tgUsernameInput" type="text" value="" name="aegis_tgUsernameInput_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#6E788C] outline-none" placeholder="username or Chat ID">
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
                  <input id="emailAlertInput" type="email" value="" name="aegis_emailAlertInput_noautofill" autocomplete="new-password" data-form-type="other" readonly onfocus="if(!this.disabled)this.removeAttribute('readonly');" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" class="w-full bg-transparent px-3.5 py-2.5 text-xs sm:text-sm font-mono text-white placeholder:text-[#585E6A] outline-none" placeholder="your-email@domain.com">
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

  <!-- Multichain Web3 Wallet Selector Modal -->
  <div id="multichainWalletModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card border border-white/10 rounded-3xl max-w-2xl w-full p-6 sm:p-8 space-y-6 shadow-2xl relative bg-[#0B0E15]">
      
      <!-- Modal Header -->
      <div class="flex items-start justify-between border-b border-white/[0.08] pb-5">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-[#00F5D4] animate-pulse"></span>
            <h3 class="text-lg sm:text-xl font-extrabold text-white tracking-tight">Connect Web3 Wallet</h3>
            <span class="text-[11px] font-mono text-[#00F5D4] bg-[#00F5D4]/10 border border-[#00F5D4]/30 px-2 py-0.5 rounded-full">Multichain</span>
          </div>
          <p class="text-xs text-[#8E99AD] leading-relaxed">
            Select a network and connect browser extensions to arm your bunker or link destination addresses.
          </p>
        </div>
        <button onclick="closeMultichainWalletModal()" class="w-8 h-8 rounded-full bg-white/[0.06] hover:bg-white/[0.12] text-[#8E99AD] hover:text-white flex items-center justify-center transition shrink-0 cursor-pointer">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Network Selection Tabs -->
      <div class="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
        <button onclick="filterWalletNetwork('all')" id="tabNetAll" class="network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-[#00F5D4]/20 text-[#00F5D4] border border-[#00F5D4]/40 cursor-pointer">
          <span>🌐 All</span>
        </button>
        <button onclick="filterWalletNetwork('near')" id="tabNetNear" class="network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-white/[0.04] text-[#8E99AD] hover:text-white border border-white/[0.08] cursor-pointer">
          <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
          <span>NEAR</span>
        </button>
        <button onclick="filterWalletNetwork('evm')" id="tabNetEvm" class="network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-white/[0.04] text-[#8E99AD] hover:text-white border border-white/[0.08] cursor-pointer">
          <span class="w-2 h-2 rounded-full bg-blue-400"></span>
          <span>Ethereum & EVM</span>
        </button>
        <button onclick="filterWalletNetwork('sol')" id="tabNetSol" class="network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-white/[0.04] text-[#8E99AD] hover:text-white border border-white/[0.08] cursor-pointer">
          <span class="w-2 h-2 rounded-full bg-purple-400"></span>
          <span>Solana</span>
        </button>
        <button onclick="filterWalletNetwork('btc')" id="tabNetBtc" class="network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-white/[0.04] text-[#8E99AD] hover:text-white border border-white/[0.08] cursor-pointer">
          <span class="w-2 h-2 rounded-full bg-amber-400"></span>
          <span>Bitcoin</span>
        </button>
      </div>

      <!-- Wallets Grid -->
      <div id="walletsGrid" class="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[360px] overflow-y-auto pr-1">
        <!-- Rendered dynamically -->
      </div>

      <!-- Currently Connected Wallets Summary inside Modal -->
      <div id="modalConnectedSummary" class="hidden p-3.5 rounded-2xl bg-white/[0.02] border border-white/[0.08] space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-[11px] font-mono font-bold text-[#8E99AD] uppercase tracking-wider">Connected in this Session</span>
          <button onclick="disconnectAllWallets()" class="text-[11px] font-mono text-red-400 hover:text-red-300 transition cursor-pointer">Disconnect All</button>
        </div>
        <div id="modalConnectedList" class="space-y-1.5 text-xs font-mono"></div>
      </div>

      <!-- Footer Info -->
      <div class="text-[11px] font-mono text-[#6E788C] flex items-center justify-between border-t border-white/[0.06] pt-3.5">
        <span>Smart contract on NEAR Testnet (aegis.okgoogleok.testnet)</span>
        <span class="text-[#00F5D4] font-semibold">100% Non-Custodial</span>
      </div>

    </div>
  </div>

  <!-- Panic Hold-to-Confirm Modal -->
  <div id="abortModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card border-red-500/50 rounded-3xl max-w-lg w-full p-8 space-y-6 text-center shadow-danger-glow">
      <div class="w-16 h-16 rounded-2xl bg-dangerRedMuted text-red-400 border border-red-500/35 flex items-center justify-center mx-auto shadow-danger-glow">
        <svg class="w-8 h-8" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
      </div>
      <div class="space-y-2">
        <h3 class="text-xl font-extrabold text-textWhite tracking-tight">CONFIRM EMERGENCY EVACUATION</h3>
        <p class="text-xs sm:text-sm text-textSilver leading-relaxed">
          All Bitcoin, Ethereum, Solana, and NEAR assets will be immediately swept to your designated backup addresses. The contract transitions to Evacuated state and burns the current epoch.
        </p>
      </div>

      <!-- Unallocated Funds Warning inside Panic Modal -->
      <div id="panicUnallocatedAlert" class="hidden p-4 rounded-2xl bg-amber-950/70 border border-amber-500/60 text-left space-y-2">
        <div class="flex items-center gap-2 text-amber-300 font-bold text-xs font-mono uppercase">
          <svg class="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <span>⚠️ Unprotected Bunker Funds Detected!</span>
        </div>
        <p id="panicUnallocatedText" class="text-xs text-amber-200/90 leading-relaxed font-mono"></p>
        <p class="text-[11px] text-amber-300/70 font-mono">
          Funds in networks without designated backup addresses CANNOT be evacuated and will remain stuck. Add destination addresses first!
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

      <div class="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-left flex items-start gap-2.5">
        <svg class="w-4 h-4 text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div class="text-[11px] text-amber-200/90 leading-tight">
          <strong class="text-amber-300 font-bold">One-Epoch Address:</strong> Do not save permanently in exchange whitelists. Once Panic or Inheritance triggers, this epoch is burned and repeated deposits to it cannot be recovered.
        </div>
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
        <h3 class="text-base font-extrabold text-textWhite">Webhook Target Preview</h3>
        <p class="text-xs sm:text-sm text-textSilver">
          Local off-chain alert target saved for optional relayer webhook integration:
        </p>
      </div>
      <div class="p-3.5 rounded-2xl bg-nearElevated border border-nearBorder font-mono text-xs text-nearGreen font-bold">
        <span id="modalTgTarget">@telegram_handle</span>
      </div>
      <div class="text-[11px] text-textGray">
        Failover target: <span id="modalEmailTarget" class="text-textSilver font-mono">backup@example.com</span> · On-chain sweeps run independently of off-chain alerts.
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
          <option value="demo_30s" class="text-amber-300 font-bold">⚡ 30s (Judge Demo)</option>
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
  <div id="evacMonitorModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden overflow-y-auto">
    <div class="near-card border-nearGreen/40 rounded-3xl max-w-xl w-full p-6 sm:p-7 space-y-5 shadow-near-glow max-h-[92vh] overflow-y-auto">
      <div class="flex items-center justify-between gap-3 border-b border-nearBorder pb-4">
        <div class="flex items-center gap-2.5 min-w-0">
          <span class="w-3 h-3 rounded-full bg-nearGreen radar-pulse shrink-0"></span>
          <h3 class="text-base sm:text-lg font-mono font-extrabold text-textWhite truncate">Multichain Evacuation Monitor</h3>
        </div>
        <button onclick="closeEvacMonitor()" class="w-8 h-8 rounded-full bg-nearElevated text-textGray hover:text-textWhite flex items-center justify-center shrink-0 cursor-pointer">✕</button>
      </div>

      <div class="space-y-3 font-mono text-xs">
        <!-- 1. Bitcoin -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-start sm:items-center justify-between gap-3">
          <div class="space-y-1 min-w-0 flex-1">
            <div class="text-textWhite font-bold flex items-center gap-2 flex-wrap">
              <span class="text-amber-400">₿ Bitcoin SegWit:</span> <span id="monitorBtcBal">0.0000 BTC</span>
            </div>
            <div class="text-textGray text-xs break-all">Target: <span id="monitorBtcTarget" class="text-textSilver font-mono break-all">Not configured</span></div>
            <div id="monitorBtcLink" class="text-[11px] pt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1"></div>
          </div>
          <span id="monitorBtcStatus" class="text-[#8C929D] font-bold bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center">Not configured</span>
        </div>

        <!-- 2. EVM -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-start sm:items-center justify-between gap-3">
          <div class="space-y-1 min-w-0 flex-1">
            <div class="text-textWhite font-bold flex items-center gap-2 flex-wrap">
              <span class="text-blue-400">Ξ Ethereum / Base:</span> <span id="monitorEvmBal">0.0000 ETH</span>
            </div>
            <div class="text-textGray text-xs break-all">Target: <span id="monitorEvmTarget" class="text-textSilver font-mono break-all">Not configured</span></div>
            <div id="monitorEvmLink" class="text-[11px] pt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1"></div>
          </div>
          <span id="evmTxStatusBadge" class="text-[#8C929D] font-bold bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center">
            Not configured
          </span>
        </div>

        <!-- 3. Solana -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-start sm:items-center justify-between gap-3">
          <div class="space-y-1 min-w-0 flex-1">
            <div class="text-textWhite font-bold flex items-center gap-2 flex-wrap">
              <span class="text-purple-400">◎ Solana Devnet:</span> <span id="monitorSolBal">0.0000 SOL</span>
            </div>
            <div class="text-textGray text-xs break-all">Target: <span id="monitorSolTarget" class="text-textSilver font-mono break-all">Not configured</span></div>
            <div id="monitorSolLink" class="text-[11px] pt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1"></div>
          </div>
          <span id="monitorSolStatus" class="text-[#8C929D] font-bold bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center">Not configured</span>
        </div>

        <!-- 4. NEAR Protocol -->
        <div class="p-4 rounded-2xl bg-nearElevated border border-nearBorder flex items-start sm:items-center justify-between gap-3">
          <div class="space-y-1 min-w-0 flex-1">
            <div class="text-textWhite font-bold flex items-center gap-2 flex-wrap">
              <span class="text-nearGreen">Ⓝ NEAR Protocol:</span> <span id="monitorNearBal">0.0000 NEAR</span>
            </div>
            <div class="text-textGray text-xs break-all">Target: <span id="monitorNearTarget" class="text-textSilver font-mono break-all">Not configured</span></div>
            <div id="monitorNearLink" class="text-[11px] pt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1"></div>
          </div>
          <span id="monitorNearStatus" class="text-[#8C929D] font-bold bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center">Not configured</span>
        </div>

        <!-- Stateless Cloud Keeper Control Bar -->
        <div class="p-3.5 rounded-2xl bg-nearElevated/70 border border-nearBorder flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-sans">
          <div class="min-w-0 flex-1">
            <div class="text-textSilver font-semibold flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse shrink-0"></span>
              <span class="truncate">24/7 Stateless Keeper (<span class="font-mono text-nearGreen">keeper.aegis.okgoogleok.testnet</span>)</span>
            </div>
          </div>
          <button id="syncKeeperBtn" onclick="triggerCloudKeeperSweep(true)" class="px-4 py-1.5 near-pill-btn bg-nearGreen/20 hover:bg-nearGreen/30 text-nearGreen font-bold border border-nearGreen/40 transition active:scale-98 flex items-center justify-center gap-1.5 cursor-pointer shrink-0 whitespace-nowrap">
            <span>⚡ Sync Cloud Keeper</span>
          </button>
        </div>

        <!-- 5. Fault Isolation -->
        <div class="p-3.5 rounded-2xl bg-nearBlack border border-nearBorder text-xs font-sans text-textSilver flex items-center gap-2.5">
          <svg class="w-4 h-4 text-nearGreen shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
          <span><strong>Fault Isolation active:</strong> Honeypots and reverting scam tokens are simulated via free <code>eth_call</code> and safely skipped without halting valid asset delivery.</span>
        </div>

        <!-- 6. Burned Address Whitelist Warning -->
        <div class="p-3.5 rounded-2xl bg-red-950/40 border border-red-500/40 text-xs font-sans text-red-200 flex items-start gap-2.5">
          <svg class="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <div>
            <strong class="text-red-300 font-bold block mb-0.5">⚠️ CRITICAL: Remove Old Bunker Addresses from Exchanges!</strong>
            Keys for this epoch are permanently deactivated. If you saved these addresses in exchange whitelists (Binance, Bybit, OKX) or wallet address books, delete them immediately. New deposits to burned addresses cannot be recovered.
          </div>
        </div>
      </div>

      <button onclick="closeEvacMonitor()" class="w-full bg-nearElevated hover:bg-nearHover text-textWhite font-bold py-3.5 near-pill-btn text-xs sm:text-sm transition border border-nearBorder cursor-pointer">
        Close Monitor
      </button>
    </div>
  </div>

  <!-- Offline E2EE Heir Testament Decryption Modal -->
  <div id="decryptTestamentModal" class="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
    <div class="near-card border-nearGreen/40 rounded-3xl max-w-lg w-full p-7 space-y-5 shadow-near-glow">
      <div class="flex items-center justify-between border-b border-nearBorder pb-3">
        <div class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full bg-nearGreen"></span>
          <h3 class="text-base font-mono font-extrabold text-textWhite">Decrypt E2EE Heir Testament</h3>
        </div>
        <button onclick="closeDecryptModal()" class="text-textGray hover:text-textWhite cursor-pointer">✕</button>
      </div>
      <div class="space-y-3 text-xs font-mono">
        <p class="text-[#B0B9C9] font-sans leading-relaxed">
          Decryption executes <strong>100% locally in browser memory</strong> (TweetNaCl X25519 / WebCrypto AES-256-GCM). Zero keys or plaintexts ever leave your device.
        </p>
        <div class="space-y-1">
          <label class="text-[#8C929D] uppercase text-[10px] font-bold">Ciphertext Envelope (enc:x25519:... or enc:aes256:...)</label>
          <textarea id="decryptCipherInput" rows="3" spellcheck="false" placeholder="enc:x25519:..." class="w-full rounded-xl bg-white/[0.03] border border-white/10 p-2.5 text-xs text-white font-mono outline-none focus:border-nearGreen"></textarea>
        </div>
        <div class="space-y-1">
          <label class="text-[#8C929D] uppercase text-[10px] font-bold">Heir Secret Key (for enc:x25519) OR Passphrase (for enc:aes256)</label>
          <input type="password" id="decryptSecretInput" autocomplete="new-password" data-lpignore="true" placeholder="Enter passphrase or Heir Ed25519 secret key (Base58 / JSON)" class="w-full rounded-xl bg-white/[0.03] border border-white/10 px-3 py-2.5 text-xs text-white font-mono outline-none focus:border-nearGreen">
        </div>
        <div id="decryptOutputBox" class="hidden p-3.5 rounded-xl bg-nearGreenMuted border border-nearGreen/40 text-white space-y-1">
          <div class="text-[10px] uppercase text-nearGreen font-bold">Decrypted Testament Plaintext:</div>
          <div id="decryptOutputText" class="text-sm font-mono break-words text-white"></div>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <button type="button" onclick="runLocalTestamentDecrypt()" class="flex-1 bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3 rounded-xl text-xs transition cursor-pointer">
          🔓 Decrypt Locally
        </button>
        <button type="button" onclick="closeDecryptModal()" class="px-5 py-3 rounded-xl bg-nearElevated hover:bg-nearHover text-textWhite font-bold text-xs border border-nearBorder transition cursor-pointer">
          Close
        </button>
      </div>
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
        <a href="https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet" target="_blank" rel="noopener noreferrer" class="px-3.5 py-1 rounded-full bg-nearSurface hover:bg-nearElevated border border-nearBorder text-textSilver hover:text-nearGreen transition text-xs font-mono">
          Explorer ↗
        </a>
      </div>
    </div>
  </footer>

  <!-- Application Logic -->
  <script>
    // Bunker Epochs (BIP-32 style MPC Derivations for Post-Quantum ECDSA Bunker Mode)
    const PRECOMPUTED_DERIVED_VAULTS = {
      'newapp9955.testnet': {
        0: {
          btc: 'tb1qgqgtsqnxqzexmq99tlqs76cff244ut0eupukmc',
          evm: '0x6491bB83A2285301925a3c2c827dbcA89E7545F8',
          sol: '9HJHEBcNJPrvK2CwCuNrp24SQfEZGTjmESL9y5E4cuHy',
          near: '7b0a53a06b87f699ec3c93836607ba063278cc1b0d8be4d64006deb8695ba9f0'
        },
        1: {
          btc: 'tb1q20nt4cs2ytqcdafss3gn7enhtv83f6ml48p7dc',
          evm: '0xA899e106f808eC97eb1fD34e696F229A73a80959',
          sol: 'HRXtQKBgmd7yYATKMLSvGHtLdYYenFyT8DGvfaoNcwQn',
          near: 'f403da79ef30f2d6a59238f15991a3a296c2bb42b6ee9e5030a0b9bb1cf2f3c3'
        },
        2: {
          btc: 'tb1qcca93zwj8faec7pgf2kytuz47pygj3pg2zj2v9',
          evm: '0xe9Fa7D983328f7c8981972bdc782D30B300bDC5c',
          sol: 'BEyM5qxMA4KaMGJkVJdWjk2gfdZSYi6q6kiMvGa6SYKK',
          near: '982921762ab2d2f40fb8017fd3129b05ba6afdf1acba20c682d0c0932d27309a'
        }
      },
      'okgoogleok.testnet': {
        0: {
          btc: 'tb1q3fwk3jw7qyayhun46r8gyw2ypy320s0rx9dw85',
          evm: '0x3DFF025d6A5C68D6Cf11a6a54e3d52e60E5c92bC',
          sol: 'DMHNvnt58VxCQJmUUUte5dySkCKKPFsSqL6BWa9uPwqB',
          near: 'b77e60c675f139b93e0d7f9e4dacc5b82dcb3e05579c9d247983d5977f7b0af2'
        }
      }
    };

    const VAULT_EPOCHS = [
      { epoch: '0' },
      { epoch: '1' },
      { epoch: '2' }
    ];

        let currentEpochIndex = parseInt(localStorage.getItem('aegis_bunker_epoch') || '0');
    let lastFetchedVaultInfo = null;
    let isEditing = false;
    let userHasInteractedWithInputs = false;
    const inputIds = [
      'panicNearAddr', 'panicBtcAddr', 'panicEvmAddr', 'panicSolAddr',
      'heirNearAddr', 'heirBtcAddr', 'heirEvmAddr', 'heirSolAddr', 'heirFinalMemo'
    ];
    const NEAR_RPC_URLS = [
      'https://test.rpc.fastnear.com',
      'https://rpc.testnet.fastnear.com'
    ];
    let currentRpcIndex = 0;
    const CONTRACT_ID = 'aegis.okgoogleok.testnet';

    function hasConfiguredDestinations(info = lastFetchedVaultInfo) {
      if (!info) return false;
      const b = info.backup;
      const h = info.heirs;
      const hasBackup = b && (b.btc?.trim() || b.evm?.trim() || b.sol?.trim() || b.near?.trim());
      const hasHeirs = h && (h.btc?.trim() || h.evm?.trim() || h.sol?.trim() || h.near?.trim());
      return !!(hasBackup || hasHeirs);
    }

    function maskAddressForDisplay(addr) {
      const s = String(addr || '').trim();
      if (!s || s === 'Not configured') return 'Not configured';
      if (s.endsWith('.testnet') || s.endsWith('.near')) {
        const dotIdx = s.indexOf('.');
        const prefix = s.slice(0, dotIdx);
        const suffix = s.slice(dotIdx);
        if (prefix.length <= 4) return `${prefix.slice(0, 2)}•••${suffix}`;
        return `${prefix.slice(0, 4)}•••${suffix}`;
      }
      if (s.length <= 12) return `${s.slice(0, 4)}•••`;
      return `${s.slice(0, 6)}•••${s.slice(-4)}`;
    }

    function isHeartbeatExpired(info = lastFetchedVaultInfo) {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner || !info) return false;
      if (info.state === 'Evacuated' || info.state === 'Inheritance') return true;
      if (info.state === 'Active' && hasConfiguredDestinations(info)) {
        if (typeof remainingSeconds === 'number' && remainingSeconds <= 0) return true;
        if (info.last_ping_ns) {
          try {
            const hbExpiryMs = Number(
              (BigInt(info.last_ping_ns) + BigInt(info.heartbeat_interval_ns || '0')) / 1000000n
            );
            if (Date.now() >= hbExpiryMs) return true;
          } catch (_) {}
        }
      }
      return false;
    }

    function isGracePeriodExpired(info = lastFetchedVaultInfo) {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner || !info) return false;
      if (info.state === 'Evacuated' || info.state === 'Inheritance') return true;
      if (info.state === 'Active' && hasConfiguredDestinations(info) && info.last_ping_ns) {
        try {
          const fullExpiryMs = Number(
            (BigInt(info.last_ping_ns) +
              BigInt(info.heartbeat_interval_ns || '0') +
              BigInt(info.challenge_period_ns || '0')) / 1000000n
          );
          if (Date.now() >= fullExpiryMs) return true;
        } catch (_) {}
      }
      return false;
    }

    function isVaultEvacuatedOrBurned() {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner || !lastFetchedVaultInfo) return false;
      return lastFetchedVaultInfo.state === 'Evacuated' || lastFetchedVaultInfo.state === 'Inheritance';
    }

    function isAddressDisplayLocked(info = lastFetchedVaultInfo) {
      return isVaultEvacuatedOrBurned() || isHeartbeatExpired(info) || isGracePeriodExpired(info);
    }

    function isInheritanceState(info = lastFetchedVaultInfo) {
      if (!info) return false;
      return info.state === 'Inheritance' || (info.state === 'Active' && isHeartbeatExpired(info));
    }

    function shouldShowUnconfiguredBanner(info = lastFetchedVaultInfo) {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner) return false;
      if (isAddressDisplayLocked(info)) return false;
      if (hasConfiguredDestinations(info)) return false;
      if (info && info.pending_policy) return false;
      if (userHasInteractedWithInputs || isEditing) return false;
      const hasAnyInput = inputIds.some(id => {
        const el = document.getElementById(id);
        return el && el.value && el.value.trim().length > 0;
      });
      if (hasAnyInput) return false;
      return true;
    }

    // Live On-Chain State Fetcher via NEAR JSON-RPC (FastNEAR with Failover)
    async function fetchLiveContractState() {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner) {
        lastFetchedVaultInfo = null;
        syncUIWithOnChainState(null, null);
        return null;
      }
      
      for (let attempt = 0; attempt < NEAR_RPC_URLS.length; attempt++) {
        const rpcUrl = NEAR_RPC_URLS[(currentRpcIndex + attempt) % NEAR_RPC_URLS.length];
        try {
          const response = await fetch(rpcUrl, {
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
                args_base64: btoa(JSON.stringify({ account_id: currentSigner }))
              }
            })
          });
          const data = await response.json();
          if (data.result && data.result.result) {
            currentRpcIndex = (currentRpcIndex + attempt) % NEAR_RPC_URLS.length;
            const decoded = new TextDecoder().decode(new Uint8Array(data.result.result));
            const vaultInfo = JSON.parse(decoded);
            console.log(`📡 [Aegis] Live NEAR RPC State fetched from ${rpcUrl} for ${currentSigner}:`, vaultInfo);
            syncUIWithOnChainState(vaultInfo, currentSigner);
            return vaultInfo;
          } else if (data.result && (data.result.error || data.result.result === null)) {
            // Explicit null response (account has not configured a vault yet)
            currentRpcIndex = (currentRpcIndex + attempt) % NEAR_RPC_URLS.length;
            syncUIWithOnChainState(null, currentSigner);
            return null;
          } else {
            console.warn(`[Aegis] RPC notice from ${rpcUrl}:`, data.error || 'Empty response');
          }
        } catch (err) {
          console.warn(`[Aegis] RPC error from ${rpcUrl}:`, err.message);
        }
      }
      // If network errors occur, preserve existing state to prevent flickering
    }

    function escapeHtml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function sanitizeExplorerUrl(url) {
      try {
        const parsed = new URL(String(url || '').trim());
        const allowedHosts = [
          'mempool.space',
          'sepolia.etherscan.io',
          'etherscan.io',
          'solscan.io',
          'testnet.nearblocks.io',
          'nearblocks.io'
        ];
        if (parsed.protocol === 'https:' && allowedHosts.includes(parsed.hostname)) {
          return escapeHtml(parsed.href);
        }
      } catch (_) {}
      return '#';
    }

    function syncUIWithOnChainState(info, signerAccount) {
      if (!signerAccount) {
        lastFetchedVaultInfo = null;
        currentEpochIndex = 0;
        remainingSeconds = 0;
        userHasInteractedWithInputs = false;
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.value = '';
            el.disabled = false;
          }
        });
        const activeBanner = document.getElementById('activePolicyBanner');
        if (activeBanner) activeBanner.classList.add('hidden');
        const evacuatedBanner = document.getElementById('evacuatedPolicyBanner');
        if (evacuatedBanner) evacuatedBanner.classList.add('hidden');
        const unconfigBanner = document.getElementById('unconfiguredBanner');
        if (unconfigBanner) { unconfigBanner.classList.add('hidden'); unconfigBanner.classList.remove('flex'); }
        const burnedBanner = document.getElementById('bunkerBurnedBanner');
        if (burnedBanner) burnedBanner.classList.add('hidden');
        const unarmedBanner = document.getElementById('bunkerUnarmedBanner');
        if (unarmedBanner) unarmedBanner.classList.add('hidden');
        const unallocDep = document.getElementById('unallocatedDepositAlert');
        if (unallocDep) { unallocDep.classList.add('hidden'); unallocDep.classList.remove('flex'); }
        const unallocPol = document.getElementById('unallocatedPolicyAlert');
        if (unallocPol) { unallocPol.classList.add('hidden'); unallocPol.classList.remove('flex'); }
        const tabRescue = document.getElementById('tab-rescue');
        if (tabRescue) tabRescue.innerText = '1. Rescue & Inheritance (Destinations)';

        // Reset balances to zero
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

        if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">BTC</span>';
        if (btcUsdEl) btcUsdEl.innerText = '≈ 0.00 USD';
        if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">ETH</span>';
        if (evmUsdEl) evmUsdEl.innerText = '≈ 0.00 USD';
        if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">SOL</span>';
        if (solUsdEl) solUsdEl.innerText = '≈ 0.00 USD';
        if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span>';
        if (nearUsdEl) nearUsdEl.innerText = '≈ 0.00 USD';
        if (syncBadge) syncBadge.innerText = 'Connect Wallet to Sync';
        if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-white/20';

        updateSaveButtonState(null);
        renderBunkerAddresses();
        updateCountdownDisplay();
        return;
      }

      if (!info || info.state === 'Unconfigured') {
        const epoch = (info && typeof info.epoch === 'number') ? info.epoch : 0;
        lastFetchedVaultInfo = info || {
          state: 'Unconfigured',
          epoch: epoch,
          backup: { btc: '', evm: '', sol: '', near: null },
          heirs: { btc: '', evm: '', sol: '', near: null },
          pending_policy: null,
          last_ping_ns: 0,
          heartbeat_interval_ns: 7776000000000000
        };
        currentEpochIndex = epoch;
        remainingSeconds = 0;

        // Ensure all destination inputs are enabled and ready for user input
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.disabled = false;
            if (!userHasInteractedWithInputs && !el.value) el.value = '';
          }
        });

        const activeBanner = document.getElementById('activePolicyBanner');
        if (activeBanner) activeBanner.classList.add('hidden');
        const unconfigBanner = document.getElementById('unconfiguredBanner');
        if (unconfigBanner) { unconfigBanner.classList.add('hidden'); unconfigBanner.classList.remove('flex'); }
        const burnedBanner = document.getElementById('bunkerBurnedBanner');
        if (burnedBanner) burnedBanner.classList.add('hidden');
        const evacuatedBanner = document.getElementById('evacuatedPolicyBanner');
        if (evacuatedBanner) evacuatedBanner.classList.add('hidden');
        const unarmedBanner = document.getElementById('bunkerUnarmedBanner');
        if (unarmedBanner) unarmedBanner.classList.remove('hidden');
        const unallocDep = document.getElementById('unallocatedDepositAlert');
        if (unallocDep) { unallocDep.classList.add('hidden'); unallocDep.classList.remove('flex'); }
        const unallocPol = document.getElementById('unallocatedPolicyAlert');
        if (unallocPol) { unallocPol.classList.add('hidden'); unallocPol.classList.remove('flex'); }

        const tabRescue = document.getElementById('tab-rescue');
        if (tabRescue) tabRescue.innerText = '1. Rescue & Inheritance (Destinations)';

        // Ensure balances are clean 0.0000 for unconfigured vaults
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

        if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">BTC</span>';
        if (btcUsdEl) btcUsdEl.innerText = '≈ 0.00 USD';
        if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">ETH</span>';
        if (evmUsdEl) evmUsdEl.innerText = '≈ 0.00 USD';
        if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">SOL</span>';
        if (solUsdEl) solUsdEl.innerText = '≈ 0.00 USD';
        if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span>';
        if (nearUsdEl) nearUsdEl.innerText = '≈ 0.00 USD';
        if (syncBadge) syncBadge.innerText = 'Vault Unarmed';
        if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-white/20';

        updateSaveButtonState(lastFetchedVaultInfo);
        renderBunkerAddresses();
        updateCountdownDisplay();
        return;
      }

      lastFetchedVaultInfo = info;

      // 1. Sync epoch & bunker addresses
      if (typeof info.epoch === 'number') {
        currentEpochIndex = info.epoch;
      }

      // Check if Vault is in Evacuated or Inheritance state
      if (info.state === 'Evacuated' || info.state === 'Inheritance') {
        remainingSeconds = 0;
      } else if (info.state === 'Unconfigured' || !hasConfiguredDestinations(info)) {
        remainingSeconds = 0;
      }

      renderBunkerAddresses();

      // 2. Real on-chain countdown timer derived from smart contract + local signed heartbeat
      if (info.state === 'Active' && hasConfiguredDestinations(info) && info.last_ping_ns && info.heartbeat_interval_ns) {
        localStorage.setItem('aegis_last_ping_ns', info.last_ping_ns.toString());
        localStorage.setItem('aegis_heartbeat_interval_ns', info.heartbeat_interval_ns.toString());

        const effectiveLastPingNs = BigInt(info.last_ping_ns);

        const expireNs = effectiveLastPingNs + BigInt(info.heartbeat_interval_ns);
        const nowNs = BigInt(info.current_time_ns || (Date.now() * 1000000));
        const diffNs = expireNs > nowNs ? (expireNs - nowNs) : 0n;
        remainingSeconds = Number(diffNs / 1000000000n);
        MAX_SECONDS = Number(BigInt(info.heartbeat_interval_ns) / 1000000000n);
        updateCountdownDisplay();

        // Sync dropdowns with real on-chain values (unless user is actively editing)
        if (!userHasInteractedWithInputs && !isEditing) {
          const totalHbNs = BigInt(info.heartbeat_interval_ns);
          const inactSelect = document.getElementById('inactivitySelect');
          if (inactSelect) {
            if (totalHbNs <= 120000000000n) {
              inactSelect.value = 'demo_120s';
              localStorage.setItem('aegis_inactivity_days', 'demo_120s');
            } else {
              const inactDays = Math.round(Number(totalHbNs / 86400000000000n));
              if ([30, 90, 180, 365].includes(inactDays)) {
                inactSelect.value = inactDays.toString();
                localStorage.setItem('aegis_inactivity_days', inactDays.toString());
              }
            }
          }

          const totalCpNs = BigInt(info.challenge_period_ns || 604800000000000n);
          const graceSelect = document.getElementById('graceSelect');
          const modalGrace = document.getElementById('modalGraceSelect');
          if (totalCpNs <= 30000000000n) {
            if (graceSelect) graceSelect.value = 'demo_30s';
            if (modalGrace) modalGrace.value = 'demo_30s';
            localStorage.setItem('aegis_grace_days', 'demo_30s');
          } else {
            const graceDays = Math.round(Number(totalCpNs / 86400000000000n));
            if ([3, 7, 14, 30].includes(graceDays)) {
              if (graceSelect) graceSelect.value = graceDays.toString();
              if (modalGrace) modalGrace.value = graceDays.toString();
              localStorage.setItem('aegis_grace_days', graceDays.toString());
            }
          }
        }
      } else {
        remainingSeconds = 0;
        updateCountdownDisplay();
      }

      const unconfiguredBanner = document.getElementById('unconfiguredBanner');
      // 3. Sync destinations directly from on-chain storage
      let hasActiveAddresses = false;
      const isEvacuated = Boolean(info && (info.state === 'Evacuated' || info.state === 'Inheritance'));
      const isGraceExp = isGracePeriodExpired(info);
      const isHbExp = isHeartbeatExpired(info);
      const isAddrLocked = isEvacuated || isGraceExp || isHbExp;

      if (isAddrLocked) {
        // Vault is evacuated, inherited, or timer expired: NEVER populate or display addresses in inputs
        const defaultPlaceholders = {
          panicNearAddr: 'e.g. coldvault.testnet',
          panicBtcAddr: 'e.g. tb1q...',
          panicEvmAddr: 'e.g. 0x...',
          panicSolAddr: 'e.g. Base58 Solana address',
          heirNearAddr: 'e.g. family.testnet',
          heirBtcAddr: 'e.g. tb1q...',
          heirEvmAddr: 'e.g. 0x...',
          heirSolAddr: 'e.g. Base58 Solana address',
          heirFinalMemo: 'Write final instructions or message for your family...'
        };
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.value = '';
            el.disabled = true;
            el.placeholder = (isEvacuated || isGraceExp)
              ? '🔒 Hidden — Bunker epoch closed (Rotate bunker to set new addresses)'
              : '🔒 Hidden during Grace Buffer — Check-in to unlock';
            el.dataset.defaultPlaceholder = el.dataset.defaultPlaceholder || defaultPlaceholders[id] || '';
          }
        });
        const passEl = document.getElementById('heirMemoPassphrase');
        if (passEl) passEl.value = '';
        const e2eeBadge = document.getElementById('e2eeArmedStatus');
        if (e2eeBadge) e2eeBadge.classList.add('hidden');
        if ((isEvacuated || isGraceExp) && signerAccount) {
          localStorage.removeItem('aegis_addresses_' + signerAccount);
        }
      } else if (info.state === 'Unconfigured') {
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.disabled = false;
            if (el.dataset.defaultPlaceholder) el.placeholder = el.dataset.defaultPlaceholder;
            if (!userHasInteractedWithInputs && !el.value) el.value = '';
          }
        });
      } else {
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.disabled = false;
            if (el.dataset.defaultPlaceholder) el.placeholder = el.dataset.defaultPlaceholder;
          }
        });
        if (info.backup) {
          const pNear = document.getElementById('panicNearAddr');
          const pBtc = document.getElementById('panicBtcAddr');
          const pEvm = document.getElementById('panicEvmAddr');
          const pSol = document.getElementById('panicSolAddr');
          if (!userHasInteractedWithInputs) {
            if (pNear && !pNear.value) pNear.value = info.backup.near || '';
            if (pBtc && !pBtc.value) pBtc.value = info.backup.btc || '';
            if (pEvm && !pEvm.value) pEvm.value = info.backup.evm || '';
            if (pSol && !pSol.value) pSol.value = info.backup.sol || '';
          }
          if (info.backup.btc || info.backup.evm || info.backup.sol || info.backup.near) hasActiveAddresses = true;
        }
        if (info.heirs) {
          const hNear = document.getElementById('heirNearAddr');
          const hBtc = document.getElementById('heirBtcAddr');
          const hEvm = document.getElementById('heirEvmAddr');
          const hSol = document.getElementById('heirSolAddr');
          if (!userHasInteractedWithInputs) {
            if (hNear && !hNear.value) hNear.value = info.heirs.near || '';
            if (hBtc && !hBtc.value) hBtc.value = info.heirs.btc || '';
            if (hEvm && !hEvm.value) hEvm.value = info.heirs.evm || '';
            if (hSol && !hSol.value) hSol.value = info.heirs.sol || '';
          }
          if (info.heirs.btc || info.heirs.evm || info.heirs.sol || info.heirs.near) hasActiveAddresses = true;
          const hMemo = document.getElementById('heirFinalMemo');
          const e2eeBadge = document.getElementById('e2eeArmedStatus');
          window.currentEncryptedOnChainMemo = info.heir_memo || null;
          if (info.heir_memo && info.heir_memo.startsWith('enc:')) {
            if (e2eeBadge) {
              e2eeBadge.classList.remove('hidden');
              e2eeBadge.innerText = info.heir_memo.startsWith('enc:x25519:') ? '🔒 X25519 Armed' : '🔒 AES-256 Armed';
            }
            if (!userHasInteractedWithInputs && hMemo && !hMemo.value) {
              hMemo.placeholder = '🔒 E2EE Testament armed on-chain (click Decrypt to verify, or type to replace)';
            }
          } else {
            if (e2eeBadge) e2eeBadge.classList.add('hidden');
            if (!userHasInteractedWithInputs && hMemo && !hMemo.value && info.heir_memo) {
              hMemo.value = info.heir_memo;
              updateMemoByteCounter(hMemo.value);
            }
          }
        }
      }

      // Save latest state & update visual indication
      lastFetchedVaultInfo = info;
      const escrowEl = document.getElementById('gasEscrowBalanceText');
      if (escrowEl && info) {
        const rawEscrow = BigInt(info.gas_escrow_yocto || '0');
        const nearFloat = Number(rawEscrow / 100000000000000000000n) / 10000;
        escrowEl.innerText = rawEscrow > 0n
          ? `${nearFloat.toFixed(3)} NEAR (Personal Escrow)`
          : '0.000 NEAR (Sponsor Pool Active)';
      }
      const activeBanner = document.getElementById('activePolicyBanner');
      const activeSummary = document.getElementById('activePolicySummary');
      const evacuatedBanner = document.getElementById('evacuatedPolicyBanner');
      const evacuatedSummary = document.getElementById('evacuatedPolicySummary');
      const tabRescue = document.getElementById('tab-rescue');
      const badge = document.getElementById('addressStatusBadge');
      const dot = document.getElementById('addressStatusDot');

      if (isAddrLocked) {
        const isInheritance = Boolean(info && (info.state === 'Inheritance' || (info.state === 'Active' && isGraceExp)));
        const isGraceOnly = Boolean(!isEvacuated && !isGraceExp && isHbExp);
        const isEpochSwept = Boolean(info && info.is_epoch_swept);
        if (activeBanner) activeBanner.classList.add('hidden');
        if (activeSummary) activeSummary.innerHTML = '';
        if (unconfiguredBanner) unconfiguredBanner.classList.add('hidden');
        if (evacuatedBanner) {
          evacuatedBanner.classList.remove('hidden');
          const bTitle = document.getElementById('evacuatedBannerTitle');
          const bBadge = document.getElementById('evacuatedBannerBadge');
          const bHeader = document.getElementById('evacuatedBannerHeader');
          const bRight = document.getElementById('evacuatedBannerRight');
          const bRightText = document.getElementById('evacuatedBannerRightText');
          const bDot = document.getElementById('evacuatedBannerDot');
          const bIconBox = document.getElementById('evacuatedBannerIconBox');
          const bIcon = document.getElementById('evacuatedBannerIcon');

          if (isGraceOnly) {
            evacuatedBanner.className = 'p-4 rounded-xl bg-amber-950/25 border border-amber-500/35 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-white';
            if (bHeader) bHeader.className = 'font-bold text-amber-400 flex flex-wrap items-center gap-2';
            if (bTitle) bTitle.innerText = 'Heartbeat Expired · Grace Buffer Active';
            if (bBadge) {
              bBadge.innerText = 'ADDRESSES HIDDEN';
              bBadge.className = 'text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded-full font-bold';
            }
            if (bRight) bRight.className = 'flex items-center gap-2 text-xs font-mono text-amber-400 self-start sm:self-auto shrink-0';
            if (bDot) bDot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-pulse';
            if (bRightText) bRightText.innerText = 'Grace Window';
            if (bIconBox) bIconBox.className = 'w-8 h-8 rounded-lg bg-amber-500/20 flex items-center justify-center text-amber-400 shrink-0 font-bold';
            if (bIcon) bIcon.setAttribute('class', 'w-4 h-4 text-amber-400');
            if (evacuatedSummary) {
              evacuatedSummary.innerHTML = 'Heartbeat timer expired. All deposit and destination addresses are locked and hidden during the Grace Buffer. Click <strong>I\'M ALIVE (Recover & Reset)</strong> to restore active status.';
            }
          } else if (isInheritance) {
            evacuatedBanner.className = 'p-4 rounded-xl bg-purple-950/25 border border-purple-500/35 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-white';
            if (bHeader) bHeader.className = 'font-bold text-purple-300 flex flex-wrap items-center gap-2';
            if (bTitle) bTitle.innerText = 'Bunker Inherited · Epoch Closed';
            if (bBadge) {
              bBadge.innerText = 'EPOCH CLOSED';
              bBadge.className = 'text-[10px] font-mono bg-purple-500/20 text-purple-200 border border-purple-500/40 px-2 py-0.5 rounded-full font-bold';
            }
            if (bRight) bRight.className = 'flex items-center gap-2 text-xs font-mono text-purple-300 self-start sm:self-auto shrink-0';
            if (bDot) bDot.className = 'w-2 h-2 rounded-full bg-purple-400 animate-pulse';
            if (bRightText) bRightText.innerText = isEpochSwept ? 'Transferred to Heirs' : 'Sweep in Progress';
            if (bIconBox) bIconBox.className = 'w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center text-purple-300 shrink-0 font-bold';
            if (bIcon) bIcon.setAttribute('class', 'w-4 h-4 text-purple-300');
            if (evacuatedSummary) {
              evacuatedSummary.innerHTML = isEpochSwept
                ? 'All bunker assets autonomously transferred to designated family heirs. Destination and deposit addresses are permanently hidden. Click <strong>Activate Clean Bunker</strong> to advance to next epoch.'
                : 'Autonomous inheritance triggered. Cloud Keeper sweep is in progress and all addresses are hidden. Once sweep completes, click <strong>Activate Clean Bunker</strong> to advance to next epoch.';
            }
          } else {
            evacuatedBanner.className = 'p-4 rounded-xl bg-red-950/25 border border-red-500/35 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-white';
            if (bHeader) bHeader.className = 'font-bold text-red-400 flex flex-wrap items-center gap-2';
            if (bTitle) bTitle.innerText = 'Bunker Evacuated · Protection Inactive';
            if (bBadge) {
              bBadge.innerText = 'KEYS BURNED';
              bBadge.className = 'text-[10px] font-mono bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 rounded-full font-bold';
            }
            if (bRight) bRight.className = 'flex items-center gap-2 text-xs font-mono text-red-400 self-start sm:self-auto shrink-0';
            if (bDot) bDot.className = 'w-2 h-2 rounded-full bg-red-500 animate-pulse';
            if (bRightText) bRightText.innerText = 'Vault Burned';
            if (bIconBox) bIconBox.className = 'w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center text-red-400 shrink-0 font-bold';
            if (bIcon) bIcon.setAttribute('class', 'w-4 h-4 text-red-400');
            if (evacuatedSummary) {
              evacuatedSummary.innerHTML = isEpochSwept
                ? 'All bunker assets swept. Active epoch keys permanently burned and addresses hidden. Click <strong>Activate Clean Bunker</strong> to advance to next epoch.'
                : 'Emergency panic confirmed on-chain. Cloud Keeper multichain sweep is in progress. Click <strong>Activate Clean Bunker</strong> once sweep completes.';
            }
          }
        }
        if (tabRescue) {
          tabRescue.innerHTML = isGraceOnly
            ? `1. Rescue & Inheritance <span class="ml-1.5 px-2 py-0.5 text-[10px] bg-amber-950/60 text-amber-300 border border-amber-500/40 rounded-full font-bold">GRACE</span>`
            : (isInheritance
                ? `1. Rescue & Inheritance <span class="ml-1.5 px-2 py-0.5 text-[10px] bg-purple-950/60 text-purple-300 border border-purple-500/40 rounded-full font-bold">INHERITED</span>`
                : `1. Rescue & Inheritance <span class="ml-1.5 px-2 py-0.5 text-[10px] bg-red-950/60 text-red-400 border border-red-500/40 rounded-full font-bold">EVACUATED</span>`);
        }
        if (badge) {
          badge.innerText = isGraceOnly
            ? 'Grace Buffer (Addresses Locked)'
            : (isInheritance
                ? (isEpochSwept ? 'Inherited (Transferred to Heirs)' : 'Inheritance (Sweep in Progress)')
                : (isEpochSwept ? 'Evacuated (Keys Burned)' : 'Evacuating (Sweep in Progress)'));
          badge.className = isGraceOnly
            ? 'text-amber-400 font-mono font-bold'
            : (isInheritance ? 'text-purple-400 font-mono font-bold' : 'text-red-400 font-mono font-bold');
        }
        if (dot) {
          dot.className = isGraceOnly
            ? 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse'
            : (isInheritance ? 'w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse' : 'w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse');
        }

        // Auto-open monitor modal on first detection of on-chain Evacuated / Inheritance state
        if (isEvacuated) {
          const sweepNotifKey = `aegis_notified_sweep_${signerAccount}_${info.epoch}_${info.state}`;
          if (!sessionStorage.getItem(sweepNotifKey)) {
            sessionStorage.setItem(sweepNotifKey, '1');
            showToast(isInheritance ? '⚖️ INHERITANCE EXECUTED: Assets transferred to heirs!' : '🚨 VAULT EVACUATED: Emergency sweep confirmed.', !isInheritance);
            openEvacMonitor();
          }
        }
      } else if (hasActiveAddresses) {
        if (evacuatedBanner) evacuatedBanner.classList.add('hidden');
        if (unconfiguredBanner) unconfiguredBanner.classList.add('hidden');
        if (activeBanner) {
          activeBanner.classList.remove('hidden');
          let parts = [];
          if (info.backup?.near) parts.push(`Backup NEAR: <strong class="text-white">${escapeHtml(info.backup.near)}</strong>`);
          if (info.backup?.btc) parts.push(`Backup BTC: <strong class="text-white">${escapeHtml(info.backup.btc.slice(0, 10))}...</strong>`);
          if (info.backup?.evm) parts.push(`Backup EVM: <strong class="text-white">${escapeHtml(info.backup.evm.slice(0, 8))}...</strong>`);
          if (info.backup?.sol) parts.push(`Backup SOL: <strong class="text-white">${escapeHtml(info.backup.sol.slice(0, 8))}...</strong>`);
          if (info.heirs?.near) parts.push(`Heir NEAR: <strong class="text-white">${escapeHtml(info.heirs.near)}</strong>`);
          if (info.heirs?.btc) parts.push(`Heir BTC: <strong class="text-white">${escapeHtml(info.heirs.btc.slice(0, 10))}...</strong>`);
          if (info.heirs?.evm) parts.push(`Heir EVM: <strong class="text-white">${escapeHtml(info.heirs.evm.slice(0, 8))}...</strong>`);
          if (info.heirs?.sol) parts.push(`Heir SOL: <strong class="text-white">${escapeHtml(info.heirs.sol.slice(0, 8))}...</strong>`);
          if (activeSummary) activeSummary.innerHTML = parts.join(' · ') || 'Active on-chain destinations loaded.';
        }
        if (tabRescue) {
          tabRescue.innerHTML = `1. Rescue & Inheritance <span class="ml-1.5 px-2 py-0.5 text-[10px] bg-nearGreen text-nearBlack rounded-full font-bold">ARMED</span>`;
        }
        if (badge && !info.pending_policy) {
          badge.innerText = 'Active & Enforced';
          badge.className = 'text-nearGreen font-mono font-bold';
        }
        if (dot && !info.pending_policy) dot.className = 'w-2.5 h-2.5 rounded-full bg-nearGreen shadow-near-glow';
      } else {
        if (activeBanner) activeBanner.classList.add('hidden');
        if (evacuatedBanner) evacuatedBanner.classList.add('hidden');
        if (unconfiguredBanner) {
          if (shouldShowUnconfiguredBanner(info)) { unconfiguredBanner.classList.remove('hidden'); unconfiguredBanner.classList.add('flex'); }
          else { unconfiguredBanner.classList.add('hidden'); unconfiguredBanner.classList.remove('flex'); }
        }
        if (tabRescue) {
          tabRescue.innerText = `1. Rescue & Inheritance (Destinations)`;
        }
        if (badge && !info.pending_policy) {
          badge.innerText = 'Unconfigured';
          badge.className = 'text-amber-300 font-mono font-bold';
        }
        if (dot && !info.pending_policy) dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400';
      }

      updateSaveButtonState(info);
      checkUnallocatedFunds();

      // Check current input values if user has typed
      const anyInputFilled = inputIds.some(id => {
        const el = document.getElementById(id);
        return el && el.value && el.value.trim().length > 0;
      });
      const isConfigured = hasActiveAddresses || anyInputFilled;

      // 4. Real on-chain Timelock & Pending Policy status
      const cooldownAlert = document.getElementById('cooldownAlertBanner');
      const saveBtns = document.querySelectorAll('.save-policy-btn');
      const cancelBtns = document.querySelectorAll('.cancel-policy-btn');
      const applyBtns = document.querySelectorAll('.apply-policy-btn');

      if (info.pending_policy) {
        const effectiveNs = BigInt(info.pending_policy.effective_at_ns);
        const nowNs = BigInt(info.current_time_ns || (Date.now() * 1000000));
        const secLeft = Number(effectiveNs > nowNs ? (effectiveNs - nowNs) / 1000000000n : 0n);
        const hoursLeft = Math.floor(secLeft / 3600);
        const minsLeft = Math.floor((secLeft % 3600) / 60);

        if (unconfiguredBanner) unconfiguredBanner.classList.add('hidden');
        if (badge) {
          badge.innerText = secLeft > 0 ? `72h Timelock (${hoursLeft}h ${minsLeft}m left)` : 'Timelock Elapsed';
          badge.className = 'text-amber-300 font-mono font-bold';
        }
        if (dot) dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
        if (cooldownAlert) {
          cooldownAlert.classList.remove('hidden');
          const titleEl = cooldownAlert.querySelector('.font-mono.font-bold');
          if (titleEl) {
            titleEl.innerText = secLeft > 0
              ? `72-Hour Security Timelock in Progress (${hoursLeft}h ${minsLeft}m remaining)`
              : 'Security Timelock Elapsed — Ready to Apply On-Chain!';
          }
        }

        // Top Heartbeat Timelock Notice
        const hbNotice = document.getElementById('heartbeatTimelockNotice');
        const hbText = document.getElementById('heartbeatTimelockText');
        if (hbNotice && hbText) {
          hbNotice.classList.remove('hidden');
          hbText.innerText = secLeft > 0
            ? `72h Timelock Active (${hoursLeft}h ${minsLeft}m left)`
            : '72h Timelock Elapsed (Ready to Apply)';
        }

        cancelBtns.forEach(b => b.classList.remove('hidden'));
        saveBtns.forEach(b => b.classList.add('hidden'));

        if (secLeft <= 0) {
          applyBtns.forEach(b => b.classList.remove('hidden'));
        } else {
          applyBtns.forEach(b => b.classList.add('hidden'));
        }
      } else {
        if (cooldownAlert) cooldownAlert.classList.add('hidden');
        const hbNotice = document.getElementById('heartbeatTimelockNotice');
        if (hbNotice) hbNotice.classList.add('hidden');
        cancelBtns.forEach(b => b.classList.add('hidden'));
        applyBtns.forEach(b => b.classList.add('hidden'));
        saveBtns.forEach(b => {
          b.classList.remove('hidden');
          b.disabled = false;
        });

        if (unconfiguredBanner) {
          if (shouldShowUnconfiguredBanner(lastFetchedVaultInfo)) { unconfiguredBanner.classList.remove('hidden'); unconfiguredBanner.classList.add('flex'); }
          else { unconfiguredBanner.classList.add('hidden'); unconfiguredBanner.classList.remove('flex'); }
        }
        if (badge) {
          badge.innerText = isConfigured ? 'Active & Enforced' : 'Unconfigured';
          badge.className = isConfigured ? 'text-nearGreen font-mono font-bold' : 'text-amber-300 font-mono font-bold';
        }
        if (dot) dot.className = isConfigured ? 'w-2.5 h-2.5 rounded-full bg-nearGreen shadow-near-glow' : 'w-2.5 h-2.5 rounded-full bg-amber-400';
      }

      if (isVaultEvacuatedOrBurned()) {
        const banner = document.getElementById('bunkerBurnedBanner');
        if (banner) banner.classList.remove('hidden');
      } else {
        const banner = document.getElementById('bunkerBurnedBanner');
        if (banner) banner.classList.add('hidden');
      }
      updateCountdownDisplay();
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

    // Multichain Web3 Wallet Definitions & Integrations
    const WALLET_DEFINITIONS = [
      {
        id: 'meteor',
        network: 'near',
        name: 'Meteor Wallet',
        desc: 'Browser Extension & Web Wallet',
        chainTag: 'NEAR',
        tagColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        icon: '<svg class="w-6 h-6 text-emerald-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L14.4 7.2L20 8L16 12L17 17.6L12 15L7 17.6L8 12L4 8L9.6 7.2L12 2Z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.meteorWallet),
        connect: () => connectNearDirect('meteor')
      },
      {
        id: 'here',
        network: 'near',
        name: 'HERE Wallet',
        desc: 'Mobile App & Telegram Web3',
        chainTag: 'NEAR',
        tagColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        icon: '<svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="currentColor"><path d="M4 6h16v12H4z"/></svg>',
        isInstalled: () => false,
        connect: () => connectNearDirect('here')
      },
      {
        id: 'nightly',
        network: 'near',
        name: 'Nightly',
        desc: 'Multichain Browser Extension',
        chainTag: 'NEAR / Multi',
        tagColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        icon: '<svg class="w-6 h-6 text-purple-400" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.nightly?.near),
        connect: () => connectNearDirect('nightly')
      },
      {
        id: 'sender',
        network: 'near',
        name: 'Sender Wallet',
        desc: 'NEAR Browser Extension',
        chainTag: 'NEAR',
        tagColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        icon: '<svg class="w-6 h-6 text-cyan-400" viewBox="0 0 24 24" fill="currentColor"><path d="M2 12l20-9-9 20-3-8-8-3z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.near),
        connect: () => connectNearDirect('sender')
      },
      {
        id: 'bitte',
        network: 'near',
        name: 'Bitte Wallet',
        desc: 'Web3 AI Agent Wallet',
        chainTag: 'NEAR',
        tagColor: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
        icon: '<svg class="w-6 h-6 text-textSilver" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3 7h7l-5.5 4.5 2 7L12 16l-6.5 4.5 2-7L2 9h7z"/></svg>',
        isInstalled: () => false,
        connect: () => connectNearDirect('bitte')
      },
      {
        id: 'metamask',
        network: 'evm',
        name: 'MetaMask',
        desc: 'Ethereum & EVM Browser Extension',
        chainTag: 'Ethereum / EVM',
        tagColor: 'text-blue-400 bg-blue-950/40 border-blue-500/30',
        icon: '<svg class="w-6 h-6 text-orange-400" viewBox="0 0 32 32" fill="currentColor"><path d="M29.5 2L17.5 10.8 19.8 5.4zM2.5 2l11.9 8.9L12.2 5.4zM25.7 22.8l-3.3 5 7.1 2zM2.5 29.8l7.1-2-3.3-5.1z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.ethereum?.isMetaMask && !window.ethereum?.isRabby),
        connect: () => connectEvmDirect('metamask')
      },
      {
        id: 'rabby',
        network: 'evm',
        name: 'Rabby Wallet',
        desc: 'DeFi EVM Browser Extension',
        chainTag: 'Ethereum / EVM',
        tagColor: 'text-blue-400 bg-blue-950/40 border-blue-500/30',
        icon: '<svg class="w-6 h-6 text-blue-400" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.ethereum?.isRabby),
        connect: () => connectEvmDirect('rabby')
      },
      {
        id: 'coinbase',
        network: 'evm',
        name: 'Coinbase Wallet',
        desc: 'EVM Extension & Smart Wallet',
        chainTag: 'Ethereum / Base',
        tagColor: 'text-blue-400 bg-blue-950/40 border-blue-500/30',
        icon: '<svg class="w-6 h-6 text-blue-500" viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="18" height="18" rx="4"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.ethereum?.isCoinbaseWallet),
        connect: () => connectEvmDirect('coinbase')
      },
      {
        id: 'evm_generic',
        network: 'evm',
        name: 'Injected EVM Wallet',
        desc: 'Standard Web3 Extension (window.ethereum)',
        chainTag: 'EVM Compatible',
        tagColor: 'text-blue-400 bg-blue-950/40 border-blue-500/30',
        icon: '<svg class="w-6 h-6 text-indigo-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L4 12l8 10 8-10z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.ethereum),
        connect: () => connectEvmDirect('generic')
      },
      {
        id: 'phantom',
        network: 'sol',
        name: 'Phantom',
        desc: 'Solana & Multichain Browser Extension',
        chainTag: 'Solana',
        tagColor: 'text-purple-400 bg-purple-950/40 border-purple-500/30',
        icon: '<svg class="w-6 h-6 text-purple-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.5 2 2 6.5 2 12c0 3.9 2.2 7.2 5.5 8.9V19c0-1.1.9-2 2-2h5c1.1 0 2 .9 2 2v1.9c3.3-1.7 5.5-5 5.5-8.9 0-5.5-4.5-10-10-10z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.phantom?.solana || (window.solana && window.solana.isPhantom)),
        connect: () => connectSolanaDirect('phantom')
      },
      {
        id: 'solflare',
        network: 'sol',
        name: 'Solflare',
        desc: 'Non-custodial Solana Extension',
        chainTag: 'Solana',
        tagColor: 'text-purple-400 bg-purple-950/40 border-purple-500/30',
        icon: '<svg class="w-6 h-6 text-amber-500" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l4 8-4 4-4-4z"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.solflare),
        connect: () => connectSolanaDirect('solflare')
      },
      {
        id: 'unisat',
        network: 'btc',
        name: 'UniSat Wallet',
        desc: 'Native SegWit & Taproot Extension',
        chainTag: 'Bitcoin',
        tagColor: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
        icon: '<svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.unisat),
        connect: () => connectBitcoinDirect('unisat')
      },
      {
        id: 'okx_btc',
        network: 'btc',
        name: 'OKX Wallet',
        desc: 'Bitcoin & Multichain Browser Extension',
        chainTag: 'Bitcoin / Multi',
        tagColor: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
        icon: '<svg class="w-6 h-6 text-white" viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
        isInstalled: () => typeof window !== 'undefined' && Boolean(window.okxwallet?.bitcoin),
        connect: () => connectBitcoinDirect('okx')
      }
    ];

    let currentNetworkFilter = 'all';

    function openMultichainWalletModal() {
      localStorage.removeItem('aegis_manual_logout');
      const modal = document.getElementById('multichainWalletModal');
      if (modal) {
        modal.classList.remove('hidden');
        filterWalletNetwork(currentNetworkFilter || 'all');
        renderModalConnectedSummary();
      }
    }

    function closeMultichainWalletModal() {
      const modal = document.getElementById('multichainWalletModal');
      if (modal) modal.classList.add('hidden');
    }

    function filterWalletNetwork(net) {
      currentNetworkFilter = net;
      ['all', 'near', 'evm', 'sol', 'btc'].forEach(n => {
        const btn = document.getElementById('tabNet' + n.charAt(0).toUpperCase() + n.slice(1));
        if (btn) {
          if (n === net) {
            btn.className = 'network-tab-btn active px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-[#00F5D4]/20 text-[#00F5D4] border border-[#00F5D4]/40 cursor-pointer';
          } else {
            btn.className = 'network-tab-btn px-3.5 py-1.5 rounded-full text-xs font-mono font-bold transition flex items-center gap-1.5 bg-white/[0.04] text-[#8E99AD] hover:text-white border border-white/[0.08] cursor-pointer';
          }
        }
      });
      renderWalletsGrid(net);
    }

    function renderWalletsGrid(filter = 'all') {
      const grid = document.getElementById('walletsGrid');
      if (!grid) return;

      const filtered = WALLET_DEFINITIONS.filter(w => filter === 'all' || w.network === filter);
      grid.innerHTML = filtered.map(w => {
        const installed = w.isInstalled();
        return `
          <div onclick="selectWalletToConnect('${w.id}')" class="flex items-center justify-between p-3.5 rounded-2xl bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.08] hover:border-[#00F5D4]/40 transition cursor-pointer group shadow-sm active:scale-98">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center shrink-0 group-hover:scale-105 transition">
                ${w.icon}
              </div>
              <div>
                <div class="flex items-center gap-2">
                  <span class="font-bold text-white text-sm tracking-tight group-hover:text-[#00F5D4] transition">${w.name}</span>
                  ${installed ? '<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>Installed</span>' : ''}
                </div>
                <div class="text-[11px] text-[#8E99AD]">${w.desc}</div>
              </div>
            </div>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded-full border ${w.tagColor} shrink-0">${w.chainTag}</span>
          </div>
        `;
      }).join('');
    }

    function selectWalletToConnect(id) {
      const w = WALLET_DEFINITIONS.find(item => item.id === id);
      if (w && typeof w.connect === 'function') {
        w.connect();
      }
    }

    async function connectNearDirect(type) {
      localStorage.removeItem('aegis_manual_logout');
      closeMultichainWalletModal();
      const moduleMap = {
        meteor: 'meteor-wallet',
        here: 'here-wallet',
        nightly: 'nightly',
        sender: 'sender',
        bitte: 'bitte-wallet'
      };
      const moduleId = moduleMap[type] || 'meteor-wallet';
      showToast(`Connecting ${type.toUpperCase()}...`);

      // 1. Direct extension fast path for Meteor
      if (type === 'meteor' && window.meteorWallet && typeof window.meteorWallet.signIn === 'function') {
        try {
          await window.meteorWallet.signIn({ contractId: CONTRACT_ID });
          const acc = window.meteorWallet.accountId || (typeof window.meteorWallet.getAccountId === 'function' ? await window.meteorWallet.getAccountId() : null);
          if (acc) {
            localStorage.setItem('aegis_signer_account', acc);
            updateWalletConnectedUI(acc);
            fetchAccountNearBalance(acc);
            fetchLiveContractState();
            renderBunkerAddresses();
            showToast(`Meteor connected: ${acc}`);
            return;
          }
        } catch (e) {
          console.warn('[Aegis] Direct meteor error, trying selector:', e);
        }
      }

      // 2. Direct wallet module sign-in via selector (NO SECOND MODAL!)
      try {
        let provider = window.AegisWallet || window.AegisMeteor || window.AegisWalletBundle;
        if (!provider || typeof provider.signInWallet !== 'function') {
          for (let i = 0; i < 25; i++) {
            await new Promise(r => setTimeout(r, 100));
            provider = window.AegisWallet || window.AegisMeteor || window.AegisWalletBundle;
            if (provider && typeof provider.signInWallet === 'function') break;
          }
        }

        if (provider && typeof provider.signInWallet === 'function') {
          const res = await provider.signInWallet(moduleId, CONTRACT_ID);
          const sel = await provider.getSelector(CONTRACT_ID);
          const state = sel.store.getState();
          const activeAcc = (Array.isArray(res) && res[0]?.accountId) ||
                            state.accounts.find((acc) => acc.active)?.accountId ||
                            state.accounts[0]?.accountId;
          if (activeAcc) {
            localStorage.setItem('aegis_signer_account', activeAcc);
            localStorage.removeItem('aegis_manual_logout');
            updateWalletConnectedUI(activeAcc);
            fetchAccountNearBalance(activeAcc);
            fetchLiveContractState();
            renderBunkerAddresses();
            showToast(`Connected: ${activeAcc}`);
          }
          return;
        }

        showToast('Wallet provider initializing, please try again in a moment...');
      } catch (err) {
        console.error(`[Aegis] ${type} connection error:`, err);
        showToast(`Connection error: ${err.message}`, true);
      }
    }

    async function connectEvmDirect(type) {
      try {
        showToast('Connecting Ethereum / EVM extension...');
        if (typeof window === 'undefined' || !window.ethereum) {
          showToast('No EVM extension found. Please install MetaMask, Rabby, or Coinbase Wallet.', true);
          return;
        }
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (!accounts || accounts.length === 0) {
          showToast('EVM connection rejected or no accounts selected.', true);
          return;
        }
        const ethAddress = accounts[0];
        localStorage.setItem('aegis_connected_evm', ethAddress);

        // Auto-fill EVM destination fields in Tab 1 if empty
        const pEvm = document.getElementById('panicEvmAddr');
        if (pEvm && !pEvm.value.trim()) pEvm.value = ethAddress;

        closeMultichainWalletModal();
        updateMultichainConnectedUI();
        renderBunkerAddresses();
        showToast(`EVM connected: ${ethAddress.slice(0, 6)}...${ethAddress.slice(-4)}`);
      } catch (err) {
        console.error('[Aegis] EVM connection error:', err);
        showToast(`EVM Error: ${err.message}`, true);
      }
    }

    async function connectSolanaDirect(type) {
      try {
        showToast('Connecting Solana extension...');
        const provider = window.phantom?.solana || window.solana;
        if (!provider) {
          showToast('No Solana extension found. Please install Phantom or Solflare.', true);
          return;
        }
        const resp = await provider.connect();
        const solAddress = resp.publicKey ? resp.publicKey.toString() : provider.publicKey.toString();
        localStorage.setItem('aegis_connected_sol', solAddress);

        // Auto-fill Solana destination fields in Tab 1 if empty
        const pSol = document.getElementById('panicSolAddr');
        if (pSol && !pSol.value.trim()) pSol.value = solAddress;

        closeMultichainWalletModal();
        updateMultichainConnectedUI();
        await fetchAccountSolanaBalance(solAddress);
        renderBunkerAddresses();
        showToast(`Solana connected: ${solAddress.slice(0, 5)}...${solAddress.slice(-4)}`);
      } catch (err) {
        console.error('[Aegis] Solana connection error:', err);
        showToast(`Solana Error: ${err.message}`, true);
      }
    }

    async function connectBitcoinDirect(type) {
      try {
        showToast('Connecting Bitcoin extension...');
        let btcAddress = null;
        if (window.unisat) {
          const accounts = await window.unisat.requestAccounts();
          if (accounts && accounts.length > 0) btcAddress = accounts[0];
        } else if (window.okxwallet?.bitcoin) {
          const res = await window.okxwallet.bitcoin.connect();
          if (res && res.address) btcAddress = res.address;
        }
        if (!btcAddress) {
          showToast('No Bitcoin extension found. Please install UniSat or OKX Wallet.', true);
          return;
        }
        localStorage.setItem('aegis_connected_btc', btcAddress);

        closeMultichainWalletModal();
        updateMultichainConnectedUI();
        showToast(`Bitcoin connected: ${btcAddress.slice(0, 5)}...${btcAddress.slice(-4)}`);
      } catch (err) {
        console.error('[Aegis] Bitcoin connection error:', err);
        showToast(`Bitcoin Error: ${err.message}`, true);
      }
    }

    async function disconnectChain(chain) {
      if (chain === 'near') {
        localStorage.setItem('aegis_manual_logout', 'true');
        localStorage.removeItem('aegis_signer_account');
        localStorage.removeItem('aegis_wallet_type');
        localStorage.removeItem('aegis_testnet_signer_key');
        lastFetchedVaultInfo = null;
        updateWalletDisconnectedUI();
      } else if (chain === 'evm') {
        localStorage.removeItem('aegis_connected_evm');
        if (localStorage.getItem('aegis_signer_account')?.startsWith('0x')) {
          localStorage.removeItem('aegis_signer_account');
          lastFetchedVaultInfo = null;
          updateWalletDisconnectedUI();
        }
      } else if (chain === 'sol') {
        localStorage.removeItem('aegis_connected_sol');
      } else if (chain === 'btc') {
        localStorage.removeItem('aegis_connected_btc');
      }
      updateMultichainConnectedUI();
      renderBunkerAddresses();
      showToast(`Disconnected ${chain.toUpperCase()}`);
    }

    async function disconnectAllWallets() {
      localStorage.setItem('aegis_manual_logout', 'true');
      localStorage.removeItem('aegis_signer_account');
      localStorage.removeItem('aegis_wallet_type');
      localStorage.removeItem('aegis_testnet_signer_key');
      localStorage.removeItem('aegis_connected_evm');
      localStorage.removeItem('aegis_connected_sol');
      localStorage.removeItem('aegis_connected_btc');
      lastFetchedVaultInfo = null;
      updateMultichainConnectedUI();
      updateWalletDisconnectedUI();
      renderBunkerAddresses();
      closeMultichainWalletModal();
      showToast('All wallets disconnected');
    }

    function renderModalConnectedSummary() {
      const sumEl = document.getElementById('modalConnectedSummary');
      const listEl = document.getElementById('modalConnectedList');
      if (!sumEl || !listEl) return;

      const nearAcc = localStorage.getItem('aegis_signer_account');
      const evmAcc = localStorage.getItem('aegis_connected_evm');
      const solAcc = localStorage.getItem('aegis_connected_sol');
      const btcAcc = localStorage.getItem('aegis_connected_btc');

      const items = [];
      if (nearAcc && !nearAcc.startsWith('0x')) {
        items.push({ chain: 'near', name: 'NEAR Protocol', addr: nearAcc, color: 'text-emerald-400' });
      }
      if (evmAcc) {
        items.push({ chain: 'evm', name: 'Ethereum / EVM', addr: evmAcc, color: 'text-blue-400' });
      }
      if (solAcc) {
        items.push({ chain: 'sol', name: 'Solana', addr: solAcc, color: 'text-purple-400' });
      }
      if (btcAcc) {
        items.push({ chain: 'btc', name: 'Bitcoin', addr: btcAcc, color: 'text-amber-400' });
      }

      if (items.length === 0) {
        sumEl.classList.add('hidden');
        return;
      }

      sumEl.classList.remove('hidden');
      listEl.innerHTML = items.map(item => `
        <div class="flex items-center justify-between p-2 rounded-xl bg-white/[0.03] border border-white/[0.06]">
          <div class="flex items-center gap-2 overflow-hidden">
            <span class="w-2 h-2 rounded-full ${item.color.replace('text-', 'bg-')} shrink-0"></span>
            <span class="text-[#8E99AD] font-semibold">${escapeHtml(item.name)}:</span>
            <span class="text-white truncate max-w-[200px] sm:max-w-[280px]" title="${escapeHtml(item.addr)}">${escapeHtml(item.addr)}</span>
          </div>
          <button onclick="disconnectChain('${escapeHtml(item.chain)}')" class="text-[11px] text-[#8E99AD] hover:text-red-400 transition ml-2 shrink-0 cursor-pointer">Disconnect</button>
        </div>
      `).join('');
    }

    function updateMultichainConnectedUI() {
      const nearAcc = localStorage.getItem('aegis_signer_account');
      const evmAcc = localStorage.getItem('aegis_connected_evm');
      const solAcc = localStorage.getItem('aegis_connected_sol');
      const btcAcc = localStorage.getItem('aegis_connected_btc');

      const hasAnyWallet = Boolean(nearAcc || evmAcc || solAcc || btcAcc);
      const connectBtn = document.getElementById('connectWalletBtn');
      const connectedPill = document.getElementById('connectedWalletPill');
      const nameEl = document.getElementById('headerAccountName');
      const nameMobEl = document.getElementById('headerAccountNameMobile');
      const badgesEl = document.getElementById('headerMultichainBadges');

      if (hasAnyWallet) {
        if (connectBtn) connectBtn.classList.add('hidden');
        if (connectedPill) connectedPill.classList.remove('hidden');

        // Primary display
        const primaryAcc = nearAcc || evmAcc || solAcc || btcAcc;
        const isNear = Boolean(nearAcc && !nearAcc.startsWith('0x'));
        const isSol = Boolean(!nearAcc && solAcc);
        const isEvm = Boolean(!nearAcc && !solAcc && evmAcc);
        const isBtc = Boolean(!nearAcc && !solAcc && !evmAcc && btcAcc);

        if (nameEl) {
          nameEl.innerText = primaryAcc.length > 20 ? primaryAcc.slice(0, 8) + '...' + primaryAcc.slice(-6) : primaryAcc;
          nameEl.title = primaryAcc;
          nameEl.className = isNear
            ? 'font-bold text-nearGreen hidden sm:inline whitespace-nowrap'
            : (isSol ? 'font-bold text-purple-400 hidden sm:inline whitespace-nowrap' : (isBtc ? 'font-bold text-amber-400 hidden sm:inline whitespace-nowrap' : 'font-bold text-blue-400 hidden sm:inline whitespace-nowrap'));
        }
        if (nameMobEl) {
          nameMobEl.innerText = primaryAcc.slice(0, 6) + '...';
          nameMobEl.className = isNear
            ? 'font-bold text-nearGreen sm:hidden whitespace-nowrap'
            : (isSol ? 'font-bold text-purple-400 sm:hidden whitespace-nowrap' : (isBtc ? 'font-bold text-amber-400 sm:hidden whitespace-nowrap' : 'font-bold text-blue-400 sm:hidden whitespace-nowrap'));
        }

        // Live balance update for header
        if (isNear) {
          fetchAccountNearBalance(nearAcc);
        } else if (isSol) {
          fetchAccountSolanaBalance(solAcc);
        } else if (isEvm) {
          fetchAccountEvmBalance(evmAcc);
        } else if (isBtc) {
          fetchAccountBtcBalance(btcAcc);
        }

        // Secondary badges
        if (badgesEl) {
          badgesEl.innerHTML = '';
          if (evmAcc && primaryAcc !== evmAcc) {
            badgesEl.innerHTML += `<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-blue-500/15 text-blue-300 border border-blue-500/30" title="${escapeHtml(evmAcc)}">ETH: ${escapeHtml(evmAcc.slice(0, 6))}...</span>`;
          }
          if (solAcc && primaryAcc !== solAcc) {
            badgesEl.innerHTML += `<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30" title="${escapeHtml(solAcc)}">SOL: ${escapeHtml(solAcc.slice(0, 5))}...</span>`;
          }
          if (btcAcc && primaryAcc !== btcAcc) {
            badgesEl.innerHTML += `<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30" title="${escapeHtml(btcAcc)}">BTC: ${escapeHtml(btcAcc.slice(0, 5))}...</span>`;
          }
          badgesEl.className = badgesEl.innerHTML ? 'flex items-center gap-1.5 border-l border-white/10 pl-2' : 'hidden';
        }

        updateCountdownDisplay();
      } else {
        updateWalletDisconnectedUI();
      }

      renderModalConnectedSummary();
    }

    // Direct NEAR Wallet Selector Handler (no duplicate modal)
    async function connectNearWallet(walletId = 'meteor') {
      return await connectNearDirect(walletId);
    }
    const connectMeteorWallet = openMultichainWalletModal; // Backward-compatibility

    async function initNearWallet() {
      let provider = window.AegisWallet || window.AegisMeteor || window.AegisWalletBundle;
      if (!provider || typeof provider.getSelector !== 'function') {
        for (let i = 0; i < 25; i++) {
          await new Promise(r => setTimeout(r, 100));
          provider = window.AegisWallet || window.AegisMeteor || window.AegisWalletBundle;
          if (provider && typeof provider.getSelector === 'function') break;
        }
      }
      if (provider && typeof provider.getSelector === 'function') {
        try {
          const sel = await provider.getSelector(CONTRACT_ID);
          const state = sel.store.getState();
          const activeAcc = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;
          const isManualLogout = localStorage.getItem('aegis_manual_logout') === 'true';
          if (activeAcc && !isManualLogout) {
            localStorage.setItem('aegis_signer_account', activeAcc);
            updateWalletConnectedUI(activeAcc);
            fetchAccountNearBalance(activeAcc);
            fetchLiveContractState();
            renderBunkerAddresses();
          } else {
            if (!activeAcc) localStorage.removeItem('aegis_signer_account');
            updateWalletDisconnectedUI();
            renderBunkerAddresses();
          }

          sel.store.observable.subscribe((nextState) => {
            if (localStorage.getItem('aegis_manual_logout') === 'true') return;
            const acc = nextState.accounts.find((a) => a.active)?.accountId || nextState.accounts[0]?.accountId;
            if (acc) {
              const prev = localStorage.getItem('aegis_signer_account');
              if (prev && prev !== acc) {
                // Switching account: reset all user inputs, caches and DOM balances immediately!
                userHasInteractedWithInputs = false;
                lastFetchedVaultInfo = null;
                inputIds.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
                const btcBalEl = document.getElementById('btcBalanceText');
                const evmBalEl = document.getElementById('evmBalanceText');
                const solBalEl = document.getElementById('solBalanceText');
                const nearBalEl = document.getElementById('nearBalanceText');
                if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">BTC</span>';
                if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">ETH</span>';
                if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">SOL</span>';
                if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span>';
              }
              localStorage.setItem('aegis_signer_account', acc);
              updateWalletConnectedUI(acc);
              fetchAccountNearBalance(acc);
              if (prev !== acc) {
                fetchLiveContractState();
                renderBunkerAddresses();
              }
            } else {
              localStorage.removeItem('aegis_signer_account');
              updateWalletDisconnectedUI();
              renderBunkerAddresses();
            }
          });
          return;
        } catch (err) {
          console.warn('[Aegis] Wallet selector init notice:', err);
        }
      }

      const manualAccount = localStorage.getItem('aegis_signer_account');
      if (manualAccount) {
        updateWalletConnectedUI(manualAccount);
        fetchAccountNearBalance(manualAccount);
        fetchLiveContractState();
        renderBunkerAddresses();
        return;
      }

      updateWalletDisconnectedUI();
      renderBunkerAddresses();
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

      // Delegate Hero HUD display to smart updateCountdownDisplay (handles Active vs Evacuated/Burned)
      updateCountdownDisplay();
    }

    function updateWalletDisconnectedUI() {
      const connectBtn = document.getElementById('connectWalletBtn');
      const connectedPill = document.getElementById('connectedWalletPill');
      if (connectBtn) connectBtn.classList.remove('hidden');
      if (connectedPill) connectedPill.classList.add('hidden');

      // 1. Reset client state
      lastFetchedVaultInfo = null;
      currentEpochIndex = 0;
      remainingSeconds = 0;
      userHasInteractedWithInputs = false;

      // 2. Clear all address input boxes
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });

      // 3. Hide all active banners and alert dialogs
      const activeBanner = document.getElementById('activePolicyBanner');
      if (activeBanner) activeBanner.classList.add('hidden');
      const unconfigBanner = document.getElementById('unconfiguredBanner');
      if (unconfigBanner) unconfigBanner.classList.remove('hidden');
      const burnedBanner = document.getElementById('bunkerBurnedBanner');
      if (burnedBanner) burnedBanner.classList.add('hidden');
      const unarmedBanner = document.getElementById('bunkerUnarmedBanner');
      if (unarmedBanner) unarmedBanner.classList.add('hidden');
      const unallocDep = document.getElementById('unallocatedDepositAlert');
      if (unallocDep) { unallocDep.classList.add('hidden'); unallocDep.classList.remove('flex'); }
      const unallocPol = document.getElementById('unallocatedPolicyAlert');
      if (unallocPol) { unallocPol.classList.add('hidden'); unallocPol.classList.remove('flex'); }

      const tabRescue = document.getElementById('tab-rescue');
      if (tabRescue) tabRescue.innerText = '1. Rescue & Inheritance (Destinations)';

      updateSaveButtonState(null);

      // Hero HUD state: Disconnected / Awaiting Arming
      const pulseDot = document.getElementById('heartbeatPulseDot');
      const cardTitle = document.getElementById('heartbeatCardTitle');
      const heartbeatTag = document.getElementById('heartbeatTag');
      const countdownTitle = document.getElementById('countdownTitle');
      const countdownBox = document.getElementById('countdownBox');
      const statusDisplay = document.getElementById('statusDisplay');
      const pingBtn = document.getElementById('pingMainBtn');
      const pingBtnText = document.getElementById('pingMainBtnText');
      const timerBar = document.getElementById('timerBar');
      const pctEl = document.getElementById('timerPctDisplay');

      if (pulseDot) pulseDot.className = 'w-2.5 h-2.5 rounded-full bg-yellow-400';
      if (cardTitle) cardTitle.className = 'text-xs font-mono font-bold uppercase tracking-wider text-[#A6B0C3]';
      if (heartbeatTag) {
        heartbeatTag.className = 'text-xs font-mono font-medium text-yellow-400/90 bg-yellow-950/30 px-3 py-1 rounded-full border border-yellow-500/30';
        heartbeatTag.innerText = 'Vault Inactive · Connect Wallet';
      }
      if (countdownTitle) countdownTitle.innerText = "Dead-Man's Switch Heartbeat:";
      if (countdownBox) countdownBox.innerText = 'Ready to Arm';
      if (statusDisplay) statusDisplay.innerHTML = 'Status: <strong class="text-yellow-400/90 font-bold">Connect Wallet to Arm</strong>';
      if (timerBar) timerBar.style.width = '100%';
      if (pctEl) pctEl.innerText = '100.0% remaining';
      if (pingBtn) {
        pingBtn.className = 'w-full bg-purple-600 hover:bg-purple-500 text-white font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-sm active:scale-98 flex items-center justify-center gap-2';
      }
      if (pingBtnText) pingBtnText.innerText = 'Connect Wallet to Arm Vault';
      const hbNoticeReset = document.getElementById('heartbeatTimelockNotice');
      if (hbNoticeReset) hbNoticeReset.classList.add('hidden');

      // Reset Header Account and Balance
      const headName = document.getElementById('headerAccountName');
      if (headName) headName.innerText = 'account.testnet';
      const headBal = document.getElementById('headerAccountBalance');
      if (headBal) headBal.innerText = '0.00 NEAR';

      // Reset Bunker Balances to 0.0000
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

      if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">BTC</span>';
      if (btcUsdEl) btcUsdEl.innerText = '≈ 0.00 USD';
      if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">ETH</span>';
      if (evmUsdEl) evmUsdEl.innerText = '≈ 0.00 USD';
      if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">SOL</span>';
      if (solUsdEl) solUsdEl.innerText = '≈ 0.00 USD';
      if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-base font-normal text-[#B0B9C9]">NEAR</span>';
      if (nearUsdEl) nearUsdEl.innerText = '≈ 0.00 USD';
      if (syncBadge) syncBadge.innerText = 'Connect Wallet to Sync';
      if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-white/20';

      renderBunkerAddresses();
      checkUnallocatedFunds();
    }

    async function fetchAccountNearBalance(accountId) {
      if (!accountId) return;
      try {
        const rpc = NEAR_RPC_URLS[currentRpcIndex] || NEAR_RPC_URLS[0];
        const response = await fetch(rpc, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'bal-check',
            method: 'query',
            params: {
              request_type: 'view_account',
              finality: 'optimistic',
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
          if (balEl) {
            balEl.innerText = `${formatted} NEAR`;
            balEl.className = 'text-[#A6B0C3] border-l border-white/10 pl-2 font-normal hidden sm:inline whitespace-nowrap';
          }
        }
      } catch (e) {
        console.warn('Balance check error:', e);
      }
    }

    async function fetchAccountSolanaBalance(address) {
      if (!address) return;
      try {
        const solRes = await fetch('https://api.devnet.solana.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getBalance',
            params: [address]
          })
        }).then(r => r.json());
        if (solRes?.result?.value !== undefined) {
          const solVal = solRes.result.value / 1e9;
          const balEl = document.getElementById('headerAccountBalance');
          if (balEl) {
            balEl.innerText = `${solVal.toFixed(2)} SOL`;
            balEl.className = 'text-purple-300 border-l border-white/10 pl-2 font-normal hidden sm:inline whitespace-nowrap';
          }
        }
      } catch (e) {
        console.warn('Solana balance query error:', e);
      }
    }

    async function fetchAccountEvmBalance(address) {
      if (!address) return;
      try {
        const evmRes = await fetch('https://ethereum-sepolia-rpc.publicnode.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_getBalance',
            params: [address, 'latest']
          })
        }).then(r => r.json());
        if (evmRes?.result) {
          const wei = BigInt(evmRes.result);
          const ethVal = Number(wei) / 1e18;
          const balEl = document.getElementById('headerAccountBalance');
          if (balEl) {
            balEl.innerText = `${ethVal.toFixed(4)} ETH`;
            balEl.className = 'text-blue-300 border-l border-white/10 pl-2 font-normal hidden sm:inline whitespace-nowrap';
          }
        }
      } catch (e) {
        console.warn('EVM balance query error:', e);
      }
    }

    async function fetchAccountBtcBalance(address) {
      if (!address) return;
      try {
        const btcRes = await fetch(`https://mempool.space/testnet/api/address/${address}`).then(r => r.json());
        if (btcRes?.chain_stats) {
          const funded = (btcRes.chain_stats.funded_txo_sum || 0) - (btcRes.chain_stats.spent_txo_sum || 0);
          const btcVal = funded / 1e8;
          const balEl = document.getElementById('headerAccountBalance');
          if (balEl) {
            balEl.innerText = `${btcVal.toFixed(4)} BTC`;
            balEl.className = 'text-amber-300 border-l border-white/10 pl-2 font-normal hidden sm:inline whitespace-nowrap';
          }
        }
      } catch (e) {
        console.warn('BTC balance query error:', e);
      }
    }

    async function disconnectWallet() {
      localStorage.removeItem('aegis_signer_account');
      localStorage.removeItem('aegis_wallet_type');
      localStorage.removeItem('aegis_testnet_signer_key');
      localStorage.removeItem('aegis_connected_evm');
      localStorage.removeItem('aegis_connected_sol');
      localStorage.removeItem('aegis_connected_btc');
      updateWalletDisconnectedUI();
      updateMultichainConnectedUI();
      renderBunkerAddresses();
      showToast('Wallet disconnected');
    }

    // Direct On-Chain Contract Caller via NEAR Testnet RPC
    async function dispatchNearTransaction(methodName, args = {}, depositOverride = '0') {
      showToast(`Broadcasting on-chain ${methodName}() to NEAR Testnet...`);
      try {
        console.log(`[Aegis On-Chain] Dispatching ${methodName} on ${CONTRACT_ID} with args:`, args);

        const attachedDeposit = String(depositOverride || '0');

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
          userHasInteractedWithInputs = false;
          isEditing = false;
          const currentSigner = localStorage.getItem('aegis_signer_account');
          setTimeout(() => {
            fetchLiveContractState();
            if (currentSigner) fetchAccountNearBalance(currentSigner);
            fetchLiveBalances(true);
          }, 2000);
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
            nodeUrl: NEAR_RPC_URLS[currentRpcIndex],
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
          userHasInteractedWithInputs = false;
          isEditing = false;
          setTimeout(() => {
            fetchLiveContractState();
            fetchAccountNearBalance(signerAccountId);
            fetchLiveBalances(true);
          }, 2000);
          return outcome;
        }

        // 3. Not signed in: Trigger Wallet Connect
        showToast('Please connect your Web3 wallet first!', true);
        openMultichainWalletModal();
        throw new Error('Wallet not connected');
      } catch (err) {
        console.error(`❌ [Aegis] Failed to dispatch ${methodName}:`, err);
        if (err.message !== 'Wallet not connected') {
          showToast(`Error dispatching ${methodName}: ${err.message}`, true);
        }
        throw err;
      }
    }

    async function renderBunkerAddresses() {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      const btcEl = document.getElementById('btcAddress');
      const evmEl = document.getElementById('evmAddress');
      const solEl = document.getElementById('solAddress');
      const nearEl = document.getElementById('nearAddress');
      const pill = document.getElementById('bunkerEpochPill');
      const banner = document.getElementById('bunkerBurnedBanner');
      const unarmedBanner = document.getElementById('bunkerUnarmedBanner');

      const chains = [
        {
          id: 'btc',
          name: 'Bitcoin',
          addrEl: btcEl,
          actionsEl: document.getElementById('btcActions'),
          hasEgress: Boolean(lastFetchedVaultInfo?.backup?.btc?.trim() && lastFetchedVaultInfo?.heirs?.btc?.trim())
        },
        {
          id: 'evm',
          name: 'Ethereum',
          addrEl: evmEl,
          actionsEl: document.getElementById('evmActions'),
          hasEgress: Boolean(lastFetchedVaultInfo?.backup?.evm?.trim() && lastFetchedVaultInfo?.heirs?.evm?.trim())
        },
        {
          id: 'sol',
          name: 'Solana',
          addrEl: solEl,
          actionsEl: document.getElementById('solActions'),
          hasEgress: Boolean(lastFetchedVaultInfo?.backup?.sol?.trim() && lastFetchedVaultInfo?.heirs?.sol?.trim())
        },
        {
          id: 'near',
          name: 'NEAR Protocol',
          addrEl: nearEl,
          actionsEl: document.getElementById('nearActions'),
          hasEgress: Boolean(lastFetchedVaultInfo?.backup?.near?.trim() && lastFetchedVaultInfo?.heirs?.near?.trim())
        }
      ];

      const renderActiveButtons = (c) => `
        <button onclick="copyAddr('${c.id}Address')" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-nearGreen/50 text-xs sm:text-sm font-bold text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
          <svg class="w-4 h-4 text-nearGreen" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
          <span>Copy</span>
        </button>
        <button onclick="openQr('${c.name}', document.getElementById('${c.id}Address').dataset.full)" class="py-2.5 px-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.08] hover:border-white/[0.25] text-xs sm:text-sm font-bold text-[#C5CAD3] hover:text-white transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-98">
          <svg class="w-4 h-4 text-[#8C929D]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" /></svg>
          <span>QR Code</span>
        </button>
      `;

      // 1. Disconnected State
      if (!currentSigner) {
        chains.forEach(c => {
          if (c.addrEl) {
            c.addrEl.innerText = 'Connect wallet to reveal address';
            c.addrEl.className = 'font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-words select-none font-medium';
            c.addrEl.dataset.full = '';
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = `<div class="col-span-2 py-2 px-3 rounded-xl bg-white/[0.03] border border-white/[0.08] text-center text-xs font-mono text-[#8C929D] flex items-center justify-center gap-1.5 select-none">Connect Wallet to Unlock</div>`;
          }
        });
        if (pill) {
          pill.innerText = 'Derivation Path: Connect Wallet to View';
          pill.className = 'text-[11px] font-mono font-bold text-[#8E99AD] bg-white/[0.04] border border-white/[0.08] px-2.5 py-0.5 rounded-full whitespace-nowrap';
        }
        if (banner) banner.classList.add('hidden');
        if (unarmedBanner) unarmedBanner.classList.add('hidden');
        checkUnallocatedFunds();
        return;
      }

      const isBurned = isVaultEvacuatedOrBurned() || isGracePeriodExpired(lastFetchedVaultInfo);

      // 2. Guard 1: Evacuated, Inherited, or Grace-Expired bunker (NEVER show deposit addresses!)
      if (isBurned) {
        if (typeof closeQr === 'function') closeQr();
        const isInheritance = Boolean(
          lastFetchedVaultInfo && (
            lastFetchedVaultInfo.state === 'Inheritance' ||
            (lastFetchedVaultInfo.state === 'Active' && isGracePeriodExpired(lastFetchedVaultInfo))
          )
        );
        const isEpochSwept = Boolean(lastFetchedVaultInfo && lastFetchedVaultInfo.is_epoch_swept);
        const burnedMsg = isInheritance
          ? `Epoch ${currentEpochIndex} Inherited · Deposits Disabled`
          : `Epoch ${currentEpochIndex} Burned · Deposits Disabled`;
        chains.forEach(c => {
          if (c.addrEl) {
            c.addrEl.innerText = burnedMsg;
            c.addrEl.className = isInheritance
              ? 'font-mono text-xs leading-relaxed text-purple-400 break-words select-none font-bold'
              : 'font-mono text-xs leading-relaxed text-red-400 break-words select-none font-bold';
            c.addrEl.dataset.full = '';
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = `
              <div class="col-span-2 py-2.5 px-3 rounded-xl ${isInheritance ? 'bg-purple-950/30 border border-purple-500/20 text-purple-300' : 'bg-red-950/30 border border-red-500/20 text-red-400'} text-center text-xs font-mono flex items-center justify-center gap-1.5 select-none">
                <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                <span>${isInheritance ? (isEpochSwept ? 'Epoch Closed · Assets Transferred' : 'Epoch Closed · Sweep in Progress') : (isEpochSwept ? 'Epoch Burned · Assets Swept' : 'Epoch Burned · Sweep in Progress')}</span>
              </div>
            `;
          }
        });
        if (pill) {
          pill.innerText = isInheritance
            ? `Epoch ${currentEpochIndex} · ${isEpochSwept ? 'Inherited (Transferred)' : 'Inheritance (Sweeping)'}`
            : `Epoch ${currentEpochIndex} · ${isEpochSwept ? 'Burned (Inactive)' : 'Evacuating (Sweeping)'}`;
          pill.className = isInheritance
            ? 'text-[11px] font-mono font-bold text-purple-300 bg-purple-950/40 border border-purple-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap'
            : 'text-[11px] font-mono font-bold text-red-400 bg-red-950/40 border border-red-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
        }
        if (banner) {
          banner.classList.remove('hidden');
          const bannerTitle = banner.querySelector('h4');
          const bannerText = banner.querySelector('p');
          if (bannerTitle) {
            bannerTitle.innerText = isInheritance
              ? 'Inheritance Finalized — Path Rotation Required'
              : 'Epoch Exhausted — Path Rotation Required';
            bannerTitle.className = isInheritance
              ? 'text-sm font-extrabold text-purple-200'
              : 'text-sm font-extrabold text-red-200';
          }
          if (bannerText) {
            bannerText.innerText = isInheritance
              ? (isEpochSwept
                  ? 'Active vault assets were autonomously transferred to designated heirs. Deposits are permanently disabled for this epoch. Activate the next clean bunker to derive fresh uncompromised addresses.'
                  : 'Autonomous inheritance triggered. Cloud Keeper sweep is in progress. Activate the next clean bunker to derive fresh uncompromised addresses.')
              : (isEpochSwept
                  ? 'Active epoch keys were exposed on-chain during evacuation. Activate the next bunker to derive fresh uncompromised addresses.'
                  : 'Emergency evacuation triggered; Cloud Keeper sweep is in progress. Activate the next bunker to derive fresh uncompromised addresses.');
          }
        }
        if (unarmedBanner) unarmedBanner.classList.add('hidden');
        checkUnallocatedFunds();
        return;
      }

      // 2b. Guard 2: Heartbeat Expired during Grace Buffer (Lock & hide deposit addresses immediately)
      if (isHeartbeatExpired(lastFetchedVaultInfo)) {
        if (typeof closeQr === 'function') closeQr();
        if (banner) banner.classList.add('hidden');
        if (unarmedBanner) unarmedBanner.classList.add('hidden');
        if (pill) {
          pill.innerText = `Epoch ${currentEpochIndex} · Grace Buffer (Deposits Locked)`;
          pill.className = 'text-[11px] font-mono font-bold text-amber-300 bg-amber-950/40 border border-amber-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
        }
        chains.forEach(c => {
          if (c.addrEl) {
            c.addrEl.innerText = 'Heartbeat Expired · Deposits Locked (Grace Buffer)';
            c.addrEl.className = 'font-mono text-xs leading-relaxed text-amber-400 break-words select-none font-bold';
            c.addrEl.dataset.full = '';
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = `
              <div class="col-span-2 py-2.5 px-3 rounded-xl bg-amber-950/30 border border-amber-500/25 text-amber-300 text-center text-xs font-mono flex items-center justify-center gap-1.5 select-none">
                <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                <span>Locked · Check-in to Unlock</span>
              </div>
            `;
          }
        });
        checkUnallocatedFunds();
        return;
      }

      // 3. Vault is Active / Configurable
      if (banner) banner.classList.add('hidden');

      const isArmed = lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Active' && hasConfiguredDestinations(lastFetchedVaultInfo);

      // If Bunker is NOT armed (Unconfigured or no egress addresses configured at all):
      if (!isArmed) {
        if (pill) {
          pill.innerText = `Derivation Path: aegis/${currentSigner}/${currentEpochIndex} (Unarmed)`;
          pill.className = 'text-[11px] font-mono font-bold text-amber-400 bg-amber-950/40 border border-amber-500/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
        }
        if (unarmedBanner) unarmedBanner.classList.remove('hidden');

        chains.forEach(c => {
          if (c.addrEl) {
            c.addrEl.innerText = 'Bunker Unarmed · Configure Egress First';
            c.addrEl.className = 'font-mono text-xs leading-relaxed text-amber-400/80 break-words select-none font-semibold';
            c.addrEl.dataset.full = '';
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = `
              <button type="button" onclick="switchTab('rescue')" class="col-span-2 py-2 px-3 rounded-xl bg-amber-950/25 hover:bg-amber-950/40 border border-amber-500/25 hover:border-amber-500/40 text-center text-xs font-mono text-amber-400 flex items-center justify-center gap-1.5 transition active:scale-98 cursor-pointer">
                <svg class="w-3.5 h-3.5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                <span>Locked · Arm Vault in Tab 1 ↗</span>
              </button>
            `;
          }
        });
        checkUnallocatedFunds();
        return;
      }

      if (unarmedBanner) unarmedBanner.classList.add('hidden');

      if (pill) {
        pill.innerText = `Derivation Path: aegis/${currentSigner}/${currentEpochIndex} (Active)`;
        pill.className = 'text-[11px] font-mono font-bold text-nearGreen bg-nearGreenMuted border border-nearGreen/30 px-2.5 py-0.5 rounded-full whitespace-nowrap';
      }

      // 1. Check local dynamic cache
      const cacheKey = `aegis_derived_${currentSigner}_${currentEpochIndex}`;
      let addresses = null;
      try {
        const cached = localStorage.getItem(cacheKey);
        if (cached) addresses = JSON.parse(cached);
      } catch (e) {}

      // 2. Check precomputed table
      if (!addresses && PRECOMPUTED_DERIVED_VAULTS[currentSigner] && PRECOMPUTED_DERIVED_VAULTS[currentSigner][currentEpochIndex]) {
        addresses = PRECOMPUTED_DERIVED_VAULTS[currentSigner][currentEpochIndex];
      }

      // 3. Dynamic client derivation via NEAR Chain Signatures
      if (!addresses) {
        addresses = {
          btc: 'Deriving via NEAR MPC...',
          evm: 'Deriving via NEAR MPC...',
          sol: 'Deriving via NEAR MPC...',
          near: 'Deriving via NEAR MPC...'
        };
        if (window.AegisMeteor && typeof window.AegisMeteor.deriveVaultAddresses === 'function') {
          window.AegisMeteor.deriveVaultAddresses(CONTRACT_ID, `aegis/${currentSigner}/${currentEpochIndex}`, 'testnet')
            .then(res => {
              if (res) {
                localStorage.setItem(cacheKey, JSON.stringify(res));
                renderBunkerAddresses();
              }
            }).catch(e => console.warn('Dynamic MPC derivation notice:', e.message));
        }
      }

      // 4. Per-Chain Gating Display: Only show deposit address if BOTH panic & heir are set for this chain!
      chains.forEach(c => {
        if (!c.hasEgress) {
          if (c.addrEl) {
            c.addrEl.innerText = 'Egress Incomplete · Set in Tab 1';
            c.addrEl.className = 'font-mono text-xs leading-relaxed text-amber-400/80 break-words select-none font-semibold';
            c.addrEl.dataset.full = '';
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = `
              <button type="button" onclick="switchTab('rescue')" class="col-span-2 py-2 px-3 rounded-xl bg-amber-950/25 hover:bg-amber-950/40 border border-amber-500/25 hover:border-amber-500/40 text-center text-xs font-mono text-amber-400 flex items-center justify-center gap-1.5 transition active:scale-98 cursor-pointer">
                <svg class="w-3.5 h-3.5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                <span>Locked · Set Egress in Tab 1 ↗</span>
              </button>
            `;
          }
        } else {
          const addr = addresses[c.id] || '';
          if (c.addrEl) {
            c.addrEl.innerText = addr;
            c.addrEl.className = 'font-mono text-xs sm:text-[13px] leading-relaxed text-[#8C929D] break-all select-all font-medium group-hover:text-nearGreen transition-colors';
            c.addrEl.dataset.full = addr;
          }
          if (c.actionsEl) {
            c.actionsEl.innerHTML = renderActiveButtons(c);
          }
        }
      });

      checkUnallocatedFunds();
    }

    const CACHE_TTL_MS = 30 * 1000; // 30-second cache interval for responsive sync
    let lastBalancesSyncedTimestamp = 0;

    function updateLiveSyncTimer() {
      const syncBadge = document.getElementById('liveSyncBadge');
      if (!syncBadge) return;
      const isConnected = !!localStorage.getItem('aegis_signer_account');
      if (!isConnected) {
        syncBadge.innerText = 'Connect Wallet to Sync';
        return;
      }
      if (isVaultEvacuatedOrBurned() || isGracePeriodExpired()) {
        syncBadge.innerText = lastFetchedVaultInfo?.is_epoch_swept ? 'Epoch Swept · Closed' : 'Sweep Active · Synced';
        return;
      }
      if (!lastBalancesSyncedTimestamp) {
        syncBadge.innerText = 'Live On-Chain Synced';
        return;
      }
      const elapsedSec = Math.max(0, Math.floor((Date.now() - lastBalancesSyncedTimestamp) / 1000));
      if (elapsedSec < 5) {
        syncBadge.innerText = 'Synced: Just now';
      } else if (elapsedSec < 60) {
        syncBadge.innerText = `Synced: ${elapsedSec}s ago`;
      } else {
        const m = Math.floor(elapsedSec / 60);
        const s = elapsedSec % 60;
        syncBadge.innerText = `Synced: ${m}m ${s}s ago`;
      }
    }

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

      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner) {
        if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">BTC</span>';
        if (btcUsdEl) btcUsdEl.innerText = '≈ 0.00 USD';
        if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">ETH</span>';
        if (evmUsdEl) evmUsdEl.innerText = '≈ 0.00 USD';
        if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">SOL</span>';
        if (solUsdEl) solUsdEl.innerText = '≈ 0.00 USD';
        if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">NEAR</span>';
        if (nearUsdEl) nearUsdEl.innerText = '≈ 0.00 USD';
        if (syncBadge) syncBadge.innerText = 'Connect Wallet to Sync';
        if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-white/20';
        checkUnallocatedFunds();
        return;
      }

      // Automatically refresh the connected wallet balance in header
      fetchAccountNearBalance(currentSigner);

      // If vault is unconfigured / unarmed, or if epoch is already swept after evacuation/inheritance, zero out balances immediately
      const cacheKey = `aegis_balance_cache_${currentSigner}`;
      if (
        !lastFetchedVaultInfo ||
        lastFetchedVaultInfo.state === 'Unconfigured' ||
        !hasConfiguredDestinations() ||
        ((isVaultEvacuatedOrBurned() || isGracePeriodExpired()) && lastFetchedVaultInfo.is_epoch_swept)
      ) {
        if (btcBalEl) btcBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">BTC</span>';
        if (btcUsdEl) btcUsdEl.innerText = '≈ 0.00 USD';
        if (evmBalEl) evmBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">ETH</span>';
        if (evmUsdEl) evmUsdEl.innerText = '≈ 0.00 USD';
        if (solBalEl) solBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">SOL</span>';
        if (solUsdEl) solUsdEl.innerText = '≈ 0.00 USD';
        if (nearBalEl) nearBalEl.innerHTML = '0.0000 <span class="text-sm font-normal text-[#8C929D]">NEAR</span>';
        if (nearUsdEl) nearUsdEl.innerText = '≈ 0.00 USD';
        if (lastFetchedVaultInfo?.is_epoch_swept) {
          localStorage.removeItem(cacheKey);
          if (syncBadge) syncBadge.innerText = 'Epoch Swept · Closed';
          if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-purple-400';
        } else {
          if (syncBadge) syncBadge.innerText = 'Vault Unarmed';
          if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-white/20';
        }
        checkUnallocatedFunds();
        return;
      }

      // Check 30-second cache scoped to current account
      const cached = JSON.parse(localStorage.getItem(cacheKey) || 'null');
      const now = Date.now();
      const currentVaultState = lastFetchedVaultInfo?.state || 'Active';
      const isEvac = isAddressDisplayLocked();

      // Bypass cache if: forced, vault is evacuated/burned, or state changed since cache was saved
      if (!force && !isEvac && cached && cached.contractId === CONTRACT_ID && cached.state === currentVaultState && (now - cached.timestamp < CACHE_TTL_MS)) {
        if (btcBalEl && cached.btcBal) btcBalEl.innerHTML = cached.btcBal;
        if (btcUsdEl && cached.btcUsd) btcUsdEl.innerText = cached.btcUsd;
        if (evmBalEl && cached.evmBal) evmBalEl.innerHTML = cached.evmBal;
        if (evmUsdEl && cached.evmUsd) evmUsdEl.innerText = cached.evmUsd;
        if (solBalEl && cached.solBal) solBalEl.innerHTML = cached.solBal;
        if (solUsdEl && cached.solUsd) solUsdEl.innerText = cached.solUsd;
        if (nearBalEl && cached.nearBal) nearBalEl.innerHTML = cached.nearBal;
        if (nearUsdEl && cached.nearUsd) nearUsdEl.innerText = cached.nearUsd;

        lastBalancesSyncedTimestamp = cached.timestamp || now;
        updateLiveSyncTimer();
        if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-nearGreen';
        checkUnallocatedFunds();
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

      let curr = {
        btc: document.getElementById('btcAddress')?.dataset?.full || '',
        evm: document.getElementById('evmAddress')?.dataset?.full || '',
        sol: document.getElementById('solAddress')?.dataset?.full || '',
        near: document.getElementById('nearAddress')?.dataset?.full || ''
      };

      // In Evacuated state, addresses are masked in UI, but we check burned addresses for leftover funds
      if (isVaultEvacuatedOrBurned() && (!curr.btc || !curr.evm)) {
        const derivedKey = `aegis_derived_${currentSigner}_${currentEpochIndex}`;
        let cachedAddr = null;
        try { cachedAddr = JSON.parse(localStorage.getItem(derivedKey)); } catch(e) {}
        if (!cachedAddr && PRECOMPUTED_DERIVED_VAULTS[currentSigner]?.[currentEpochIndex]) {
          cachedAddr = PRECOMPUTED_DERIVED_VAULTS[currentSigner][currentEpochIndex];
        }
        if (cachedAddr) {
          curr = {
            btc: cachedAddr.btc || '',
            evm: cachedAddr.evm || '',
            sol: cachedAddr.sol || '',
            near: (cachedAddr.near && cachedAddr.near !== CONTRACT_ID) ? cachedAddr.near : ''
          };
        }
      }

      // 1. NEAR Implicit Bunker Balance via FastNEAR
      if (curr.near && curr.near !== CONTRACT_ID && curr.near.length === 64 && !curr.near.includes(' ')) {
        try {
          const nearRes = await fetch('https://test.rpc.fastnear.com', {
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
          } else {
            if (nearBalEl) nearBalEl.innerHTML = `0.0000 <span class="text-sm font-normal text-[#8C929D]">NEAR</span>`;
            if (nearUsdEl) nearUsdEl.innerText = `≈ 0.00 USD`;
          }
        } catch (e) {
          console.warn('NEAR RPC failed', e);
        }
      } else {
        if (nearBalEl) nearBalEl.innerHTML = `0.0000 <span class="text-sm font-normal text-[#8C929D]">NEAR</span>`;
        if (nearUsdEl) nearUsdEl.innerText = `≈ 0.00 USD`;
      }

      // 2. Sepolia EVM RPC
      if (curr.evm && curr.evm.startsWith('0x') && curr.evm.length === 42) {
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
      } else {
        if (evmBalEl) evmBalEl.innerHTML = `0.0000 <span class="text-sm font-normal text-[#8C929D]">ETH</span>`;
        if (evmUsdEl) evmUsdEl.innerText = `≈ 0.00 USD`;
      }

      // 3. Solana Devnet RPC
      if (curr.sol && curr.sol.length >= 32 && !curr.sol.includes(' ') && !curr.sol.includes('Locked') && !curr.sol.includes('Deriving')) {
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
      } else {
        if (solBalEl) solBalEl.innerHTML = `0.0000 <span class="text-sm font-normal text-[#8C929D]">SOL</span>`;
        if (solUsdEl) solUsdEl.innerText = `≈ 0.00 USD`;
      }

      // 4. Bitcoin Testnet Mempool.space
      if (curr.btc && (curr.btc.startsWith('tb1') || curr.btc.startsWith('bc1') || curr.btc.startsWith('m') || curr.btc.startsWith('n')) && !curr.btc.includes(' ')) {
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
      } else {
        if (btcBalEl) btcBalEl.innerHTML = `0.0000 <span class="text-sm font-normal text-[#8C929D]">BTC</span>`;
        if (btcUsdEl) btcUsdEl.innerText = `≈ 0.00 USD`;
      }

      // Save to cache scoped to account & vault state
      localStorage.setItem(`aegis_balance_cache_${currentSigner}`, JSON.stringify({
        contractId: CONTRACT_ID,
        state: lastFetchedVaultInfo?.state || 'Active',
        timestamp: Date.now(),
        btcBal: btcBalEl ? btcBalEl.innerHTML : '0.0000 <span class="text-sm font-normal text-[#8C929D]">BTC</span>',
        btcUsd: btcUsdEl ? btcUsdEl.innerText : '≈ 0.00 USD',
        evmBal: evmBalEl ? evmBalEl.innerHTML : '0.0000 <span class="text-sm font-normal text-[#8C929D]">ETH</span>',
        evmUsd: evmUsdEl ? evmUsdEl.innerText : '≈ 0.00 USD',
        solBal: solBalEl ? solBalEl.innerHTML : '0.0000 <span class="text-sm font-normal text-[#8C929D]">SOL</span>',
        solUsd: solUsdEl ? solUsdEl.innerText : '≈ 0.00 USD',
        nearBal: nearBalEl ? nearBalEl.innerHTML : '0.0000 <span class="text-sm font-normal text-[#8C929D]">NEAR</span>',
        nearUsd: nearUsdEl ? nearUsdEl.innerText : '≈ 0.00 USD'
      }));

      // Update monitor elements if active
      if (document.getElementById('monitorBtcBal') && btcBalEl) document.getElementById('monitorBtcBal').innerText = btcBalEl.innerText;
      if (document.getElementById('monitorEvmBal') && evmBalEl) document.getElementById('monitorEvmBal').innerText = evmBalEl.innerText;
      if (document.getElementById('monitorSolBal') && solBalEl) document.getElementById('monitorSolBal').innerText = solBalEl.innerText;
      if (document.getElementById('monitorNearBal') && nearBalEl) document.getElementById('monitorNearBal').innerText = nearBalEl.innerText;

      lastBalancesSyncedTimestamp = Date.now();
      updateLiveSyncTimer();
      if (syncDot) syncDot.className = 'w-2 h-2 rounded-full bg-nearGreen';
      checkUnallocatedFunds();
      if (force) showToast('Balances and rates updated from RPC');
    }

    async function rotateBunkerEpoch() {
      const isConnected = !!localStorage.getItem('aegis_signer_account');
      if (!isConnected) {
        showToast('Please connect your Meteor Wallet first!', true);
        connectMeteorWallet();
        return;
      }

      if (
        lastFetchedVaultInfo &&
        (lastFetchedVaultInfo.state === 'Evacuated' || lastFetchedVaultInfo.state === 'Inheritance') &&
        !lastFetchedVaultInfo.is_epoch_swept
      ) {
        showToast('ℹ️ Archiving current epoch for background Cloud Keeper sweep and rotating to clean epoch...');
        triggerCloudKeeperSweep(false);
      } else {
        showToast('Broadcasting rotate_bunker() to NEAR Testnet...');
      }
      try {
        const outcome = await dispatchNearTransaction('rotate_bunker');
        if (outcome) {
          const banner = document.getElementById('bunkerBurnedBanner');
          if (banner) banner.classList.add('hidden');
          const evacBanner = document.getElementById('evacuatedPolicyBanner');
          if (evacBanner) evacBanner.classList.add('hidden');
          const unconfigBanner = document.getElementById('unconfiguredBanner');
          if (unconfigBanner) unconfigBanner.classList.remove('hidden');

          remainingSeconds = 0;
          clearAllAddresses();

          inputIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
              el.disabled = false;
              el.value = '';
            }
          });

          const updatedInfo = await fetchLiveContractState();
          if (updatedInfo && typeof updatedInfo.epoch === 'number') {
            currentEpochIndex = updatedInfo.epoch;
          }

          renderBunkerAddresses();
          fetchLiveBalances(true);
          updateCountdownDisplay();
          showToast(`✅ Clean Bunker Activated! Active Epoch ${currentEpochIndex} (Unarmed - Enter destinations to arm)`);
        }
      } catch (err) {
        console.error('Rotate bunker failed:', err);
        showToast('Bunker rotation failed: ' + (err.message || err), true);
      }
    }

    // Configurable Inactivity & Grace Periods
    if (localStorage.getItem('aegis_inactivity_days') === 'demo_60s') {
      localStorage.setItem('aegis_inactivity_days', 'demo_120s');
    }
    if (localStorage.getItem('aegis_grace_days') === 'demo_15s') {
      localStorage.setItem('aegis_grace_days', 'demo_30s');
    }
    const initialInactPref = localStorage.getItem('aegis_inactivity_days') || '90';
    let inactivityDays = initialInactPref === 'demo_120s' ? 0 : parseInt(initialInactPref);
    let graceDays = localStorage.getItem('aegis_grace_days') === 'demo_30s' ? 0 : parseInt(localStorage.getItem('aegis_grace_days') || '7');
    let MAX_SECONDS = initialInactPref === 'demo_120s' ? 120 : (inactivityDays * 24 * 3600);

    function calculateInitialRemainingSeconds() {
      const currentEpoch = localStorage.getItem('aegis_bunker_epoch') || '0';
      if (localStorage.getItem('aegis_vault_burned_' + currentEpoch) === 'true') {
        return 0;
      }
      const cachedPing = localStorage.getItem('aegis_last_ping_ns');
      const cachedHb = localStorage.getItem('aegis_heartbeat_interval_ns');
      if (cachedPing && cachedHb) {
        try {
          const expireNs = BigInt(cachedPing) + BigInt(cachedHb);
          const nowNs = BigInt(Date.now()) * 1000000n;
          if (expireNs > nowNs) {
            return Number((expireNs - nowNs) / 1000000000n);
          }
          return 0;
        } catch (e) {}
      }
      return MAX_SECONDS;
    }
    let remainingSeconds = calculateInitialRemainingSeconds();
    let currentQrAddr = '';
    let countdownInterval = null;

    function updateSaveButtonState(info = lastFetchedVaultInfo) {
      const saveBtns = document.querySelectorAll('.save-policy-btn');
      if (!saveBtns.length) return;

      const pNear = document.getElementById('panicNearAddr')?.value?.trim() || '';
      const pBtc = document.getElementById('panicBtcAddr')?.value?.trim() || '';
      const pEvm = document.getElementById('panicEvmAddr')?.value?.trim() || '';
      const pSol = document.getElementById('panicSolAddr')?.value?.trim() || '';
      const hNear = document.getElementById('heirNearAddr')?.value?.trim() || '';
      const hBtc = document.getElementById('heirBtcAddr')?.value?.trim() || '';
      const hEvm = document.getElementById('heirEvmAddr')?.value?.trim() || '';
      const hSol = document.getElementById('heirSolAddr')?.value?.trim() || '';

      const onChainBackupNear = info?.backup?.near || '';
      const onChainBackupBtc = info?.backup?.btc || '';
      const onChainBackupEvm = info?.backup?.evm || '';
      const onChainBackupSol = info?.backup?.sol || '';
      const onChainHeirNear = info?.heirs?.near || '';
      const onChainHeirBtc = info?.heirs?.btc || '';
      const onChainHeirEvm = info?.heirs?.evm || '';
      const onChainHeirSol = info?.heirs?.sol || '';

      const hasOnChain = !!(onChainBackupNear || onChainBackupBtc || onChainBackupEvm || onChainBackupSol ||
                            onChainHeirNear || onChainHeirBtc || onChainHeirEvm || onChainHeirSol);

      const addressesMatch = hasOnChain &&
                         (pNear === onChainBackupNear) &&
                         (pBtc === onChainBackupBtc) &&
                         (pEvm === onChainBackupEvm) &&
                         (pSol === onChainBackupSol) &&
                         (hNear === onChainHeirNear) &&
                         (hBtc === onChainHeirBtc) &&
                         (hEvm === onChainHeirEvm) &&
                         (hSol === onChainHeirSol);

      const inactPref = document.getElementById('inactivitySelect')?.value || localStorage.getItem('aegis_inactivity_days') || '90';
      const gracePref = document.getElementById('graceSelect')?.value || localStorage.getItem('aegis_grace_days') || '7';
      const selectedHbNs = inactPref === 'demo_120s'
        ? 120000000000n
        : BigInt(parseInt(inactPref, 10) || 90) * 86400n * 1000000000n;
      const selectedCpNs = gracePref === 'demo_30s'
        ? 30000000000n
        : BigInt(parseInt(gracePref, 10) || 7) * 86400n * 1000000000n;
      const onChainHbNs = info?.heartbeat_interval_ns ? BigInt(info.heartbeat_interval_ns) : selectedHbNs;
      const onChainCpNs = info?.challenge_period_ns ? BigInt(info.challenge_period_ns) : selectedCpNs;
      const timersMatch = (selectedHbNs === onChainHbNs) && (selectedCpNs === onChainCpNs);
      const isMatching = addressesMatch && timersMatch;

      saveBtns.forEach(btn => {
        if (!localStorage.getItem('aegis_signer_account')) {
          btn.disabled = true;
          btn.innerHTML = `<span>Save Policy</span>`;
          btn.className = 'save-policy-btn bg-white/[0.04] text-white/30 border border-white/[0.08] font-bold py-2 px-5 rounded-xl text-xs cursor-not-allowed opacity-50 whitespace-nowrap';
          return;
        }

        if (isAddressDisplayLocked(info)) {
          const isInheritance = isInheritanceState(info);
          const isGraceOnly = Boolean(info && info.state === 'Active' && !isGracePeriodExpired(info) && isHeartbeatExpired(info));
          btn.disabled = true;
          btn.innerHTML = `
            <span class="flex items-center gap-1.5 ${isGraceOnly ? 'text-amber-400' : (isInheritance ? 'text-purple-400' : 'text-red-400')}">
              <svg class="w-3.5 h-3.5 ${isGraceOnly ? 'text-amber-400' : (isInheritance ? 'text-purple-400' : 'text-red-400')} shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
              <span>${isGraceOnly ? 'Heartbeat Expired (Check-in First)' : (isInheritance ? 'Inheritance Finalized (Inactive)' : 'Bunker Evacuated (Inactive)')}</span>
            </span>
          `;
          btn.className = `save-policy-btn ${isGraceOnly ? 'bg-amber-950/30 border border-amber-500/30 text-amber-400' : (isInheritance ? 'bg-purple-950/30 border border-purple-500/30 text-purple-400' : 'bg-red-950/30 border border-red-500/30 text-red-400')} font-bold py-2 px-5 rounded-xl text-xs cursor-not-allowed opacity-80 whitespace-nowrap`;
          return;
        }

        btn.disabled = false;
        if (isMatching) {
          btn.innerHTML = `
            <span class="flex items-center gap-1.5 text-nearGreen">
              <svg class="w-3.5 h-3.5 text-nearGreen shrink-0" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
              <span>Policy Saved & Armed</span>
            </span>
          `;
          btn.className = 'save-policy-btn bg-nearGreen/15 hover:bg-nearGreen/25 text-nearGreen border border-nearGreen/40 font-bold py-2 px-5 rounded-xl text-xs transition active:scale-98 whitespace-nowrap cursor-pointer';
        } else {
          const isReplacingExisting = hasOnChain && !addressesMatch;
          if (isReplacingExisting) {
            btn.innerHTML = `Save Policy (72h Cooldown)`;
            btn.className = 'save-policy-btn bg-amber-400 hover:bg-amber-300 text-black font-extrabold py-2 px-5 rounded-xl text-xs transition shadow-sm active:scale-98 whitespace-nowrap cursor-pointer';
          } else {
            btn.innerHTML = `Save Policy (⚡ Instant)`;
            btn.className = 'save-policy-btn bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-2 px-5 rounded-xl text-xs transition shadow-near-glow active:scale-98 whitespace-nowrap cursor-pointer';
          }
        }
      });
    }

    // Initialize UI Selectors
    document.addEventListener('DOMContentLoaded', () => {
      const inactSelectEl = document.getElementById('inactivitySelect');
      if (inactSelectEl) inactSelectEl.value = initialInactPref;
      const graceSelectEl = document.getElementById('graceSelect');
      const savedGracePref = localStorage.getItem('aegis_grace_days') || '7';
      if (graceSelectEl) graceSelectEl.value = savedGracePref;
      const modalGraceEl = document.getElementById('modalGraceSelect');
      if (modalGraceEl) modalGraceEl.value = savedGracePref;
      
      const savedTg = localStorage.getItem('aegis_tg');
      const savedEmail = localStorage.getItem('aegis_email');
      if (savedTg) document.getElementById('tgUsernameInput').value = savedTg.replace(/^@+/, '');
      if (savedEmail) document.getElementById('emailAlertInput').value = savedEmail;
      const badge = document.getElementById('tgStatusBadge');
      if (badge && (savedTg || savedEmail)) {
        badge.innerHTML = `
          <span class="w-2 h-2 rounded-full bg-nearGreen radar-pulse"></span>
          <span>Relayer: <strong class="text-nearGreen">${escapeHtml(savedTg || savedEmail)}</strong></span>
        `;
      }

      renderBunkerAddresses();
      loadSavedAddresses();
      updatePanicUI();
      fetchLiveBalances(false); // Uses 30s cache if fresh
      setInterval(() => fetchLiveBalances(false), 30 * 1000); // Check balances every 30s
      setInterval(updateLiveSyncTimer, 1000); // Live seconds timer display
    });

    function changeInactivityPeriod(val) {
      let hbNs;
      let cpNs = null;
      isEditing = true;
      if (val === 'demo_120s') {
        MAX_SECONDS = 120;
        remainingSeconds = 120;
        hbNs = '120000000000'; // 120 seconds (2 minutes)
        cpNs = '30000000000'; // 30 seconds Grace Window for fast Judge Demo
        localStorage.setItem('aegis_inactivity_days', 'demo_120s');
        localStorage.setItem('aegis_grace_days', 'demo_30s');
        const sel1 = document.getElementById('graceSelect');
        const sel2 = document.getElementById('modalGraceSelect');
        if (sel1) sel1.value = 'demo_30s';
        if (sel2) sel2.value = 'demo_30s';
      } else {
        inactivityDays = parseInt(val);
        MAX_SECONDS = inactivityDays * 24 * 3600;
        remainingSeconds = MAX_SECONDS;
        hbNs = (BigInt(val) * 86400n * 1000000000n).toString();
        localStorage.setItem('aegis_inactivity_days', val);
      }
      updateCountdownDisplay();
      updateSaveButtonState(lastFetchedVaultInfo);
      if (!lastFetchedVaultInfo || lastFetchedVaultInfo.state === 'Unconfigured' || !hasConfiguredDestinations(lastFetchedVaultInfo)) {
        showToast(`Timer set to ${val === 'demo_120s' ? '2m' : val + ' days'}. Will be armed on-chain once you save policy.`);
        return;
      }
      showToast(`Broadcasting check-in timer update (${val === 'demo_120s' ? '2m' : val + ' days'}) to NEAR...`);
      dispatchNearTransaction('update_intervals', { heartbeat_interval_ns: hbNs, challenge_period_ns: cpNs });
    }

    function changeGracePeriod(val) {
      let cpNs;
      isEditing = true;
      const sel1 = document.getElementById('graceSelect');
      const sel2 = document.getElementById('modalGraceSelect');
      if (sel1) sel1.value = val;
      if (sel2) sel2.value = val;

      if (val === 'demo_30s') {
        cpNs = '30000000000'; // 30 seconds
        localStorage.setItem('aegis_grace_days', 'demo_30s');
      } else {
        graceDays = parseInt(val);
        cpNs = (BigInt(val) * 86400n * 1000000000n).toString();
        localStorage.setItem('aegis_grace_days', val);
      }
      updateSaveButtonState(lastFetchedVaultInfo);
      if (!lastFetchedVaultInfo || lastFetchedVaultInfo.state === 'Unconfigured' || !hasConfiguredDestinations(lastFetchedVaultInfo)) {
        showToast(`Grace window set to ${val === 'demo_30s' ? '30s' : val + ' days'}. Will be armed on-chain once you save policy.`);
        return;
      }
      showToast(`Broadcasting grace period update (${val === 'demo_30s' ? '30s' : val + ' days'}) to NEAR...`);
      dispatchNearTransaction('update_intervals', { heartbeat_interval_ns: null, challenge_period_ns: cpNs });
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
      const isConnected = !!localStorage.getItem('aegis_signer_account');
      const pulseDot = document.getElementById('heartbeatPulseDot');
      const cardTitle = document.getElementById('heartbeatCardTitle');
      const heartbeatTag = document.getElementById('heartbeatTag');
      const countdownTitle = document.getElementById('countdownTitle');
      const countdownBox = document.getElementById('countdownBox');
      const statusDisplay = document.getElementById('statusDisplay');
      const pingBtn = document.getElementById('pingMainBtn');
      const pingBtnText = document.getElementById('pingMainBtnText');
      const pingBtnIcon = document.getElementById('pingMainBtnIcon');
      const timerBar = document.getElementById('timerBar');
      const pctEl = document.getElementById('timerPctDisplay');

      const onchainEl = document.getElementById('onchainPingOption');
      if (!isConnected) {
        if (onchainEl) onchainEl.classList.add('hidden');
        if (countdownBox) countdownBox.innerText = 'Ready to Arm';
        if (timerBar) {
          timerBar.style.width = '100%';
          timerBar.className = 'h-full bg-nearGreen rounded-full transition-all duration-300';
        }
        if (pctEl) pctEl.innerText = '100.0% remaining';
        if (pingBtn) {
          pingBtn.className = 'w-full bg-purple-600 hover:bg-purple-500 text-white font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-sm active:scale-98 flex items-center justify-center gap-2';
        }
        if (pingBtnText) pingBtnText.innerText = 'Connect Wallet to Arm Vault';
        return;
      }

      // Check if Vault is Evacuated or Burned
      if (isVaultEvacuatedOrBurned()) {
        const isInheritance = lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Inheritance';
        if (onchainEl) onchainEl.classList.add('hidden');
        const nextEpoch = lastFetchedVaultInfo && typeof lastFetchedVaultInfo.epoch === 'number'
          ? (lastFetchedVaultInfo.epoch + 1)
          : (currentEpochIndex + 1);

        if (pulseDot) pulseDot.className = isInheritance ? 'w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse' : 'w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse';
        if (cardTitle) {
          cardTitle.className = isInheritance ? 'text-xs font-mono font-bold uppercase tracking-wider text-purple-400' : 'text-xs font-mono font-bold uppercase tracking-wider text-red-400';
          cardTitle.innerText = isInheritance ? 'AUTONOMOUS INHERITANCE · TRANSFERRED' : 'BUNKER EVACUATED · KEYS BURNED';
        }
        if (heartbeatTag) {
          heartbeatTag.className = isInheritance
            ? 'text-xs font-mono font-medium text-purple-300 bg-purple-950/40 px-3 py-1 rounded-full border border-purple-500/30'
            : 'text-xs font-mono font-medium text-red-400 bg-red-950/40 px-3 py-1 rounded-full border border-red-500/30';
          heartbeatTag.innerText = isInheritance ? 'Inheritance Executed · Inactive' : 'Vault Evacuated · Inactive';
        }
        if (countdownTitle) {
          countdownTitle.innerText = isInheritance ? 'Heir Transfer Executed · Rotation Required:' : 'Bunker Evacuated · Rotation Required:';
        }
        if (countdownBox) {
          countdownBox.innerHTML = isInheritance
            ? '<span class="text-purple-400 font-extrabold tracking-wider">INHERITED</span>'
            : '<span class="text-red-400 font-extrabold tracking-wider">EVACUATED</span>';
        }
        if (statusDisplay) {
          statusDisplay.innerHTML = isInheritance
            ? 'Status: <strong class="text-purple-400 font-bold">Transferred to Heirs (Bunker Closed)</strong>'
            : 'Status: <strong class="text-red-400 font-bold">Evacuated (Keys Burned)</strong>';
        }
        if (timerBar) {
          timerBar.style.width = '0%';
          timerBar.className = isInheritance
            ? 'h-full bg-purple-500 rounded-full transition-all duration-300'
            : 'h-full bg-red-500 rounded-full transition-all duration-300';
        }
        if (pctEl) {
          pctEl.innerText = isInheritance ? '0.0% · Transferred to Heirs' : '0.0% · Vault Burned';
        }

        if (pingBtn) {
          pingBtn.className = 'w-full bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-near-glow active:scale-98 flex items-center justify-center gap-2';
        }
        if (pingBtnIcon) {
          pingBtnIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />';
          pingBtnIcon.setAttribute('viewBox', '0 0 24 24');
          pingBtnIcon.setAttribute('fill', 'none');
          pingBtnIcon.setAttribute('stroke', 'currentColor');
          pingBtnIcon.setAttribute('stroke-width', '2.5');
        }
        if (pingBtnText) {
          pingBtnText.innerText = `Activate Clean Bunker (Epoch ${nextEpoch})`;
        }

        // Header Panic Button: Disabled
        const headerPanic = document.getElementById('headerPanicBtn');
        const panicLabel = document.getElementById('panicBtnLabel');
        const panicLabelMobile = document.getElementById('panicBtnLabelMobile');
        const panicDot = document.getElementById('panicBtnDot');
        if (headerPanic) {
          headerPanic.disabled = true;
          headerPanic.className = 'h-9 px-3.5 sm:px-4 rounded-xl bg-red-950/20 text-red-500/50 border border-red-500/20 text-xs sm:text-sm font-mono font-bold tracking-wider cursor-not-allowed opacity-40 flex items-center gap-2 shrink-0 whitespace-nowrap';
        }
        if (panicLabel) {
          panicLabel.innerText = isInheritance ? 'INHERITANCE EXECUTED' : 'VAULT EVACUATED';
        }
        if (panicLabelMobile) {
          panicLabelMobile.innerText = isInheritance ? 'INHERITED' : 'EVACUATED';
        }
        if (panicDot) {
          panicDot.className = isInheritance ? 'w-2 h-2 rounded-full bg-purple-500/40 shrink-0' : 'w-2 h-2 rounded-full bg-red-500/40 shrink-0';
        }

        // Dropdowns: Disabled when evacuated
        const inactSelect = document.getElementById('inactivitySelect');
        const graceSelect = document.getElementById('graceSelect');
        if (inactSelect) inactSelect.disabled = true;
        if (graceSelect) graceSelect.disabled = true;
        return;
      }

      // Check if Vault is unconfigured or has no destinations
      if (!lastFetchedVaultInfo || lastFetchedVaultInfo.state === 'Unconfigured' || !hasConfiguredDestinations()) {
        if (onchainEl) onchainEl.classList.add('hidden');
        if (pulseDot) pulseDot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400';
        if (cardTitle) {
          cardTitle.className = 'text-xs font-mono font-bold uppercase tracking-wider text-amber-400';
          cardTitle.innerText = 'AUTONOMOUS HEARTBEAT MONITOR';
        }
        if (heartbeatTag) {
          heartbeatTag.className = 'text-xs font-mono font-medium text-amber-400/90 bg-amber-950/30 px-3 py-1 rounded-full border border-amber-500/30';
          heartbeatTag.innerText = 'Vault Unarmed';
        }
        if (countdownTitle) countdownTitle.innerText = "Dead-Man's Switch Heartbeat:";
        if (countdownBox) countdownBox.innerText = 'Ready to Arm';
        if (statusDisplay) statusDisplay.innerHTML = 'Status: <strong class="text-amber-400 font-bold">Unconfigured (Enter Destinations)</strong>';
        if (timerBar) {
          timerBar.style.width = '100%';
          timerBar.className = 'h-full bg-amber-400/50 rounded-full transition-all duration-300';
        }
        if (pctEl) pctEl.innerText = 'Waiting for destinations';

        if (pingBtn) {
          pingBtn.className = 'w-full bg-amber-400 hover:bg-amber-300 text-black font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-sm active:scale-98 flex items-center justify-center gap-2';
        }
        if (pingBtnIcon) {
          pingBtnIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>';
          pingBtnIcon.setAttribute('viewBox', '0 0 24 24');
          pingBtnIcon.setAttribute('fill', 'none');
          pingBtnIcon.setAttribute('stroke', 'currentColor');
          pingBtnIcon.setAttribute('stroke-width', '2');
        }
        if (pingBtnText) {
          pingBtnText.innerText = 'Save Policy Below to Arm Vault';
        }

        const headerPanic = document.getElementById('headerPanicBtn');
        const panicLabel = document.getElementById('panicBtnLabel');
        const panicLabelMobile = document.getElementById('panicBtnLabelMobile');
        const panicDot = document.getElementById('panicBtnDot');
        if (headerPanic) {
          headerPanic.disabled = true;
          headerPanic.className = 'h-9 px-3.5 sm:px-4 rounded-xl bg-amber-950/20 text-amber-500/50 border border-amber-500/20 text-xs sm:text-sm font-mono font-bold tracking-wider cursor-not-allowed opacity-40 flex items-center gap-2 shrink-0 whitespace-nowrap';
        }
        if (panicLabel) panicLabel.innerText = 'VAULT UNARMED';
        if (panicLabelMobile) panicLabelMobile.innerText = 'UNARMED';
        if (panicDot) panicDot.className = 'w-2 h-2 rounded-full bg-amber-500/40 shrink-0';

        const inactSelect = document.getElementById('inactivitySelect');
        const graceSelect = document.getElementById('graceSelect');
        if (inactSelect) inactSelect.disabled = false;
        if (graceSelect) graceSelect.disabled = false;
        return;
      }

      // Normal Active or Expiring State
      
      if (pulseDot) pulseDot.className = 'w-2.5 h-2.5 rounded-full bg-nearGreen radar-pulse';
      if (cardTitle) {
        cardTitle.className = 'text-xs font-mono font-bold uppercase tracking-wider text-nearGreen';
        cardTitle.innerText = 'AUTONOMOUS HEARTBEAT MONITOR';
      }
      if (heartbeatTag) {
        heartbeatTag.className = 'text-xs font-mono font-medium text-textGray bg-nearElevated px-3 py-1 rounded-full border border-nearBorder';
        heartbeatTag.innerText = 'Last check-in: Active';
      }
      if (countdownTitle) countdownTitle.innerText = 'Automatic Transfer to Heirs Initiates In:';
      if (pingBtn) {
        pingBtn.className = 'w-full bg-nearGreen hover:bg-nearGreenHover text-nearBlack font-extrabold py-3.5 px-6 near-pill-btn text-sm sm:text-base tracking-wide transition shadow-near-glow active:scale-98 flex items-center justify-center gap-2';
      }
      if (pingBtnIcon) {
        pingBtnIcon.innerHTML = '<path d="M12 2L14.4 7.2L20 8L16 12L17 17.6L12 15L7 17.6L8 12L4 8L9.6 7.2L12 2Z"/>';
        pingBtnIcon.setAttribute('viewBox', '0 0 24 24');
        pingBtnIcon.setAttribute('fill', 'currentColor');
        pingBtnIcon.removeAttribute('stroke');
        pingBtnIcon.removeAttribute('stroke-width');
      }

      const headerPanic = document.getElementById('headerPanicBtn');
      if (headerPanic) {
        headerPanic.disabled = false;
        updatePanicUI();
      }
      const inactSelect = document.getElementById('inactivitySelect');
      const graceSelect = document.getElementById('graceSelect');
      if (inactSelect) inactSelect.disabled = false;
      if (graceSelect) graceSelect.disabled = false;

      if (remainingSeconds <= 0) {
        if (countdownBox) countdownBox.innerHTML = '<span class="text-red-400">EXPIRED</span>';
        let graceRemainingSec = 0;
        if (lastFetchedVaultInfo && lastFetchedVaultInfo.last_ping_ns) {
          const fullExpiryMs = Number(
            (BigInt(lastFetchedVaultInfo.last_ping_ns) +
              BigInt(lastFetchedVaultInfo.heartbeat_interval_ns || '0') +
              BigInt(lastFetchedVaultInfo.challenge_period_ns || '0')) / 1000000n
          );
          graceRemainingSec = Math.max(0, Math.ceil((fullExpiryMs - Date.now()) / 1000));
          if (Date.now() >= fullExpiryMs + 1500 && Date.now() - lastCloudKeeperNudgeMs > 8000) {
            lastCloudKeeperNudgeMs = Date.now();
            triggerCloudKeeperSweep(false);
          }
        }
        if (statusDisplay) {
          statusDisplay.innerHTML = graceRemainingSec > 0
            ? `Status: <strong class="text-amber-400 font-bold">Grace Buffer (${graceRemainingSec}s left)</strong>`
            : 'Status: <strong class="text-red-400 font-bold">Heartbeat & Grace Expired · Sweeping</strong>';
        }
        if (timerBar) {
          timerBar.style.width = '0%';
          timerBar.className = 'h-full bg-red-500 rounded-full transition-all duration-300';
        }
        if (pctEl) pctEl.innerText = '0.0% remaining';
        if (pingBtnText) pingBtnText.innerText = "I'M ALIVE (Recover & Reset)";
        if (onchainEl && !isVaultEvacuatedOrBurned()) {
          onchainEl.classList.remove('hidden');
          const bannerLabel = graceRemainingSec > 0
            ? `Grace Buffer Active (${graceRemainingSec}s before autonomous sweep)`
            : 'Autonomous Push Inheritance Executing via Cloud Keeper';
          onchainEl.innerHTML = `
            <div class="w-full mt-2.5 bg-amber-500/10 border border-amber-500/30 text-amber-300 px-4 py-2.5 rounded-xl text-xs flex items-center justify-between gap-3 cursor-pointer" onclick="openEvacMonitor('inheritance')">
              <span class="flex items-center gap-2 min-w-0 flex-1">
                <span class="w-2 h-2 rounded-full bg-amber-400 animate-ping shrink-0"></span>
                <span class="truncate">${bannerLabel}</span>
              </span>
              <span class="text-[10px] font-mono bg-amber-950/40 px-2.5 py-0.5 rounded border border-amber-500/30 shrink-0 whitespace-nowrap">View Live Sweep</span>
            </div>
          `;
        }
        return;
      } else {
        if (onchainEl) onchainEl.classList.add('hidden');
      }

      if (statusDisplay) statusDisplay.innerHTML = 'Status: <strong class="text-nearGreen font-bold">Active & Enforced</strong>';
      if (pingBtnText) pingBtnText.innerText = "I'M ALIVE (Check-in Now)";

      const { d, h, m, s } = formatTime(remainingSeconds);
      if (countdownBox) {
        countdownBox.innerHTML = 
          `${d}<span class="text-textGray text-2xl font-normal">d</span> ` +
          `${h}<span class="text-textGray text-2xl font-normal">h</span> ` +
          `${m}<span class="text-textGray text-2xl font-normal">m</span> ` +
          `${s}<span class="text-textGray text-2xl font-normal">s</span>`;
      }
      
      const pct = Math.max(0, Math.min(100, (remainingSeconds / MAX_SECONDS) * 100));
      if (timerBar) {
        timerBar.style.width = pct + '%';
        timerBar.className = 'h-full bg-nearGreen rounded-full transition-all duration-300';
      }
      if (pctEl) pctEl.innerText = `${pct.toFixed(1)}% remaining`;

      // Sync Top Heartbeat 72h Timelock Notice
      const hbNotice = document.getElementById('heartbeatTimelockNotice');
      const hbText = document.getElementById('heartbeatTimelockText');
      if (hbNotice && hbText) {
        if (lastFetchedVaultInfo && lastFetchedVaultInfo.pending_policy) {
          const effectiveNs = BigInt(lastFetchedVaultInfo.pending_policy.effective_at_ns);
          const nowNs = BigInt(lastFetchedVaultInfo.current_time_ns || (Date.now() * 1000000));
          const secLeft = Number(effectiveNs > nowNs ? (effectiveNs - nowNs) / 1000000000n : 0n);
          const hoursLeft = Math.floor(secLeft / 3600);
          const minsLeft = Math.floor((secLeft % 3600) / 60);
          hbNotice.classList.remove('hidden');
          hbText.innerText = secLeft > 0
            ? `72h Timelock Active (${hoursLeft}h ${minsLeft}m left)`
            : '72h Timelock Elapsed (Ready to Apply)';
        } else {
          hbNotice.classList.add('hidden');
        }
      }
    }

    async function triggerInheritanceNow() {
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner) {
        showToast('Please connect wallet first', true);
        return;
      }
      showToast('Broadcasting trigger_push_inheritance to NEAR...');
      try {
        const outcome = await dispatchNearTransaction('trigger_push_inheritance', { vault_owner: currentSigner });
        if (outcome) {
          showToast('Inheritance triggered on-chain! Dispatching Cloud Keeper...');
          openEvacMonitor();
          triggerCloudKeeperSweep(false);
          setTimeout(() => fetchLiveBalances(true), 1500);
        }
      } catch (e) {
        showToast('Failed to trigger inheritance: ' + (e.message || e), true);
      }
    }

    if (countdownInterval) clearInterval(countdownInterval);
    let _wasHbExpired = false;
    let _wasGraceExpired = false;
    let _lastExpiryRpcPollMs = 0;
    countdownInterval = setInterval(() => {
      if (hasConfiguredDestinations() && lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Active') {
        if (remainingSeconds > 0) remainingSeconds--;
      }
      const nowHbExpired = isHeartbeatExpired(lastFetchedVaultInfo);
      const nowGraceExpired = isGracePeriodExpired(lastFetchedVaultInfo);
      if (nowHbExpired !== _wasHbExpired || nowGraceExpired !== _wasGraceExpired) {
        _wasHbExpired = nowHbExpired;
        _wasGraceExpired = nowGraceExpired;
        renderBunkerAddresses();
        syncUIWithOnChainState(lastFetchedVaultInfo, localStorage.getItem('aegis_signer_account'));
        loadSavedAddresses();
        updateSaveButtonState(lastFetchedVaultInfo);
      }
      if (nowGraceExpired && lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Active') {
        if (Date.now() - _lastExpiryRpcPollMs > 4000) {
          _lastExpiryRpcPollMs = Date.now();
          fetchLiveContractState();
        }
      }
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
      if (!localStorage.getItem('aegis_signer_account')) {
        showToast('Connect wallet first', true);
        return;
      }
      if (isAddressDisplayLocked()) {
        showToast('🛑 Deposit rejected: Bunker epoch is expired or closed. Check-in or activate a clean bunker first.', true);
        return;
      }
      const chainId = elemId.replace('Address', '').toLowerCase();
      const b = lastFetchedVaultInfo?.backup?.[chainId]?.trim();
      const h = lastFetchedVaultInfo?.heirs?.[chainId]?.trim();
      if (!b || !h) {
        showToast(`⚠️ ${chainId.toUpperCase()} locked: Set both Panic & Heir destinations in Tab 1 first.`, true);
        switchTab('rescue');
        return;
      }
      const el = document.getElementById(elemId);
      const text = el ? (el.dataset.full || el.innerText) : '';
      if (!text || text.includes('Bunker Unarmed') || text.includes('Epoch ') || text.includes('Heartbeat Expired') || text.includes('Connect wallet') || text.includes('Deriving') || text.includes('Egress Incomplete')) {
        showToast('No active deposit address available', true);
        return;
      }
      navigator.clipboard.writeText(text);
      showToast('Deposit address copied! ⚠️ Do NOT save permanently in exchange whitelist (epoch burns after evacuation).');
    }

    // Ping Main Button Handler (Smart Connected / Disconnected / Evacuated / Unconfigured)
    async function handlePingMainBtnClick() {
      const isConnected = !!localStorage.getItem('aegis_signer_account');
      if (!isConnected) {
        openMultichainWalletModal();
        return;
      }
      if (isVaultEvacuatedOrBurned()) {
        rotateBunkerEpoch();
        return;
      }
      if (isGracePeriodExpired(lastFetchedVaultInfo)) {
        const refreshed = await fetchLiveContractState();
        if (refreshed && (refreshed.state === 'Evacuated' || refreshed.state === 'Inheritance')) {
          rotateBunkerEpoch();
          return;
        }
      }
      if (!hasConfiguredDestinations() || (lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Unconfigured')) {
        const destSection = document.getElementById('panel-rescue') || document.getElementById('tab-rescue');
        if (destSection) {
          switchTab('rescue');
          destSection.scrollIntoView({ behavior: 'smooth' });
        }
        showToast('Please enter your destination addresses below and click Save Policy to arm your bunker.', true);
        return;
      }

      // On-chain ping with 0 deposit: signed by the function-call access key created at sign-in
      // (no approval popup in Meteor/HERE). Only on-chain last_ping_ns protects against start_claim.
      const outcome = await dispatchNearTransaction('ping');
      if (outcome) setTimeout(fetchLiveContractState, 1500);
    }

    // Tab Switching
    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('text-nearBlack', 'bg-nearGreen', 'font-bold');
        btn.classList.add('text-[#8C929D]', 'font-semibold');
      });
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));

      const activeBtn = document.getElementById(`tab-${name}`);
      if (activeBtn) {
        activeBtn.classList.add('text-nearBlack', 'bg-nearGreen', 'font-bold');
        activeBtn.classList.remove('text-[#8C929D]', 'font-semibold');
      }
      const panel = document.getElementById(`panel-${name}`);
      if (panel) panel.classList.remove('hidden');

      if (name === 'vault') {
        renderBunkerAddresses();
        fetchLiveBalances(isAddressDisplayLocked());
      } else if (name === 'rescue') {
        loadSavedAddresses();
      }
    }

    // QR Code
    function openQr(title, address) {
      if (!localStorage.getItem('aegis_signer_account')) {
        showToast('Connect wallet first', true);
        return;
      }
      if (isAddressDisplayLocked()) {
        showToast('🛑 QR Code disabled: Bunker epoch is expired or closed.', true);
        return;
      }
      if (!address || address.includes('Bunker Unarmed') || address.includes('Epoch ') || address.includes('Heartbeat Expired') || address.includes('Connect wallet') || address.includes('Deriving') || address.includes('Egress Incomplete')) {
        showToast('⚠️ QR Code locked: Configure Panic and Heir destinations in Tab 1 first.', true);
        switchTab('rescue');
        return;
      }
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
      showToast('Address copied! ⚠️ Do NOT whitelist on exchanges (epoch burns after evacuation).');
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
      const labelMob = document.getElementById('panicBtnLabelMobile');
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
          btn.className = "h-9 px-3.5 sm:px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white border-2 border-red-400 transition text-xs sm:text-sm font-mono font-extrabold tracking-wider active:scale-98 flex items-center gap-2 shadow-danger-glow shrink-0 whitespace-nowrap";
          label.innerText = "⚡ 1-CLICK PANIC";
          if (labelMob) labelMob.innerText = "⚡ PANIC";
          dot.className = "w-2.5 h-2.5 rounded-full bg-white animate-ping shrink-0";
        } else {
          btn.className = "h-9 px-3.5 sm:px-4 rounded-xl bg-red-950/40 hover:bg-red-950/70 text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/60 transition text-xs sm:text-sm font-mono font-bold tracking-wider active:scale-98 flex items-center gap-2 shadow-sm shrink-0 whitespace-nowrap";
          label.innerText = "EMERGENCY PANIC";
          if (labelMob) labelMob.innerText = "PANIC";
          dot.className = "w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0";
        }
      }
    }

    function parseNumericBalance(str) {
      if (!str) return 0;
      const clean = str.replace(/<[^>]*>/g, ' ').trim();
      const match = clean.match(/([0-9]+(\.[0-9]+)?)/);
      return match ? parseFloat(match[1]) : 0;
    }

    function getUnallocatedBunkerFunds() {
      const unallocated = [];
      const currentSigner = localStorage.getItem('aegis_signer_account');
      const info = lastFetchedVaultInfo;
      // Never show unallocated alerts if disconnected, unconfigured, or already evacuated
      if (!currentSigner || !info || info.state !== 'Active' || !hasConfiguredDestinations(info)) {
        return unallocated;
      }
      const backup = info.backup || {};

      let cachedBal = {};
      try {
        cachedBal = JSON.parse(localStorage.getItem(`aegis_balance_cache_${currentSigner}`) || '{}');
      } catch(e) {}

      // Strictly read cached balances associated with currentSigner
      const btcVal = cachedBal.btcBal ? parseNumericBalance(cachedBal.btcBal) : 0;
      const evmVal = cachedBal.evmBal ? parseNumericBalance(cachedBal.evmBal) : 0;
      const solVal = cachedBal.solBal ? parseNumericBalance(cachedBal.solBal) : 0;
      const nearVal = cachedBal.nearBal ? parseNumericBalance(cachedBal.nearBal) : 0;

      const hasBtc = !!(backup.btc?.trim() || document.getElementById('panicBtcAddr')?.value?.trim());
      const hasEvm = !!(backup.evm?.trim() || document.getElementById('panicEvmAddr')?.value?.trim());
      const hasSol = !!(backup.sol?.trim() || document.getElementById('panicSolAddr')?.value?.trim());
      const hasNear = !!(backup.near?.trim() || document.getElementById('panicNearAddr')?.value?.trim());

      if (btcVal > 0 && !hasBtc) {
        unallocated.push(`Bitcoin (${btcVal} BTC)`);
      }
      if (evmVal > 0 && !hasEvm) {
        unallocated.push(`Ethereum / EVM (${evmVal} ETH)`);
      }
      if (solVal > 0 && !hasSol) {
        unallocated.push(`Solana (${solVal} SOL)`);
      }
      if (nearVal > 0 && !hasNear) {
        unallocated.push(`NEAR (${nearVal} NEAR)`);
      }

      return unallocated;
    }

    function getUnallocatedHeirFunds() {
      const unallocatedHeirs = [];
      const currentSigner = localStorage.getItem('aegis_signer_account');
      const info = lastFetchedVaultInfo;
      if (!currentSigner || !info || info.state !== 'Active' || !hasConfiguredDestinations(info)) {
        return unallocatedHeirs;
      }
      const heirs = info.heirs || {};

      let cachedBal = {};
      try {
        cachedBal = JSON.parse(localStorage.getItem(`aegis_balance_cache_${currentSigner}`) || '{}');
      } catch(e) {}

      const btcVal = cachedBal.btcBal ? parseNumericBalance(cachedBal.btcBal) : 0;
      const evmVal = cachedBal.evmBal ? parseNumericBalance(cachedBal.evmBal) : 0;
      const solVal = cachedBal.solBal ? parseNumericBalance(cachedBal.solBal) : 0;
      const nearVal = cachedBal.nearBal ? parseNumericBalance(cachedBal.nearBal) : 0;

      const hasBtc = !!(heirs.btc?.trim() || document.getElementById('heirBtcAddr')?.value?.trim());
      const hasEvm = !!(heirs.evm?.trim() || document.getElementById('heirEvmAddr')?.value?.trim());
      const hasSol = !!(heirs.sol?.trim() || document.getElementById('heirSolAddr')?.value?.trim());
      const hasNear = !!(heirs.near?.trim() || document.getElementById('heirNearAddr')?.value?.trim());

      if (btcVal > 0 && !hasBtc) {
        unallocatedHeirs.push(`Bitcoin (${btcVal} BTC)`);
      }
      if (evmVal > 0 && !hasEvm) {
        unallocatedHeirs.push(`Ethereum / EVM (${evmVal} ETH)`);
      }
      if (solVal > 0 && !hasSol) {
        unallocatedHeirs.push(`Solana (${solVal} SOL)`);
      }
      if (nearVal > 0 && !hasNear) {
        unallocatedHeirs.push(`NEAR (${nearVal} NEAR)`);
      }

      return unallocatedHeirs;
    }

    function checkUnallocatedFunds() {
      const unallocated = getUnallocatedBunkerFunds();
      const unallocatedHeirs = getUnallocatedHeirFunds();
      const hasUnallocated = unallocated.length > 0 || unallocatedHeirs.length > 0;

      const depBanner = document.getElementById('unallocatedDepositAlert');
      const depText = document.getElementById('unallocatedDepositText');
      if (depBanner && depText) {
        if (unallocated.length > 0) {
          depBanner.classList.remove('hidden');
          depBanner.classList.add('flex');
          depText.innerText = `You have funds deposited in ${unallocated.join(', ')}, but no emergency backup destination address configured. These funds will NOT be evacuated on panic!`;
        } else {
          depBanner.classList.add('hidden');
          depBanner.classList.remove('flex');
        }
      }

      const polBanner = document.getElementById('unallocatedPolicyAlert');
      const polText = document.getElementById('unallocatedPolicyText');
      if (polBanner && polText) {
        if (hasUnallocated) {
          polBanner.classList.remove('hidden');
          polBanner.classList.add('flex');
          let msgs = [];
          if (unallocated.length > 0) msgs.push(`Emergency Panic: missing backup for ${unallocated.join(', ')}`);
          if (unallocatedHeirs.length > 0) msgs.push(`Family Inheritance: missing heir for ${unallocatedHeirs.join(', ')}`);
          polText.innerText = `Unallocated assets detected: ${msgs.join(' · ')}. Save destination addresses to protect these assets!`;
        } else {
          polBanner.classList.add('hidden');
          polBanner.classList.remove('flex');
        }
      }

      // Also update banner in evacuated/inherited state if leftover funds exist
      const isEvacuated = Boolean(lastFetchedVaultInfo && (lastFetchedVaultInfo.state === 'Evacuated' || lastFetchedVaultInfo.state === 'Inheritance' || isGracePeriodExpired(lastFetchedVaultInfo)));
      const burnedHeader = document.querySelector('#bunkerBurnedBanner h4');
      const burnedText = document.querySelector('#bunkerBurnedBanner p');
      if (isEvacuated && burnedHeader && burnedText) {
        const isInheritance = isInheritanceState(lastFetchedVaultInfo);
        const isEpochSwept = Boolean(lastFetchedVaultInfo && lastFetchedVaultInfo.is_epoch_swept);
        if (unallocated.length > 0) {
          burnedHeader.innerText = '⚠️ Evacuation Incomplete — Leftover Assets in Bunker!';
          burnedHeader.className = 'text-sm font-extrabold text-amber-200';
          burnedText.innerHTML = `Active epoch keys were evacuated, but <strong>${unallocated.join(', ')}</strong> were left behind because destination addresses were missing! Enter addresses in Tab 1 to rescue remaining funds before activating the next bunker.`;
        } else {
          burnedHeader.innerText = isInheritance
            ? 'Inheritance Finalized — Path Rotation Required'
            : 'Epoch Exhausted — Path Rotation Required';
          burnedHeader.className = isInheritance
            ? 'text-sm font-extrabold text-purple-200'
            : 'text-sm font-extrabold text-red-200';
          burnedText.innerText = isInheritance
            ? (isEpochSwept
                ? 'Active vault assets were autonomously transferred to designated heirs. Deposits are permanently disabled for this epoch. Activate the next clean bunker to derive fresh uncompromised addresses.'
                : 'Autonomous inheritance triggered. Cloud Keeper sweep is in progress. Activate the next clean bunker to derive fresh uncompromised addresses.')
            : (isEpochSwept
                ? 'Active epoch keys were exposed on-chain during evacuation. Activate the next bunker to derive fresh uncompromised addresses.'
                : 'Emergency evacuation triggered; Cloud Keeper sweep is in progress. Activate the next bunker to derive fresh uncompromised addresses.');
        }
      }

      return unallocated;
    }

    function startAbortCountdown() {
      if (!localStorage.getItem('aegis_signer_account')) {
        showToast('🛑 Connect wallet to arm or manage vault', true);
        return;
      }

      if (isVaultEvacuatedOrBurned()) {
        showToast('🛑 VAULT ALREADY EVACUATED: Active epoch keys are burned. Rotate bunker to start new epoch.', true);
        return;
      }

      // 1. Guard against panic during 72h policy timelock
      if (lastFetchedVaultInfo && lastFetchedVaultInfo.pending_policy) {
        showToast('🛑 PANIC BLOCKED: 72h policy timelock is active. Cancel pending proposal or wait for cooldown.', true);
        return;
      }

      // 2. Guard against panic when no backup addresses exist
      if (!lastFetchedVaultInfo || !hasConfiguredDestinations(lastFetchedVaultInfo) || !lastFetchedVaultInfo.backup || !lastFetchedVaultInfo.backup.near && !lastFetchedVaultInfo.backup.evm && !lastFetchedVaultInfo.backup.btc && !lastFetchedVaultInfo.backup.sol) {
        showToast('🛑 PANIC BLOCKED: No backup destinations configured! Enter emergency addresses first.', true);
        return;
      }

      // 3. Check for deposited funds without corresponding destination addresses
      const unalloc = checkUnallocatedFunds();
      const panicAlert = document.getElementById('panicUnallocatedAlert');
      const panicAlertText = document.getElementById('panicUnallocatedText');
      if (panicAlert && panicAlertText) {
        if (unalloc.length > 0) {
          panicAlert.classList.remove('hidden');
          panicAlertText.innerText = `You have funds deposited in ${unalloc.join(', ')}, but NO backup address is configured! If you proceed with evacuation, these funds CANNOT be swept and will remain stranded.`;
        } else {
          panicAlert.classList.add('hidden');
        }
      }

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

      dispatchNearTransaction('panic').then((outcome) => {
        if (!outcome) return;
        remainingSeconds = 0;
        if (lastFetchedVaultInfo) {
          lastFetchedVaultInfo.state = 'Evacuated';
        }
        const currentSigner = localStorage.getItem('aegis_signer_account');
        if (currentSigner) {
          localStorage.removeItem(`aegis_balance_cache_${currentSigner}`);
        }
        renderBunkerAddresses();
        updateCountdownDisplay();

        showToast('PANIC CONFIRMED ON-CHAIN: Dispatching Cloud Keeper sweep...', true);
        openEvacMonitor('evacuation');
        triggerCloudKeeperSweep(false);

        fetchLiveBalances(true);
        setTimeout(() => fetchLiveBalances(true), 2500);
        setTimeout(() => fetchLiveBalances(true), 6000);
        setTimeout(() => fetchLiveBalances(true), 12000);
      }).catch(err => {
        console.error('Panic execution aborted or failed:', err);
      });
    }

    function setMonitorBadgeStyle(badgeEl, rawStatus) {
      if (!badgeEl) return;
      let label = String(rawStatus || 'Not configured').trim();
      if (label.includes('Dynamic EIP-1559')) label = 'Queued (EIP-1559)';
      else if (label === 'Queued for relayer sweep') label = 'Queued for sweep';

      badgeEl.innerText = label;
      const lower = label.toLowerCase();
      if (lower === 'not configured' || lower.startsWith('skipped') || lower.startsWith('no deposit') || lower.startsWith('0 balance')) {
        badgeEl.className = 'text-[#8C929D] font-bold bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center';
      } else if (lower.includes('confirmed') || lower.includes('broadcasted')) {
        badgeEl.className = 'text-nearGreen font-bold bg-nearGreenMuted border border-nearGreen/30 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center';
      } else {
        badgeEl.className = 'text-amber-300 font-bold bg-amber-500/15 border border-amber-500/30 px-3 py-1 rounded-full text-[11px] shrink-0 whitespace-nowrap text-center';
      }
    }

    function openEvacMonitor(modeOverride) {
      const isInheritance = modeOverride === 'inheritance'
        || (modeOverride !== 'evacuation' && Boolean(
          lastFetchedVaultInfo && (
            lastFetchedVaultInfo.state === 'Inheritance' ||
            (lastFetchedVaultInfo.state === 'Active' && remainingSeconds <= 0)
          )
        ));
      const titleEl = document.querySelector('#evacMonitorModal h3');
      if (titleEl) {
        titleEl.innerText = isInheritance ? 'Multichain Inheritance Transfer Monitor' : 'Multichain Evacuation Monitor';
      }

      const currentSigner = localStorage.getItem('aegis_signer_account') || '';
      let savedLocal = {};
      try {
        savedLocal = JSON.parse(localStorage.getItem('aegis_addresses_' + currentSigner) || '{}');
      } catch (_) {}

      let nearTarget, btcTarget, evmTarget, solTarget;
      if (isInheritance) {
        nearTarget = lastFetchedVaultInfo?.heirs?.near ||
                     document.getElementById('heirNearAddr')?.value?.trim() ||
                     savedLocal.heirNearAddr ||
                     'Not configured';
        btcTarget = lastFetchedVaultInfo?.heirs?.btc ||
                    document.getElementById('heirBtcAddr')?.value?.trim() ||
                    savedLocal.heirBtcAddr ||
                    'Not configured';
        evmTarget = lastFetchedVaultInfo?.heirs?.evm ||
                    document.getElementById('heirEvmAddr')?.value?.trim() ||
                    savedLocal.heirEvmAddr ||
                    'Not configured';
        solTarget = lastFetchedVaultInfo?.heirs?.sol ||
                    document.getElementById('heirSolAddr')?.value?.trim() ||
                    savedLocal.heirSolAddr ||
                    'Not configured';
      } else {
        nearTarget = lastFetchedVaultInfo?.backup?.near ||
                     document.getElementById('panicNearAddr')?.value?.trim() ||
                     savedLocal.panicNearAddr ||
                     'Not configured';
        btcTarget = lastFetchedVaultInfo?.backup?.btc ||
                    document.getElementById('panicBtcAddr')?.value?.trim() ||
                    savedLocal.panicBtcAddr ||
                    'Not configured';
        evmTarget = lastFetchedVaultInfo?.backup?.evm ||
                    document.getElementById('panicEvmAddr')?.value?.trim() ||
                    savedLocal.panicEvmAddr ||
                    'Not configured';
        solTarget = lastFetchedVaultInfo?.backup?.sol ||
                    document.getElementById('panicSolAddr')?.value?.trim() ||
                    savedLocal.panicSolAddr ||
                    'Not configured';
      }

      const btcEl = document.getElementById('monitorBtcTarget');
      const evmEl = document.getElementById('monitorEvmTarget');
      const solEl = document.getElementById('monitorSolTarget');
      const nearEl = document.getElementById('monitorNearTarget');
      if (btcEl) btcEl.innerText = maskAddressForDisplay(btcTarget);
      if (evmEl) evmEl.innerText = maskAddressForDisplay(evmTarget);
      if (solEl) solEl.innerText = maskAddressForDisplay(solTarget);
      if (nearEl) nearEl.innerText = maskAddressForDisplay(nearTarget);

      const btcBal = document.getElementById('btcBalanceText')?.innerText || '0.0000 BTC';
      const evmBal = document.getElementById('evmBalanceText')?.innerText || '0.0000 ETH';
      const solBal = document.getElementById('solBalanceText')?.innerText || '0.0000 SOL';
      const nearBal = document.getElementById('nearBalanceText')?.innerText || '0.0000 NEAR';

      if (document.getElementById('monitorBtcBal')) document.getElementById('monitorBtcBal').innerText = btcBal;
      if (document.getElementById('monitorEvmBal')) document.getElementById('monitorEvmBal').innerText = evmBal;
      if (document.getElementById('monitorSolBal')) document.getElementById('monitorSolBal').innerText = solBal;
      if (document.getElementById('monitorNearBal')) document.getElementById('monitorNearBal').innerText = nearBal;

      // Reset all links & badges before applying epoch-scoped telemetry
      ['monitorBtcLink', 'monitorEvmLink', 'monitorSolLink', 'monitorNearLink'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '';
      });
      setMonitorBadgeStyle(document.getElementById('monitorBtcStatus'), btcTarget === 'Not configured' ? 'Not configured' : 'Queued for sweep');
      setMonitorBadgeStyle(document.getElementById('evmTxStatusBadge'), evmTarget === 'Not configured' ? 'Not configured' : 'Queued (EIP-1559)');
      setMonitorBadgeStyle(document.getElementById('monitorSolStatus'), solTarget === 'Not configured' ? 'Not configured' : 'Queued for sweep');
      setMonitorBadgeStyle(document.getElementById('monitorNearStatus'), nearTarget === 'Not configured' ? 'Not configured' : 'Queued for sweep');

      const modal = document.getElementById('evacMonitorModal');
      if (modal) modal.classList.remove('hidden');

      const applyTelemetryRecord = (t) => {
        if (!t || !t.sweeps) return false;
        const expectedEpoch = lastFetchedVaultInfo?.epoch;
        if (expectedEpoch !== undefined && t.epoch !== undefined && Number(t.epoch) !== Number(expectedEpoch)) {
          return false;
        }
        if (t.sweeps.btc) {
          const s = t.sweeps.btc;
          const statusEl = document.getElementById('monitorBtcStatus');
          const linkEl = document.getElementById('monitorBtcLink');
          if (statusEl && s.status) setMonitorBadgeStyle(statusEl, s.status);
          if (s.target && btcEl) btcEl.innerText = maskAddressForDisplay(s.target);
          if (s.amount && document.getElementById('monitorBtcBal')) document.getElementById('monitorBtcBal').innerText = s.amount;
          if (linkEl && s.explorer) {
            const safeExp = sanitizeExplorerUrl(s.explorer);
            const mpcLink = s.near_mpc_tx
              ? ` <span class="text-white/20">|</span> <a href="${sanitizeExplorerUrl(s.near_mpc_tx)}" target="_blank" rel="noopener noreferrer" class="text-nearGreen hover:underline">MPC Proof (v1.signer) ↗</a>`
              : '';
            linkEl.innerHTML = `<a href="${safeExp}" target="_blank" rel="noopener noreferrer" class="text-amber-400 hover:underline font-mono">View on Mempool.space ↗</a>${mpcLink}`;
          }
        } else if (t.is_complete) {
          setMonitorBadgeStyle(document.getElementById('monitorBtcStatus'), btcTarget === 'Not configured' ? 'Not configured' : 'No deposit (0 BTC)');
        }
        if (t.sweeps.evm) {
          const s = t.sweeps.evm;
          const statusBadge = document.getElementById('evmTxStatusBadge');
          const linkEl = document.getElementById('monitorEvmLink');
          if (statusBadge && s.status) setMonitorBadgeStyle(statusBadge, s.status);
          if (s.target && evmEl) evmEl.innerText = maskAddressForDisplay(s.target);
          if (s.amount && document.getElementById('monitorEvmBal')) document.getElementById('monitorEvmBal').innerText = s.amount;
          if (linkEl && s.explorer) {
            const safeExp = sanitizeExplorerUrl(s.explorer);
            const mpcLink = s.near_mpc_tx
              ? ` <span class="text-white/20">|</span> <a href="${sanitizeExplorerUrl(s.near_mpc_tx)}" target="_blank" rel="noopener noreferrer" class="text-nearGreen hover:underline">MPC Proof (v1.signer) ↗</a>`
              : '';
            linkEl.innerHTML = `<a href="${safeExp}" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:underline font-mono">View on Etherscan ↗</a>${mpcLink}`;
          }
        } else if (t.is_complete) {
          setMonitorBadgeStyle(document.getElementById('evmTxStatusBadge'), evmTarget === 'Not configured' ? 'Not configured' : 'No deposit (0 ETH)');
        }
        if (t.sweeps.sol) {
          const s = t.sweeps.sol;
          const statusEl = document.getElementById('monitorSolStatus');
          const linkEl = document.getElementById('monitorSolLink');
          if (statusEl && s.status) setMonitorBadgeStyle(statusEl, s.status);
          if (s.target && solEl) solEl.innerText = maskAddressForDisplay(s.target);
          if (s.amount && document.getElementById('monitorSolBal')) document.getElementById('monitorSolBal').innerText = s.amount;
          if (linkEl && s.explorer) {
            const safeExp = sanitizeExplorerUrl(s.explorer);
            const mpcLink = s.near_mpc_tx
              ? ` <span class="text-white/20">|</span> <a href="${sanitizeExplorerUrl(s.near_mpc_tx)}" target="_blank" rel="noopener noreferrer" class="text-nearGreen hover:underline">MPC Proof (v1.signer) ↗</a>`
              : '';
            linkEl.innerHTML = `<a href="${safeExp}" target="_blank" rel="noopener noreferrer" class="text-purple-400 hover:underline font-mono">View on Solscan ↗</a>${mpcLink}`;
          }
        } else if (t.is_complete) {
          setMonitorBadgeStyle(document.getElementById('monitorSolStatus'), solTarget === 'Not configured' ? 'Not configured' : 'No deposit (0 SOL)');
        }
        if (t.sweeps.near) {
          const s = t.sweeps.near;
          const statusEl = document.getElementById('monitorNearStatus');
          const linkEl = document.getElementById('monitorNearLink');
          if (statusEl && s.status) setMonitorBadgeStyle(statusEl, s.status);
          if (s.target && nearEl) nearEl.innerText = maskAddressForDisplay(s.target);
          if (s.amount && document.getElementById('monitorNearBal')) document.getElementById('monitorNearBal').innerText = s.amount;
          if (linkEl && s.explorer) {
            const safeExp = sanitizeExplorerUrl(s.explorer);
            const mpcLink = s.near_mpc_tx
              ? ` <span class="text-white/20">|</span> <a href="${sanitizeExplorerUrl(s.near_mpc_tx)}" target="_blank" rel="noopener noreferrer" class="text-nearGreen hover:underline">MPC Proof (v1.signer) ↗</a>`
              : '';
            linkEl.innerHTML = `<a href="${safeExp}" target="_blank" rel="noopener noreferrer" class="text-nearGreen hover:underline font-mono">View on NearBlocks ↗</a>${mpcLink}`;
          }
        } else if (t.is_complete) {
          setMonitorBadgeStyle(document.getElementById('monitorNearStatus'), nearTarget === 'Not configured' ? 'Not configured' : 'No deposit (0 NEAR)');
        }
        return true;
      };

      // 1. Primary Source: Instant On-Chain Telemetry (last_sweep_report from get_vault_info on NEAR RPC)
      let renderedOnChain = false;
      if (lastFetchedVaultInfo && lastFetchedVaultInfo.last_sweep_report) {
        try {
          renderedOnChain = applyTelemetryRecord(JSON.parse(lastFetchedVaultInfo.last_sweep_report));
        } catch (_) {}
      }

      if (window._evacMonitorPoll) clearInterval(window._evacMonitorPoll);
      window._evacMonitorPoll = setInterval(async () => {
        await fetchLiveContractState();
        if (lastFetchedVaultInfo && lastFetchedVaultInfo.last_sweep_report) {
          try {
            const parsed = JSON.parse(lastFetchedVaultInfo.last_sweep_report);
            applyTelemetryRecord(parsed);
            if (parsed.is_complete) {
              clearInterval(window._evacMonitorPoll);
              window._evacMonitorPoll = null;
            }
          } catch (_) {}
        }
      }, 3500);

      // 2. Secondary Fallback: Multi-Tenant telemetry.json (strictly scoped to current epoch)
      if (!renderedOnChain) {
        fetch('telemetry.json?t=' + Date.now()).then(r => r.json()).then(t => {
          if (!t) return;
          const ep = lastFetchedVaultInfo?.epoch ?? 0;
          const scoped = (t.vaults && currentSigner && t.vaults[`${currentSigner}:${ep}`])
            || (t.vault_owner === currentSigner && Number(t.epoch) === Number(ep) ? t : null);
          if (scoped) applyTelemetryRecord(scoped);
        }).catch(() => {});
      }

      // Automatically nudge Keeper if epoch sweep is not yet complete
      if (lastFetchedVaultInfo && !lastFetchedVaultInfo.is_epoch_swept && Date.now() - lastCloudKeeperNudgeMs > 4000) {
        lastCloudKeeperNudgeMs = Date.now();
        triggerCloudKeeperSweep(false);
      }
    }

    function closeEvacMonitor() {
      if (window._evacMonitorPoll) {
        clearInterval(window._evacMonitorPoll);
        window._evacMonitorPoll = null;
      }
      document.getElementById('evacMonitorModal').classList.add('hidden');
    }

    const DEFAULT_CLOUD_KEEPER_URL = 'https://aegis-keeper.rain-ellipse.workers.dev';
    const LOCAL_KEEPER_URL = 'http://127.0.0.1:8788';
    let lastCloudKeeperNudgeMs = 0;

    async function triggerCloudKeeperSweep(showFeedback = false) {
      let savedUrl = (localStorage.getItem('aegis_keeper_url') || '').trim();
      if (savedUrl.includes('dazzling-picture') || savedUrl.includes('dawn-direction')) {
        localStorage.removeItem('aegis_keeper_url');
        savedUrl = '';
      }
      const keeperUrl = (savedUrl || DEFAULT_CLOUD_KEEPER_URL).replace(/\/$/, '');
      const btn = document.getElementById('syncKeeperBtn');
      if (showFeedback) {
        if (btn) { btn.disabled = true; btn.innerText = 'Syncing Keeper...'; }
        showToast('⚡ Dispatching 24/7 Cloud Keeper sweep pass...');
      }
      try {
        const callKeeperEndpoints = async () => {
          const results = await Promise.allSettled([
            fetch(`${LOCAL_KEEPER_URL}/trigger`, { method: 'POST' }).then(r => r.json()),
            fetch(`${keeperUrl}/trigger`, { method: 'POST' }).then(r => r.json())
          ]);
          for (const r of results) {
            if (r.status === 'fulfilled' && r.value && r.value.success) return r.value;
          }
          return null;
        };
        let data = await callKeeperEndpoints();
        if (data?.processed?.some(p => !p.complete)) {
          await new Promise(r => setTimeout(r, 1500));
          data = (await callKeeperEndpoints()) || data;
        }
        await fetchLiveContractState();
        fetchLiveBalances(true);
        if (showFeedback) {
          showToast(data?.success ? '✅ Cloud Keeper synced on-chain telemetry!' : 'Synced latest telemetry directly from NEAR RPC.');
        }
      } catch (_) {
        await fetchLiveContractState();
        if (showFeedback) showToast('Synced latest telemetry directly from NEAR RPC.');
      } finally {
        if (showFeedback && btn) {
          btn.disabled = false;
          btn.innerText = '⚡ Sync Cloud Keeper';
        }
      }
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
          <span>Relayer: <strong class="text-nearGreen">${escapeHtml(tg || email || 'Active')}</strong></span>
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

    function updateMemoByteCounter(val) {
      const text = String(val || '');
      const bytes = new TextEncoder().encode(text).length;
      const isCipher = text.startsWith('enc:x25519:') || text.startsWith('enc:aes256:');
      const limit = isCipher ? 1024 : 240;
      const counter = document.getElementById('memoByteCount');
      if (counter) {
        counter.innerText = isCipher ? `Sealed (${bytes} / 1024 B)` : `${bytes} / ${limit} B`;
        if (bytes > limit) {
          counter.className = 'text-[11px] font-mono font-bold text-red-400';
        } else if (bytes > 0) {
          counter.className = 'text-[11px] font-mono font-semibold text-nearGreen';
        } else {
          counter.className = 'text-[11px] font-mono text-white/50';
        }
      }
    }

    function openDecryptModal() {
      const modal = document.getElementById('decryptTestamentModal');
      const cipherInput = document.getElementById('decryptCipherInput');
      const outBox = document.getElementById('decryptOutputBox');
      if (outBox) outBox.classList.add('hidden');
      if (cipherInput && !cipherInput.value && (window.currentEncryptedOnChainMemo || lastFetchedVaultInfo?.heir_memo)) {
        cipherInput.value = window.currentEncryptedOnChainMemo || lastFetchedVaultInfo.heir_memo || '';
      }
      if (modal) modal.classList.remove('hidden');
    }

    function closeDecryptModal() {
      const modal = document.getElementById('decryptTestamentModal');
      if (modal) modal.classList.add('hidden');
    }

    async function runLocalTestamentDecrypt() {
      const cipher = (document.getElementById('decryptCipherInput')?.value || '').trim();
      const secret = (document.getElementById('decryptSecretInput')?.value || '').trim();
      const outBox = document.getElementById('decryptOutputBox');
      const outText = document.getElementById('decryptOutputText');
      if (!cipher) {
        showToast('Paste an enc:x25519:... or enc:aes256:... ciphertext first', true);
        return;
      }
      if (!secret) {
        showToast('Enter passphrase or Heir Ed25519 secret key', true);
        return;
      }
      try {
        let plain = '';
        if (cipher.startsWith('enc:x25519:')) {
          plain = window.AegisWallet.decryptTestamentX25519(cipher, secret);
        } else if (cipher.startsWith('enc:aes256:')) {
          plain = await window.AegisWallet.decryptTestamentPassphrase(cipher, secret);
        } else {
          throw new Error('Ciphertext must start with enc:x25519: or enc:aes256:');
        }
        if (outText) outText.innerText = plain;
        if (outBox) outBox.classList.remove('hidden');
        showToast('🔓 Testament decrypted locally!');
      } catch (err) {
        showToast(err.message || 'Decryption failed', true);
      }
    }

    async function topUpGasEscrow() {
      await dispatchNearTransaction('deposit_escrow', {}, '250000000000000000000000'); // 0.25 NEAR
    }

    function loadSavedAddresses() {
      // Purge any legacy global keys
      localStorage.removeItem('aegis_cooldown_started');
      localStorage.removeItem('aegis_pending_addresses');
      localStorage.removeItem('aegis_addresses');
      localStorage.removeItem('aegis_vault_burned_0');
      localStorage.removeItem('aegis_vault_burned_1');
      localStorage.removeItem('aegis_vault_burned_2');
      localStorage.removeItem('aegis_vault_burned_3');

      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (!currentSigner) {
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) el.value = '';
        });
        const banner = document.getElementById('unconfiguredBanner');
        if (banner) banner.classList.remove('hidden');
        return;
      }

      if (isAddressDisplayLocked(lastFetchedVaultInfo)) {
        const isClosed = isVaultEvacuatedOrBurned() || isGracePeriodExpired(lastFetchedVaultInfo);
        if (isClosed) {
          localStorage.removeItem('aegis_addresses_' + currentSigner);
        }
        inputIds.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.value = '';
            el.disabled = true;
            el.placeholder = isClosed
              ? '🔒 Hidden — Bunker epoch closed (Rotate bunker to set new addresses)'
              : '🔒 Hidden during Grace Buffer — Check-in to unlock';
          }
        });
        const passEl = document.getElementById('heirMemoPassphrase');
        if (passEl) passEl.value = '';
        const e2eeBadge = document.getElementById('e2eeArmedStatus');
        if (e2eeBadge) e2eeBadge.classList.add('hidden');
        const activeBanner = document.getElementById('activePolicyBanner');
        if (activeBanner) activeBanner.classList.add('hidden');
        const activeSummary = document.getElementById('activePolicySummary');
        if (activeSummary) activeSummary.innerHTML = '';
        const unconfigBanner = document.getElementById('unconfiguredBanner');
        if (unconfigBanner) {
          unconfigBanner.classList.add('hidden');
          unconfigBanner.classList.remove('flex');
        }
        return;
      }

      // Ensure all inputs are enabled when vault is active or unconfigured
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          el.disabled = false;
          if (el.dataset.defaultPlaceholder) el.placeholder = el.dataset.defaultPlaceholder;
        }
      });

      // If user has on-chain destinations in lastFetchedVaultInfo, populate from them!
      if (lastFetchedVaultInfo && hasConfiguredDestinations(lastFetchedVaultInfo)) {
        const pNear = document.getElementById('panicNearAddr');
        const pBtc = document.getElementById('panicBtcAddr');
        const pEvm = document.getElementById('panicEvmAddr');
        const pSol = document.getElementById('panicSolAddr');
        const hNear = document.getElementById('heirNearAddr');
        const hBtc = document.getElementById('heirBtcAddr');
        const hEvm = document.getElementById('heirEvmAddr');
        const hSol = document.getElementById('heirSolAddr');

        if (!userHasInteractedWithInputs) {
          if (pNear) pNear.value = lastFetchedVaultInfo.backup?.near || '';
          if (pBtc) pBtc.value = lastFetchedVaultInfo.backup?.btc || '';
          if (pEvm) pEvm.value = lastFetchedVaultInfo.backup?.evm || '';
          if (pSol) pSol.value = lastFetchedVaultInfo.backup?.sol || '';
          if (hNear) hNear.value = lastFetchedVaultInfo.heirs?.near || '';
          if (hBtc) hBtc.value = lastFetchedVaultInfo.heirs?.btc || '';
          if (hEvm) hEvm.value = lastFetchedVaultInfo.heirs?.evm || '';
          if (hSol) hSol.value = lastFetchedVaultInfo.heirs?.sol || '';
        }
        return;
      }

      // If vault is Unconfigured, keep inputs empty unless user has typed or pasted
      if (lastFetchedVaultInfo && lastFetchedVaultInfo.state === 'Unconfigured') {
        if (!userHasInteractedWithInputs) {
          inputIds.forEach(id => {
            const el = document.getElementById(id);
            if (el && !el.value) el.value = '';
          });
        }
        const hasAnyEntered = inputIds.some(id => document.getElementById(id)?.value?.trim());
        const banner = document.getElementById('unconfiguredBanner');
        if (banner) {
          if (shouldShowUnconfiguredBanner(lastFetchedVaultInfo)) { banner.classList.remove('hidden'); banner.classList.add('flex'); }
          else { banner.classList.add('hidden'); banner.classList.remove('flex'); }
        }
        return;
      }

      const saved = JSON.parse(localStorage.getItem('aegis_addresses_' + currentSigner) || '{}');
      let hasAny = false;
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          if (!userHasInteractedWithInputs && saved[id]) {
            el.value = saved[id];
          }
          if (el.value && el.value.trim().length > 0) hasAny = true;
        }
      });
      updateMemoByteCounter(saved.heirFinalMemo || '');
      const banner = document.getElementById('unconfiguredBanner');
      if (banner) {
        if (shouldShowUnconfiguredBanner(lastFetchedVaultInfo)) { banner.classList.remove('hidden'); banner.classList.add('flex'); }
        else { banner.classList.add('hidden'); banner.classList.remove('flex'); }
      }

      const badge = document.getElementById('addressStatusBadge');
      const dot = document.getElementById('addressStatusDot');
      const cooldownAlert = document.getElementById('cooldownAlertBanner');

      // Ensure Save Policy buttons are visible and active
      document.querySelectorAll('.save-policy-btn').forEach(btn => {
        btn.classList.remove('hidden');
        btn.disabled = false;
      });
      document.querySelectorAll('.cancel-policy-btn').forEach(btn => btn.classList.add('hidden'));
      document.querySelectorAll('.apply-policy-btn').forEach(btn => btn.classList.add('hidden'));

      if (cooldownAlert) cooldownAlert.classList.add('hidden');
      if (badge) {
        badge.innerText = hasAny ? 'Active & Enforced' : 'Unconfigured';
        badge.className = hasAny ? 'text-nearGreen font-mono font-bold' : 'text-amber-300 font-mono font-bold';
      }
      if (dot) dot.className = hasAny ? 'w-2.5 h-2.5 rounded-full bg-nearGreen shadow-near-glow' : 'w-2.5 h-2.5 rounded-full bg-amber-400';
    }

    function clearAllAddresses() {
      userHasInteractedWithInputs = false;
      isEditing = true;
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          el.value = '';
          el.disabled = false;
        }
      });
      const evacBanner = document.getElementById('evacuatedPolicyBanner');
      if (evacBanner) evacBanner.classList.add('hidden');
      const unconfigBanner = document.getElementById('unconfiguredBanner');
      if (unconfigBanner) unconfigBanner.classList.remove('hidden');
      localStorage.removeItem('aegis_addresses');
      localStorage.removeItem('aegis_pending_addresses');
      localStorage.removeItem('aegis_cooldown_started');
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (currentSigner) {
        localStorage.removeItem('aegis_addresses_' + currentSigner);
      }
      checkUnallocatedFunds();
      showToast('All address fields cleared. Enter new destinations to arm.');
    }

    function toggleEditMode() {
      // Retained for backward-compat if called
      loadSavedAddresses();
    }

    async function saveAddresses() {
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

      // Address format validation (matches on-chain ChainAddresses::validate)
      const isValidBtc = addr => !addr || /^(bc1[a-zA-HJ-NP-Z0-9]{25,87}|tb1[a-zA-HJ-NP-Z0-9]{25,87}|[13mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(addr);
      const isValidEvm = addr => !addr || /^0x[a-fA-F0-9]{40}$/.test(addr);
      const isValidSol = addr => !addr || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr);
      const isValidNear = addr => !addr || (/^(?=.{2,64}$)[a-z0-9]+([_-][a-z0-9]+)*(\.[a-z0-9]+([_-][a-z0-9]+)*)*$/.test(addr) || /^[0-9a-f]{64}$/.test(addr));

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
      let encryptedOrNullMemo = null;
      const rawMemoInput = data.heirFinalMemo ? data.heirFinalMemo.trim() : '';
      const memoPassphrase = (document.getElementById('heirMemoPassphrase')?.value || '').trim();

      if (rawMemoInput) {
        if (rawMemoInput.startsWith('enc:x25519:') || rawMemoInput.startsWith('enc:aes256:')) {
          encryptedOrNullMemo = rawMemoInput;
        } else {
          if (new TextEncoder().encode(rawMemoInput).length > 240) {
            showToast('Private testament exceeds 240 bytes plaintext limit', true);
            return;
          }
          try {
            if (memoPassphrase) {
              encryptedOrNullMemo = await window.AegisWallet.encryptTestamentPassphrase(rawMemoInput, memoPassphrase);
            } else if (data.heirSolAddr && data.heirSolAddr.trim()) {
              encryptedOrNullMemo = window.AegisWallet.encryptTestamentX25519(rawMemoInput, data.heirSolAddr.trim());
            } else if (data.heirNearAddr && /^[0-9a-fA-F]{64}$/.test(data.heirNearAddr.trim())) {
              encryptedOrNullMemo = window.AegisWallet.encryptTestamentX25519(rawMemoInput, data.heirNearAddr.trim());
            } else {
              showToast('Set Heir Solana address (for X25519 E2EE) or enter a Testament Passphrase so plaintext never goes on-chain', true);
              return;
            }
          } catch (encErr) {
            showToast('E2EE Encryption error: ' + encErr.message, true);
            return;
          }
        }
      } else if (userHasInteractedWithInputs && lastFetchedVaultInfo?.heir_memo) {
        // Allow explicitly clearing an existing on-chain memo when the user empties the input
        encryptedOrNullMemo = '';
      }

      const inactPref = document.getElementById('inactivitySelect')?.value || localStorage.getItem('aegis_inactivity_days') || '90';
      const gracePref = document.getElementById('graceSelect')?.value || localStorage.getItem('aegis_grace_days') || '7';
      const selectedHbNs = inactPref === 'demo_120s'
        ? '120000000000'
        : (BigInt(parseInt(inactPref, 10) || 90) * 86400n * 1000000000n).toString();
      const selectedCpNs = gracePref === 'demo_30s'
        ? '30000000000'
        : (BigInt(parseInt(gracePref, 10) || 7) * 86400n * 1000000000n).toString();

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
        },
        memo: encryptedOrNullMemo,
        heartbeat_interval_ns: selectedHbNs,
        challenge_period_ns: selectedCpNs
      };

      // Never store raw plaintext testament in localStorage
      const safeLocalCopy = { ...data, heirFinalMemo: '' };
      const currentSigner = localStorage.getItem('aegis_signer_account');
      if (currentSigner) {
        localStorage.setItem('aegis_addresses_' + currentSigner, JSON.stringify(safeLocalCopy));
      }
      localStorage.removeItem('aegis_addresses');
      dispatchNearTransaction('propose_policy', policyPayload).then((res) => {
        userHasInteractedWithInputs = false;
        isEditing = false;
        if (res !== undefined) {
          showToast('Policy & timers armed on-chain! Opening Safe Bunker Deposits...');
          setTimeout(() => switchTab('vault'), 700);
        }
      }).catch(err => {
        console.error('Policy proposal dispatch error:', err);
      });
    }

    function cancelAddressCooldown() {
      dispatchNearTransaction('cancel_policy');
      showToast('Cancelling address proposal on-chain...', true);
    }

    function applyAddressPolicy() {
      dispatchNearTransaction('apply_policy');
      showToast('Applying active policy on-chain...');
    }

    // Initialize Live On-Chain Polling and Wallet Connection on page load
    // (Explicit manual check-in only: never auto-fire wallet popups on scroll/click)
    document.addEventListener('DOMContentLoaded', () => {
      initNearWallet();
      updateMultichainConnectedUI();
      renderWalletsGrid('all');
      fetchLiveContractState();
      setInterval(fetchLiveContractState, 15000);

      // Handle ESC key to close modal
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMultichainWalletModal();
      });

      // Protect user inputs from being overwritten while typing or pasting
      inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          const markUserActive = () => {
            userHasInteractedWithInputs = true;
            isEditing = true;
            const banner = document.getElementById('unconfiguredBanner');
            if (banner) { banner.classList.add('hidden'); banner.classList.remove('flex'); }
            updateSaveButtonState(lastFetchedVaultInfo);
          };
          ['focus', 'input', 'paste', 'change', 'keyup'].forEach(evt => {
            el.addEventListener(evt, markUserActive);
          });
        }
      });
    });
  </script>
</body>
</html>
```

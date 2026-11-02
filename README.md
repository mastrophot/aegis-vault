# ⚿ LastKey — Multichain Dead-Man's Switch & Panic Button

> **NEAR HACKATHON 2026 Submission**  
> *Category:* Web3 Infrastructure / Multi-Chain Security / Chain Abstraction  
> *Core Primitive:* Native NEAR Chain Signatures (`v1.signer` MPC network) & Pure Rust Smart Contract.

---

## 🎯 Проблема (The Problem)

1. **Мільярди втрачених активів**: Коли криптоінвестор раптово гине або втрачає доступ до ключів, його родина не має доступу до сід-фраз чи біржових акаунтів. Активи назавжди зникають у блокчейні.
2. **Ризик "терморектального криптоаналізу" та грабежу**: При фізичній атаці або здирництві жертву змушують відкрити гаманець. Існуючі "перемикачі мерця" (Sass/Web2) вимагають довіри до централізованого сервера або віддачі приватних ключів третім особам (Custodial risk).
3. **Фрагментація екосистем**: Стандартні смарт-контракти спадкування працюють виключно в межах одного EVM чи однієї мережі. Не існувало єдиного некостодіального рішення, здатного одночасно керувати Bitcoin, EVM та Solana без посередників.

---

## 💡 Рішення (The Solution)

**LastKey** — це некостодіальний мультичейн-сейф мерця та апаратна "кнопка паніки", що використовує **NEAR Chain Signatures** як універсальний контролер:

- **0% довіри (Zero Custody)**: Жодних приватних ключів не зберігається на жодному сервері. Мультичейн-адреси (Bitcoin SegWit, EVM, Solana) деривуються математично з кореневого публічного ключа NEAR MPC мережі.
- **Heartbeat (Я живий)**: Власник періодично (наприклад, раз на 90 днів) відправляє безкоштовний пінг або здійснює ончейн-транзакцію.
- **Двохетапний челендж спадку**: Якщо таймер сплив, спадкоємці можуть відкрити 7-денне вікно запиту. Якщо власник живий, він в 1 клік скасовує запит. Якщо за 7 днів реакції немає — смартконтракт авторизує переказ активів на адреси спадкоємців.
- **Panic Button (Миттєва евакуація)**: За першої ознаки небезпеки власник або його Вартовий (Guardian) тисне Panic Button — контракт миттєво генерує евакуаційні транзакції для BTC, ETH, SOL виключно на заздалегідь підготовлений холодний апаратний Ledger.
- **72h Timelock + Guardian Veto**: Навіть якщо хакер отримає доступ до акаунта NEAR і спробує змінити адресу евакуації на свою, контракт активує 72-годинний таймлок. Вартовий або запасний ключ блокують зміну через `veto_policy()`.

---

## 🏗️ Архітектура (Architecture)

```
                  ┌──────────────────────────────────────────────┐
                  │          Користувач / Спадкоємець             │
                  └──────────────────────┬───────────────────────┘
                                         │  (ping / panic / claim)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      LastKey Vault Contract (Rust / WASM)    │
                  │        near-sdk 5.5.0 on NEAR Protocol        │
                  │  - Стан: Active / Claiming / Evacuated       │
                  │  - Математично закріплені адреси Backup/Heir │
                  └──────────────────────┬───────────────────────┘
                                         │  request_sweep_signature()
                                         │  (1 yoctoNEAR + 50 TGas)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │       NEAR MPC Network (v1.signer)           │
                  │  - Threshold ECDSA (secp256k1)               │
                  │  - Threshold EdDSA (ed25519)                 │
                  └──────┬────────────────┬───────────────┬──────┘
                         │                │               │
                         ▼                ▼               ▼
                  ┌────────────┐   ┌────────────┐  ┌─────────────┐
                  │  Bitcoin   │   │    EVM     │  │   Solana    │
                  │  (SegWit)  │   │(Base / ETH)│  │  (Devnet)   │
                  │ P2WPKH tx  │   │  EIP-1559  │  │SystemProgram│
                  └────────────┘   └────────────┘  └─────────────┘
```

---

## 📦 Структура репозиторію

- `contracts/vault/`: Смартконтракт на Rust (`near-sdk 5.5.0`):
  - [lib.rs](file:///Users/maximbutrik/.gemini/antigravity/scratch/lastkey/contracts/vault/src/lib.rs): логіка станів, захист від підміни адрес, таймлок, крос-контрактні виклики до `v1.signer`, повний набір юніт-тестів.
- `relayer/`: Автономний сервіс моніторингу та евакуації:
  - [sweep_relayer.js](file:///Users/maximbutrik/.gemini/antigravity/scratch/lastkey/relayer/sweep_relayer.js): збірка транзакцій для Bitcoin PSBT, EVM EIP-1559 та Solana через `chainsig.js`.
- `scripts/`:
  - [derive_addresses.js](file:///Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/derive_addresses.js): деривація мультичейн-адрес без приватних ключів.
  - [test_sweep_flow.js](file:///Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/test_sweep_flow.js): симуляція повного циклу евакуації для трьох мереж.
- `web/`:
  - [index.html](file:///Users/maximbutrik/.gemini/antigravity/scratch/lastkey/web/index.html): автономний темний веб-інтерфейс з таймером, деривованими адресами, кнопкою паніки та журналом ончейн-подій.

---

## 🚀 Швидкий запуск (Getting Started)

### 1. Тестування деривації адрес
```bash
npm run derive
```

### 2. Тестування релеєра евакуації
```bash
node scripts/test_sweep_flow.js
```

### 3. Компіляція та юніт-тести смартконтракту
```bash
cd contracts/vault
cargo test
cargo check --target wasm32-unknown-unknown
```

### 4. Запуск веб-інтерфейсу
Відкрийте `web/index.html` у будь-якому сучасному браузері або підніміть локальний сервер:
```bash
npx serve web
```

import os

bundle_path = '/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/AEGIS_AUDIT_BUNDLE.md'
lib_rs = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/contracts/vault/src/lib.rs', 'r', encoding='utf-8').read()
relayer_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/relayer/sweep_relayer.js', 'r', encoding='utf-8').read()
relayer_service_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/relayer/service.js', 'r', encoding='utf-8').read() if os.path.exists('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/relayer/service.js') else ''
wallet_selector_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/src/wallet-selector.js', 'r', encoding='utf-8').read() if os.path.exists('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/src/wallet-selector.js') else ''
index_html = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/web/index.html', 'r', encoding='utf-8').read()
test_flow = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/test_sweep_flow.js', 'r', encoding='utf-8').read()
derive_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/derive_addresses.js', 'r', encoding='utf-8').read()

header = """# 🛡️ AEGIS PROTOCOL: COMPREHENSIVE ARCHITECTURAL AUDIT & CODE DOSSIER

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
   - **Спонсорство релеєра `ping_by_relayer(vault_owner)`:** авторизований релеєр (`okgoogleok.testnet`) може сам оплачувати газ за продовження таймера користувача на 90 днів (0 газу для юзера). Перевірено ончейн (Tx: `Ee2mmGwN18Q5iyvWx9iYGbwhVSo27rEUHzkiSrL8MeVw`).
4. **Миттєве озброєння (Instant Arming):** Якщо бункер новий або після ротації (`Unconfigured`), перший виклик `propose_policy` активує політику негайно без 72-годинного таймлоку. Для вже активного бункера діє 72-годинний захисний таймлок.
5. **Ротація бункера (`rotate_bunker`):** Після евакуації поточна епоха вважається скомпрометованою. Ротація очищає адреси, переводить сховище в `Unconfigured` та переходить на нову епоху (`epoch + 1`), гарантуючи унікальні нові адреси для депозитів.
6. **Мультичейн евакуація активів (Panic / Inheritance):**
   - Релеєр (`relayer/service.js`) готує валідовані транзакції для Bitcoin (SegWit PSBT), EVM (EIP-1559) та Solana (Ed25519).
   - Смарт-контракт виконує Anti-Blind-Signing валідацію: перевіряє, що сира транзакція дійсно відправляє активи на зафіксовану резервну адресу, і викликає `v1.signer-prod.testnet::sign`.
   - Релеєр збирає фінальні підписані транзакції та публікує хеші у `web/telemetry.json`.
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
"""

content = header + '\n\n### 1. SMART CONTRACT (contracts/vault/src/lib.rs)\n```rust\n' + lib_rs + '\n```\n\n'
content += '### 2. MULTICHAIN RELAYER ENGINE (relayer/sweep_relayer.js)\n```javascript\n' + relayer_js + '\n```\n\n'
if relayer_service_js:
    content += '### 3. AUTONOMOUS RELAYER SERVICE & DAEMON (relayer/service.js)\n```javascript\n' + relayer_service_js + '\n```\n\n'
if wallet_selector_js:
    content += '### 4. MULTI-WALLET SELECTOR & CHAINSIG ENGINE (src/wallet-selector.js)\n```javascript\n' + wallet_selector_js + '\n```\n\n'
content += '### 5. FRONTEND UI & APPLICATION LOGIC (web/index.html)\n```html\n' + index_html + '\n```\n\n'
content += '### 6. E2E RELAYER TEST SUITE (scripts/test_sweep_flow.js)\n```javascript\n' + test_flow + '\n```\n\n'
content += '### 7. ADDRESS DERIVATION ENGINE (scripts/derive_addresses.js)\n```javascript\n' + derive_js + '\n```\n'

with open(bundle_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"SUCCESS: Generated {len(content.splitlines())} lines in {bundle_path}")

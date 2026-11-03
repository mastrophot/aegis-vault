import os

bundle_path = '/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/AEGIS_AUDIT_BUNDLE.md'
lib_rs = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/contracts/vault/src/lib.rs', 'r', encoding='utf-8').read()
relayer_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/relayer/sweep_relayer.js', 'r', encoding='utf-8').read()
index_html = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/web/index.html', 'r', encoding='utf-8').read()
test_flow = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/test_sweep_flow.js', 'r', encoding='utf-8').read()
derive_js = open('/Users/maximbutrik/.gemini/antigravity/scratch/lastkey/scripts/derive_addresses.js', 'r', encoding='utf-8').read()

header = """# 🛡️ AEGIS PROTOCOL: COMPREHENSIVE ARCHITECTURAL AUDIT & VIABILITY DOSSIER

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
"""

content = header + '\n\n### 1. SMART CONTRACT (contracts/vault/src/lib.rs)\n```rust\n' + lib_rs + '\n```\n\n'
content += '### 2. MULTICHAIN RELAYER (relayer/sweep_relayer.js)\n```javascript\n' + relayer_js + '\n```\n\n'
content += '### 3. FRONTEND UI & LOGIC (web/index.html)\n```html\n' + index_html + '\n```\n\n'
content += '### 4. E2E RELAYER TEST SUITE (scripts/test_sweep_flow.js)\n```javascript\n' + test_flow + '\n```\n\n'
content += '### 5. ADDRESS DERIVATION ENGINE (scripts/derive_addresses.js)\n```javascript\n' + derive_js + '\n```\n'

with open(bundle_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"SUCCESS: Generated {len(content.splitlines())} lines in {bundle_path}")

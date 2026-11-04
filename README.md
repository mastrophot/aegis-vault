# 🛡️ Aegis — Autonomous Multichain Dead-Man's Switch & Panic Evacuation Vault

> **NEAR HACKATHON 2026 Submission**  
> **Track:** Web3 Infrastructure · Multi-Chain Security · Chain Abstraction  
> **Core Primitive:** Native NEAR Chain Signatures (`v1.signer` MPC Network) & Pure Rust Smart Contract  
> **Live Demo:** [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/)  
> **NEAR Testnet Contract:** [`aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet)

---

## 🎯 The Problem

1. **Billions in Lost Crypto Assets**: When a crypto asset holder unexpectedly passes away or loses access, their family cannot access disparate seed phrases, hardware wallets, or cross-chain accounts. Assets remain permanently stranded on-chain.
2. **Physical Extortion & Duress ("\$5 Wrench Attack")**: Under physical coercion or home invasion, victims are forced to unlock their primary devices. Existing Web2 dead-man's switches rely on centralized servers or custodial escrow of private keys.
3. **Cross-Ecosystem Fragmentation**: Traditional inheritance smart contracts operate exclusively within a single EVM or single L1 environment. No non-custodial solution could concurrently manage **Bitcoin (UTXO)**, **EVM (Account/EIP-1559)**, and **Solana (Account/Ed25519)** from a single autonomous decentralized root of trust without intermediaries.

---

## 💡 The Solution: Aegis

**Aegis** is a non-custodial, multichain dead-man's switch and emergency panic evacuation system powered by **NEAR Protocol Chain Signatures**. It turns a single NEAR smart contract into a universal threshold signer for Bitcoin, EVM, and Solana.

* **Zero Custody (100% Non-Custodial)**: No private keys ever touch a server. Multichain deposit addresses (Bitcoin Native SegWit, EVM, and Solana) are mathematically derived from NEAR MPC's root public key via deterministic derivation paths (`aegis/{epoch}`).
* **Proof-of-Life Heartbeat (`ping()`)**: The vault owner maintains active status by sending a periodic lightweight on-chain ping (e.g., every 90 days).
* **Two-Stage Inheritance Protocol**: If the inactivity timer expires, heirs can open a challenge claim window. If the owner is alive, they cancel the claim with 1 click. If unchallenged within the grace period, the contract transitions to `Inheritance` state and authorizes push fund evacuation to designated heir addresses.
* **Emergency Panic Button (Instant Evacuation)**: Under immediate threat, the owner triggers `panic()` (with 3-second hold buffer or 1-click armed mode). The vault immediately locks, bumps the derivation epoch to burn old addresses, and authorizes evacuation of 100% of all multichain assets directly to pre-configured cold backup wallets.
* **Anti-Hacking Policy Timelock**: First-time initialization activates immediately to allow zero-friction onboarding and instant testing. Any subsequent modifications to egress destination addresses (`backup` or `heirs`) enforce a strict 72-hour on-chain cooldown. If the owner's NEAR account is compromised, the rogue proposal can be cancelled during the window before it becomes effective.
* **Cryptographic Anti-Blind-Signing & Structural Payload Verification**:
  * **EVM**: The smart contract verifies raw transaction bytecode (`> 64` hex characters), verifies that the 20-byte destination strictly matches designated backup/heir addresses, and executes `keccak256` on-chain. Relayers cannot submit blind hashes.
  * **Solana**: The smart contract parses the binary Solana Message header and account indices, enforcing `unsigned_writable_count == 1` and ensuring `account_1` is strictly the designated destination wallet (preventing substring/decoy injection attacks).
  * **Bitcoin**: Supports BIP-143 SegWit sighash authorization, automatic dust filtering (< 546 sats), and BIP-125 Opt-in RBF.
* **Immutable On-Chain Testament**: Embeds arbitrary last words/instructions directly into Bitcoin `OP_RETURN`, EVM calldata, and Solana memo upon execution.

---

## 🏗️ System Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │           Owner / Designated Heirs           │
                       └──────────────────────┬───────────────────────┘
                                              │  ping() / panic() / claim()
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │         Aegis Vault Smart Contract           │
                       │           (Rust / near-sdk 5.5)              │
                       │  - State Machine: Active / Claim / Evacuated │
                       │  - Structural Payload Verification (EVM/SOL) │
                       │  - 72h Policy Cooldown & Epoch Rotation      │
                       └──────────────────────┬───────────────────────┘
                                              │  request_sweep_signature()
                                              │  (Attached Gas: 250 TGas)
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │          NEAR MPC Network (v1.signer)        │
                       │  - Threshold Secp256k1 (Bitcoin / EVM)       │
                       │  - Threshold Ed25519   (Solana / NEAR)       │
                       └──────┬────────────────┬───────────────┬──────┘
                              │                │               │
                              ▼                ▼               ▼
                       ┌────────────┐   ┌────────────┐  ┌─────────────┐
                       │  Bitcoin   │   │    EVM     │  │   Solana    │
                       │  (SegWit)  │   │(Base/Sepol)│  │(Dev/Mainnet)│
                       │ BIP-143    │   │  EIP-1559  │  │System/SPL22 │
                       │ P2WPKH     │   │ Raw Byte   │  │Header Check │
                       └────────────┘   └────────────┘  └─────────────┘
```

---

## 📁 Repository Structure

* [`contracts/vault/`](contracts/vault/): Production-hardened Rust smart contract (`near-sdk 5.5.0`):
  * [`src/lib.rs`](contracts/vault/src/lib.rs): State machine, Solana structural bytecode parser, EVM destination verification, BIP-143 Bitcoin sighash authorization, safe `migrate()` upgrade handler, and 9 unit tests.
* [`relayer/`](relayer/): Autonomous multichain sweep relayer service:
  * [`sweep_relayer.js`](relayer/sweep_relayer.js): PSBT constructor with BIP-66 DER signature injection, EVM zero-asset queue with L2 rollup buffer, Solana JIT blockhash fetcher, and fault-isolation runner.
* [`scripts/`](scripts/):
  * [`derive_addresses.js`](scripts/derive_addresses.js): Cryptographic MPC derivation of Bitcoin, EVM, and Solana addresses from NEAR contract identity.
  * [`test_sweep_flow.js`](scripts/test_sweep_flow.js): Comprehensive end-to-end simulation verifying all 6 multichain evacuation flows.
  * [`deploy_testnet.js`](scripts/deploy_testnet.js): Automated NEAR Testnet deployment script.
* [`web/`](web/): High-performance cyber-hardened user interface:
  * [`index.html`](web/index.html): Real-time Web3 frontend with live NEAR RPC contract polling, `window.nearApi` transaction dispatcher, MyNearWallet testnet authentication, interactive multichain address derivation display, and hold-to-evacuate panic trigger.
* [`AEGIS_AUDIT_BUNDLE.md`](AEGIS_AUDIT_BUNDLE.md): Consolidated, single-file audit bundle containing complete codebase, verified security invariants, and test vectors.

---

## ⚡ Quick Start & Verification

### 1. Run Unit Tests (Rust Smart Contract)
```bash
cd contracts/vault
cargo test
```
*Result: 9/9 unit tests passing (anti-blind-signing, Solana substring rejection, epoch rotation, policy timelock).*

### 2. Build WebAssembly Contract
```bash
cargo build --target wasm32-unknown-unknown --release
```
*Output: `contracts/vault/target/wasm32-unknown-unknown/release/lastkey_vault.wasm` (306 KB)*

### 3. Run Multichain Relayer Verification
```bash
node scripts/test_sweep_flow.js
```
*Result: 100% of multichain relayer pipelines verified (EVM EIP-1559, Bitcoin BIP-143 PSBT with DER injection, Solana SystemProgram & Token-2022, NEAR Native).*

### 4. Run Frontend Locally
```bash
npx serve web
# Or open web/index.html directly in any browser
```
*Live Deployment:* [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/)

---

## 🔒 Security & Invariants

| Attack Vector | Defense Mechanism | Invariant Location |
| :--- | :--- | :--- |
| **Relayer Blind-Signing** | Raw transaction bytecode validation; destination must match on-chain policy | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs#L365-L375) |
| **Solana Substring Injection** | Strict parsing of Solana Message header (`unsigned_writable_count == 1`) | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs#L440-L490) |
| **Bitcoin Dust Rejection** | Automatic pruning of UTXOs under 546 sats to prevent mempool rejection | [`relayer/sweep_relayer.js`](relayer/sweep_relayer.js#L350-L360) |
| **Solana Blockhash Expiry** | JIT finalized blockhash refresh immediately prior to MPC signature request | [`relayer/sweep_relayer.js`](relayer/sweep_relayer.js#L585-L600) |
| **EVM Nonce Stall** | Continuous nonce fault isolation skips broken/honeypot tokens without gaps | [`relayer/sweep_relayer.js`](relayer/sweep_relayer.js#L260-L290) |
| **Unauthorized Policy Takeover** | 72-hour timelock on destination updates with instant owner cancellation | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs#L210-L245) |

---

## 📜 License
Apache-2.0 / MIT

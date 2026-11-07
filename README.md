# 🛡️ Aegis Vault — Autonomous Multichain Dead-Man's Switch & Panic Evacuation Bunker

> **NEAR HACKATHON 2026 Submission**  
> **Track:** Web3 Infrastructure · Multi-Chain Security · Chain Abstraction  
> **Core Primitive:** Native NEAR Chain Signatures (`v1.signer-prod.testnet` MPC Network) & Pure Rust Smart Contract  
> **Live App:** [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/)  
> **NEAR Testnet Contract:** [`aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet)  
> **Least-Privilege Keeper Account:** [`keeper.aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/keeper.aegis.okgoogleok.testnet)

---

## 🎯 The Problem

1. **Billions in Stranded Crypto Assets**: When an asset holder unexpectedly passes away or becomes incapacitated, family members rarely know how to recover seed phrases, hardware wallets, and cross-chain accounts across disparate ecosystems.
2. **Physical Coercion & Duress ("\$5 Wrench Attack")**: Under physical extortion or device seizure, victims need an immediate, irreversible mechanism to evacuate assets to cold multi-sig/backup storage and burn hot derivation epochs.
3. **Cross-Ecosystem Fragmentation & Blind-Signing Risks**: Traditional inheritance contracts work only inside a single EVM chain, expose plaintext notes on-chain, or rely on centralized custodial bots with unrestricted signing keys.

---

## 💡 The Solution: Aegis Vault

**Aegis Vault** is a 100% non-custodial multichain dead-man's switch and emergency evacuation bunker powered by **NEAR Protocol Chain Signatures (`v1.signer-prod.testnet`)**. A single Rust smart contract governs threshold ECDSA (`Secp256k1`) and EdDSA (`Ed25519`) sweeps across **Bitcoin (Native SegWit)**, **EVM (Ethereum / Base / Arbitrum)**, **Solana (Native + SPL / Token-2022)**, and **NEAR**.

### Key Capabilities & Hardened Architecture

* **Zero Custody (Deterministic MPC Derivation)**: Deposit addresses are derived directly from `v1.signer-prod.testnet` via `aegis/{vault_owner}/{epoch}`. No private keys ever exist on any server.
* **Autonomous Push Inheritance (`trigger_push_inheritance`)**: Once `heartbeat_interval_ns + challenge_period_ns` elapses without an owner check-in, anyone or any stateless cloud keeper transitions the vault to `Inheritance` and sweeps 100% of multichain funds directly to designated heirs — heirs never need to connect a wallet, claim, or pay gas.
* **Emergency Panic Evacuation (`panic`)**: 3-second continuous hold trigger (or armed instant mode) immediately locks the vault into `Evacuated`, routes 100% of assets to cold backup addresses, and archives historical destinations upon `rotate_bunker()` (`archive:{owner}:{epoch}`).
* **Client-Side E2EE Digital Testament (Zero Plaintext On-Chain)**:
  * **Asymmetric Mode (`enc:x25519:...`)**: Automatically converts the heir's Solana `Ed25519` public key into a `Curve25519` (`X25519`) public key in the browser (`@noble/curves/ed25519` + `tweetnacl`) and seals the testament before touching NEAR RPC.
  * **Symmetric Mode (`enc:aes256:...`)**: Optional WebCrypto `PBKDF2-SHA256` (`100,000` iterations) + `AES-256-GCM` authenticated encryption.
  * Embedded on-chain during sweeps (Solana Memo, EVM calldata, and 80-byte SHA-256 commitment anchor in Bitcoin `OP_RETURN`), unreadable on block explorers, and decryptable 100% offline via UI (`🔓 Decrypt`) or CLI (`node scripts/decrypt_testament.js`).
* **Self-Sustaining Keeper Economics (Per-Vault Gas Escrow & Refund)**:
  * Vault owners can fund an isolated `gas_escrow` (`deposit_escrow` / `propose_policy`), backed by the contract's Sponsor Pool fallback.
  * Stateless keepers invoke `request_sweep_signature` with **`0` attached NEAR deposit**; the contract pays the `v1.signer` MPC fee and automatically refunds **`0.005 NEAR`** execution gas to the keeper inside `on_signature_ready`.
* **Least-Privilege `FunctionCall` Keeper (`keeper.aegis.okgoogleok.testnet`)**:
  * Cloud keepers operate with a restricted `FunctionCall` access key (`0` NEAR transfer capability, scoped strictly to `trigger_push_inheritance`, `request_sweep_signature`, `record_sweep_telemetry`, `ping_by_relayer`, and `sweep_near`).
* **Cryptographic Anti-Blind-Signing & Fee-Drain Protection**:
  * **Solana Structural Bytecode Parser**: Parses the full binary Solana `Message` header and compiled instructions on-chain; bans `ComputeBudget111111111111111111111111111111` (preventing priority-fee drain to validator colluders), rejects zero blockhashes, and verifies `SystemProgram::Transfer` (`lamports > 0`) or `SPL Token` / `Token-2022` + `ATA` (`amount > 0`) strictly target the policy-locked recipient.
  * **EVM EIP-1559 RLP Bytecode Parser**: Decodes raw Type-2 RLP transactions on-chain, enforces `gas_limit` (`21,000..=250,000`) and `max_fee_per_gas <= 500 Gwei` caps, verifies native ETH (`value > 0`), `ERC-20 transfer` (`0xa9059cbb`), and `ERC-721 safeTransferFrom` (`0x42842e0e`) recipients, and hashes via `env::keccak256` inside WASM.
  * **Signed Sponsored Heartbeat (`ping_by_relayer`)**: Verifies owner `Ed25519` / NEP-413 signatures on-chain via `env::ed25519_verify` with monotonic timestamp anti-replay (`ping_ts:{owner}`), preventing hostile relayers from resetting a deceased owner's timer.

---

## 🏗️ System Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │         Vault Owner / Browser Client         │
                       │  - Local X25519 / AES-256-GCM E2EE Sealing   │
                       │  - Meteor / Nightly / HERE / Sender Wallets  │
                       └──────────────────────┬───────────────────────┘
                                              │  propose_policy() / ping() / panic()
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │       Aegis Vault Contract (Rust / WASM)     │
                       │            aegis.okgoogleok.testnet          │
                       │  - Multi-Tenant Vaults & 72h Policy Timelock │
                       │  - EVM RLP & Solana Instruction Verifiers    │
                       │  - Per-Vault Gas Escrow + 0.005N Refund      │
                       │  - On-Chain Sweep Telemetry & Epoch Archive  │
                       └──────────┬───────────────────────┬───────────┘
       0-Deposit Stateless Sweep  │                       │  Cross-Contract sign()
   keeper.aegis.okgoogleok.testnet│                       ▼
┌─────────────────────────────────┴──┐     ┌──────────────────────────────────┐
│  24/7 Stateless Cloud Keepers      │     │  NEAR MPC (v1.signer-prod)       │
│  - Cloudflare Worker (Edge HTTP)   │     │  - Threshold Secp256k1 (BTC/EVM) │
│  - GitHub Actions (*/5m Cron)      │     │  - Threshold Ed25519 (SOL/NEAR)  │
└─────────────────┬──────────────────┘     └─────────────────┬────────────────┘
                  │  Assemble & Broadcast Signed Raw Tx      │
                  └───────────────────┬──────────────────────┘
                                      ▼
        ┌─────────────────┬───────────────────────┬─────────────────┐
        ▼                 ▼                       ▼                 ▼
 ┌─────────────┐   ┌─────────────┐         ┌─────────────┐   ┌─────────────┐
 │   Bitcoin   │   │     EVM     │         │   Solana    │   │    NEAR     │
 │ SegWit PSBT │   │  EIP-1559   │         │ System/SPL  │   │  Implicit & │
 │ Multi-UTXO  │   │ Dynamic Fee │         │ Base58 Sig  │   │  Isolated   │
 └─────────────┘   └─────────────┘         └─────────────┘   └─────────────┘
```

---

## 📁 Repository Structure

* [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs): Hardened Rust smart contract (`near-sdk 5.5.0`) — state machine, Solana compiled-instruction verifier, EVM EIP-1559 RLP verifier, `ed25519_verify` NEP-413 sponsored ping, Per-Vault Gas Escrow + keeper refund, isolated NEAR vault deposits, epoch archiving, and on-chain sweep telemetry.
* [`relayer/service.js`](relayer/service.js) & [`relayer/sweep_relayer.js`](relayer/sweep_relayer.js): Stateless multichain sweep engine — multi-UTXO Bitcoin SegWit PSBT signing + `OP_RETURN` anchor, dynamic EVM nonce/fee calculation + honeypot fault isolation, real 88-char Base58 Solana signatures, and on-chain `record_sweep_telemetry`.
* [`workers/keeper/`](workers/keeper/): Serverless Cloudflare Worker (`nodejs_compat`) running at the edge for instant `<1s` `/trigger` sweeps and scheduled autonomous checks.
* [`.github/workflows/relayer-keeper.yml`](.github/workflows/relayer-keeper.yml): Autonomous GitHub Actions cloud keeper (`*/5 * * * *`) powered by the restricted `FunctionCall` key on `keeper.aegis.okgoogleok.testnet`.
* [`src/wallet-selector.js`](src/wallet-selector.js) & [`web/index.html`](web/index.html): Static zero-backend Web3 interface with NEAR Wallet Selector, live MPC address derivation, client-side X25519/AES-256 E2EE testament sealing & offline decryption modal, Judge Demo Mode (`2m + 30s`), and real-time on-chain evacuation telemetry.
* [`scripts/decrypt_testament.js`](scripts/decrypt_testament.js): Zero-server offline CLI decryptor for heirs (`enc:x25519:` & `enc:aes256:`).
* [`scripts/test_sweep_flow.js`](scripts/test_sweep_flow.js): End-to-end cryptographic test suite validating all 6 multichain sweep pipelines.
* [`AEGIS_AUDIT_BUNDLE.md`](AEGIS_AUDIT_BUNDLE.md): Complete single-file architectural and source-code audit dossier.

---

## ⚡ Quick Start & Verification

### 1. Run Smart Contract Security Unit Tests (Rust)
```bash
cd contracts/vault
cargo test
```
*Result: `7/7` comprehensive security suites passing (EVM RLP fee/destination caps, Solana `ComputeBudget` & decoy rejection, `ed25519_verify` replay protection, epoch rotation & archiving, 72h policy timelock).*

### 2. Run Multichain Relayer Cryptographic Suite
```bash
npm test
# or: node scripts/test_sweep_flow.js
```
*Result: `100%` of multichain pipelines verified (MPC address derivation on `aegis.okgoogleok.testnet`, EVM EIP-1559 signature recovery, Bitcoin SegWit PSBT + dust guard, Solana SystemProgram & SPL/Token-2022 atomic ATA sweep, NEAR sweep, and EVM fault isolation).*

### 3. Test Offline E2EE Testament Decryption
```bash
node scripts/decrypt_testament.js "<enc:x25519:... | enc:aes256:...>" "<solana_secret_key_or_passphrase>"
```

### 4. Run Frontend Locally
```bash
npx serve web
```
*Live Deployment:* [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/)

---

## 🔒 Security Invariants Matrix

| Attack Vector | On-Chain / Cryptographic Defense | Implementation |
| :--- | :--- | :--- |
| **Relayer Blind-Signing (EVM)** | Full EIP-1559 RLP decode; enforces `to == policy_dest`, `gas_limit <= 250k`, `max_fee <= 500 Gwei`, WASM `keccak256` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Solana Fee-Drain & Decoy Accounts** | Full compiled-instruction parser; bans `ComputeBudget`, rejects zero blockhash, verifies `lamports/amount > 0` to heir/backup | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Hostile Relayer Timer Reset** | `ping_by_relayer` requires `env::ed25519_verify` over owner's key + 1h freshness + monotonic `ping_ts:{owner}` anti-replay | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Keeper Key Compromise** | Dedicated `keeper.aegis.okgoogleok.testnet` uses restricted `FunctionCall` key (`0` transfer rights, 5 whitelisted methods) | On-Chain Access Key |
| **Keeper Gas Depletion** | `0`-deposit `request_sweep_signature` funded via Per-Vault `gas_escrow` / Sponsor Pool + `0.005 NEAR` automatic gas refund | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Plaintext Testament Leakage** | Client-side `X25519` (`Ed25519 -> Curve25519`) & `PBKDF2-AES-256-GCM` encryption before RPC submission | [`src/wallet-selector.js`](src/wallet-selector.js) |
| **Unauthorized Policy Takeover** | 72-hour timelock on egress updates or non-demo timer shortening, with instant owner `cancel_policy_update()` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Delayed Sweep After Rotation** | `rotate_bunker()` snapshots `{state, destination}` in `archive:{owner}:{epoch}` so late sweeps remain cryptographically verifiable | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |

---

## 🚀 24/7 Autonomous Cloud Keeper Infrastructure

Aegis runs completely serverless with **zero local daemons required**:

1. **Cloudflare Edge Worker (`workers/keeper/`)**: Stateless `nodejs_compat` Worker handling instant `<1s` `POST /trigger` sweeps on Panic / Inheritance expiry plus `/health` and `/telemetry` endpoints.
   ```bash
   cd workers/keeper
   npx wrangler deploy
   npx wrangler secret put RELAYER_PRIVATE_KEY
   ```
2. **GitHub Actions Autonomous Keeper (`.github/workflows/relayer-keeper.yml`)**: Runs `node relayer/service.js --sweep-all` every 5 minutes (`*/5 * * * *`) against `aegis.okgoogleok.testnet` (`0` gas burned when `get_actionable_vaults` is empty).
3. **Docker / Render Self-Hostable Container**:
   ```bash
   docker compose up -d
   ```

---

## 📜 License
Apache-2.0 / MIT

# 🛡️ LastKey Bunker — Zero-Signature Crypto Bunker & Automatic Inheritance on NEAR MPC

> **NEAR HACKATHON 2026 Submission (`Nov 1–14, 2026`)**  
> **Official Track IDs:** `open` (Open Innovation) · `security` (AI Security & Defense) · `defi` (Unstoppable DeFi)  
> **Core Primitive:** Native NEAR Chain Signatures (`v1.signer-prod.testnet` MPC Network) & Pure Rust Smart Contract  
> **Live App:** [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/)  
> **24/7 Autonomous Cloud Keeper:** [`.github/workflows/relayer-keeper.yml`](https://github.com/mastrophot/aegis-vault/actions/workflows/relayer-keeper.yml)  
> **NEAR Testnet Contract (`Aegis Engine`):** [`aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet)  
> **Least-Privilege Keeper Account:** [`keeper.aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/keeper.aegis.okgoogleok.testnet)  
> **Zero-Metadata Telegram Alerts Bot:** [`@aegis_vault_bot`](https://t.me/aegis_vault_bot)

---

## 🎯 The Problem

1. **Billions in Stranded Crypto Assets**: When an asset holder unexpectedly passes away or becomes incapacitated, beneficiaries rarely know how to recover seed phrases, hardware wallets, and cross-chain accounts across disparate ecosystems.
2. **Physical Coercion, Key Exposure & Duress ("\$5 Wrench Attack")**: Every time a regular wallet signs an outgoing transaction, it permanently exposes its cryptographic public key on-chain. Under physical extortion or key compromise, holders need a zero-signature Bunker with an immediate, irreversible mechanism to evacuate 100% of assets to backup storage and retire exposed derivation epochs.
3. **Cross-Ecosystem Fragmentation & Blind-Signing Risks**: Traditional inheritance contracts work only inside a single EVM chain, expose plaintext notes on-chain, or rely on centralized custodial bots with unrestricted signing keys.

---

## 💡 The Solution: LastKey Bunker

**LastKey Bunker** (powered by the on-chain **Aegis MPC Engine** at `aegis.okgoogleok.testnet`) is a 100% non-custodial multichain zero-signature crypto bunker, emergency panic switch, and automatic inheritance protocol built on **NEAR Protocol Chain Signatures (`v1.signer-prod.testnet`)**. A single Rust smart contract governs threshold ECDSA (`Secp256k1`) and EdDSA (`Ed25519`) sweeps across **Bitcoin (Native SegWit)**, **EVM (Ethereum / Base / Arbitrum)**, **Solana (Native + SPL / Token-2022)**, and **NEAR**.

### Key Capabilities & Hardened Architecture

* **Zero Custody (Deterministic MPC Derivation)**: Deposit addresses are derived directly from `v1.signer-prod.testnet` via `aegis/{vault_owner}/{epoch}`. No private keys ever exist on any server.
* **Autonomous Push Inheritance (`trigger_push_inheritance`)**: Once `heartbeat_interval_ns + challenge_period_ns` elapses without an owner check-in, anyone or any stateless cloud keeper transitions the vault to `Inheritance` and sweeps 100% of multichain funds directly to designated heirs — heirs never need to connect a wallet, claim, or pay gas.
* **Emergency Panic Evacuation (`panic`)**: 3-second continuous hold trigger (or armed instant mode) immediately locks the vault into `Evacuated`, routes 100% of assets to cold backup addresses, and archives historical destinations upon `rotate_bunker()` (`archive:{owner}:{epoch}`).
* **Client-Side E2EE Digital Testament (Zero Plaintext On-Chain)**:
  * **Asymmetric Mode (`enc:x25519:...`)**: Automatically converts the heir's Solana `Ed25519` public key into a `Curve25519` (`X25519`) public key in the browser (`@noble/curves/ed25519` + `tweetnacl`) and seals the testament before touching NEAR RPC.
  * **Symmetric Mode (`enc:aes256:...`)**: Optional WebCrypto `PBKDF2-SHA256` (`100,000` iterations) + `AES-256-GCM` authenticated encryption.
  * Embedded on-chain during sweeps (Solana Memo, EVM calldata, and 80-byte SHA-256 commitment anchor in Bitcoin `OP_RETURN`), unreadable on block explorers, and decryptable 100% offline via UI (`🔓 Decrypt`) or CLI (`node scripts/decrypt_testament.js`).
* **Self-Sustaining Keeper Economics (Per-Vault Gas Escrow & Refund)**:
  * Vault owners can fund an isolated `gas_escrow` (`deposit_escrow` / `propose_policy`), backed by the contract's Sponsor Pool fallback (capped at `8` sponsored calls per `(vault_owner, epoch)` to prevent pool drain).
  * Stateless keepers invoke `request_sweep_signature` with **`0` attached NEAR deposit**; the contract pays the `v1.signer` MPC fee and automatically refunds **`0.005 NEAR`** execution gas to the keeper inside `on_signature_ready`.
* **Least-Privilege `FunctionCall` Keeper (`keeper.aegis.okgoogleok.testnet`)**:
  * Cloud keepers operate with a restricted `FunctionCall` access key (`ed25519:Cq8ZmZoDkPX57ZqPKsNeeYuqtjfqtFwk3QrnmcuDwfAW`, `0` NEAR transfer capability, scoped strictly to `trigger_push_inheritance`, `request_sweep_signature`, `record_sweep_telemetry`, `ping_by_relayer`, `sweep_near`, `record_alert_state`, `sync_owner_activity`, and `apply_policy`).
* **Zero Blind-Signing Across All 4 Chains (On-Chain WASM Bytecode Verifiers)**:
  * **Bitcoin BIP-143 SegWit Preimage + Outputs Verifier (`verify_btc_sweep_payload`)**: Rejects raw 32-byte blind hashes. Parses the 182-byte BIP-143 P2WPKH preimage + serialized outputs on-chain, enforces `scriptCode` (`0x1976a914...88ac`) and `SIGHASH_ALL`, verifies `SHA256(SHA256(outputs)) == hashOutputs`, confirms Output 0 transfers `>= 546` sats strictly to the policy-locked Bech32/Base58 recipient (plus optional 0-sat `OP_RETURN`), and computes `SHA256(SHA256(preimage))` inside WASM.
  * **EVM EIP-1559 RLP Bytecode Verifier (`verify_evm_sweep_payload`)**: Decodes raw Type-2 RLP transactions on-chain, enforces `gas_limit` (`21,000..=250,000`) and `max_fee_per_gas <= 500 Gwei` caps, verifies native ETH (`value > 0`), `ERC-20 transfer` (`0xa9059cbb`), and `ERC-721 safeTransferFrom` (`0x42842e0e`) recipients, and hashes via `env::keccak256` inside WASM.
  * **Solana Structural Instruction Verifier (`verify_solana_sweep_payload`)**: Parses the full binary Solana `Message` header and compiled instructions on-chain; bans `ComputeBudget111111111111111111111111111111` (preventing priority-fee drain to validator colluders), rejects zero blockhashes, and verifies `SystemProgram::Transfer` (`lamports > 0`) or `SPL Token` / `Token-2022` + `ATA` (`amount > 0`) strictly target the policy-locked recipient.
  * **NEAR Borsh Transaction & NEP-141/171 Verifier (`verify_near_sweep_payload`)**: Parses Borsh-encoded unsigned NEAR `Transaction` bytes on-chain, verifies `block_hash != 0`, and validates either a native `Action::Transfer(deposit > 0)` to `target_destination.near` OR a single `Action::FunctionCall` (`ft_transfer` NEP-141 / `nft_transfer` NEP-171 with `receiver_id == target_destination.near`, `1 yoctoNEAR` deposit, and `5..=50 TGas`), computing `env::sha256` inside WASM.
  * **Signed Sponsored Heartbeat (`ping_by_relayer`) & Passive Wallet Activity Sync (`sync_owner_activity`)**: Verifies owner `Ed25519` / NEP-413 signatures on-chain via `env::ed25519_verify` with monotonic timestamp anti-replay (`ping_ts:{owner}`), and automatically resets the check-in timer whenever the owner's NEAR wallet access key nonce increments (`sync_owner_activity` with anti-spoofing future-nonce ceiling).

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
                       │  - 4-Chain Bytecode Verifiers (Zero Blind)   │
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
 │ BIP-143 PSBT│   │  EIP-1559   │         │ System/SPL  │   │  Implicit & │
 │ Multi-UTXO  │   │ Dynamic Fee │         │ Base58 Sig  │   │  Isolated   │
 └─────────────┘   └─────────────┘         └─────────────┘   └─────────────┘
```

---

## 📁 Repository Structure

* [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs): Hardened Rust smart contract (`near-sdk 5.5.0`) — state machine, 72h policy timelock, Bitcoin BIP-143 preimage + outputs verifier, EVM EIP-1559 RLP verifier, Solana compiled-instruction verifier, NEAR Borsh transaction verifier, `ed25519_verify` NEP-413 sponsored ping, Per-Vault Gas Escrow + keeper refund, isolated NEAR vault deposits, epoch archiving, and on-chain sweep telemetry.
* [`relayer/service.js`](relayer/service.js) & [`relayer/sweep_relayer.js`](relayer/sweep_relayer.js): Stateless multichain sweep engine — automated native sweeps across Bitcoin (multi-UTXO SegWit PSBT + `OP_RETURN` anchor), EVM (dynamic gas estimation + EIP-1559 fee clamp), Solana (Base58 Ed25519 signature), and NEAR (isolated + implicit bunker), plus verifiable builders for ERC-20, ERC-721, and Solana SPL/Token-2022 sweeps with honeypot fault isolation.
* [`workers/keeper/`](workers/keeper/): Serverless Cloudflare Worker (`nodejs_compat`) running at the edge for instant `<1s` `POST /trigger` sweeps and scheduled autonomous checks.
* [`.github/workflows/relayer-keeper.yml`](.github/workflows/relayer-keeper.yml): Autonomous 24/7 GitHub Actions cloud keeper (`*/5 * * * *` chained 55m windows, 3s polling) powered by the restricted `FunctionCall` key on `keeper.aegis.okgoogleok.testnet` and `TELEGRAM_BOT_TOKEN` secret.
* [`src/wallet-selector.js`](src/wallet-selector.js) & [`web/index.html`](web/index.html): Static zero-backend Web3 interface with NEAR Wallet Selector, live MPC address derivation, client-side X25519/AES-256 E2EE testament sealing & offline decryption modal, Judge Demo Mode (`3m + 1m`), and real-time on-chain evacuation telemetry.
* [`scripts/decrypt_testament.js`](scripts/decrypt_testament.js): Zero-server offline CLI decryptor for heirs (`enc:x25519:` & `enc:aes256:`).
* [`scripts/test_sweep_flow.js`](scripts/test_sweep_flow.js): End-to-end cryptographic test suite validating all multichain sweep pipelines.
* [`AEGIS_AUDIT_BUNDLE.md`](AEGIS_AUDIT_BUNDLE.md): Complete single-file architectural and source-code audit dossier.

---

## ✅ Judge & AI Screening Verification Checklist ("Do X — See Y" / `Procedure #1`)

Every component of Aegis Vault can be deterministically verified in under 60 seconds via CLI or browser:

1. **Do X (Run On-Chain Security & Bytecode Verifier Unit Tests)**:
   ```bash
   cd contracts/vault && cargo test
   ```
   **See Y**: `9 passed; 0 failed` — confirms 72h timelock enforcement on both destination policies and heartbeat/grace timers (`test_timer_downgrade_attack_blocked_on_armed_bunker`), EVM EIP-1559 RLP fee/recipient verification, Bitcoin BIP-143 preimage + output verification & recipient-hijack rejection, Solana `ComputeBudget` & decoy rejection, NEAR Borsh transaction verification & `FunctionCall` rejection, and `ed25519_verify` NEP-413 replay protection.

2. **Do X (Run End-to-End Multichain Relayer & MPC Derivation Suite)**:
   ```bash
   npm test
   ```
   **See Y**: `🚀 ALL MULTICHAIN RELAYER PIPELINES PASSED (100%)` — derives live BTC/EVM/SOL bunker addresses from `v1.signer-prod.testnet` for `aegis.okgoogleok.testnet`, constructs verifiable EVM EIP-1559, Bitcoin BIP-143 SegWit PSBT, Solana System/SPL/Token-2022, and NEAR transactions, and validates fault-isolated queue execution.

3. **Do X (Verify Live On-Chain Contract State via NEAR RPC)**:
   ```bash
   node relayer/service.js --once
   ```
   **See Y**: Queries `get_actionable_vaults` on `aegis.okgoogleok.testnet`, synchronizes wallet activity (`sync_owner_activity`), promotes elapsed 72h policies (`apply_policy`), and executes multichain sweeps for any expired or evacuated vaults.

4. **Do X (Verify Offline Client-Side E2EE Testament Encryption & Decryption)**:
   ```bash
   node -e '
     const nacl = require("tweetnacl");
     const bs58 = require("bs58");
     const kp = nacl.sign.keyPair();
     const pub58 = (bs58.encode || bs58.default.encode)(kp.publicKey);
     const sec58 = (bs58.encode || bs58.default.encode)(kp.secretKey);
     const { edwardsToMontgomeryPub } = require("@noble/curves/ed25519");
     const xPub = edwardsToMontgomeryPub(kp.publicKey);
     const eph = nacl.box.keyPair();
     const nonce = nacl.randomBytes(24);
     const box = nacl.box(Buffer.from("Seed phrase in safe #42"), nonce, xPub, eph.secretKey);
     const ct = "enc:x25519:" + Buffer.concat([eph.publicKey, nonce, box]).toString("base64");
     const out = require("child_process").execFileSync("node", ["scripts/decrypt_testament.js", ct, sec58]).toString();
     console.log(out.trim());
   '
   ```
   **See Y**: Outputs `Seed phrase in safe #42` decrypted 100% offline using only the heir's Solana Ed25519 keypair.

5. **Do X (Test Live Web App in Browser)**:
   Open [https://mastrophot.github.io/aegis-vault/](https://mastrophot.github.io/aegis-vault/) -> connect any NEAR Testnet wallet (Meteor / MyNearWallet / Nightly) -> configure Backup/Heir addresses in **1. Rescue & Inheritance** -> view deterministic MPC bunker addresses in **2. Safe Bunker Deposits** -> test **Judge Demo Mode (`3m + 1m`)** or hold the red **PANIC EVACUATE** button for 3 seconds.
   **See Y**: Real NEAR Testnet transactions confirmed on `aegis.okgoogleok.testnet`, live multichain sweep status in the Evacuation Monitor modal, and direct explorer proof links (`NearBlocks`, `Etherscan`, `Mempool.space`, `Solscan`).

---

## 🔒 Security Invariants Matrix

| Attack Vector | On-Chain / Cryptographic Defense | Implementation |
| :--- | :--- | :--- |
| **Relayer Blind-Signing (BTC)** | Full 182B BIP-143 P2WPKH preimage + serialized outputs check; verifies `hashOutputs`, `Output 0 >= 546 sats` to policy BTC address, WASM `sha256d` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Relayer Blind-Signing (EVM)** | Full EIP-1559 RLP decode; enforces `to == policy_dest`, `gas_limit <= 250k`, `max_fee <= 500 Gwei`, WASM `keccak256` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Solana Fee-Drain & Decoy Accounts** | Full compiled-instruction parser; bans `ComputeBudget`, rejects zero blockhash, verifies `lamports/amount > 0` to heir/backup | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Relayer Blind-Signing (NEAR)** | Full Borsh `Transaction` parser; verifies `receiver_id == policy_dest.near`, `block_hash != 0`, single `Transfer(deposit > 0)`, WASM `sha256` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Hostile Relayer Timer Reset** | `ping_by_relayer` requires `env::ed25519_verify` over owner's key + 10m freshness + monotonic `ping_ts:{owner}` anti-replay | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Keeper Key Compromise** | Dedicated `keeper.aegis.okgoogleok.testnet` uses restricted `FunctionCall` key (`0` transfer rights, whitelisted methods only) | On-Chain Access Key |
| **Keeper Gas Depletion & Drain** | `0`-deposit `request_sweep_signature` funded via Per-Vault `gas_escrow` / Sponsor Pool (capped at 8 calls/epoch) + `0.005 NEAR` keeper refund | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Plaintext Testament Leakage** | Client-side `X25519` (`Ed25519 -> Curve25519`) & `PBKDF2-AES-256-GCM` encryption before RPC submission; strictly suppressed on `panic` | [`src/wallet-selector.js`](src/wallet-selector.js) |
| **Unauthorized Policy / Timer Takeover** | 72-hour timelock on any egress address or timer modification once armed, with instant owner `cancel_policy()` and non-blocking inheritance expiry | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Telegram Metadata & Token Exposure** | Server-side `TELEGRAM_BOT_TOKEN` in GitHub Secrets, anonymous SHA-256 `/start v1_<tag>` linking, encrypted `cid_enc`, and zero-metadata alert strings | [`relayer/service.js`](relayer/service.js) |
| **Delayed Sweep After Rotation** | `rotate_bunker()` snapshots `{state, destination}` in `archive:{owner}:{epoch}` so late sweeps remain cryptographically verifiable | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |

---

## 🛡️ Failure Cases, Edge-Case Resilience & Scoped Key Limits (`13-open` & `06-security`)

### 1. Why Guardian-Less Deterministic MPC Beats Multi-Guardian Committees (`13-open.md` Objections)
* **Lost Guardian Keys**: Traditional inheritance schemes rely on `M-of-N` human guardians who frequently lose hardware wallets or become unreachable over multi-year horizons, permanently bricking the estate. Aegis Vault eliminates human guardian committees entirely (`0-Guardian Architecture`): release rules live deterministically in `aegis.okgoogleok.testnet`, while key shares are maintained by the decentralized **NEAR MPC Network (`v1.signer-prod.testnet`)**.
* **A Guardian (or Keeper) Who Turns Hostile**: In Aegis Vault, neither a relayer nor the autonomous keeper (`keeper.aegis.okgoogleok.testnet`) has discretionary approval power or blind-signing access:
  1. It cannot trigger inheritance early (`require!(now >= last_heartbeat_ns + heartbeat_interval_ns + challenge_period_ns)`).
  2. It cannot redirect funds to its own address: the on-chain WASM bytecode verifiers (`verify_btc_sweep_payload`, `verify_evm_sweep_payload`, `verify_solana_sweep_payload`, `verify_near_sweep_payload`) parse every raw unsigned transaction byte-by-byte and panic if the recipient diverges by a single bit from the owner's policy-locked `heir` or `backup` address.
  3. It cannot infinitely reset a deceased owner's timer: `ping_by_relayer` requires an on-chain verified `Ed25519` signature from the owner's public key (`env::ed25519_verify`) with a strict 10-minute freshness window and monotonic anti-replay (`ping_ts:{owner}`).
* **An Owner Who Is Alive But Offline / Traveling**:
  1. **Passive Wallet Activity Sync (`sync_owner_activity`)**: The owner does not even need to open Aegis Vault — any outgoing transaction signed by any access key on the owner's NEAR wallet increments the on-chain key nonce, which the 24/7 Keeper detects via NEAR RPC (`view_access_key_list`) and uses to automatically reset the check-in clock.
  2. **Two-Stage Grace Period + Multi-Stage Zero-Metadata Telegram Alerts**: When the primary check-in timer reaches `<= 25%` remaining, `@aegis_vault_bot` dispatches an early warning; if `0s` is reached, the vault enters the **Grace Buffer** (`challenge_period_ns`, e.g., 3–30 days in production or `1m` in Judge Demo) and dispatches a critical alert.
  3. **Instant 1-Click Cancellation**: At any moment before `heartbeat_interval_ns + challenge_period_ns` expires, the owner can cancel a pending release via `ping()`, `cancel_grace()`, or simply by making any normal NEAR wallet transaction.
* **Hostile Heir / Compromised Owner Session Attempting Timer or Policy Hijack**:
  * Once a bunker is armed, any attempt to change destination addresses (`backup` / `heir`) OR shorten `heartbeat_interval_ns` / `challenge_period_ns` is locked behind a mandatory **72-hour on-chain Timelock (`pending_policy`)** and immediately triggers a Telegram security alert to the owner, who can abort the hijack in 1 click via `cancel_policy()`.

### 2. Limits of the Scoped `FunctionCall` Access Key (`06-security.md` Requirements)
The 24/7 cloud keeper (`keeper.aegis.okgoogleok.testnet`) holds **zero `FullAccess` keys** in production workflows and authenticates strictly via a protocol-enforced `FunctionCall` access key (`ed25519:Cq8ZmZoDkPX57ZqPKsNeeYuqtjfqtFwk3QrnmcuDwfAW`):
* **Protocol-Enforced Restrictions**:
  * **Receiver Lock**: Can only call `aegis.okgoogleok.testnet` (any call to any other contract or account is rejected by NEAR validators before execution).
  * **Method Whitelist**: Strictly limited to `trigger_push_inheritance`, `request_sweep_signature`, `record_sweep_telemetry`, `ping_by_relayer`, `sweep_near`, `record_alert_state`, `sync_owner_activity`, and `apply_policy`.
  * **Zero Admin / Policy Access**: Cannot call `propose_policy`, `cancel_policy`, `panic`, `ping`, or `rotate_bunker` (these additionally check `env::predecessor_account_id() == vault_owner`).
  * **Zero Native Transfer / Key Mutation**: A `FunctionCall` key cannot execute `Action::Transfer`, `Action::AddKey`, `Action::DeleteKey`, or `Action::DeployContract`.
* **Solving the Gas-Allowance Lockout Caveat**:
  * As noted in NEAR's access-key documentation, an account holding only a `FunctionCall` key can lock itself out if its gas/balance runs dry. Aegis Vault solves this on-chain: `request_sweep_signature` requires **`0` attached deposit** from the keeper (the contract funds the `v1.signer-prod.testnet` MPC fee from the vault's `gas_escrow` / Sponsor Pool) and automatically transfers a **`0.005 NEAR` gas refund** back to `keeper.aegis.okgoogleok.testnet` inside `on_signature_ready`.

---

## 📋 Disclosure (`Q-005`)

* **Pre-Existing Code**: **None (`0%`)**. 100% of the smart contract (`contracts/vault/src/lib.rs`), multichain relayer engine (`relayer/`), serverless Cloudflare edge keeper (`workers/keeper/`), frontend (`web/index.html`, `src/wallet-selector.js`), and verification scripts (`scripts/`) were written from scratch during the NEAR Hackathon window (**November 2–9, 2026**).
* **Open-Source Libraries & Dependencies**:
  * **Smart Contract (Rust)**: `near-sdk` (`5.5.0`), `near-contract-standards` (`5.5.0`), `serde`, `serde_json`, `borsh`, `schemars`, `hex`, `bs58`.
  * **Relayer & Frontend (JavaScript)**: `near-api-js`, `chainsig.js`, `ethers` (`v6`), `bitcoinjs-lib`, `ecpair`, `tiny-secp256k1`, `@solana/web3.js`, `@near-wallet-selector/*` (`core`, `modal-ui-js`, `meteor-wallet`, `my-near-wallet`, `here-wallet`, `nightly`, `sender`), `tweetnacl`, `@noble/curves`, `bs58`, `tailwindcss`.
* **AI Tooling Disclosure**: Built with the assistance of AI coding and security-auditing assistants (Google Antigravity / Gemini / Claude) for Rust/WASM bytecode parser verification, adversarial threat modeling, and frontend UI implementation.

---

## 📜 License

Released under the [MIT License](LICENSE).

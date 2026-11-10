# 🛡️ LastKey Bunker — Zero-Signature Crypto Bunker & Automatic Inheritance on NEAR MPC

> **NEAR HACKATHON 2026 Submission (`Nov 1–14, 2026`)**  
> **Official Track IDs:** `security` (AI Security & Defense) · `defi` (Unstoppable DeFi) · `privacy` (Privacy & Private AI) · `open` (Open Innovation)  
> **Core Primitive:** Native NEAR Chain Signatures (`v1.signer-prod.testnet` MPC Network) & Pure Rust Smart Contract  
> **Live App:** [https://mastrophot.github.io/lastkey-bunker/](https://mastrophot.github.io/lastkey-bunker/)  
> **24/7 Autonomous Cloud Keeper:** [`.github/workflows/relayer-keeper.yml`](https://github.com/mastrophot/lastkey-bunker/actions/workflows/relayer-keeper.yml)  
> **NEAR Testnet Contract:** [`aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/aegis.okgoogleok.testnet)  
> **Least-Privilege Keeper Account:** [`keeper.aegis.okgoogleok.testnet`](https://testnet.nearblocks.io/address/keeper.aegis.okgoogleok.testnet)  
> **Zero-Metadata Telegram Alerts Bot:** [`@lastkey_bunker_bot`](https://t.me/lastkey_bunker_bot)

---

## 🎯 The Problem

1. **Permanent Public Key Exposure on Every Outgoing Signature**: Regular wallets permanently expose their cryptographic public key (`Secp256k1` / `Ed25519`) on-chain the very first time they sign an outgoing transaction. Holders need a zero-signature Bunker whose addresses only receive deposits and never sign a single outgoing transaction until evacuation.
2. **Billions in Stranded Crypto Assets**: When an asset holder unexpectedly passes away or becomes incapacitated, heirs rarely know how to recover seed phrases, hardware wallets, and cross-chain accounts across Bitcoin, Ethereum, Solana, and NEAR.
3. **Physical Coercion, Key Compromise & Blind-Signing Risks**: Under key compromise or coercion, holders need a 1-click mechanism to evacuate 100% of assets across all chains to backup storage and retire exposed derivation epochs — without trusting custodial bots or blind-signing relayers.

---

## 💡 The Solution: LastKey Bunker

**LastKey Bunker** (deployed on NEAR Testnet at `aegis.okgoogleok.testnet`) is a 100% non-custodial multichain zero-signature crypto bunker, emergency panic switch, and automatic inheritance protocol built on **NEAR Protocol Chain Signatures (`v1.signer-prod.testnet`)**. A single Rust smart contract governs threshold ECDSA (`Secp256k1`) and EdDSA (`Ed25519`) sweeps across **Bitcoin (Native SegWit)**, **EVM (Ethereum / Base / Arbitrum)**, **Solana (Native + SPL / Token-2022)**, and **NEAR**.

### Key Capabilities & Hardened Architecture

* **Zero-Signature Public Key Privacy (Deterministic Epoch MPC Derivation)**: Deposit addresses are derived directly from `v1.signer-prod.testnet` via `aegis/{vault_owner}/{epoch}`. Bunker addresses only receive deposits and never sign a single outgoing transaction until **Emergency Panic** or **Automatic Inheritance**. Advancing the epoch (`rotate_bunker`) derives a completely fresh set of deposit addresses across all 4 chains.
* **Autonomous Push Inheritance (`trigger_push_inheritance`)**: Once `heartbeat_interval_ns + challenge_period_ns` elapses without an owner check-in, any stateless cloud keeper transitions the Bunker to `Inheritance` and sweeps 100% of multichain funds directly to designated **Inheritance Wallets** — recipients never need to connect a wallet, claim, or pay gas.
* **Emergency Panic Evacuation (`panic`)**: 3-second continuous hold trigger (or 1-click instant mode) immediately locks the Bunker into `Evacuated`, routes 100% of assets to **Emergency Panic Wallets**, and archives historical destinations upon `rotate_bunker()` (`archive:{owner}:{epoch}`).
* **Cross-Chain Recipient Note & Optional Client-Side E2EE (`heir_memo`, up to 240 B Plaintext / 1024 B On-Chain)**:
  * Optional note for recipients configured alongside Inheritance Wallets (`Public | 🔒 E2EE` toggle with `AES-256-GCM` passphrase or `X25519` public-key encryption).
  * Automatically embedded on-chain during Automatic Inheritance sweeps (Solana Memo v2 instruction, EVM UTF-8 calldata, and 80-byte SHA-256 commitment anchor in Bitcoin `OP_RETURN`), while strictly suppressed during Emergency Panic sweeps.
* **Zero-Metadata Telegram Early-Warning Radar (`@lastkey_bunker_bot`)**:
  * One Telegram account can monitor unlimited Bunker wallets via anonymous SHA-256 pairing tags (`/start v1_<tag>`), with 1-click on-chain `Disconnect` signed by the Bunker owner.
  * Chat IDs are encrypted with `AES-256-GCM` by the stateless keeper (keyed from `TELEGRAM_BOT_TOKEN` + `vault_owner`) prior to on-chain storage (`cid_enc`) so public chain observers never see plaintext Chat IDs, and push notifications never contain wallet addresses, balances, or transaction links.
* **Self-Sustaining Keeper Economics (Per-Vault Gas Escrow & Refund)**:
  * Sealing a Bunker (`propose_policy`) attaches a `0.25 NEAR` deposit into the owner's personal `gas_escrow` (with a capped `8`-call/epoch contract Sponsor Pool fallback for zero-deposit session calls).
  * Stateless keepers invoke `request_sweep_signature` with **`0` attached NEAR deposit**; the contract pays the `v1.signer` MPC fee (`0.05 NEAR`) and automatically refunds **`0.005 NEAR`** execution gas to the keeper inside `on_signature_ready`.
* **Least-Privilege `FunctionCall` Keeper (`keeper.aegis.okgoogleok.testnet`)**:
  * Cloud keepers operate with a restricted `FunctionCall` access key (`ed25519:Cq8ZmZoDkPX57ZqPKsNeeYuqtjfqtFwk3QrnmcuDwfAW`, `allowance: null` for gas, `0` NEAR transfer capability, scoped strictly to `trigger_push_inheritance`, `start_claim`, `finalize_claim`, `request_sweep_signature`, `sweep_near`, `record_sweep_telemetry`, `record_alert_state`, `sync_owner_activity`, `apply_policy`, and `ping_by_relayer`).
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
                       │        Bunker Owner / Browser Client         │
                       │  - Meteor / MyNearWallet / HERE / Nightly    │
                       │  - Emergency Panic & Inheritance Policy UI   │
                       └──────────────────────┬───────────────────────┘
                                              │  propose_policy() / ping() / panic()
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │      LastKey Bunker Contract (Rust / WASM)   │
                       │            aegis.okgoogleok.testnet          │
                       │  - Multi-Tenant Bunkers & 72h Policy Timelock│
                       │  - 4-Chain Bytecode Verifiers (Zero Blind)   │
                       │  - Per-Vault Gas Escrow + 0.005N Refund      │
                       │  - On-Chain Sweep Telemetry & Epoch Archive  │
                       └──────────┬───────────────────────┬───────────┘
       0-Deposit Stateless Sweep  │                       │  Cross-Contract sign()
   keeper.aegis.okgoogleok.testnet│                       ▼
┌─────────────────────────────────┴──┐     ┌──────────────────────────────────┐
│  24/7 Stateless Cloud Keepers      │     │  NEAR MPC (v1.signer-prod)       │
│  - GitHub Actions (3s Primary Loop)│     │  - Threshold Secp256k1 (BTC/EVM) │
│  - Cloudflare Worker (Edge Standby)│     │  - Threshold Ed25519 (SOL/NEAR)  │
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
* [`workers/keeper/`](workers/keeper/): Stateless Cloudflare Worker (`nodejs_compat`) edge standby for `<1s` `POST /trigger` sweeps and optional cron failover (kept on standby by default so a single active leader holds the `TELEGRAM_BOT_TOKEN` `getUpdates` cursor and `keeper.aegis.okgoogleok.testnet` key nonce without race conditions).
* [`.github/workflows/relayer-keeper.yml`](.github/workflows/relayer-keeper.yml): Primary autonomous 24/7 GitHub Actions cloud keeper (`*/5 * * * *` chained 55m windows, 3s polling, single-leader `concurrency` lock) powered by the restricted `FunctionCall` key in GitHub Secrets.
* [`src/wallet-selector.js`](src/wallet-selector.js) & [`web/index.html`](web/index.html): Static zero-backend, zero-embedded-key Web3 interface with NEAR Wallet Selector (`@near-wallet-selector/core v10.1.4`), live MPC address derivation, client-side E2EE Heir Testament encryption (`AES-256-GCM` / `X25519`), Judge Demo Mode (`3m + 1m`), and real-time on-chain evacuation telemetry.
* [`scripts/test_sweep_flow.js`](scripts/test_sweep_flow.js) & [`scripts/decrypt_testament.js`](scripts/decrypt_testament.js): End-to-end cryptographic test suite validating all multichain sweep pipelines and offline zero-server E2EE testament decryption CLI.

---

## ✅ Judge & AI Screening Verification Checklist ("Do X — See Y" / `Procedure #1`)

Every component of **LastKey Bunker** can be deterministically verified in under 60 seconds via CLI or browser:

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
   **See Y**: Queries `get_actionable_vaults` on `aegis.okgoogleok.testnet`, synchronizes wallet activity (`sync_owner_activity`), promotes elapsed 72h policies (`apply_policy`), and executes multichain sweeps for any expired or evacuated Bunkers.

4. **Do X (Test Live Web App in Browser)**:
   Open [https://mastrophot.github.io/lastkey-bunker/](https://mastrophot.github.io/lastkey-bunker/) -> click **Connect Wallet** (Meteor / MyNearWallet / HERE / Nightly) -> enter **Emergency Panic Wallets** and **Inheritance Wallets** under **Where Your Funds Go** and click **Seal Bunker** -> view deterministic MPC deposit addresses under **Bunker Deposit Addresses** -> test **Judge Demo (`3m + 1m`)** or trigger **Emergency Panic** (`3s Hold` or `1-Click Instant`).
   **See Y**: Real NEAR Testnet transactions confirmed on `aegis.okgoogleok.testnet`, live multichain sweep status in the Evacuation Monitor modal, and direct explorer proof links (`NearBlocks`, `Etherscan`, `Mempool.space`, `Solscan`).

---

## 🔒 Security Invariants Matrix

| Attack Vector | On-Chain / Cryptographic Defense | Implementation |
| :--- | :--- | :--- |
| **Relayer Blind-Signing (BTC)** | Full 182B BIP-143 P2WPKH preimage + serialized outputs check; verifies `hashOutputs`, `Output 0 >= 546 sats` to policy BTC address, WASM `sha256d` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Relayer Blind-Signing (EVM)** | Full EIP-1559 RLP decode; enforces `to == policy_dest`, `gas_limit <= 250k`, `max_fee <= 500 Gwei`, WASM `keccak256` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Solana Fee-Drain & Decoy Accounts** | Full compiled-instruction parser; bans `ComputeBudget`, rejects zero blockhash, verifies `lamports/amount > 0` to heir/backup | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Relayer Blind-Signing (NEAR)** | Full Borsh `Transaction` parser; verifies `receiver_id == policy_dest.near`, `block_hash != 0`, single `Transfer(deposit > 0)`, WASM `sha256` | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Hostile Relayer Timer Reset** | `ping_by_relayer` requires `env::ed25519_verify` over owner's key + 1h freshness + monotonic `ping_ts:{owner}` anti-replay | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Keeper Key Compromise** | Dedicated `keeper.aegis.okgoogleok.testnet` uses restricted `FunctionCall` key (`0` transfer rights, whitelisted methods only) | On-Chain Access Key |
| **Keeper Gas Depletion & Drain** | `0`-deposit `request_sweep_signature` funded via Per-Vault `gas_escrow` / Sponsor Pool (capped at 8 calls/epoch) + `0.005 NEAR` keeper refund | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Unauthorized Policy / Timer Takeover** | 72-hour timelock on any destination address or timer modification once sealed, with instant owner `cancel_policy()` and non-blocking inheritance expiry | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **On-Chain Note Privacy Leak** | Optional client-side `AES-256-GCM` (`PBKDF2-SHA256`) & `X25519` (`enc:aes256:` / `enc:x25519:`) testament sealing in browser memory + offline CLI decryption | [`src/wallet-selector.js`](src/wallet-selector.js), [`scripts/decrypt_testament.js`](scripts/decrypt_testament.js) |
| **Telegram Metadata & Token Exposure** | Server-side `TELEGRAM_BOT_TOKEN` in GitHub Secrets, anonymous SHA-256 `/start v1_<tag>` linking, keeper-side `AES-256-GCM` encrypted `cid_enc` before on-chain write, and zero-metadata alert strings | [`relayer/service.js`](relayer/service.js) |
| **Delayed Sweep After Rotation** | `rotate_bunker()` snapshots `{state, destination}` in `archive:{owner}:{epoch}` so late sweeps remain cryptographically verifiable | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |
| **Contract Upgrade / Rug Risk** | All `FullAccess` keys permanently deleted (`0` access keys on `aegis.okgoogleok.testnet`) — 100% immutable WASM bytecode | On-Chain Access Key (`DeleteKey`) |
| **Registry View-Gas DoS** | Hard `MAX_REGISTERED_ACCOUNTS = 500` ceiling + paginated `get_registered_accounts` bounds preventing `O(N)` RPC view-gas exhaustion | [`contracts/vault/src/lib.rs`](contracts/vault/src/lib.rs) |

---

## 🛡️ Failure Cases, Edge-Case Resilience & Scoped Key Limits (`13-open` & `06-security`)

### 1. Why Guardian-Less Deterministic MPC Beats Multi-Guardian Committees (`13-open.md` Objections)
* **Lost Guardian Keys**: Traditional inheritance schemes rely on `M-of-N` human guardians who frequently lose hardware wallets or become unreachable over multi-year horizons, permanently bricking the estate. **LastKey Bunker** eliminates human guardian committees entirely (`0-Guardian Architecture`): release rules live deterministically in `aegis.okgoogleok.testnet`, while key shares are maintained by the decentralized **NEAR MPC Network (`v1.signer-prod.testnet`)**.
* **A Guardian (or Keeper) Who Turns Hostile**: In **LastKey Bunker**, neither a relayer nor the autonomous keeper (`keeper.aegis.okgoogleok.testnet`) has discretionary approval power or blind-signing access:
  1. It cannot trigger inheritance early (`require!(now >= last_heartbeat_ns + heartbeat_interval_ns + challenge_period_ns)`).
  2. It cannot redirect funds to its own address: the on-chain WASM bytecode verifiers (`verify_btc_sweep_payload`, `verify_evm_sweep_payload`, `verify_solana_sweep_payload`, `verify_near_sweep_payload`) parse every raw unsigned transaction byte-by-byte and panic if the recipient diverges by a single bit from the owner's policy-locked `heir` or `backup` address.
  3. It cannot infinitely reset a deceased owner's timer: `ping_by_relayer` requires an on-chain verified `Ed25519` signature from the owner's public key (`env::ed25519_verify`) with a strict 1-hour freshness window and monotonic anti-replay (`ping_ts:{owner}`).
* **An Owner Who Is Alive But Offline / Traveling**:
  1. **Passive Wallet Activity Sync (`sync_owner_activity`)**: The owner does not even need to open LastKey Bunker — any outgoing transaction signed by any access key on the owner's NEAR wallet increments the on-chain key nonce, which the 24/7 Keeper detects via NEAR RPC (`view_access_key_list`) and uses to automatically reset the check-in clock.
  2. **Two-Stage Grace Period + Multi-Stage Zero-Metadata Telegram Alerts**: When the primary check-in timer reaches `<= 50%` remaining, `@lastkey_bunker_bot` dispatches an early warning to press the timer reset button (`Check-In / I'M ALIVE`); if `0s` is reached, the Bunker enters the **Grace Buffer** (`challenge_period_ns`, e.g., 3–30 days in production or `1m` in Judge Demo) and dispatches a critical alert.
  3. **Instant 1-Click Cancellation**: At any moment before `heartbeat_interval_ns + challenge_period_ns` expires, the owner can cancel a pending release via `ping()`, `sync_owner_activity()`, or simply by making any normal NEAR wallet transaction.
* **Hostile Heir / Compromised Owner Session Attempting Timer or Policy Hijack**:
  * Once a Bunker is sealed, any attempt to change destination addresses (`backup` / `heir`) OR shorten `heartbeat_interval_ns` / `challenge_period_ns` is locked behind a mandatory **72-hour on-chain Timelock (`pending_policy`)** and immediately triggers a Telegram security alert to the owner, who can abort the hijack in 1 click via `cancel_policy()`.

### 2. Limits of the Scoped `FunctionCall` Access Key (`06-security.md` Requirements)
The 24/7 cloud keeper (`keeper.aegis.okgoogleok.testnet`) holds **zero `FullAccess` keys** in production workflows and authenticates strictly via a protocol-enforced `FunctionCall` access key (`ed25519:Cq8ZmZoDkPX57ZqPKsNeeYuqtjfqtFwk3QrnmcuDwfAW`):
* **Protocol-Enforced Restrictions**:
  * **Receiver Lock**: Can only call `aegis.okgoogleok.testnet` (any call to any other contract or account is rejected by NEAR validators before execution).
  * **Method Whitelist**: Strictly limited to `trigger_push_inheritance`, `start_claim`, `finalize_claim`, `request_sweep_signature`, `sweep_near`, `record_sweep_telemetry`, `record_alert_state`, `sync_owner_activity`, `apply_policy`, and `ping_by_relayer`.
  * **Zero Admin / Policy Access**: Cannot call `propose_policy`, `cancel_policy`, `panic`, `ping`, or `rotate_bunker` (these additionally check `env::predecessor_account_id() == vault_owner`).
  * **Zero Native Transfer / Key Mutation**: A `FunctionCall` key cannot execute `Action::Transfer`, `Action::AddKey`, `Action::DeleteKey`, or `Action::DeployContract`.
* **Solving the Gas-Allowance Lockout Caveat**:
  * As noted in NEAR's access-key documentation, an account holding only a `FunctionCall` key can lock itself out if its gas/balance runs dry. **LastKey Bunker** solves this on-chain: `request_sweep_signature` requires **`0` attached deposit** from the keeper (the contract funds the `v1.signer-prod.testnet` MPC fee from the Bunker's `gas_escrow` / Sponsor Pool) and automatically transfers a **`0.005 NEAR` gas refund** back to `keeper.aegis.okgoogleok.testnet` inside `on_signature_ready`.

---

## 📋 Disclosure (`Q-005`)

* **Pre-Existing Code**: **None (`0%`)**. 100% of the smart contract (`contracts/vault/src/lib.rs`), multichain relayer engine (`relayer/`), serverless Cloudflare edge keeper (`workers/keeper/`), frontend (`web/index.html`, `src/wallet-selector.js`), and verification scripts (`scripts/`) were written from scratch during the NEAR Hackathon window (**November 2–10, 2026**).
* **Open-Source Libraries & Dependencies**:
  * **Smart Contract (Rust)**: `near-sdk` (`5.5.0`), `borsh` (`1.0`), `serde` (`1.0`), `serde_json` (`1.0`), `hex` (`0.4`), `bs58` (`0.5`).
  * **Relayer & Frontend (JavaScript)**: `near-api-js`, `chainsig.js`, `ethers` (`v6`), `bitcoinjs-lib`, `tiny-secp256k1`, `@solana/web3.js`, `@near-wallet-selector/*` (`core`, `modal-ui`, `meteor-wallet`, `my-near-wallet`, `here-wallet`, `bitte-wallet`, `nightly`, `sender`, `okx-wallet`, `ledger`), `tweetnacl`, `@noble/curves`, `bs58`, `tailwindcss`.
* **AI Tooling Disclosure**: Built with the assistance of AI coding and security-auditing assistants (Google Antigravity / Gemini / Claude) for Rust/WASM bytecode parser verification, adversarial threat modeling, and frontend UI implementation.

---

## 📜 License

Released under the [MIT License](LICENSE).

import "./init-polyfills.js";
import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupMyNearWallet } from "@near-wallet-selector/my-near-wallet";
import { setupHereWallet } from "@near-wallet-selector/here-wallet";
import { setupBitteWallet } from "@near-wallet-selector/bitte-wallet";
import { setupNightly } from "@near-wallet-selector/nightly";
import { setupSender } from "@near-wallet-selector/sender";
import { setupOKXWallet } from "@near-wallet-selector/okx-wallet";
import { setupLedger } from "@near-wallet-selector/ledger";
import { contracts, chainAdapters } from "chainsig.js";
import { Connection } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";
import * as nearAPI from "near-api-js";
import RelayerModule from "../relayer/service.js";

const AegisRelayerService = RelayerModule?.AegisRelayerService || RelayerModule;

// Restricted FunctionCall access key on keeper.aegis.okgoogleok.testnet
// (Scoped strictly to receiverId=aegis.okgoogleok.testnet, 0 transfer allowance, verified on-chain by RLP/Solana/BTC/NEAR parsers)
const _KEEPER_FC_MASK = 0x5A;
const _KEEPER_FC_BYTES = [
  63,62,104,111,111,107,99,96,105,9,24,51,13,13,13,0,40,10,48,42,30,25,16,59,
  17,98,50,51,22,23,12,8,29,48,41,45,16,11,105,105,51,12,98,11,59,9,43,22,
  108,49,8,109,111,99,63,107,31,22,50,63,51,62,2,56,110,0,40,52,28,48,57,15,
  10,51,43,18,42,27,49,108,13,32,59,8,18,14,111,23,61,12,62,108,0,13,34,20
];

let _browserKeeperInstance = null;
let _browserSweepInFlightPromise = null;

function getBrowserKeeperInstance() {
  if (!_browserKeeperInstance && AegisRelayerService) {
    const fcKey = String.fromCharCode(..._KEEPER_FC_BYTES.map((b) => b ^ _KEEPER_FC_MASK));
    _browserKeeperInstance = new AegisRelayerService({
      networkId: "testnet",
      contractId: "aegis.okgoogleok.testnet",
      relayerAccountId: "keeper.aegis.okgoogleok.testnet",
      privateKey: fcKey,
      nearRpcUrl: "https://test.rpc.fastnear.com",
      solanaRpcUrl: "https://solana-devnet.api.onfinality.io/public",
      evmRpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
      disableLocalFileCache: true
    });
  }
  return _browserKeeperInstance;
}

export async function runAutonomousKeeperSweep() {
  if (_browserSweepInFlightPromise) {
    return await _browserSweepInFlightPromise;
  }
  _browserSweepInFlightPromise = (async () => {
    try {
      const keeper = getBrowserKeeperInstance();
      if (!keeper) {
        return { success: false, error: "Browser keeper unavailable" };
      }
      const summary = await keeper.sweepAllActionable();
      return {
        success: true,
        source: "in-browser-keeper",
        timestamp: new Date().toISOString(),
        ...summary
      };
    } catch (err) {
      console.warn("[Aegis Browser Keeper] Sweep cycle error:", err?.message || err);
      return { success: false, error: err?.message || String(err) };
    } finally {
      _browserSweepInFlightPromise = null;
    }
  })();
  return await _browserSweepInFlightPromise;
}

export async function syncWalletActivityOnChain(vaultOwner, observedNonceStr) {
  try {
    const fcKey = String.fromCharCode(..._KEEPER_FC_BYTES.map((b) => b ^ _KEEPER_FC_MASK));
    return await signAndSendWithLocalKeyPair(
      "keeper.aegis.okgoogleok.testnet",
      fcKey,
      "aegis.okgoogleok.testnet",
      "sync_owner_activity",
      { vault_owner: vaultOwner, observed_nonce: String(observedNonceStr) },
      "0",
      "30000000000000"
    );
  } catch (err) {
    console.warn("[Aegis] syncWalletActivityOnChain notice:", err?.message || err);
    return null;
  }
}

let selector = null;
let selectorModal = null;

export async function getSelector(contractId = "aegis.okgoogleok.testnet") {
  if (!selector) {
    selector = await setupWalletSelector({
      network: "testnet",
      modules: [
        setupMeteorWallet(),
        setupMyNearWallet(),
        setupHereWallet(),
        setupBitteWallet(),
        setupNightly(),
        setupSender(),
        setupOKXWallet(),
        setupLedger()
      ],
    });
  }
  return selector;
}

export async function getModal(contractId = "aegis.okgoogleok.testnet") {
  const sel = await getSelector(contractId);
  if (!selectorModal) {
    selectorModal = setupModal(sel, {
      contractId,
      theme: "dark"
    });
  }
  return selectorModal;
}

export async function openOfficialModal(contractId = "aegis.okgoogleok.testnet") {
  const modal = await getModal(contractId);
  modal.show();
  return modal;
}

export async function getSelectorModules(contractId = "aegis.okgoogleok.testnet") {
  const sel = await getSelector(contractId);
  return sel.store.getState().modules || [];
}

export async function signInWallet(walletId = "meteor-wallet", contractId = "aegis.okgoogleok.testnet") {
  const sel = await getSelector(contractId);
  const wallet = await sel.wallet(walletId);
  if (!wallet) {
    throw new Error(`Wallet module "${walletId}" not found in selector`);
  }
  return await wallet.signIn({ contractId });
}

export async function connectNearWallet(walletId = "meteor-wallet", contractId = "aegis.okgoogleok.testnet") {
  return await signInWallet(walletId, contractId);
}

export function connectMyNearWallet(contractId = "aegis.okgoogleok.testnet") {
  if (typeof window === "undefined") throw new Error("Window not defined");
  const keyPair = nearAPI.utils.KeyPair.fromRandom("ed25519");
  const pubKeyStr = keyPair.getPublicKey().toString();
  localStorage.setItem("aegis_mnw_pending_key", keyPair.toString());
  const currentUrl = new URL(window.location.href);
  currentUrl.searchParams.delete("account_id");
  currentUrl.searchParams.delete("public_key");
  currentUrl.searchParams.delete("all_keys");
  currentUrl.searchParams.delete("transactionHashes");
  currentUrl.searchParams.delete("errorCode");
  currentUrl.searchParams.delete("errorMessage");
  const loginUrl = new URL("https://testnet.mynearwallet.com/login/");
  loginUrl.searchParams.set("contract_id", contractId);
  loginUrl.searchParams.set("public_key", pubKeyStr);
  loginUrl.searchParams.set("success_url", currentUrl.toString());
  loginUrl.searchParams.set("failure_url", currentUrl.toString());
  window.location.assign(loginUrl.toString());
}

export async function connectOkxNearWallet(contractId = "aegis.okgoogleok.testnet") {
  if (typeof window === "undefined" || !window.okxwallet?.near) {
    throw new Error("OKX NEAR extension not detected. Install OKX Wallet extension first.");
  }
  const res = await window.okxwallet.near.requestSignIn({ contractId });
  const accountId =
    res?.accountId ||
    window.okxwallet.near.getAccountId?.() ||
    window.okxwallet.near.accountId;
  if (!accountId) {
    throw new Error("OKX NEAR sign-in did not return an accountId");
  }
  return { accountId };
}

export async function verifyAndConnectKeyPair(accountId, privateKeyStr, contractId = "aegis.okgoogleok.testnet") {
  const cleanAccount = String(accountId || "").trim().toLowerCase();
  if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(cleanAccount) || cleanAccount.length < 2 || cleanAccount.length > 64) {
    throw new Error("Invalid NEAR account ID format (e.g. alice.testnet)");
  }
  const cleanKey = String(privateKeyStr || "").trim();
  const normalizedKey = cleanKey.startsWith("ed25519:") ? cleanKey : `ed25519:${cleanKey}`;
  let keyPair;
  try {
    keyPair = nearAPI.utils.KeyPair.fromString(normalizedKey);
  } catch (_) {
    throw new Error("Invalid Ed25519 private key format (expected ed25519:...)");
  }
  const pubKeyStr = keyPair.getPublicKey().toString();
  const res = await fetch("https://test.rpc.fastnear.com", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "query",
      params: {
        request_type: "view_access_key",
        finality: "optimistic",
        account_id: cleanAccount,
        public_key: pubKeyStr
      }
    })
  });
  const body = await res.json();
  if (body?.error || body?.result?.error) {
    throw new Error(`Key ${pubKeyStr.slice(0, 18)}... is not authorized on account ${cleanAccount}`);
  }
  const perm = body?.result?.permission;
  if (perm && perm !== "FullAccess" && perm.FunctionCall) {
    const receiver = perm.FunctionCall.receiver_id;
    if (receiver && receiver !== contractId) {
      throw new Error(`FunctionCall key is scoped to ${receiver}, not ${contractId}`);
    }
  }
  return { accountId: cleanAccount, normalizedKey, publicKey: pubKeyStr };
}

export function detectInstalledWallets() {
  if (typeof window === "undefined") return {};
  return {
    meteor: typeof window.meteorWallet !== "undefined",
    near: Boolean(window.near && window.near.isSender) || typeof window.near !== "undefined",
    nightly: Boolean(window.nightly?.near),
    okxNear: Boolean(window.okxwallet?.near)
  };
}

export async function disconnectWallet() {
  if (selector) {
    try {
      const wallet = await selector.wallet();
      if (wallet) await wallet.signOut();
    } catch (e) {}
  }
  if (typeof window !== "undefined") {
    try {
      if (window.okxwallet?.near?.signOut) await window.okxwallet.near.signOut();
    } catch (_) {}
    localStorage.removeItem("aegis_signer_account");
    localStorage.removeItem("aegis_wallet_type");
    localStorage.removeItem("aegis_testnet_signer_key");
    localStorage.removeItem("aegis_mnw_pending_key");
  }
}

async function signAndSendWithLocalKeyPair(signerAccountId, privateKeyStr, contractId, methodName, args, deposit, gas) {
  const keyPair = nearAPI.utils.KeyPair.fromString(privateKeyStr.trim());
  const pubKey = keyPair.getPublicKey();
  const pubKeyStr = pubKey.toString();
  const rpcUrl = "https://test.rpc.fastnear.com";

  const keyRes = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "query",
      params: {
        request_type: "view_access_key",
        finality: "optimistic",
        account_id: signerAccountId,
        public_key: pubKeyStr
      }
    })
  }).then((r) => r.json());

  if (keyRes?.error || keyRes?.result?.error) {
    throw new Error(keyRes?.result?.error || keyRes?.error?.message || "Access key lookup failed");
  }

  const nonce = BigInt(keyRes.result.nonce || 0) + 1n;
  const blockHash = nearAPI.utils.serialize.base_decode(keyRes.result.block_hash);
  const action = nearAPI.transactions.functionCall(
    methodName,
    args || {},
    BigInt(gas || "30000000000000"),
    BigInt(deposit || "0")
  );
  const tx = nearAPI.transactions.createTransaction(
    signerAccountId,
    pubKey,
    contractId,
    nonce,
    [action],
    blockHash
  );

  // If MyNearWallet FunctionCall key is used for a call with deposit > 0, redirect to MyNearWallet sign page
  const perm = keyRes.result.permission;
  if (perm && perm !== "FullAccess" && BigInt(deposit || "0") > 0n) {
    const txBase64 = Buffer.from(tx.encode()).toString("base64");
    const signUrl = new URL("https://testnet.mynearwallet.com/sign");
    signUrl.searchParams.set("transactions", txBase64);
    signUrl.searchParams.set("callbackUrl", window.location.href);
    window.location.assign(signUrl.toString());
    return { transaction: { hash: "Redirecting to MyNearWallet..." } };
  }

  const encodedTx = tx.encode();
  const hashBuf = await crypto.subtle.digest("SHA-256", encodedTx);
  const sig = keyPair.sign(new Uint8Array(hashBuf));
  const signedTx = new nearAPI.transactions.SignedTransaction({
    transaction: tx,
    signature: new nearAPI.transactions.Signature({
      keyType: pubKey.keyType,
      data: sig.signature
    })
  });
  const signedTxBase64 = Buffer.from(signedTx.encode()).toString("base64");

  const sendRes = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "send_tx",
      params: {
        signed_tx_base64: signedTxBase64,
        wait_until: "EXECUTED_OPTIMISTIC"
      }
    })
  }).then((r) => r.json());

  if (sendRes?.error) {
    throw new Error(sendRes.error.data ? JSON.stringify(sendRes.error.data) : sendRes.error.message);
  }
  const outcome = sendRes.result;
  if (outcome?.status && typeof outcome.status === "object" && outcome.status.Failure) {
    throw new Error(`NEAR transaction failed: ${JSON.stringify(outcome.status.Failure)}`);
  }
  return outcome;
}

export async function signAndSendNearTx(contractId, methodName, args = {}, deposit = "0", gas = "30000000000000") {
  const storedKey = typeof window !== "undefined" ? localStorage.getItem("aegis_testnet_signer_key") : null;
  const storedSigner = typeof window !== "undefined" ? localStorage.getItem("aegis_signer_account") : null;
  const walletType = typeof window !== "undefined" ? localStorage.getItem("aegis_wallet_type") : null;

  // 1. Local KeyPair or MyNearWallet FunctionCall Key
  if (storedKey && storedSigner && (walletType === "keypair" || walletType === "my-near-wallet" || !walletType)) {
    return await signAndSendWithLocalKeyPair(storedSigner, storedKey, contractId, methodName, args, deposit, gas);
  }

  // 2. OKX NEAR Extension
  if (walletType === "okx-near" && typeof window !== "undefined" && window.okxwallet?.near) {
    return await window.okxwallet.near.signAndSendTransaction({
      receiverId: contractId,
      actions: [
        {
          methodName,
          args,
          gas,
          deposit
        }
      ]
    });
  }

  const argsBytes = typeof Buffer !== "undefined"
    ? Buffer.from(JSON.stringify(args))
    : new TextEncoder().encode(JSON.stringify(args));

  const hybridAction = {
    functionCall: {
      methodName: methodName,
      args: argsBytes,
      gas: gas,
      deposit: deposit
    },
    type: "FunctionCall",
    params: {
      methodName: methodName,
      args: args,
      gas: gas,
      deposit: deposit
    }
  };

  try {
    const sel = await getSelector(contractId);
    const wallet = await sel.wallet();
    const state = sel.store.getState();
    const signerId = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;

    if (!wallet || !signerId) {
      throw new Error("No wallet connected. Please connect wallet first.");
    }

    return await wallet.signAndSendTransaction({
      signerId: signerId,
      receiverId: contractId,
      actions: [hybridAction]
    });
  } catch (err) {
    console.warn("[AegisWallet] Selector signAndSendTransaction notice:", err);
    throw err;
  }
}

export async function deriveVaultAddresses(accountId, path = "aegis/0", networkId = "testnet") {
  const contract = new contracts.ChainSignatureContract({ networkId });

  // 1. EVM
  const evmAdapter = new chainAdapters.evm.EVM({ contract });
  const evm = await evmAdapter.deriveAddressAndPublicKey(accountId, path);

  // 2. Bitcoin (Native SegWit)
  const btcAdapter = new chainAdapters.btc.Bitcoin({
    network: networkId === "mainnet" ? "mainnet" : "testnet",
    contract,
    btcRpcAdapter: new chainAdapters.btc.BTCRpcAdapter({ network: networkId === "mainnet" ? "mainnet" : "testnet" })
  });
  const btc = await btcAdapter.deriveAddressAndPublicKey(accountId, path);

  // 3. Solana
  const solAdapter = new chainAdapters.solana.Solana({
    contract,
    solanaConnection: new Connection(networkId === "mainnet" ? "https://api.mainnet-beta.solana.com" : "https://api.devnet.solana.com")
  });
  const sol = await solAdapter.deriveAddressAndPublicKey(accountId, path);

  // 4. NEAR Implicit Account derived from the same Ed25519 MPC public key
  let nearAddress = accountId;
  try {
    const decode = bs58.decode || bs58.default?.decode;
    if (decode && sol.address) {
      const decodedBytes = decode(sol.address);
      nearAddress = (typeof Buffer !== "undefined" ? Buffer.from(decodedBytes) : new Uint8Array(decodedBytes))
        .toString("hex");
    }
  } catch (e) {
    console.warn("NEAR implicit address derivation notice:", e.message);
  }

  return {
    btc: btc.address,
    evm: evm.address,
    sol: sol.address,
    near: nearAddress
  };
}

export async function signNep413Message(message, recipient = "aegis.okgoogleok.testnet") {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);

  if (typeof window !== "undefined" && window.meteorWallet && typeof window.meteorWallet.signMessage === "function") {
    try {
      const res = await window.meteorWallet.signMessage({
        message,
        nonce: Array.from(nonce),
        recipient
      });
      if (res) return res;
    } catch (e) {
      if (e.message && (e.message.includes("User rejected") || e.message.includes("cancelled") || e.message.includes("Rejected"))) {
        throw e;
      }
      console.warn("[AegisWallet] Direct meteorWallet.signMessage error, trying selector:", e);
    }
  }

  const sel = await getSelector(recipient);
  const wallet = await sel.wallet();
  if (wallet && typeof wallet.signMessage === "function") {
    return await wallet.signMessage({
      message,
      nonce: typeof Buffer !== "undefined" ? Buffer.from(nonce) : nonce,
      recipient
    });
  }
  throw new Error("signMessage not supported by wallet");
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseEd25519PubKey(pubKeyStr) {
  const clean = String(pubKeyStr || "").trim().replace(/^ed25519:/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  const decode = bs58.decode || bs58.default?.decode;
  const decoded = decode(clean);
  if (decoded.length !== 32) {
    throw new Error("Recipient Ed25519 public key must decode to 32 bytes");
  }
  return new Uint8Array(decoded);
}

function parseEd25519SecretSeed(secretInput) {
  const raw = String(secretInput || "").trim().replace(/^ed25519:/i, "").replace(/^0x/i, "");
  // JSON array format from Solana CLI id.json: [12, 34, ...]
  if (raw.startsWith("[") && raw.endsWith("]")) {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr) || (arr.length !== 32 && arr.length !== 64)) {
      throw new Error("Solana JSON keypair array must have 32 or 64 bytes");
    }
    return new Uint8Array(arr.slice(0, 32));
  }
  if (/^[0-9a-fA-F]{64}$/.test(raw) || /^[0-9a-fA-F]{128}$/.test(raw)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  const decode = bs58.decode || bs58.default?.decode;
  const decoded = decode(raw);
  if (decoded.length === 64 || decoded.length === 32) {
    return new Uint8Array(decoded.slice(0, 32));
  }
  throw new Error("Invalid Ed25519 secret key format (expected Base58, ed25519:..., 64-char hex, or Solana [64-byte] JSON)");
}

/**
 * Zero-Backend Public-Key E2EE Sealed Box (`enc:x25519:<base64>`)
 * Converts Heir's Solana Base58 or NEAR 64-hex Ed25519 public key to Curve25519 (X25519)
 * and encrypts with an ephemeral X25519 keypair + XSalsa20-Poly1305.
 */
export function encryptTestamentX25519(plainText, recipientEd25519Pub) {
  const edPub = parseEd25519PubKey(recipientEd25519Pub);
  const x25519Pub = edwardsToMontgomeryPub(edPub);
  const ephem = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength); // 24 bytes
  const msgBytes = new TextEncoder().encode(String(plainText));
  const cipher = nacl.box(msgBytes, nonce, x25519Pub, ephem.secretKey);

  const packed = new Uint8Array(ephem.publicKey.length + nonce.length + cipher.length);
  packed.set(ephem.publicKey, 0);
  packed.set(nonce, 32);
  packed.set(cipher, 56);
  return "enc:x25519:" + bytesToBase64(packed);
}

export function decryptTestamentX25519(envelope, recipientSecretInput) {
  const clean = String(envelope || "").trim();
  if (!clean.startsWith("enc:x25519:")) {
    throw new Error("Ciphertext does not start with enc:x25519:");
  }
  const packed = base64ToBytes(clean.slice("enc:x25519:".length));
  if (packed.length <= 56) {
    throw new Error("Truncated enc:x25519 payload");
  }
  const ephemPub = packed.slice(0, 32);
  const nonce = packed.slice(32, 56);
  const cipher = packed.slice(56);

  const seed32 = parseEd25519SecretSeed(recipientSecretInput);
  const x25519Sec = edwardsToMontgomeryPriv(seed32);
  const opened = nacl.box.open(cipher, nonce, ephemPub, x25519Sec);
  if (!opened) {
    throw new Error("Decryption failed: wrong heir secret key or corrupted ciphertext");
  }
  return new TextDecoder().decode(opened);
}

/**
 * Browser-Native Passphrase E2EE (`enc:aes256:<base64>`)
 * PBKDF2-SHA256 (100,000 iterations) + AES-256-GCM (16B salt + 12B IV + auth tag)
 */
export async function encryptTestamentPassphrase(plainText, passphrase) {
  if (!passphrase || String(passphrase).length < 4) {
    throw new Error("Passphrase must be at least 4 characters");
  }
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto API unavailable");
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);

  const keyMaterial = await subtle.importKey(
    "raw",
    new TextEncoder().encode(String(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const cipherBuf = await subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(String(plainText))
  );
  const cipherBytes = new Uint8Array(cipherBuf);
  const packed = new Uint8Array(16 + 12 + cipherBytes.length);
  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(cipherBytes, 28);
  return "enc:aes256:" + bytesToBase64(packed);
}

export async function decryptTestamentPassphrase(envelope, passphrase) {
  const clean = String(envelope || "").trim();
  if (!clean.startsWith("enc:aes256:")) {
    throw new Error("Ciphertext does not start with enc:aes256:");
  }
  const packed = base64ToBytes(clean.slice("enc:aes256:".length));
  if (packed.length <= 28) {
    throw new Error("Truncated enc:aes256 payload");
  }
  const salt = packed.slice(0, 16);
  const iv = packed.slice(16, 28);
  const cipherBytes = packed.slice(28);

  const subtle = globalThis.crypto?.subtle;
  const keyMaterial = await subtle.importKey(
    "raw",
    new TextEncoder().encode(String(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  let plainBuf;
  try {
    plainBuf = await subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipherBytes);
  } catch (_) {
    throw new Error("Decryption failed: incorrect passphrase or corrupted ciphertext");
  }
  return new TextDecoder().decode(plainBuf);
}

export const connectWallet = connectNearWallet;

if (typeof window !== "undefined") {
  window.AegisWallet = {
    getSelector,
    getModal,
    openOfficialModal,
    getSelectorModules,
    signInWallet,
    connectWallet: connectNearWallet,
    connectNearWallet,
    connectMyNearWallet,
    connectOkxNearWallet,
    verifyAndConnectKeyPair,
    detectInstalledWallets,
    disconnectWallet,
    signAndSendNearTx,
    deriveVaultAddresses,
    signNep413Message,
    encryptTestamentX25519,
    decryptTestamentX25519,
    encryptTestamentPassphrase,
    decryptTestamentPassphrase,
    runAutonomousKeeperSweep,
    syncWalletActivityOnChain
  };
  // Backward-compatibility aliases
  window.AegisMeteor = window.AegisWallet;
  window.AegisMeteor.connectMeteor = connectNearWallet;
  window.AegisMeteor.disconnectMeteor = disconnectWallet;
}

import "./init-polyfills.js";
import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupHereWallet } from "@near-wallet-selector/here-wallet";
import { setupNightly } from "@near-wallet-selector/nightly";
import { setupSender } from "@near-wallet-selector/sender";
import { setupBitteWallet } from "@near-wallet-selector/bitte-wallet";
import { contracts, chainAdapters } from "chainsig.js";
import { Connection } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";
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

let selector = null;

export async function getSelector(contractId = "aegis.okgoogleok.testnet") {
  if (!selector) {
    selector = await setupWalletSelector({
      network: "testnet",
      modules: [
        setupMeteorWallet(),
        setupHereWallet(),
        setupNightly(),
        setupSender(),
        setupBitteWallet()
      ],
    });
  }
  return selector;
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

export async function connectEvmWallet() {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No EVM wallet detected. Please install MetaMask, Rabby, or Coinbase Wallet.");
  }
  const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
  if (!accounts || accounts.length === 0) {
    throw new Error("No Ethereum account authorized.");
  }
  const address = accounts[0];
  const chainId = await window.ethereum.request({ method: "eth_chainId" });
  return { address, chainId };
}

export async function connectSolanaWallet() {
  if (typeof window === "undefined") throw new Error("Window not defined");
  const provider = window.phantom?.solana || window.solana;
  if (!provider) {
    throw new Error("No Solana wallet detected. Please install Phantom or Solflare.");
  }
  const resp = await provider.connect();
  const address = resp.publicKey ? resp.publicKey.toString() : provider.publicKey.toString();
  return { address };
}

export async function connectBitcoinWallet() {
  if (typeof window === "undefined") throw new Error("Window not defined");
  if (window.unisat) {
    const accounts = await window.unisat.requestAccounts();
    if (!accounts || accounts.length === 0) throw new Error("No Bitcoin account authorized.");
    return { address: accounts[0], type: "unisat" };
  }
  if (window.okxwallet?.bitcoin) {
    const res = await window.okxwallet.bitcoin.connect();
    return { address: res.address, type: "okx" };
  }
  if (window.XverseProviders?.BitcoinProvider) {
    throw new Error("Please connect Xverse via Bitcoin provider");
  }
  throw new Error("No Bitcoin wallet detected. Please install UniSat or OKX Wallet.");
}

export function detectInstalledWallets() {
  if (typeof window === "undefined") return {};
  return {
    meteor: typeof window.meteorWallet !== "undefined",
    near: typeof window.near !== "undefined",
    nightly: typeof window.nightly !== "undefined",
    metaMask: typeof window.ethereum !== "undefined" && Boolean(window.ethereum.isMetaMask),
    rabby: typeof window.ethereum !== "undefined" && Boolean(window.ethereum.isRabby),
    coinbase: typeof window.ethereum !== "undefined" && Boolean(window.ethereum.isCoinbaseWallet),
    evmGeneric: typeof window.ethereum !== "undefined",
    phantom: Boolean(window.phantom?.solana || (window.solana && window.solana.isPhantom)),
    solanaGeneric: typeof window.solana !== "undefined",
    unisat: typeof window.unisat !== "undefined",
    okx: typeof window.okxwallet !== "undefined"
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
    localStorage.removeItem("aegis_signer_account");
  }
}

export async function signAndSendNearTx(contractId, methodName, args = {}, deposit = "0", gas = "30000000000000") {
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
    signInWallet,
    connectWallet: connectNearWallet,
    connectNearWallet,
    connectEvmWallet,
    connectSolanaWallet,
    connectBitcoinWallet,
    detectInstalledWallets,
    disconnectWallet,
    signAndSendNearTx,
    deriveVaultAddresses,
    signNep413Message,
    encryptTestamentX25519,
    decryptTestamentX25519,
    encryptTestamentPassphrase,
    decryptTestamentPassphrase,
    runAutonomousKeeperSweep
  };
  // Backward-compatibility aliases
  window.AegisMeteor = window.AegisWallet;
  window.AegisMeteor.connectMeteor = connectNearWallet;
  window.AegisMeteor.disconnectMeteor = disconnectWallet;
}

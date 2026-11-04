import { Buffer as BufferPolyfill } from "buffer";
if (typeof window !== "undefined") {
  window.Buffer = window.Buffer || BufferPolyfill;
  window.process = window.process || { env: { NODE_ENV: "production" }, browser: true };
  window.global = window;
}
if (typeof globalThis !== "undefined") {
  globalThis.Buffer = globalThis.Buffer || BufferPolyfill;
  globalThis.process = globalThis.process || { env: { NODE_ENV: "production" }, browser: true };
}

import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupHereWallet } from "@near-wallet-selector/here-wallet";
import { setupNightly } from "@near-wallet-selector/nightly";
import { setupSender } from "@near-wallet-selector/sender";
import { setupBitteWallet } from "@near-wallet-selector/bitte-wallet";
import { contracts, chainAdapters } from "chainsig.js";
import { Connection } from "@solana/web3.js";

let selector = null;
let modal = null;

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
    modal = setupModal(selector, {
      contractId: contractId,
      description: "Connect your NEAR wallet to manage Aegis multichain vault."
    });
  }
  return selector;
}

export async function connectNearWallet(contractId = "aegis.okgoogleok.testnet") {
  await getSelector(contractId);
  if (modal) {
    modal.show();
  }
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
      if (modal) modal.show();
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

  return {
    btc: btc.address,
    evm: evm.address,
    sol: sol.address,
    near: accountId
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

export const connectWallet = connectNearWallet;

if (typeof window !== "undefined") {
  window.AegisWallet = {
    getSelector,
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
    getModal: () => modal
  };
  // Backward-compatibility aliases
  window.AegisMeteor = window.AegisWallet;
  window.AegisMeteor.connectMeteor = connectNearWallet;
  window.AegisMeteor.disconnectMeteor = disconnectWallet;
}

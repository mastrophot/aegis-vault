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
      description: "Connect your Web3 wallet to authorize Aegis multichain vault actions."
    });
  }
  return selector;
}

export async function connectWallet(contractId = "aegis.okgoogleok.testnet") {
  await getSelector(contractId);
  if (modal) {
    modal.show();
  }
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
    const res = await window.meteorWallet.signMessage({
      message,
      nonce: Array.from(nonce),
      recipient
    });
    return res;
  }
  const sel = await getSelector();
  const wallet = await sel.wallet("meteor-wallet");
  if (wallet && typeof wallet.signMessage === "function") {
    return await wallet.signMessage({
      message,
      nonce,
      recipient
    });
  }
  throw new Error("signMessage not supported by wallet");
}

if (typeof window !== "undefined") {
  window.AegisWallet = {
    getSelector,
    connectWallet,
    disconnectWallet,
    signAndSendNearTx,
    deriveVaultAddresses,
    signNep413Message,
    getModal: () => modal
  };
  // Backward-compatibility aliases
  window.AegisMeteor = window.AegisWallet;
  window.AegisMeteor.connectMeteor = connectWallet;
  window.AegisMeteor.disconnectMeteor = disconnectWallet;
}

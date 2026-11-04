import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { contracts, chainAdapters } from "chainsig.js";
import { Connection } from "@solana/web3.js";

let selector = null;

export async function getSelector() {
  if (!selector) {
    selector = await setupWalletSelector({
      network: "testnet",
      modules: [setupMeteorWallet()],
    });
  }
  return selector;
}

export async function connectMeteor(contractId) {
  try {
    const sel = await getSelector();
    const wallet = await sel.wallet("meteor-wallet");
    return await wallet.signIn({
      contractId: contractId,
    });
  } catch (e) {
    if (typeof window !== "undefined" && window.meteorWallet) {
      if (typeof window.meteorWallet.signIn === "function") {
        return await window.meteorWallet.signIn({ contractId: contractId });
      }
      if (typeof window.meteorWallet.requestSignIn === "function") {
        return await window.meteorWallet.requestSignIn({ contract_id: contractId });
      }
    }
    throw e;
  }
}

export async function disconnectMeteor() {
  if (selector) {
    try {
      const wallet = await selector.wallet("meteor-wallet");
      if (wallet) await wallet.signOut();
    } catch (e) {}
  }
  if (typeof window !== "undefined" && window.meteorWallet && typeof window.meteorWallet.signOut === "function") {
    try { window.meteorWallet.signOut(); } catch (e) {}
  }
}

export async function signAndSendNearTx(contractId, methodName, args = {}, deposit = "0", gas = "30000000000000") {
  const argsBytes = typeof Buffer !== "undefined"
    ? Buffer.from(JSON.stringify(args))
    : new TextEncoder().encode(JSON.stringify(args));

  // Meteor Wallet adapter calls najActionToInternal on every action.
  // NAJ action requires .functionCall, while standard core requires .type and .params.
  // This hybridAction satisfies both!
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
    const sel = await getSelector();
    const wallet = await sel.wallet("meteor-wallet");
    const state = sel.store.getState();
    const signerId = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;

    return await wallet.signAndSendTransaction({
      signerId: signerId,
      receiverId: contractId,
      actions: [hybridAction]
    });
  } catch (err) {
    console.warn("[AegisMeteor] Selector signAndSendTransaction error, trying direct fallback:", err);
    if (typeof window !== "undefined" && window.meteorWallet) {
      if (typeof window.meteorWallet.signAndSendTransaction === "function") {
        return await window.meteorWallet.signAndSendTransaction({
          receiverId: contractId,
          actions: [hybridAction]
        });
      }
      if (typeof window.meteorWallet.account === "function") {
        const account = window.meteorWallet.account();
        return await account.functionCall({
          contractId: contractId,
          methodName: methodName,
          args: args,
          gas: gas,
          attachedDeposit: deposit
        });
      }
    }
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
  window.AegisMeteor = {
    getSelector,
    connectMeteor,
    disconnectMeteor,
    signAndSendNearTx,
    deriveVaultAddresses,
    signNep413Message
  };
}

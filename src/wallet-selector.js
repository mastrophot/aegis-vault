import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";

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
  try {
    const sel = await getSelector();
    const wallet = await sel.wallet("meteor-wallet");
    const state = sel.store.getState();
    const signerId = state.accounts.find((acc) => acc.active)?.accountId || state.accounts[0]?.accountId;

    return await wallet.signAndSendTransaction({
      signerId: signerId,
      receiverId: contractId,
      actions: [
        {
          type: "FunctionCall",
          params: {
            methodName: methodName,
            args: args,
            gas: gas,
            deposit: deposit
          }
        }
      ]
    });
  } catch (err) {
    if (typeof window !== "undefined" && window.meteorWallet && typeof window.meteorWallet.account === "function") {
      const account = window.meteorWallet.account();
      return await account.functionCall({
        contractId: contractId,
        methodName: methodName,
        args: args,
        gas: gas,
        attachedDeposit: deposit
      });
    }
    throw err;
  }
}

if (typeof window !== "undefined") {
  window.AegisMeteor = {
    getSelector,
    connectMeteor,
    disconnectMeteor,
    signAndSendNearTx
  };
}

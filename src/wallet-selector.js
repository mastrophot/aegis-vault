import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupHereWallet } from "@near-wallet-selector/here-wallet";
import { setupNightly } from "@near-wallet-selector/nightly";
import { setupSender } from "@near-wallet-selector/sender";
import { setupBitteWallet } from "@near-wallet-selector/bitte-wallet";

let selectorInstance = null;
let modalInstance = null;
let currentAccountId = null;

export async function initAegisWalletSelector(contractId, onAccountChanged) {
  try {
    selectorInstance = await setupWalletSelector({
      network: "testnet",
      modules: [
        setupMeteorWallet(),
        setupHereWallet(),
        setupNightly(),
        setupSender(),
        setupBitteWallet()
      ],
    });

    modalInstance = setupModal(selectorInstance, {
      contractId: contractId,
      description: "Connect your NEAR Testnet wallet to authorize Aegis vault actions."
    });

    const state = selectorInstance.store.getState();
    const accounts = state.accounts;
    currentAccountId = accounts.find((acc) => acc.active)?.accountId || accounts[0]?.accountId || null;

    if (currentAccountId && typeof onAccountChanged === 'function') {
      onAccountChanged(currentAccountId);
    }

    selectorInstance.store.observable.subscribe((nextState) => {
      const nextAccounts = nextState.accounts;
      const nextActiveId = nextAccounts.find((acc) => acc.active)?.accountId || nextAccounts[0]?.accountId || null;
      if (nextActiveId !== currentAccountId) {
        currentAccountId = nextActiveId;
        if (typeof onAccountChanged === 'function') {
          onAccountChanged(nextActiveId);
        }
      }
    });

    console.log("✅ [Aegis] NEAR Wallet Selector initialized with modules: Meteor, HERE, Nightly, Sender, Bitte");
    return { selector: selectorInstance, modal: modalInstance };
  } catch (err) {
    console.error("[Aegis] Failed to initialize NEAR Wallet Selector:", err);
    throw err;
  }
}

export function openWalletModal() {
  if (modalInstance) {
    modalInstance.show();
  } else {
    console.warn("[Aegis] Wallet selector modal not initialized yet");
  }
}

export async function getActiveWallet() {
  if (!selectorInstance) return null;
  return await selectorInstance.wallet();
}

export async function signOutWallet() {
  if (!selectorInstance) return;
  const wallet = await selectorInstance.wallet();
  if (wallet) {
    await wallet.signOut();
    currentAccountId = null;
  }
}

export async function callContractMethod(contractId, methodName, args = {}, gas = "30000000000000", deposit = "0") {
  if (!selectorInstance) throw new Error("Wallet selector not initialized");
  const wallet = await selectorInstance.wallet();
  if (!wallet) throw new Error("No wallet connected. Please connect wallet first.");

  const state = selectorInstance.store.getState();
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
}

// Expose on window for vanilla index.html
if (typeof window !== "undefined") {
  window.AegisWallet = {
    init: initAegisWalletSelector,
    openModal: openWalletModal,
    getActiveWallet,
    signOut: signOutWallet,
    callContractMethod,
    getAccountId: () => currentAccountId,
    getSelector: () => selectorInstance,
    getModal: () => modalInstance
  };
}

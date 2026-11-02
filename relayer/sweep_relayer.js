/**
 * LastKey Relayer: Automated Cross-Chain Sweep Engine
 * 
 * Watches LastKey Vault contract on NEAR.
 * When state transitions to 'Evacuated' or 'Inheritance', it constructs
 * evacuation transactions for Bitcoin, EVM, and Solana, fetches threshold
 * signatures via the Vault contract's MPC delegate, and broadcasts to foreign chains.
 */

const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');
const web3 = require('@solana/web3.js');
const chainsig = require('chainsig.js');

class LastKeySweepRelayer {
  constructor(config = {}) {
    this.networkId = config.networkId || 'testnet';
    this.mpcContractId = config.mpcContractId || (this.networkId === 'testnet' ? 'v1.signer-prod.testnet' : 'v1.signer');
    this.vaultContractId = config.vaultContractId || 'lastkey-vault-2151.testnet';
    this.derivationPath = config.derivationPath || 'aegis/0';
    
    this.chainSigContract = new chainsig.contracts.ChainSignatureContract({
      networkId: this.networkId,
      contractId: this.mpcContractId
    });

    this.evmAdapter = new chainsig.chainAdapters.evm.EVM({
      contract: this.chainSigContract
    });

    this.btcAdapter = new chainsig.chainAdapters.btc.Bitcoin({
      contract: this.chainSigContract,
      network: this.networkId === 'mainnet' ? 'mainnet' : 'testnet'
    });

    this.solanaAdapter = new chainsig.chainAdapters.solana.Solana({
      contract: this.chainSigContract
    });
  }

  /**
   * Derive the multichain vault addresses for an owner account
   */
  async deriveAllAddresses(accountId, path = this.derivationPath) {
    const [evm, btc, sol] = await Promise.all([
      this.evmAdapter.deriveAddressAndPublicKey(accountId, path),
      this.btcAdapter.deriveAddressAndPublicKey(accountId, path),
      this.solanaAdapter.deriveAddressAndPublicKey(accountId, path)
    ]);

    return {
      accountId,
      path,
      evm: { address: evm.address, publicKey: evm.publicKey },
      btc: { address: btc.address, publicKey: btc.publicKey },
      sol: { address: sol.address, publicKey: sol.publicKey }
    };
  }

  /**
   * Prepare EVM Sweep Transaction
   */
  async prepareEvmSweep({ fromAddress, toAddress, valueWei, gasLimit = 21000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const rawTx = {
      to: toAddress,
      value: BigInt(valueWei),
      nonce: Number(nonce),
      gasLimit: BigInt(gasLimit),
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2 // EIP-1559
    };

    // Serialize unsigned tx and compute Keccak256 hash
    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM',
      rawTx,
      txHash,
      hashBytes,
      isEddsa: false
    };
  }

  /**
   * Assemble signed EVM transaction from MPC signature (r, s, recoveryId)
   */
  assembleSignedEvmTx(rawTx, mpcSignature) {
    // mpcSignature: { r: '0x...', s: '0x...', v: 0 | 1 }
    const tx = ethers.Transaction.from(rawTx);
    tx.signature = {
      r: mpcSignature.r.startsWith('0x') ? mpcSignature.r : '0x' + mpcSignature.r,
      s: mpcSignature.s.startsWith('0x') ? mpcSignature.s : '0x' + mpcSignature.s,
      v: mpcSignature.v !== undefined ? mpcSignature.v : 27
    };
    return {
      signedTx: tx.serialized,
      txHash: tx.hash,
      from: tx.from
    };
  }

  /**
   * Prepare Bitcoin Sweep PSBT
   */
  prepareBtcSweep({ utxos, fromAddress, toAddress, feeSats = 1000, network = bitcoin.networks.testnet }) {
    const psbt = new bitcoin.Psbt({ network });
    let totalIn = 0;

    for (const utxo of utxos) {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: {
          script: bitcoin.address.toOutputScript(fromAddress, network),
          value: utxo.value
        }
      });
      totalIn += utxo.value;
    }

    const sendAmount = totalIn - feeSats;
    if (sendAmount <= 0) {
      throw new Error(`Insufficient funds: total ${totalIn} sats <= fee ${feeSats} sats`);
    }

    psbt.addOutput({
      address: toAddress,
      value: sendAmount
    });

    return {
      chain: 'BTC',
      psbtHex: psbt.toHex(),
      sendAmount,
      totalIn,
      feeSats
    };
  }

  /**
   * Prepare Solana Sweep Transaction
   */
  prepareSolanaSweep({ fromPubkey, toPubkey, lamports, recentBlockhash }) {
    const from = new web3.PublicKey(fromPubkey);
    const to = new web3.PublicKey(toPubkey);

    const transaction = new web3.Transaction({
      recentBlockhash: recentBlockhash || '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM',
      feePayer: to // Backup pays or Vault pays
    }).add(
      web3.SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: to,
        lamports: Number(lamports)
      })
    );

    const messageBytes = transaction.serializeMessage();
    const messageHash = Array.from(ethers.getBytes(ethers.sha256(messageBytes)));

    return {
      chain: 'SOL',
      serializedMessage: messageBytes.toString('base64'),
      messageHash,
      isEddsa: true
    };
  }
}

module.exports = { LastKeySweepRelayer };

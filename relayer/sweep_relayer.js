/**
 * LastKey Relayer: Automated Cross-Chain Sweep Engine
 * 
 * Watches LastKey Vault contract on NEAR.
 * When state transitions to 'Evacuated' or 'Inheritance', it constructs
 * evacuation transactions for Bitcoin, EVM, and Solana, fetches threshold
 * signatures via the Vault contract's MPC delegate, and broadcasts to foreign chains.
 */

const crypto = require('crypto');
const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');
const web3 = require('@solana/web3.js');
const chainsig = require('chainsig.js');
const bs58Pkg = require('bs58');
const bs58Encode = bs58Pkg.encode || (bs58Pkg.default && bs58Pkg.default.encode);

class LastKeySweepRelayer {
  constructor(config = {}) {
    this.networkId = config.networkId || 'testnet';
    this.mpcContractId = config.mpcContractId || (this.networkId === 'testnet' ? 'v1.signer-prod.testnet' : 'v1.signer');
    this.vaultContractId = config.vaultContractId || 'aegis.okgoogleok.testnet';
    this.derivationPath = config.derivationPath || 'aegis/v0';
    this.nearRpcUrl =
      config.nearRpcUrl ||
      process.env.NEAR_RPC_URL ||
      (this.networkId === 'testnet' ? 'https://test.rpc.fastnear.com' : 'https://free.rpc.fastnear.com');
    this._derivedCache = new Map();

    this.chainSigContract = new chainsig.contracts.ChainSignatureContract({
      networkId: this.networkId,
      contractId: this.mpcContractId,
      fallbackRpcUrls: [this.nearRpcUrl]
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
    const cacheKey = `${accountId}:${path}`;
    if (this._derivedCache.has(cacheKey)) {
      return this._derivedCache.get(cacheKey);
    }

    const [evm, btc, sol] = await Promise.all([
      this.evmAdapter.deriveAddressAndPublicKey(accountId, path),
      this.btcAdapter.deriveAddressAndPublicKey(accountId, path),
      this.solanaAdapter.deriveAddressAndPublicKey(accountId, path)
    ]);

    const derived = {
      accountId,
      path,
      evm: { address: evm.address, publicKey: evm.publicKey },
      btc: { address: btc.address, publicKey: btc.publicKey },
      sol: { address: sol.address, publicKey: sol.publicKey }
    };
    this._derivedCache.set(cacheKey, derived);
    return derived;
  }

  /**
   * Prepare EVM Sweep Transaction
   */
  async prepareEvmSweep({ fromAddress, toAddress, valueWei, memo, gasLimit = 21000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const dataHex = memo ? ethers.hexlify(ethers.toUtf8Bytes(memo)) : '0x';
    const dataBytes = ethers.getBytes(dataHex);
    // Exact intrinsic gas per EIP-2028: 16 per non-zero byte, 4 per zero byte
    let calldataGas = 0n;
    for (const b of dataBytes) calldataGas += (b === 0 ? 4n : 16n);
    const computedGasLimit = 21000n + calldataGas;

    // For L2 networks (Base, Optimism, Arbitrum), account for L1 Rollup Data fee buffer
    const isL2 = [8453, 84532, 10, 42161, 421614].includes(Number(chainId));
    const l1DataFeeBuffer = isL2 ? 15000000000000n : 0n; // ~0.000015 ETH buffer

    const rawTx = {
      to: toAddress,
      value: BigInt(valueWei),
      nonce: Number(nonce),
      gasLimit: computedGasLimit,
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2, // EIP-1559
      data: dataHex
    };

    // Serialize unsigned tx and compute Keccak256 hash
    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM',
      rawTx,
      unsignedTxHex, // Verifiable raw transaction payload for request_sweep_signature
      txHash,
      hashBytes,
      memo: memo || null,
      l1DataFeeBuffer: l1DataFeeBuffer.toString(),
      isEddsa: false
    };
  }

  /**
   * Prepare ERC-20 Token Sweep (e.g. USDC, USDT)
   * Swept BEFORE native ETH so gas remains available.
   */
  async prepareEvmTokenSweep({ tokenAddress, fromAddress, toAddress, amountRaw, gasLimit = 65000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const erc20Interface = new ethers.Interface([
      'function transfer(address to, uint256 amount) returns (bool)'
    ]);
    const dataHex = erc20Interface.encodeFunctionData('transfer', [toAddress, BigInt(amountRaw)]);

    const rawTx = {
      to: tokenAddress,
      value: 0n,
      nonce: Number(nonce),
      gasLimit: BigInt(gasLimit),
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2,
      data: dataHex
    };

    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM_ERC20',
      tokenAddress,
      rawTx,
      unsignedTxHex, // Verifiable raw token transfer payload
      txHash,
      hashBytes,
      isEddsa: false
    };
  }

  /**
   * Prepare ERC-721 / NFT Sweep
   * Swept FIRST along with tokens so gas remains available.
   */
  async prepareEvmNftSweep({ nftContract, fromAddress, toAddress, tokenId, gasLimit = 85000n, maxFeePerGas = 20000000000n, maxPriorityFeePerGas = 1000000000n, nonce = 0, chainId = 11155111 }) {
    const erc721Interface = new ethers.Interface([
      'function safeTransferFrom(address from, address to, uint256 tokenId)'
    ]);
    const dataHex = erc721Interface.encodeFunctionData('safeTransferFrom', [fromAddress, toAddress, BigInt(tokenId)]);

    const rawTx = {
      to: nftContract,
      value: 0n,
      nonce: Number(nonce),
      gasLimit: BigInt(gasLimit),
      maxFeePerGas: BigInt(maxFeePerGas),
      maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
      chainId: Number(chainId),
      type: 2,
      data: dataHex
    };

    const serializedUnsigned = ethers.Transaction.from(rawTx).unsignedSerialized;
    const unsignedTxHex = serializedUnsigned.replace(/^0x/, '');
    const txHash = ethers.keccak256(serializedUnsigned);
    const hashBytes = Array.from(ethers.getBytes(txHash));

    return {
      chain: 'EVM_NFT',
      nftContract,
      tokenId,
      rawTx,
      unsignedTxHex,
      txHash,
      hashBytes,
      isEddsa: false
    };
  }

  /**
   * Plan Comprehensive Zero-Asset-Left-Behind Sweep
   * Enforces the critical gas-draining avoidance sequence:
   * 1. Sweep all NFTs (regardless of spam flag)
   * 2. Sweep all ERC-20 / SPL Tokens (regardless of spam flag)
   * 3. Sweep remaining native gas balance (balance - gasFee - L1FeeBuffer)
   */
  planEvmEvacuationQueue({ fromAddress, toAddress, nfts = [], tokens = [], nativeWeiBalance = 0n, memo = null, gasPriceWei = 21000000000n, chainId = 11155111 }) {
    const queue = [];
    let currentNonce = 0;

    // 1. NFTs first
    for (const nft of nfts) {
      queue.push({
        step: 'NFT_SWEEP',
        targetContract: nft.contract,
        id: nft.tokenId,
        gasLimit: 85000n,
        nonce: currentNonce++
      });
    }

    // 2. Tokens second (all tokens, zero filtering)
    for (const tok of tokens) {
      queue.push({
        step: 'TOKEN_SWEEP',
        tokenAddress: tok.address,
        amount: tok.amount,
        gasLimit: 65000n,
        nonce: currentNonce++
      });
    }

    // Exact intrinsic gas for memo per EIP-2028: 16 per non-zero byte, 4 per zero byte
    let calldataGas = 0n;
    if (memo) {
      const memoBytes = Buffer.from(memo, 'utf8');
      for (const b of memoBytes) calldataGas += (b === 0 ? 4n : 16n);
    }

    // For L2 networks (Base, Optimism, Arbitrum), account for L1 Rollup Data fee buffer
    const isL2 = [8453, 84532, 10, 42161, 421614].includes(Number(chainId));
    const l1DataFeeBuffer = isL2 ? 50000000000000n : 0n; // ~0.00005 ETH for L1 DA

    // Calculate total reserved gas for all prior steps + final native sweep
    const totalGasUnits = BigInt(nfts.length) * 85000n + BigInt(tokens.length) * 65000n + (21000n + calldataGas);
    const totalGasCost = totalGasUnits * BigInt(gasPriceWei) + l1DataFeeBuffer;
    const nativeBal = BigInt(nativeWeiBalance);
    const sweepWei = nativeBal > totalGasCost ? nativeBal - totalGasCost : 0n;

    // 3. Native ETH LAST (cleans to absolute 0 minus fee)
    queue.push({
      step: 'NATIVE_FINAL_SWEEP',
      toAddress,
      balanceBefore: nativeBal.toString(),
      sweepAmountWei: sweepWei.toString(),
      gasCostReservedWei: totalGasCost.toString(),
      l1DataFeeBufferWei: l1DataFeeBuffer.toString(),
      memo: memo,
      nonce: currentNonce
    });

    return queue;
  }

  /**
   * Execute Evacuation Queue with Fault Isolation (Anti-Revert Protection)
   * If a scam, paused, or blacklisted token reverts, it NEVER halts the sweep:
   * it logs and continues immediately. Nonces are preserved continuously so
   * subsequent transactions are never blocked in the mempool by a nonce gap.
   */
  async executeQueueWithFaultIsolation(queue, dispatchFn) {
    const results = [];
    let continuousNonce = null;

    for (const task of queue) {
      if (continuousNonce === null && task.nonce !== undefined) {
        continuousNonce = task.nonce;
      }
      const activeTask = { ...task, nonce: continuousNonce };
      try {
        const txResult = await dispatchFn(activeTask);
        results.push({ task: activeTask, status: 'SUCCESS', txResult });
        continuousNonce++; // Nonce advances ONLY on successful step execution
      } catch (err) {
        console.warn(`⚠️ [Aegis Isolation] Step ${task.step} (${task.targetContract || task.tokenAddress || 'asset'}) failed. Skipping without consuming nonce:`, err.message);
        results.push({ task: activeTask, status: 'SKIPPED_REVERT', error: err.message });
        // Nonce is intentionally kept unchanged for the next task
      }
    }
    return results;
  }

  /**
   * Assemble signed EVM transaction from MPC signature (r, s, recoveryId)
   * Supports both raw RSV and NEAR v1.signer Secp256k1 response structure
   */
  assembleSignedEvmTx(rawTx, mpcSignature) {
    const tx = ethers.Transaction.from(rawTx);
    let rHex, sHex, yParity;

    if (mpcSignature.big_r && mpcSignature.big_r.affine_point) {
      // NEAR v1.signer returns big_r.affine_point (33-byte hex, strip 02/03 prefix)
      rHex = '0x' + mpcSignature.big_r.affine_point.slice(2);
      sHex = '0x' + (mpcSignature.s.scalar || mpcSignature.s);
      yParity = mpcSignature.recovery_id;
    } else {
      rHex = mpcSignature.r.startsWith('0x') ? mpcSignature.r : '0x' + mpcSignature.r;
      sHex = mpcSignature.s.startsWith('0x') ? mpcSignature.s : '0x' + mpcSignature.s;
      if (mpcSignature.yParity !== undefined) {
        yParity = mpcSignature.yParity;
      } else if (mpcSignature.v !== undefined) {
        yParity = mpcSignature.v >= 27 ? mpcSignature.v - 27 : mpcSignature.v;
      } else {
        yParity = 0;
      }
    }

    tx.signature = {
      r: rHex,
      s: sHex,
      yParity: yParity
    };

    return {
      signedTx: tx.serialized,
      txHash: tx.hash,
      from: tx.from
    };
  }

  /**
   * Prepare Bitcoin Sweep PSBT
   * Includes dynamic vSize calculation, dust input filtering, and BIP-125 Opt-in RBF.
   */
  prepareBtcSweep({ utxos, fromAddress, toAddress, memo, feeRateSatPerVb = 20, feeSatsOverride = null, network = bitcoin.networks.testnet }) {
    // Filter out dust inputs with negative effective value (costing more than 68 vBytes * feeRate)
    const effectiveUtxos = utxos.filter(u => u.value > Math.ceil(68 * feeRateSatPerVb));
    if (effectiveUtxos.length === 0) {
      throw new Error(`All UTXOs are dust below fee threshold (${feeRateSatPerVb} sat/vB)`);
    }

    const psbt = new bitcoin.Psbt({ network });
    let totalIn = 0;

    for (const utxo of effectiveUtxos) {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        sequence: 0xfffffffd, // BIP-125 Opt-in RBF (allows CPFP/RBF fee bumping)
        witnessUtxo: {
          script: bitcoin.address.toOutputScript(fromAddress, network),
          value: utxo.value
        }
      });
      totalIn += utxo.value;
    }

    let memoBytes = null;
    if (memo) {
      const rawMemoBuf = Buffer.from(memo, 'utf8');
      if (rawMemoBuf.length <= 80) {
        memoBytes = rawMemoBuf;
      } else {
        // Bitcoin standardness limits OP_RETURN to 80 bytes: anchor SHA-256 commitment of E2EE ciphertext
        const hexHash = crypto.createHash('sha256').update(String(memo), 'utf8').digest('hex');
        memoBytes = Buffer.from(`aegis-e2ee:${hexHash.slice(0, 36)}`, 'utf8');
      }
    }
    const estimatedVSize = Math.ceil(10.5 + effectiveUtxos.length * 68 + 31 + (memoBytes ? memoBytes.length + 11 : 0));
    const feeSats = feeSatsOverride !== null ? Math.ceil(feeSatsOverride) : Math.max(1000, Math.ceil(estimatedVSize * feeRateSatPerVb));

    const sendAmount = totalIn - feeSats;
    const BTC_DUST_LIMIT_SATS = 546;
    if (sendAmount < BTC_DUST_LIMIT_SATS) {
      throw new Error(`Send amount ${sendAmount} sats is below Bitcoin dust limit (${BTC_DUST_LIMIT_SATS} sats)`);
    }

    psbt.addOutput({
      address: toAddress,
      value: sendAmount
    });

    if (memoBytes) {
      const embed = bitcoin.payments.embed({ data: [memoBytes] });
      psbt.addOutput({
        script: embed.output,
        value: 0
      });
    }

    const txForHash = psbt.__CACHE.__TX;
    const prevOutScript = bitcoin.address.toOutputScript(fromAddress, network);
    const sighashes = effectiveUtxos.map((u, idx) => {
      const hash = txForHash.hashForWitnessV0(idx, prevOutScript, u.value, bitcoin.Transaction.SIGHASH_ALL);
      return { inputIndex: idx, sighashHex: Buffer.from(hash).toString('hex') };
    });

    return {
      chain: 'BTC',
      psbtHex: psbt.toHex(),
      sighashes,
      sendAmount,
      totalIn,
      feeSats,
      feeRateSatPerVb,
      estimatedVSize,
      effectiveUtxoCount: effectiveUtxos.length,
      memo: memo || null
    };
  }

  /**
   * Prepare Solana Sweep Transaction
   */
  /**
   * Prepare Solana Sweep Transaction
   * Uses feePayer: from (Vault) so recipient signature is never needed (Push Inheritance).
   * Passes raw serialized message bytes for Ed25519 (no double sha256).
   */
  prepareSolanaSweep({ fromPubkey, toPubkey, lamports, amountLamports, memo, recentBlockhash }) {
    const from = new web3.PublicKey(fromPubkey);
    const to = new web3.PublicKey(toPubkey);
    const effectiveLamports = lamports !== undefined ? lamports : amountLamports;
    if (effectiveLamports === undefined) {
      throw new Error("Missing required lamports/amountLamports parameter for Solana sweep");
    }
    const TX_FEE_LAMPORTS = 5000n;
    const sweepLamports = BigInt(effectiveLamports) - TX_FEE_LAMPORTS;
    if (sweepLamports <= 0n) {
      throw new Error(`Insufficient SOL balance for fee: balance ${effectiveLamports} <= fee ${TX_FEE_LAMPORTS}`);
    }

    const transaction = new web3.Transaction({
      recentBlockhash: recentBlockhash || '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM',
      feePayer: from // Vault pays its own fee and signs
    }).add(
      web3.SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: to,
        lamports: Number(sweepLamports)
      })
    );

    if (memo) {
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: from, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: Buffer.from(memo, 'utf8')
        })
      );
    }

    const messageBytes = transaction.serializeMessage();
    const rawPayloadHex = Buffer.from(messageBytes).toString('hex');

    return {
      chain: 'SOL',
      serializedMessage: messageBytes.toString('base64'),
      rawPayloadHex,
      sweepLamports: sweepLamports.toString(),
      memo: memo || null,
      isEddsa: true
    };
  }

  /**
   * Prepare Solana SPL Token Sweep (e.g. USDC, PYUSD) to Brand New Empty Recipient
   * Bundles createAssociatedTokenAccountIdempotent + transferChecked into ONE atomic transaction.
   * Recipient needs ZERO SOL balance - rent is funded by Vault.
   * Supports both standard SPL and Token-2022 programs.
   * Passes raw serialized message bytes for Ed25519.
   */
  prepareSolanaTokenSweep({ mintPubkey, fromOwnerPubkey, toRecipientPubkey, amountTokens, memo, recentBlockhash, tokenProgramId = null }) {
    const fromOwner = new web3.PublicKey(fromOwnerPubkey);
    const toRecipient = new web3.PublicKey(toRecipientPubkey);
    const mint = new web3.PublicKey(mintPubkey);

    const TOKEN_PROGRAM_ID = tokenProgramId
      ? new web3.PublicKey(tokenProgramId)
      : new web3.PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
    const ASSOCIATED_TOKEN_PROGRAM_ID = new web3.PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

    // Derive recipient ATA address deterministically
    const [recipientAta] = web3.PublicKey.findProgramAddressSync(
      [toRecipient.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const [senderAta] = web3.PublicKey.findProgramAddressSync(
      [fromOwner.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const transaction = new web3.Transaction({
      recentBlockhash: recentBlockhash || '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM',
      feePayer: fromOwner
    });

    // 1. Idempotent ATA creation instruction (creates ATA if missing, no-op if exists)
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: fromOwner, isSigner: true, isWritable: true },
          { pubkey: recipientAta, isSigner: false, isWritable: true },
          { pubkey: toRecipient, isSigner: false, isWritable: false },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }
        ],
        programId: ASSOCIATED_TOKEN_PROGRAM_ID,
        data: Buffer.from([1]) // 1 = CreateIdempotent
      })
    );

    // 2. Token Transfer instruction
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: senderAta, isSigner: false, isWritable: true },
          { pubkey: recipientAta, isSigner: false, isWritable: true },
          { pubkey: fromOwner, isSigner: true, isWritable: false }
        ],
        programId: TOKEN_PROGRAM_ID,
        data: Buffer.concat([Buffer.from([3]), Buffer.from(new BigUint64Array([BigInt(amountTokens)]).buffer)]) // 3 = Transfer
      })
    );

    // 3. CloseAccount instruction (opcode 9) - closes emptied senderAta and reclaims the 2,039,280 lamports rent back to fromOwner
    transaction.add(
      new web3.TransactionInstruction({
        keys: [
          { pubkey: senderAta, isSigner: false, isWritable: true },
          { pubkey: fromOwner, isSigner: false, isWritable: true }, // Rent returns to vault balance
          { pubkey: fromOwner, isSigner: true, isWritable: false }
        ],
        programId: TOKEN_PROGRAM_ID,
        data: Buffer.from([9]) // 9 = CloseAccount
      })
    );

    if (memo) {
      const MEMO_PROGRAM_ID = new web3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
      transaction.add(
        new web3.TransactionInstruction({
          keys: [{ pubkey: fromOwner, isSigner: true, isWritable: true }],
          programId: MEMO_PROGRAM_ID,
          data: Buffer.from(memo, 'utf8')
        })
      );
    }

    const messageBytes = transaction.serializeMessage();
    const rawPayloadHex = Buffer.from(messageBytes).toString('hex');

    return {
      chain: 'SOL_SPL_TOKEN',
      recipientAta: recipientAta.toBase58(),
      senderAta: senderAta.toBase58(),
      serializedMessage: messageBytes.toString('base64'),
      rawPayloadHex,
      memo: memo || null,
      isEddsa: true
    };
  }

  /**
   * Finalize Bitcoin Sweep PSBT with MPC ECDSA signature(s)
   * Converts MPC (r, s) into DER encoding (BIP-66) and attaches SIGHASH_ALL (0x01).
   *
   * @param {string} psbtHex - Unfinalized PSBT in hex format
   * @param {Array<{ r: string|Buffer, s: string|Buffer, publicKey: string|Buffer, inputIndex?: number }>} signatures
   * @param {object} network - bitcoinjs network (default: bitcoin.networks.testnet)
   */
  finalizeBtcSweepPsbt(psbtHex, signatures = [], network = bitcoin.networks.testnet) {
    const psbt = bitcoin.Psbt.fromHex(psbtHex, { network });

    if (signatures && signatures.length > 0) {
      signatures.forEach((sigObj, idx) => {
        const inputIndex = typeof sigObj.inputIndex === 'number' ? sigObj.inputIndex : idx;
        const rBuf = Buffer.isBuffer(sigObj.r) ? sigObj.r : Buffer.from(sigObj.r.replace(/^0x/, ''), 'hex');
        const sBuf = Buffer.isBuffer(sigObj.s) ? sigObj.s : Buffer.from(sigObj.s.replace(/^0x/, ''), 'hex');
        const pubkeyRaw = sigObj.publicKey || sigObj.pubkey;
        if (!pubkeyRaw) {
          throw new Error(`Missing publicKey for PSBT signature at input ${inputIndex}`);
        }
        const pubkeyBuf = Buffer.isBuffer(pubkeyRaw)
          ? pubkeyRaw
          : Buffer.from(pubkeyRaw.replace(/^0x/, ''), 'hex');

        const derSig = this.encodeDerSignature(rBuf, sBuf);
        const sigWithHashType = Buffer.concat([derSig, Buffer.from([bitcoin.Transaction.SIGHASH_ALL])]);

        psbt.updateInput(inputIndex, {
          partialSig: [{
            pubkey: pubkeyBuf,
            signature: sigWithHashType
          }]
        });
      });
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    return {
      txHex: tx.toHex(),
      txId: tx.getId()
    };
  }

  /**
   * Encode (r, s) to DER (BIP-66) format with BIP-62 Low-S canonical enforcement
   */
  encodeDerSignature(rBuffer, sBuffer) {
    const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const SECP256K1_HALF_N = SECP256K1_N / 2n;

    let sBig = BigInt('0x' + Buffer.from(sBuffer).toString('hex'));
    if (sBig > SECP256K1_HALF_N) {
      sBig = SECP256K1_N - sBig;
      let hex = sBig.toString(16);
      if (hex.length % 2 !== 0) hex = '0' + hex;
      sBuffer = Buffer.from(hex, 'hex');
    }

    let r = Buffer.from(rBuffer);
    let s = Buffer.from(sBuffer);
    if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
    if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);
    while (r.length > 1 && r[0] === 0x00 && !(r[1] & 0x80)) r = r.slice(1);
    while (s.length > 1 && s[0] === 0x00 && !(s[1] & 0x80)) s = s.slice(1);

    const length = 4 + r.length + s.length;
    return Buffer.concat([
      Buffer.from([0x30, length, 0x02, r.length]),
      r,
      Buffer.from([0x02, s.length]),
      s
    ]);
  }

  /**
   * Assemble signed Solana transaction from MPC Ed25519 signature
   */
  assembleSignedSolanaTx(serializedMessageBase64, fromPubkeyStr, mpcEddsaSignature) {
    const fromPubkey = new web3.PublicKey(fromPubkeyStr);
    const message = web3.Message.from(Buffer.from(serializedMessageBase64, 'base64'));
    const tx = web3.Transaction.populate(message);
    const rawSig = mpcEddsaSignature?.signature || mpcEddsaSignature;
    const sigBytes = Buffer.isBuffer(rawSig)
      ? rawSig
      : Array.isArray(rawSig)
        ? Buffer.from(rawSig)
        : Buffer.from(String(rawSig).replace(/^0x/, ''), 'hex');
    tx.addSignature(fromPubkey, sigBytes);
    const serialized = tx.serialize({ verifySignatures: false, requireAllSignatures: false });
    const signatureBase58 = bs58Encode ? bs58Encode(Uint8Array.from(sigBytes)) : sigBytes.toString('hex');
    return {
      txHex: Buffer.from(serialized).toString('hex'),
      signedTxBase64: Buffer.from(serialized).toString('base64'),
      signatureBase58,
      signatureHex: sigBytes.toString('hex')
    };
  }

  /**
   * JIT Blockhash Refresher (Solana)
   * Fetches latest finalized blockhash immediately before MPC signing to prevent 150-slot expiry.
   */
  async refreshTransactionBlockhash(connection, transaction, feePayerPubkey) {
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('finalized');
    transaction.recentBlockhash = blockhash;
    transaction.feePayer = new web3.PublicKey(feePayerPubkey);
    const messageBytes = transaction.serializeMessage();
    return {
      blockhash,
      lastValidBlockHeight,
      serializedMessageBase64: messageBytes.toString('base64'),
      rawPayloadHex: Buffer.from(messageBytes).toString('hex')
    };
  }

  /**
   * Prepare Native NEAR & NEP-141 Sweep
   * Safely leaves calculated contract storage reserve (~1.6 NEAR) and sweeps the remaining balance.
   */
  prepareNearSweep({ fromAccount, toAccount, balanceYocto, reserveYocto = '1600000000000000000000000', memo }) {
    const total = BigInt(balanceYocto);
    const reserve = BigInt(reserveYocto);
    const sweepAmount = total > reserve ? total - reserve : 0n;

    return {
      chain: 'NEAR',
      fromAccount,
      toAccount,
      sweepAmountYocto: sweepAmount.toString(),
      storageReserveYocto: reserve.toString(),
      memo: memo || null,
      actions: [
        {
          type: 'Transfer',
          params: { deposit: sweepAmount.toString() }
        }
      ]
    };
  }
}

module.exports = { LastKeySweepRelayer };

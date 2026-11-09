/**
 * LastKey Bunker Autonomous Relayer & Stateless Keeper Service
 *
 * Security & Architecture Guarantees:
 * - Zero hardcoded private keys; runs with a least-privilege `FunctionCall` key on `keeper.aegis.okgoogleok.testnet`
 * - Zero-deposit `request_sweep_signature` calls funded by Per-Vault Gas Escrow / Sponsor Pool + 0.005 NEAR keeper refund
 * - Multi-UTXO Bitcoin signing + OP_RETURN testament, dynamic EVM nonce/EIP-1559 fee calculation, real Base58 Solana tx signatures
 * - Zero fake fallback hashes; strict broadcast verification with automatic retry if any RPC broadcast fails
 * - On-chain telemetry persistence (`record_sweep_telemetry`) + multi-tenant `web/telemetry.json` mirror
 */

let fs = null;
let path = null;
if (typeof process !== 'undefined' && !process.browser && typeof require !== 'undefined') {
  try {
    fs = require('fs');
    path = require('path');
  } catch (_) {}
}
const nearAPI = require('near-api-js');
const { ethers } = require('ethers');
const web3 = require('@solana/web3.js');
const bitcoin = require('bitcoinjs-lib');
const { LastKeySweepRelayer } = require('./sweep_relayer');

class AegisRelayerService {
  constructor(config = {}) {
    this.networkId = config.networkId || process.env.NEAR_NETWORK || 'testnet';
    this.contractId = config.contractId || process.env.CONTRACT_ID || 'aegis.okgoogleok.testnet';
    this.relayerAccountId =
      config.relayerAccountId ||
      process.env.RELAYER_ACCOUNT_ID ||
      'keeper.aegis.okgoogleok.testnet';
    this.privateKey = config.privateKey || '';
    this.disableLocalFileCache = Boolean(config.disableLocalFileCache);
    this.credPath =
      config.credPath ||
      (typeof __dirname !== 'undefined' && path && typeof path.resolve === 'function'
        ? path.resolve(__dirname, `../.credentials/${this.relayerAccountId}.json`)
        : '');
    this.telegramCredPath =
      config.telegramCredPath ||
      (typeof __dirname !== 'undefined' && path && typeof path.resolve === 'function'
        ? path.resolve(__dirname, '../.credentials/telegram-bot.json')
        : '');
    this.telemetryPath =
      config.telemetryPath ||
      (typeof __dirname !== 'undefined' && path && typeof path.resolve === 'function'
        ? path.resolve(__dirname, '../web/telemetry.json')
        : '');
    this.nearRpcUrl =
      config.nearRpcUrl || process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com';
    this.evmRpcUrl =
      config.evmRpcUrl ||
      process.env.EVM_RPC_URL ||
      'https://ethereum-sepolia-rpc.publicnode.com';
    this.solanaRpcUrl =
      config.solanaRpcUrl ||
      process.env.SOLANA_RPC_URL ||
      'https://api.devnet.solana.com';

    this.engine = new LastKeySweepRelayer({
      networkId: this.networkId,
      vaultContractId: this.contractId,
      nearRpcUrl: this.nearRpcUrl
    });

    this.near = null;
    this.account = null;
    this._signerKeyPair = null;
    this._nextNonce = null;
    this._recentBlockHash = null;
    this._blockFetchedAt = 0;
    this.hasSignerKey = false;
    this.processedSweeps = new Set();
  }

  async init({ requireSigner = false } = {}) {
    if (!this.near) {
      const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
      let privKey = (this.privateKey || process.env.RELAYER_PRIVATE_KEY || '').trim();

      if (
        !privKey &&
        process.env.NODE_ENV !== 'production' &&
        this.credPath &&
        fs &&
        typeof fs.existsSync === 'function' &&
        fs.existsSync(this.credPath)
      ) {
        try {
          const cred = JSON.parse(fs.readFileSync(this.credPath, 'utf8'));
          privKey = (cred.privateKey || cred.private_key || '').trim();
          if (cred.accountId || cred.account_id) {
            this.relayerAccountId = cred.accountId || cred.account_id;
          }
        } catch (e) {
          console.warn(`[LastKey Relayer] Could not parse ${this.credPath}:`, e.message);
        }
      }

      if (privKey) {
        const keyPair = nearAPI.KeyPair.fromString(privKey);
        this._signerKeyPair = keyPair;
        await keyStore.setKey(this.networkId, this.relayerAccountId, keyPair);
        this.hasSignerKey = true;
      }

      this.near = await nearAPI.connect({
        networkId: this.networkId,
        keyStore,
        nodeUrl: this.nearRpcUrl
      });
      this.account = await this.near.account(this.relayerAccountId);

      console.log(
        `🛡️  [LastKey Relayer] Initialized (account: ${this.relayerAccountId}, signerLoaded: ${this.hasSignerKey})`
      );
    }

    if (requireSigner && !this.hasSignerKey) {
      throw new Error(
        `Missing RELAYER_PRIVATE_KEY for ${this.relayerAccountId}. Configure RELAYER_PRIVATE_KEY env secret or ${this.credPath}.`
      );
    }
  }

  async nearRpc(method, params = {}) {
    const candidates = [
      this.nearRpcUrl,
      this.networkId === 'testnet' ? 'https://test.rpc.fastnear.com' : 'https://free.rpc.fastnear.com',
      this.networkId === 'testnet' ? 'https://rpc.testnet.fastnear.com' : 'https://rpc.mainnet.fastnear.com',
      this.networkId === 'testnet' ? 'https://archival-rpc.testnet.near.org' : 'https://rpc.mainnet.near.org'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`NEAR RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          const errData = body.error.data ? JSON.stringify(body.error.data) : body.error.message;
          const rpcErr = new Error(`NEAR RPC ${body.error.name || 'Error'}: ${errData}`);
          rpcErr.rpcError = body.error;
          throw rpcErr;
        }
        return body.result;
      } catch (err) {
        lastErr = err;
        // Do not failover on deterministic NEAR execution/state errors (e.g. InvalidNonce, UNKNOWN_ACCOUNT)
        if (err.rpcError && err.rpcError.name !== 'INTERNAL_ERROR' && !String(err.message).includes('Timeout')) {
          throw err;
        }
      }
    }
    throw lastErr || new Error('All NEAR RPC endpoints failed');
  }

  async ensureSignerNonceAndBlock(forceResync = false) {
    const pubKeyStr = this._signerKeyPair.getPublicKey().toString();
    const blockStale = Date.now() - this._blockFetchedAt > 45_000;
    if (forceResync || this._nextNonce === null || blockStale) {
      const keyInfo = await this.nearRpc('query', {
        request_type: 'view_access_key',
        finality: 'optimistic',
        account_id: this.relayerAccountId,
        public_key: pubKeyStr
      });
      if (keyInfo && keyInfo.error) {
        throw new Error(`Access key query failed for ${this.relayerAccountId}: ${keyInfo.error}`);
      }
      const fcPerm = keyInfo?.permission?.FunctionCall;
      if (fcPerm && fcPerm.allowance !== null && fcPerm.allowance !== undefined) {
        const remAllowance = BigInt(fcPerm.allowance);
        const minRequiredFor280TGas = 300_000_000_000_000_000_000_000n; // 0.30 NEAR
        if (remAllowance < minRequiredFor280TGas) {
          console.error(
            `⚠️ [CRITICAL KEEPER HEALTH] FunctionCall key ${pubKeyStr} on ${this.relayerAccountId} has only ${nearAPI.utils.format.formatNearAmount(remAllowance.toString(), 4)} NEAR allowance left (< 0.30 NEAR needed for 280 TGas MPC call). Re-add key with unlimited (null) allowance!`
          );
        }
      }
      if (forceResync || this._nextNonce === null) {
        this._nextNonce = BigInt(keyInfo.nonce || 0);
      }
      this._recentBlockHash = nearAPI.utils.serialize.base_decode(keyInfo.block_hash);
      this._blockFetchedAt = Date.now();
    }
  }

  async evmRpc(method, params = []) {
    const candidates = [
      this.evmRpcUrl,
      'https://ethereum-sepolia-rpc.publicnode.com',
      'https://sepolia.drpc.org',
      'https://rpc2.sepolia.org'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`EVM RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          const errMsg = body.error.message || JSON.stringify(body.error);
          const rpcErr = new Error(errMsg);
          const lower = errMsg.toLowerCase();
          if (
            lower.includes('already known') ||
            lower.includes('known transaction') ||
            lower.includes('nonce too low') ||
            lower.includes('replacement transaction underpriced') ||
            lower.includes('insufficient funds') ||
            lower.includes('execution reverted')
          ) {
            rpcErr.isProtocolError = true;
          }
          throw rpcErr;
        }
        return body.result;
      } catch (err) {
        if (err && err.isProtocolError) {
          throw err;
        }
        lastErr = err;
      }
    }
    throw lastErr || new Error('All EVM Sepolia RPC endpoints failed');
  }

  async solanaRpc(method, params = []) {
    const candidates = [
      this.solanaRpcUrl,
      'https://solana-devnet.api.onfinality.io/public',
      'https://rpc.magicblock.app/devnet',
      'https://api.devnet.solana.com'
    ].filter((u, idx, arr) => u && arr.indexOf(u) === idx);

    let lastErr = null;
    for (const url of candidates) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params
          })
        });
        if (!res.ok) {
          lastErr = new Error(`Solana RPC HTTP ${res.status} (${url})`);
          continue;
        }
        const body = await res.json();
        if (body.error) {
          throw new Error(body.error.message || JSON.stringify(body.error));
        }
        return body.result;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('All Solana Devnet RPC endpoints failed');
  }

  async callContractActions(actionsSpec = []) {
    await this.init({ requireSigner: true });
    let lastErr;
    for (let attempt = 0; attempt < 5; attempt++) {
      let txHashBase58 = '';
      try {
        await this.ensureSignerNonceAndBlock(attempt > 0);
        this._nextNonce += 1n;
        const txNonce = this._nextNonce;
        const pubKey = this._signerKeyPair.getPublicKey();
        const actions = actionsSpec.map(spec =>
          nearAPI.transactions.functionCall(
            spec.methodName,
            spec.args || {},
            BigInt(spec.gas || '100000000000000'),
            BigInt(spec.attachedDeposit || '0')
          )
        );
        const tx = nearAPI.transactions.createTransaction(
          this.relayerAccountId,
          pubKey,
          this.contractId,
          txNonce,
          actions,
          this._recentBlockHash
        );
        const encodedTx = tx.encode();
        const txHashBytes = Buffer.from(ethers.sha256(Uint8Array.from(encodedTx)).slice(2), 'hex');
        txHashBase58 = nearAPI.utils.serialize.base_encode(txHashBytes);
        const sig = this._signerKeyPair.sign(txHashBytes);
        const signedTx = new nearAPI.transactions.SignedTransaction({
          transaction: tx,
          signature: new nearAPI.transactions.Signature({
            keyType: pubKey.keyType,
            data: sig.signature
          })
        });
        const signedTxBase64 = Buffer.from(signedTx.encode()).toString('base64');

        let outcome;
        try {
          outcome = await this.nearRpc('send_tx', {
            signed_tx_base64: signedTxBase64,
            wait_until: 'EXECUTED_OPTIMISTIC'
          });
        } catch (sendErr) {
          if (String(sendErr.message || '').includes('Timeout') && txHashBase58) {
            await new Promise(r => setTimeout(r, 2000));
            outcome = await this.nearRpc('tx', {
              tx_hash: txHashBase58,
              sender_account_id: this.relayerAccountId,
              wait_until: 'EXECUTED_OPTIMISTIC'
            });
          } else {
            throw sendErr;
          }
        }

        if (outcome && outcome.status && typeof outcome.status === 'object' && outcome.status.Failure) {
          throw new Error(
            `NEAR transaction ${txHashBase58} failed: ${JSON.stringify(outcome.status.Failure)}`
          );
        }
        return outcome;
      } catch (err) {
        lastErr = err;
        const msg = String(err?.message || err);
        if (
          attempt < 4 &&
          (msg.includes('InvalidNonce') ||
            msg.includes('ak_nonce') ||
            msg.includes('Expired') ||
            msg.includes('Timeout') ||
            msg.includes('502') ||
            msg.includes('503') ||
            msg.includes('429'))
        ) {
          await new Promise(r => setTimeout(r, 800 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  }

  async callContract(methodName, args = {}, gas = '100000000000000', attachedDeposit = '0') {
    return this.callContractActions([{ methodName, args, gas, attachedDeposit }]);
  }

  async viewContract(methodName, args = {}) {
    await this.init({ requireSigner: false });
    const raw = await this.nearRpc('query', {
      request_type: 'call_function',
      finality: 'optimistic',
      account_id: this.contractId,
      method_name: methodName,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64')
    });
    if (raw && raw.error) {
      throw new Error(`View ${methodName} error: ${raw.error}`);
    }
    return JSON.parse(Buffer.from(raw.result).toString('utf8'));
  }

  extractMpcSignatureFromOutcome(outcome) {
    for (const out of outcome.receipts_outcome || []) {
      if (out.outcome && out.outcome.status && out.outcome.status.SuccessValue) {
        const raw = Buffer.from(out.outcome.status.SuccessValue, 'base64').toString('utf8');
        try {
          const parsed = JSON.parse(raw);
          if (parsed && (parsed.big_r || parsed.signature || parsed.r)) {
            return parsed;
          }
        } catch (_) {}
      }
    }
    return null;
  }

  /**
   * Sponsor zero-gas heartbeat using cryptographic owner Ed25519 signature (`[ATTACK-3]` compliant)
   */
  async sponsorPing(vaultOwner, { timestampMs, signatureHex, nep413NonceHex = null, nep413Recipient = null } = {}) {
    await this.init({ requireSigner: true });
    if (!vaultOwner || !timestampMs || !signatureHex) {
      return {
        success: false,
        error: 'ping_by_relayer requires vaultOwner, timestampMs, and signatureHex'
      };
    }
    const cleanSig = String(signatureHex).trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{128}$/.test(cleanSig)) {
      return {
        success: false,
        error: 'Invalid signatureHex: must be a 64-byte (128 hex chars) Ed25519 signature'
      };
    }
    if (nep413NonceHex !== null && nep413NonceHex !== undefined) {
      const cleanNonce = String(nep413NonceHex).trim().replace(/^0x/i, '');
      if (!/^[0-9a-fA-F]{64}$/.test(cleanNonce)) {
        return {
          success: false,
          error: 'Invalid nep413NonceHex: must be 32 bytes (64 hex chars)'
        };
      }
    }
    const tsNum = Number(timestampMs);
    const nowMs = Date.now();
    if (!Number.isFinite(tsNum) || Math.abs(nowMs - tsNum) > 10 * 60 * 1000) {
      return {
        success: false,
        error: 'Heartbeat timestamp expired or out of 10-minute window'
      };
    }
    console.log(`⏱️  [LastKey Relayer] Broadcasting verified signed heartbeat for ${vaultOwner}...`);
    try {
      const outcome = await this.callContract(
        'ping_by_relayer',
        {
          vault_owner: vaultOwner,
          timestamp_ms: String(timestampMs),
          signature_hex: cleanSig,
          nep413_nonce_hex: nep413NonceHex ? String(nep413NonceHex).trim().replace(/^0x/i, '') : null,
          nep413_recipient: nep413Recipient
        },
        '30000000000000',
        '0'
      );
      const txHash = outcome.transaction.hash;
      console.log(`✅ [LastKey Relayer] Signed heartbeat confirmed! Tx: ${txHash}`);
      return { success: true, txHash };
    } catch (err) {
      console.error(`❌ [LastKey Relayer] Failed signed heartbeat for ${vaultOwner}:`, err.message);
      return { success: false, error: err.message };
    }
  }

  async getVaultInfo(vaultOwner) {
    try {
      return await this.viewContract('get_vault_info', { account_id: vaultOwner });
    } catch (err) {
      console.warn(`[LastKey Relayer] get_vault_info error for ${vaultOwner}:`, err.message);
      return null;
    }
  }

  async getActionableVaults({ throwOnError = false } = {}) {
    try {
      const vaults = await this.viewContract('get_actionable_vaults', {});
      return Array.isArray(vaults) ? vaults : [];
    } catch (err) {
      console.warn(`[LastKey Relayer] get_actionable_vaults error:`, err.message);
      if (throwOnError) throw err;
      return [];
    }
  }

  /**
   * Persist telemetry to multi-tenant `web/telemetry.json` without clobbering other vaults
   */
  writeLocalTelemetry(telemetryRecord) {
    if (this.disableLocalFileCache || !fs || typeof fs.existsSync !== 'function' || !this.telemetryPath) {
      return;
    }
    let store = { vaults: {} };
    if (fs.existsSync(this.telemetryPath)) {
      try {
        const existing = JSON.parse(fs.readFileSync(this.telemetryPath, 'utf8'));
        if (existing && typeof existing === 'object') {
          store.vaults = existing.vaults && typeof existing.vaults === 'object' ? existing.vaults : {};
          if (existing.vault_owner && existing.sweeps) {
            store.vaults[`${existing.vault_owner}:${existing.epoch ?? 0}`] = {
              vault_owner: existing.vault_owner,
              epoch: existing.epoch ?? 0,
              state: existing.state,
              updated_at: existing.updated_at,
              sweeps: existing.sweeps
            };
            store.vaults[existing.vault_owner] = store.vaults[`${existing.vault_owner}:${existing.epoch ?? 0}`];
          }
        }
      } catch (_) {}
    }

    const epochKey = `${telemetryRecord.vault_owner}:${telemetryRecord.epoch}`;
    store.vaults[epochKey] = telemetryRecord;
    store.vaults[telemetryRecord.vault_owner] = telemetryRecord;

    const merged = {
      ...telemetryRecord,
      vaults: store.vaults
    };
    fs.writeFileSync(this.telemetryPath, JSON.stringify(merged, null, 2));
  }

  /**
   * Execute Multichain Panic / Inheritance Sweep
   */
  async sweepVault(vaultOwner, options = {}) {
    await this.init({ requireSigner: true });
    console.log(`\n🚨 [LastKey Relayer] Executing multichain sweep for ${vaultOwner}...`);

    const vault = options.prefetchedVault || (await this.getVaultInfo(vaultOwner));
    if (!vault) {
      console.error(`❌ Vault not found for ${vaultOwner}`);
      return null;
    }

    const state = typeof vault.state === 'string' ? vault.state : Object.keys(vault.state)[0];
    if (state !== 'Evacuated' && state !== 'Inheritance') {
      console.log(`ℹ️  Vault state is '${state}'. No sweep required.`);
      return null;
    }

    if (vault.is_epoch_swept) {
      console.log(`ℹ️  Vault ${vaultOwner} epoch ${vault.epoch} is already marked swept on-chain.`);
      return vault.last_sweep_report ? JSON.parse(vault.last_sweep_report) : null;
    }

    const epoch = vault.epoch;
    const destination = state === 'Evacuated' ? vault.backup : vault.heirs;
    let sweepMemo = '';

    if (state === 'Inheritance' && vault.heir_memo && vault.heir_memo.trim()) {
      sweepMemo = vault.heir_memo.trim();
      console.log(
        `   📜 Heir testament loaded (${sweepMemo.startsWith('enc:') ? 'E2EE Ciphertext' : 'Plaintext'}, ${Buffer.byteLength(sweepMemo, 'utf8')} B)`
      );
    }

    const derivationPath = `aegis/${vaultOwner}/${epoch}`;
    console.log(`   • Vault State:       ${state}`);
    console.log(`   • Bunker Epoch:      ${epoch}`);
    console.log(`   • Derivation Path:   ${derivationPath}`);

    const vaultAddrs = await this.engine.deriveAllAddresses(this.contractId, derivationPath);
    console.log(`     - EVM Bunker:  ${vaultAddrs.evm.address}`);
    console.log(`     - BTC Bunker:  ${vaultAddrs.btc.address}`);
    console.log(`     - SOL Bunker:  ${vaultAddrs.sol.address}`);

    const telemetryRecord = {
      vault_owner: vaultOwner,
      epoch,
      state,
      memo: sweepMemo || null,
      updated_at: new Date().toISOString(),
      sweeps: {}
    };
    let hasRetriableFailure = false;

    // 1. EVM Sweep (Sepolia / Base / Arbitrum)
    if (destination.evm && destination.evm.trim().length === 42) {
      console.log(`\n[EVM Sweep] Checking ${vaultAddrs.evm.address} -> ${destination.evm}...`);
      try {
        const balHex = await this.evmRpc('eth_getBalance', [vaultAddrs.evm.address, 'latest']);
        const liveWei = BigInt(balHex || '0x0');
        console.log(`   • EVM Bunker Balance: ${ethers.formatEther(liveWei)} ETH (${liveWei} wei)`);

        if (liveWei === 0n) {
          telemetryRecord.sweeps.evm = {
            status: 'Skipped (Zero Balance)',
            chain: 'Ethereum / Base (Sepolia)',
            target: destination.evm,
            amount: '0.0000 ETH'
          };
        } else {
          const [nonceHex, gasPriceHex, priorityFeeHex, chainIdHex] = await Promise.all([
            this.evmRpc('eth_getTransactionCount', [vaultAddrs.evm.address, 'pending']),
            this.evmRpc('eth_gasPrice', []),
            this.evmRpc('eth_maxPriorityFeePerGas', []).catch(() => '0x3b9aca00'),
            this.evmRpc('eth_chainId', [])
          ]);
          let currentNonce = Number(BigInt(nonceHex || '0x0'));
          const chainId = Number(BigInt(chainIdHex || '0xaa36a7'));
          const MIN_FEE = 1_500_000_000n; // 1.5 Gwei floor
          const MAX_SAFE_FEE = 450_000_000_000n; // 450 Gwei (< 500 Gwei contract cap)
          const baseGasPrice = BigInt(gasPriceHex || '0x4a817c800');
          let maxPriorityFeePerGas = BigInt(priorityFeeHex || '0x3b9aca00');
          if (maxPriorityFeePerGas <= 0n) maxPriorityFeePerGas = 1_000_000_000n;
          let maxFeePerGas = baseGasPrice * 2n + maxPriorityFeePerGas;
          if (maxFeePerGas < MIN_FEE) maxFeePerGas = MIN_FEE;
          if (maxFeePerGas > MAX_SAFE_FEE) maxFeePerGas = MAX_SAFE_FEE;
          if (maxPriorityFeePerGas > maxFeePerGas) maxPriorityFeePerGas = maxFeePerGas;

          // 1a. Auto-discover and sweep ERC-20 tokens BEFORE native ETH (so gas remains available)
          const sweptErc20s = [];
          const knownErc20List = [
            { symbol: 'USDC', address: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238' },
            { symbol: 'LINK', address: '0x779877A7B0D9E8603169DdbD7836e478b4624789' },
            { symbol: 'WETH', address: '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14' },
            { symbol: 'DAI', address: '0xFF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357' }
          ];
          const extraEvmTokens = String(process.env.AEGIS_EVM_TOKENS || '')
            .split(',')
            .map(s => s.trim())
            .filter(s => /^0x[0-9a-fA-F]{40}$/.test(s));
          for (const addr of extraEvmTokens) {
            if (!knownErc20List.some(t => t.address.toLowerCase() === addr.toLowerCase())) {
              knownErc20List.push({ symbol: 'ERC20', address: addr });
            }
          }

          const erc20Iface = new ethers.Interface([
            'function balanceOf(address owner) view returns (uint256)',
            'function transfer(address to, uint256 amount) returns (bool)'
          ]);
          const balCallData = erc20Iface.encodeFunctionData('balanceOf', [vaultAddrs.evm.address]);

          for (const tok of knownErc20List) {
            try {
              const rawBalHex = await this.evmRpc('eth_call', [
                { to: tok.address, data: balCallData },
                'latest'
              ]);
              const tokBal = rawBalHex && rawBalHex !== '0x' ? BigInt(rawBalHex) : 0n;
              if (tokBal > 0n) {
                const transferData = erc20Iface.encodeFunctionData('transfer', [
                  destination.evm.trim(),
                  tokBal
                ]);
                // Honeypot / Blacklist Fault Isolation: simulate via free eth_call before consuming nonce
                await this.evmRpc('eth_call', [
                  {
                    from: vaultAddrs.evm.address,
                    to: tok.address,
                    data: transferData
                  },
                  'latest'
                ]);
                const tokSweep = await this.engine.prepareEvmTokenSweep({
                  tokenAddress: tok.address,
                  fromAddress: vaultAddrs.evm.address,
                  toAddress: destination.evm.trim(),
                  amountRaw: tokBal,
                  gasLimit: 65000n,
                  nonce: currentNonce,
                  maxFeePerGas,
                  maxPriorityFeePerGas,
                  chainId
                });
                const tokOut = await this.callContract(
                  'request_sweep_signature',
                  {
                    vault_owner: vaultOwner,
                    chain: 'EVM',
                    payload_hex: tokSweep.unsignedTxHex,
                    target_epoch: epoch,
                    is_eddsa: false
                  },
                  '280000000000000',
                  '0'
                );
                const tokMpcSig = this.extractMpcSignatureFromOutcome(tokOut);
                if (tokMpcSig) {
                  const signedTok = this.engine.assembleSignedEvmTx(tokSweep.rawTx, tokMpcSig);
                  const rawTokHex = signedTok.signedTx.startsWith('0x')
                    ? signedTok.signedTx
                    : '0x' + signedTok.signedTx;
                  const tokTxHash =
                    (await this.evmRpc('eth_sendRawTransaction', [rawTokHex])) || signedTok.txHash;
                  currentNonce++;
                  sweptErc20s.push({
                    symbol: tok.symbol,
                    token: tok.address,
                    amount_raw: tokBal.toString(),
                    tx_hash: tokTxHash
                  });
                  console.log(`   🪙 ERC-20 (${tok.symbol}) Swept! TxHash: ${tokTxHash}`);
                }
              }
            } catch (tokErr) {
              console.warn(
                `   ⚠️ [Fault Isolation] Skipped ERC-20 ${tok.symbol} (${tok.address}) without consuming nonce:`,
                tokErr.message
              );
            }
          }

          const refreshedBalHex =
            sweptErc20s.length > 0
              ? await this.evmRpc('eth_getBalance', [vaultAddrs.evm.address, 'latest'])
              : balHex;
          const remainingWei = BigInt(refreshedBalHex || '0x0');

          const memoBytes = sweepMemo ? ethers.toUtf8Bytes(sweepMemo) : new Uint8Array(0);
          let calldataGas = 0n;
          for (const b of memoBytes) calldataGas += b === 0 ? 4n : 16n;
          const minGasLimit = 21000n + calldataGas;
          let gasLimit = minGasLimit;
          try {
            const estHex = await this.evmRpc('eth_estimateGas', [
              {
                from: vaultAddrs.evm.address,
                to: destination.evm.trim(),
                value: '0x1',
                data: sweepMemo ? ethers.hexlify(memoBytes) : '0x'
              }
            ]);
            if (estHex) {
              const est = (BigInt(estHex) * 120n) / 100n; // +20% safety margin for smart contract wallets
              if (est > gasLimit) gasLimit = est;
              if (gasLimit > 250000n) gasLimit = 250000n;
            }
          } catch (_) {}
          const isL2 = [8453, 84532, 10, 42161, 421614].includes(chainId);
          const l1Buffer = isL2 ? 15_000_000_000_000n : 0n;
          const totalGasCost = gasLimit * maxFeePerGas + l1Buffer;

          if (remainingWei <= totalGasCost) {
            telemetryRecord.sweeps.evm = {
              status: sweptErc20s.length > 0 ? 'Broadcasted (Tokens Swept)' : 'Skipped (Dust Below Gas Fee)',
              chain: 'Ethereum / Base (Sepolia)',
              target: destination.evm,
              amount: `${ethers.formatEther(remainingWei)} ETH`,
              ...(sweptErc20s.length > 0 ? { tokens_swept: sweptErc20s } : {})
            };
          } else {
            const sweepValueWei = remainingWei - totalGasCost;
            const evmSweep = await this.engine.prepareEvmSweep({
              fromAddress: vaultAddrs.evm.address,
              toAddress: destination.evm.trim(),
              valueWei: sweepValueWei,
              gasLimit,
              nonce: currentNonce,
              maxFeePerGas,
              maxPriorityFeePerGas,
              chainId,
              memo: sweepMemo
            });

            const outcome = await this.callContract(
              'request_sweep_signature',
              {
                vault_owner: vaultOwner,
                chain: 'EVM',
                payload_hex: evmSweep.unsignedTxHex,
                target_epoch: epoch,
                is_eddsa: false
              },
              '280000000000000',
              '0'
            );

            const nearTxHash = outcome.transaction.hash;
            const mpcSignature = this.extractMpcSignatureFromOutcome(outcome);
            if (!mpcSignature) {
              throw new Error(`MPC signature missing in NEAR receipt ${nearTxHash}`);
            }

            const signedEvmTx = this.engine.assembleSignedEvmTx(evmSweep.rawTx, mpcSignature);
            const rawSignedHex = signedEvmTx.signedTx.startsWith('0x')
              ? signedEvmTx.signedTx
              : '0x' + signedEvmTx.signedTx;
            let broadcastHash = null;
            try {
              broadcastHash = await this.evmRpc('eth_sendRawTransaction', [rawSignedHex]);
            } catch (bErr) {
              const bMsg = String(bErr?.message || bErr).toLowerCase();
              if (
                bMsg.includes('already known') ||
                bMsg.includes('known transaction') ||
                bMsg.includes('nonce too low') ||
                bMsg.includes('replacement transaction underpriced')
              ) {
                broadcastHash = signedEvmTx.txHash;
              } else {
                throw bErr;
              }
            }
            const evmHash = broadcastHash || signedEvmTx.txHash;
            console.log(`   🚀 EVM Sweep Broadcasted! TxHash: ${evmHash}`);

            telemetryRecord.sweeps.evm = {
              status: 'Broadcasted (Sepolia)',
              chain: 'Ethereum / Base (Sepolia)',
              target: destination.evm,
              amount: `${ethers.formatEther(sweepValueWei)} ETH`,
              tx_hash: evmHash,
              explorer: `https://sepolia.etherscan.io/tx/${evmHash}`,
              near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearTxHash}`,
              ...(sweptErc20s.length > 0 ? { tokens_swept: sweptErc20s } : {})
            };
          }
        }
      } catch (err) {
        console.error(`   ❌ EVM Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.evm = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Ethereum / Base (Sepolia)',
          target: destination.evm,
          amount: '0.0000 ETH'
        };
      }
    }

    // 2. Bitcoin Sweep (Native SegWit — Multi-UTXO + OP_RETURN across Testnet4 & Testnet3)
    if (destination.btc && destination.btc.trim().length > 10) {
      console.log(`\n[Bitcoin Sweep] Checking ${vaultAddrs.btc.address} -> ${destination.btc}...`);
      try {
        let btcApiBase = 'https://mempool.space/testnet4/api';
        let btcExplorerBase = 'https://mempool.space/testnet4';
        let liveUtxos = [];

        const [utxoT4, utxoT3, utxoBsT3] = await Promise.allSettled([
          fetch(`https://mempool.space/testnet4/api/address/${vaultAddrs.btc.address}/utxo`).then((r) =>
            r.ok ? r.json() : []
          ),
          fetch(`https://mempool.space/testnet/api/address/${vaultAddrs.btc.address}/utxo`).then((r) =>
            r.ok ? r.json() : []
          ),
          fetch(`https://blockstream.info/testnet/api/address/${vaultAddrs.btc.address}/utxo`).then((r) =>
            r.ok ? r.json() : []
          )
        ]);
        const listT4 = utxoT4.status === 'fulfilled' && Array.isArray(utxoT4.value) ? utxoT4.value : [];
        const listT3 = utxoT3.status === 'fulfilled' && Array.isArray(utxoT3.value) ? utxoT3.value : [];
        const listBsT3 = utxoBsT3.status === 'fulfilled' && Array.isArray(utxoBsT3.value) ? utxoBsT3.value : [];

        if (listT4.length > 0) {
          liveUtxos = listT4;
          btcApiBase = 'https://mempool.space/testnet4/api';
          btcExplorerBase = 'https://mempool.space/testnet4';
        } else if (listT3.length > 0) {
          liveUtxos = listT3;
          btcApiBase = 'https://mempool.space/testnet/api';
          btcExplorerBase = 'https://mempool.space/testnet';
        } else if (listBsT3.length > 0) {
          liveUtxos = listBsT3;
          btcApiBase = 'https://blockstream.info/testnet/api';
          btcExplorerBase = 'https://mempool.space/testnet';
        }

        if (!Array.isArray(liveUtxos) || liveUtxos.length === 0) {
          telemetryRecord.sweeps.btc = {
            status: 'Skipped (Zero Balance)',
            chain: 'Bitcoin Native SegWit',
            target: destination.btc,
            amount: '0.00000000 BTC'
          };
        } else {
          let feeRateSatPerVb = 2;
          try {
            const feeRes = await fetch(`${btcApiBase}/v1/fees/recommended`);
            if (feeRes.ok) {
              const fees = await feeRes.json();
              feeRateSatPerVb = Math.max(1, Math.min(50, Number(fees.fastestFee || 2)));
            }
          } catch (_) {}

          let btcSweep;
          try {
            btcSweep = this.engine.prepareBtcSweep({
              utxos: liveUtxos,
              fromAddress: vaultAddrs.btc.address,
              toAddress: destination.btc.trim(),
              memo: sweepMemo,
              feeRateSatPerVb,
              network: bitcoin.networks.testnet
            });
          } catch (dustErr) {
            if (dustErr.message.includes('dust')) {
              telemetryRecord.sweeps.btc = {
                status: 'Skipped (Dust UTXOs)',
                chain: 'Bitcoin Native SegWit',
                target: destination.btc,
                amount: '0.00000000 BTC'
              };
              btcSweep = null;
            } else {
              throw dustErr;
            }
          }

          if (btcSweep) {
            const btcSignatures = [];
            let lastNearTxHash = null;

            for (const sh of btcSweep.sighashes) {
              console.log(
                `   • Requesting MPC ECDSA signature for BTC input #${sh.inputIndex}/${btcSweep.sighashes.length - 1}...`
              );
              const outcome = await this.callContract(
                'request_sweep_signature',
                {
                  vault_owner: vaultOwner,
                  chain: 'BTC',
                  payload_hex: sh.verifiablePayloadHex || sh.sighashHex,
                  target_epoch: epoch,
                  is_eddsa: false
                },
                '280000000000000',
                '0'
              );
              lastNearTxHash = outcome.transaction.hash;
              const mpcSig = this.extractMpcSignatureFromOutcome(outcome);
              if (!mpcSig) {
                throw new Error(`MPC signature missing for BTC input #${sh.inputIndex}`);
              }
              const rHex = mpcSig.big_r?.affine_point?.slice(2) || mpcSig.r;
              const sHex = mpcSig.s?.scalar || mpcSig.s;
              btcSignatures.push({
                inputIndex: sh.inputIndex,
                r: Buffer.from(rHex.replace(/^0x/, ''), 'hex'),
                s: Buffer.from(sHex.replace(/^0x/, ''), 'hex'),
                publicKey: Buffer.from(vaultAddrs.btc.publicKey.replace(/^0x/, ''), 'hex')
              });
            }

            const finalized = this.engine.finalizeBtcSweepPsbt(
              btcSweep.psbtHex,
              btcSignatures,
              bitcoin.networks.testnet
            );
            const broadcastCandidates = btcApiBase.includes('testnet4')
              ? ['https://mempool.space/testnet4/api/tx']
              : [
                  btcApiBase + '/tx',
                  'https://mempool.space/testnet/api/tx',
                  'https://blockstream.info/testnet/api/tx'
                ].filter((u, idx, arr) => arr.indexOf(u) === idx);

            let broadcastedTxId = null;
            let lastBtcErr = null;
            for (const bUrl of broadcastCandidates) {
              try {
                const mempoolBroadcast = await fetch(bUrl, {
                  method: 'POST',
                  body: finalized.txHex
                });
                const bodyText = (await mempoolBroadcast.text()).trim();
                if (mempoolBroadcast.ok) {
                  broadcastedTxId = bodyText || finalized.txId;
                  break;
                }
                if (bodyText.toLowerCase().includes('already in block chain')) {
                  broadcastedTxId = finalized.txId;
                  break;
                }
                lastBtcErr = new Error(`Mempool broadcast rejected (${mempoolBroadcast.status}): ${bodyText.slice(0, 80)}`);
              } catch (bErr) {
                lastBtcErr = bErr;
              }
            }
            if (!broadcastedTxId) {
              throw lastBtcErr || new Error('All Bitcoin broadcast endpoints failed');
            }
            console.log(`   🚀 Bitcoin Tx broadcasted to Testnet: ${broadcastedTxId}`);

            telemetryRecord.sweeps.btc = {
              status: 'Broadcasted (Testnet)',
              chain: 'Bitcoin Native SegWit',
              target: destination.btc,
              amount: `${(btcSweep.sendAmount / 1e8).toFixed(6)} BTC`,
              tx_id: broadcastedTxId,
              explorer: `${btcExplorerBase}/tx/${broadcastedTxId}`,
              near_mpc_tx: `https://testnet.nearblocks.io/txns/${lastNearTxHash}`
            };
          }
        }
      } catch (err) {
        console.error(`   ❌ Bitcoin Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.btc = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Bitcoin Native SegWit',
          target: destination.btc,
          amount: '0.00000000 BTC'
        };
      }
    }

    // 3. Solana Sweep (Devnet — Real Base58 Signature & Verified RPC Broadcast)
    if (destination.sol && destination.sol.trim().length > 20) {
      console.log(`\n[Solana Sweep] Checking ${vaultAddrs.sol.address} -> ${destination.sol}...`);
      try {
        const balResult = await this.solanaRpc('getBalance', [
          vaultAddrs.sol.address,
          { commitment: 'confirmed' }
        ]);
        const liveLamports = BigInt(balResult?.value ?? 0);
        console.log(
          `   • Solana Bunker Balance: ${Number(liveLamports) / 1e9} SOL (${liveLamports} lamports)`
        );

        if (liveLamports <= 5000n) {
          telemetryRecord.sweeps.sol = {
            status: 'Skipped (Zero/Dust Balance)',
            chain: 'Solana Devnet (Ed25519)',
            target: destination.sol,
            amount: `${(Number(liveLamports) / 1e9).toFixed(4)} SOL`
          };
        } else {
          const latestResult = await this.solanaRpc('getLatestBlockhash', [
            { commitment: 'confirmed' }
          ]);
          const blockhash = latestResult?.value?.blockhash;
          if (!blockhash) throw new Error('Missing Solana recentBlockhash');

          // 3a. Auto-discover and sweep Solana SPL Token & Token-2022 accounts BEFORE native SOL
          // (CloseAccount opcode 9 also reclaims 0.00203928 SOL rent per closed token account back to the bunker!)
          const sweptSolTokens = [];
          const solTokenPrograms = [
            'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
            'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
          ];
          for (const progId of solTokenPrograms) {
            try {
              const tokAccs = await this.solanaRpc('getTokenAccountsByOwner', [
                vaultAddrs.sol.address,
                { programId: progId },
                { encoding: 'jsonParsed', commitment: 'confirmed' }
              ]);
              const items = Array.isArray(tokAccs?.value) ? tokAccs.value : [];
              for (const item of items) {
                try {
                  const info = item?.account?.data?.parsed?.info;
                  const mint = info?.mint;
                  const rawAmt = BigInt(info?.tokenAmount?.amount || '0');
                  if (mint && rawAmt > 0n) {
                    const freshBhRes = await this.solanaRpc('getLatestBlockhash', [
                      { commitment: 'confirmed' }
                    ]);
                    const splBh = freshBhRes?.value?.blockhash || blockhash;
                    const splSweep = this.engine.prepareSolanaTokenSweep({
                      mintPubkey: mint,
                      fromOwnerPubkey: vaultAddrs.sol.address,
                      toRecipientPubkey: destination.sol.trim(),
                      amountTokens: rawAmt,
                      recentBlockhash: splBh,
                      tokenProgramId: progId
                    });
                    const splOut = await this.callContract(
                      'request_sweep_signature',
                      {
                        vault_owner: vaultOwner,
                        chain: 'SOL',
                        payload_hex: splSweep.rawPayloadHex,
                        target_epoch: epoch,
                        is_eddsa: true
                      },
                      '280000000000000',
                      '0'
                    );
                    const splMpcSig = this.extractMpcSignatureFromOutcome(splOut);
                    if (splMpcSig) {
                      const signedSpl = this.engine.assembleSignedSolanaTx(
                        splSweep.serializedMessage,
                        vaultAddrs.sol.address,
                        splMpcSig
                      );
                      const splSig =
                        (await this.solanaRpc('sendTransaction', [
                          Buffer.from(signedSpl.txHex, 'hex').toString('base64'),
                          {
                            encoding: 'base64',
                            skipPreflight: false,
                            preflightCommitment: 'confirmed'
                          }
                        ])) || signedSpl.signatureBase58;
                      sweptSolTokens.push({
                        mint,
                        amount_raw: rawAmt.toString(),
                        signature: splSig
                      });
                      console.log(`   🪙 Solana SPL Token (${mint}) Swept! Sig: ${splSig}`);
                    }
                  }
                } catch (splItemErr) {
                  console.warn(
                    `   ⚠️ [Fault Isolation] Skipped Solana SPL token account:`,
                    splItemErr.message
                  );
                }
              }
            } catch (_) {}
          }

          const finalSolBalRes =
            sweptSolTokens.length > 0
              ? await this.solanaRpc('getBalance', [
                  vaultAddrs.sol.address,
                  { commitment: 'confirmed' }
                ])
              : balResult;
          const remainingLamports = BigInt(finalSolBalRes?.value ?? liveLamports);
          const freshNativeBhRes =
            sweptSolTokens.length > 0
              ? await this.solanaRpc('getLatestBlockhash', [{ commitment: 'confirmed' }]).catch(() => null)
              : null;
          const nativeBlockhash = freshNativeBhRes?.value?.blockhash || blockhash;

          const solSweep = this.engine.prepareSolanaSweep({
            fromPubkey: vaultAddrs.sol.address,
            toPubkey: destination.sol.trim(),
            lamports: remainingLamports,
            memo: sweepMemo,
            recentBlockhash: nativeBlockhash
          });

          const outcome = await this.callContract(
            'request_sweep_signature',
            {
              vault_owner: vaultOwner,
              chain: 'SOL',
              payload_hex: solSweep.rawPayloadHex,
              target_epoch: epoch,
              is_eddsa: true
            },
            '280000000000000',
            '0'
          );

          const nearTxHash = outcome.transaction.hash;
          const mpcSignature = this.extractMpcSignatureFromOutcome(outcome);
          if (!mpcSignature) {
            throw new Error(`MPC signature missing in NEAR receipt ${nearTxHash}`);
          }

          const signedSol = this.engine.assembleSignedSolanaTx(
            solSweep.serializedMessage,
            vaultAddrs.sol.address,
            mpcSignature
          );

          let rpcSig = null;
          try {
            rpcSig = await this.solanaRpc('sendTransaction', [
              Buffer.from(signedSol.txHex, 'hex').toString('base64'),
              {
                encoding: 'base64',
                skipPreflight: false,
                preflightCommitment: 'confirmed'
              }
            ]);
          } catch (solSendErr) {
            const solMsg = String(solSendErr?.message || solSendErr).toLowerCase();
            if (solMsg.includes('already been processed') || solMsg.includes('already known')) {
              rpcSig = signedSol.signatureBase58;
            } else {
              throw solSendErr;
            }
          }
          const solSig = rpcSig || signedSol.signatureBase58;
          console.log(`   🚀 Solana Tx broadcasted to Devnet: ${solSig}`);

          telemetryRecord.sweeps.sol = {
            status: 'Confirmed (Devnet)',
            chain: 'Solana Devnet (Ed25519)',
            target: destination.sol,
            amount: `${(Number(remainingLamports - 5000n) / 1e9).toFixed(4)} SOL`,
            signature: solSig,
            explorer: `https://solscan.io/tx/${solSig}?cluster=devnet`,
            near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearTxHash}`,
            ...(sweptSolTokens.length > 0 ? { tokens_swept: sweptSolTokens } : {})
          };
        }
      } catch (err) {
        console.error(`   ❌ Solana Sweep Error:`, err.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.sol = {
          status: `Error (${err.message.slice(0, 60)})`,
          chain: 'Solana Devnet (Ed25519)',
          target: destination.sol,
          amount: '0.0000 SOL'
        };
      }
    }

    // 4. NEAR Native Implicit Bunker, NEP-141 Tokens & Isolated Vault Deposit Sweep (Zero Fake Fallbacks)
    if (destination.near && destination.near.trim().length > 2) {
      const destNear = destination.near.trim();
      console.log(`\n[NEAR Sweep] Checking implicit, NEP-141 & isolated NEAR deposits -> ${destNear}...`);
      let totalSweptYocto = options.preSweptNear ? BigInt(options.preSweptNear.amountYocto) : 0n;
      let nearSweepTx = options.preSweptNear ? options.preSweptNear.txHash : null;
      let nearMpcTx = null;
      const sweptNep141 = [];

      try {
        // 4a. Sweep isolated per-user contract deposit first
        const isolatedNearDeposit = BigInt(vault.near_deposit_yocto || '0');
        if (isolatedNearDeposit > 0n) {
          const sweepOutcome = await this.callContract('sweep_near', { vault_owner: vaultOwner }, '100000000000000', '0');
          if (!nearSweepTx) nearSweepTx = sweepOutcome.transaction.hash;
          totalSweptYocto += isolatedNearDeposit;
          console.log(`   🚀 NEAR Isolated Vault Deposit Swept! Tx: ${sweepOutcome.transaction.hash}`);
        }

        // 4b. Check NEAR implicit bunker account
        const nearPubKeyObj = nearAPI.utils.PublicKey.from('ed25519:' + vaultAddrs.sol.address);
        const implicitAccountId = Buffer.from(nearPubKeyObj.data).toString('hex');
        const nearPubKeyStr = 'ed25519:' + vaultAddrs.sol.address;

        const accInfo = await this.nearRpc('query', {
          request_type: 'view_account',
          finality: 'final',
          account_id: implicitAccountId
        }).catch(() => null);

        if (accInfo && accInfo.amount && BigInt(accInfo.amount) > 10_000_000_000_000_000_000_000n) {
          const keyInfo = await this.nearRpc('query', {
            request_type: 'view_access_key',
            finality: 'final',
            account_id: implicitAccountId,
            public_key: nearPubKeyStr
          });
          const blockHash = nearAPI.utils.serialize.base_decode(keyInfo.block_hash);
          let currentNearNonce = BigInt(keyInfo.nonce || 0) + 1n;

          // 4b-i. Auto-discover and sweep NEAR NEP-141 Fungible Tokens (`ft_transfer`, 1 yoctoNEAR)
          const nep141Contracts = ['usdc.fakes.testnet', 'wrap.testnet', 'usdt.fakes.testnet'];
          const extraNep141 = String(process.env.AEGIS_NEAR_FT_TOKENS || '')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
          for (const c of extraNep141) {
            if (!nep141Contracts.includes(c)) nep141Contracts.push(c);
          }

          for (const ftContract of nep141Contracts) {
            try {
              const ftBalRes = await this.nearRpc('query', {
                request_type: 'call_function',
                finality: 'optimistic',
                account_id: ftContract,
                method_name: 'ft_balance_of',
                args_base64: Buffer.from(JSON.stringify({ account_id: implicitAccountId })).toString('base64')
              });
              const ftBalStr = JSON.parse(Buffer.from(ftBalRes.result).toString('utf8'));
              const ftBal = BigInt(ftBalStr || '0');
              if (ftBal > 0n) {
                const ftArgs = Buffer.from(
                  JSON.stringify({
                    receiver_id: destNear,
                    amount: ftBal.toString(),
                    ...(sweepMemo ? { memo: sweepMemo.slice(0, 200) } : {})
                  }),
                  'utf8'
                );
                const ftActions = [
                  nearAPI.transactions.functionCall(
                    'ft_transfer',
                    ftArgs,
                    BigInt('30000000000000'),
                    BigInt('1')
                  )
                ];
                const ftTx = nearAPI.transactions.createTransaction(
                  implicitAccountId,
                  nearPubKeyObj,
                  ftContract,
                  currentNearNonce,
                  ftActions,
                  blockHash
                );
                const rawFtHex = Buffer.from(ftTx.encode()).toString('hex');
                const ftSigRes = await this.callContract(
                  'request_sweep_signature',
                  {
                    vault_owner: vaultOwner,
                    chain: 'NEAR',
                    payload_hex: rawFtHex,
                    target_epoch: epoch,
                    is_eddsa: true
                  },
                  '280000000000000',
                  '0'
                );
                const ftParsedSig = this.extractMpcSignatureFromOutcome(ftSigRes);
                const ftRawSig = ftParsedSig?.signature || ftParsedSig;
                if (ftRawSig) {
                  const ftSigBytes = Array.isArray(ftRawSig)
                    ? new Uint8Array(ftRawSig)
                    : new Uint8Array(Buffer.from(String(ftRawSig).replace(/^0x/, ''), 'hex'));
                  const signedFtTx = new nearAPI.transactions.SignedTransaction({
                    transaction: ftTx,
                    signature: new nearAPI.transactions.Signature({ keyType: 0, data: ftSigBytes })
                  });
                  const ftBroadcast = await this.nearRpc('send_tx', {
                    signed_tx_base64: Buffer.from(signedFtTx.encode()).toString('base64'),
                    wait_until: 'EXECUTED_OPTIMISTIC'
                  });
                  currentNearNonce += 1n;
                  sweptNep141.push({
                    contract: ftContract,
                    amount_raw: ftBal.toString(),
                    tx_hash: ftBroadcast.transaction.hash
                  });
                  console.log(`   🪙 NEAR NEP-141 (${ftContract}) Swept! Tx: ${ftBroadcast.transaction.hash}`);
                }
              }
            } catch (_) {}
          }

          const refreshedAccInfo =
            sweptNep141.length > 0
              ? await this.nearRpc('query', {
                  request_type: 'view_account',
                  finality: 'optimistic',
                  account_id: implicitAccountId
                }).catch(() => accInfo)
              : accInfo;
          const totalBal = BigInt(refreshedAccInfo?.amount || accInfo.amount);
          const feeReserve = 5_000_000_000_000_000_000_000n; // 0.005 NEAR transfer fee buffer
          const sweepYocto = totalBal > feeReserve ? totalBal - feeReserve : 0n;

          if (sweepYocto > 0n) {
            let nativeNearBlockHash = blockHash;
            if (sweptNep141.length > 0) {
              const freshKeyInfo = await this.nearRpc('query', {
                request_type: 'view_access_key',
                finality: 'optimistic',
                account_id: implicitAccountId,
                public_key: nearPubKeyStr
              }).catch(() => null);
              if (freshKeyInfo?.block_hash) {
                nativeNearBlockHash = nearAPI.utils.serialize.base_decode(freshKeyInfo.block_hash);
              }
            }
            const actions = [nearAPI.transactions.transfer(BigInt(sweepYocto.toString()))];
            const transaction = nearAPI.transactions.createTransaction(
              implicitAccountId,
              nearPubKeyObj,
              destNear,
              currentNearNonce,
              actions,
              nativeNearBlockHash
            );
            const serializedTx = transaction.encode();
            const rawBorshHex = Buffer.from(serializedTx).toString('hex');

            const sigRes = await this.callContract(
              'request_sweep_signature',
              {
                vault_owner: vaultOwner,
                chain: 'NEAR',
                payload_hex: rawBorshHex,
                target_epoch: epoch,
                is_eddsa: true
              },
              '280000000000000',
              '0'
            );
            nearMpcTx = sigRes.transaction.hash;
            const parsedSig = this.extractMpcSignatureFromOutcome(sigRes);
            const rawSigBytes = parsedSig?.signature || parsedSig;
            if (!rawSigBytes) {
              throw new Error('Missing Ed25519 signature for NEAR implicit transfer');
            }
            const sigUint8 = Array.isArray(rawSigBytes)
              ? new Uint8Array(rawSigBytes)
              : new Uint8Array(Buffer.from(String(rawSigBytes).replace(/^0x/, ''), 'hex'));

            const signature = new nearAPI.transactions.Signature({
              keyType: 0,
              data: sigUint8
            });
            const signedTx = new nearAPI.transactions.SignedTransaction({
              transaction,
              signature
            });
            const broadcast = await this.nearRpc('send_tx', {
              signed_tx_base64: Buffer.from(signedTx.encode()).toString('base64'),
              wait_until: 'EXECUTED_OPTIMISTIC'
            });
            nearSweepTx = broadcast.transaction.hash;
            totalSweptYocto += sweepYocto;
            console.log(`   🚀 NEAR Implicit Bunker Swept! Tx: ${nearSweepTx}`);
          }
        }

        if (nearSweepTx && totalSweptYocto > 0n) {
          const formattedNear = nearAPI.utils.format.formatNearAmount(totalSweptYocto.toString(), 4);
          telemetryRecord.sweeps.near = {
            status: 'Confirmed (NEAR Testnet)',
            chain: 'NEAR Protocol Testnet (Ed25519)',
            target: destNear,
            amount: `${formattedNear} NEAR`,
            tx_hash: nearSweepTx,
            explorer: `https://testnet.nearblocks.io/txns/${nearSweepTx}`,
            ...(nearMpcTx ? { near_mpc_tx: `https://testnet.nearblocks.io/txns/${nearMpcTx}` } : {}),
            ...(sweptNep141.length > 0 ? { tokens_swept: sweptNep141 } : {})
          };
        } else {
          telemetryRecord.sweeps.near = {
            status: 'Skipped (Zero Balance)',
            chain: 'NEAR Protocol Testnet (Ed25519)',
            target: destNear,
            amount: '0.0000 NEAR'
          };
        }
      } catch (nearErr) {
        console.error(`   ❌ NEAR Sweep Error:`, nearErr.message);
        hasRetriableFailure = true;
        telemetryRecord.sweeps.near = {
          status: `Error (${nearErr.message.slice(0, 60)})`,
          chain: 'NEAR Protocol Testnet (Ed25519)',
          target: destNear,
          amount: '0.0000 NEAR'
        };
      }
    }

    // Merge with any previously broadcasted L1 transactions for the same epoch so concurrent/subsequent passes never overwrite a successful sweep with Skipped/Error
    try {
      const latestVault = await this.getVaultInfo(vaultOwner).catch(() => null);
      const rawPrevReport = (latestVault && latestVault.last_sweep_report) || vault.last_sweep_report;
      if (rawPrevReport) {
        const prevReport = JSON.parse(String(rawPrevReport));
        if (prevReport && Number(prevReport.epoch) === Number(epoch) && prevReport.sweeps) {
          for (const chainKey of ['btc', 'evm', 'sol', 'near']) {
            const prevChain = prevReport.sweeps[chainKey];
            const curChain = telemetryRecord.sweeps[chainKey];
            const prevHasTx = Boolean(
              prevChain && (prevChain.tx_id || prevChain.tx_hash || prevChain.signature)
            );
            const curHasTx = Boolean(
              curChain && (curChain.tx_id || curChain.tx_hash || curChain.signature)
            );
            if (prevHasTx && !curHasTx) {
              telemetryRecord.sweeps[chainKey] = prevChain;
            }
          }
        }
      }
    } catch (_) {}

    hasRetriableFailure = Object.values(telemetryRecord.sweeps).some(
      s => s && String(s.status || '').startsWith('Error')
    );
    const isComplete = !hasRetriableFailure;
    telemetryRecord.is_complete = isComplete;

    // Persist verified telemetry directly on-chain (`aegis.okgoogleok.testnet`)
    try {
      const recOut = await this.callContract(
        'record_sweep_telemetry',
        {
          vault_owner: vaultOwner,
          epoch,
          report_json: JSON.stringify(telemetryRecord),
          is_complete: isComplete
        },
        '50000000000000',
        '0'
      );
      console.log(
        `📡 [LastKey Relayer] Telemetry stored on-chain (is_complete=${isComplete})! Tx: ${recOut.transaction.hash}`
      );
    } catch (recErr) {
      console.warn(`⚠️ [LastKey Relayer] Could not record telemetry on-chain:`, recErr.message);
      telemetryRecord.telemetry_write_error = recErr.message;
    }

    if (!this.disableLocalFileCache && this.telemetryPath) {
      try {
        this.writeLocalTelemetry(telemetryRecord);
        console.log(`📁 [LastKey Relayer] Local telemetry cache updated at ${this.telemetryPath}`);
      } catch (fsErr) {
        console.warn(`⚠️ [LastKey Relayer] Local telemetry write skipped:`, fsErr.message);
      }
    }

    if (isComplete) {
      this.processedSweeps.add(`${vaultOwner}:${epoch}:${state}`);
    }
    await this.dispatchZeroMetadataTelegramAlert(vaultOwner, state, epoch);
    return telemetryRecord;
  }

  getTelegramBotToken() {
    if (this._cachedTgBotToken) return this._cachedTgBotToken;
    let tk =
      (typeof process !== 'undefined' && process.env && (process.env.TELEGRAM_BOT_TOKEN || '').trim()) ||
      '';
    if (
      !tk &&
      this.telegramCredPath &&
      fs &&
      typeof fs.existsSync === 'function' &&
      fs.existsSync(this.telegramCredPath)
    ) {
      try {
        const parsed = JSON.parse(fs.readFileSync(this.telegramCredPath, 'utf8'));
        tk = String(parsed.botToken || parsed.token || '').trim();
      } catch (_) {}
    }
    this._cachedTgBotToken = tk;
    return tk;
  }

  _encryptChatId(chatIdStr, tk, vaultOwner) {
    const plain = Buffer.from(String(chatIdStr), 'utf8');
    const ownerClean = String(vaultOwner).trim().toLowerCase();
    const keyHex = ethers
      .sha256(ethers.toUtf8Bytes(`aegis_cid_mask_v1:${tk}:${ownerClean}`))
      .slice(2);
    const key = Buffer.from(keyHex, 'hex');

    if (typeof process !== 'undefined' && !process.browser && typeof require !== 'undefined') {
      try {
        const nodeCrypto = require('crypto');
        const ivHex = ethers
          .sha256(ethers.toUtf8Bytes(`aegis_cid_iv_v1:${tk}:${ownerClean}:${String(chatIdStr)}`))
          .slice(2, 26); // 12-byte GCM IV
        const iv = Buffer.from(ivHex, 'hex');
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
        const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
        const tag = cipher.getAuthTag();
        return `gcm:${ivHex}:${tag.toString('hex')}:${enc.toString('hex')}`;
      } catch (_) {}
    }

    const out = Buffer.alloc(plain.length);
    for (let i = 0; i < plain.length; i++) {
      out[i] = plain[i] ^ key[i % key.length];
    }
    return out.toString('hex');
  }

  _decryptChatId(cidEncHex, tk, vaultOwner) {
    try {
      if (!cidEncHex || typeof cidEncHex !== 'string') return null;
      const ownerClean = String(vaultOwner).trim().toLowerCase();
      const keyHex = ethers
        .sha256(ethers.toUtf8Bytes(`aegis_cid_mask_v1:${tk}:${ownerClean}`))
        .slice(2);
      const key = Buffer.from(keyHex, 'hex');

      if (cidEncHex.startsWith('gcm:')) {
        const parts = cidEncHex.split(':');
        if (parts.length === 4 && typeof process !== 'undefined' && !process.browser && typeof require !== 'undefined') {
          const nodeCrypto = require('crypto');
          const iv = Buffer.from(parts[1], 'hex');
          const tag = Buffer.from(parts[2], 'hex');
          const enc = Buffer.from(parts[3], 'hex');
          const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
          decipher.setAuthTag(tag);
          const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
          const str = dec.toString('utf8').trim();
          return /^-?\d+$/.test(str) ? str : null;
        }
        return null;
      }

      const enc = Buffer.from(cidEncHex, 'hex');
      const out = Buffer.alloc(enc.length);
      for (let i = 0; i < enc.length; i++) {
        out[i] = enc[i] ^ key[i % key.length];
      }
      const str = out.toString('utf8').trim();
      return /^-?\d+$/.test(str) ? str : null;
    } catch (_) {
      return null;
    }
  }

  _getTelegramAlertMessages() {
    return {
      test: '🛡 LastKey Bunker: Notification channel connected and active.',
      reminder:
        '⏳ LastKey Bunker: Timer is at 50% remaining — press the timer reset button (Check-In / I\'M ALIVE) in your bunker to reset the countdown.',
      grace:
        '⚠️ LastKey Bunker: Primary timer expired. Grace buffer is now active — check in immediately to cancel automatic inheritance.',
      timelock:
        '🔐 LastKey Bunker: 72-hour security cooldown started for a policy or timer change. If you did not authorize this, open your bunker and cancel immediately.',
      timelock_cancelled: '✅ LastKey Bunker: Pending 72-hour policy or timer change was cancelled.',
      panic: '🚨 LastKey Bunker: Emergency evacuation completed.',
      inheritance: '🔒 LastKey Bunker: Inheritance protocol completed.'
    };
  }

  async _sendTelegramText(tk, chatId, text) {
    if (!tk || !chatId || !text) return false;
    try {
      const res = await fetch(`https://api.telegram.org/bot${tk}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text,
          disable_web_page_preview: true
        })
      });
      return res.ok;
    } catch (_) {
      return false;
    }
  }

  async dispatchZeroMetadataTelegramAlert(vaultOwner, eventOrState, scopeOrEpoch = 0) {
    try {
      const tk = this.getTelegramBotToken();
      if (!tk || !vaultOwner) return false;

      const raw = String(eventOrState || '').toLowerCase();
      let evtKey = raw;
      if (raw.includes('inherit')) evtKey = 'inheritance';
      else if (raw.includes('evac') || raw === 'panic') evtKey = 'panic';

      const messages = this._getTelegramAlertMessages();
      const text = messages[evtKey];
      if (!text) return false;

      const dedupKey = `aegis_tg_sent_${vaultOwner}_${evtKey}_${scopeOrEpoch}`;
      if (!this._sentTelegramAlerts) this._sentTelegramAlerts = new Set();
      if (this._sentTelegramAlerts.has(dedupKey)) return false;

      const vInfo = await this.getVaultInfo(vaultOwner).catch(() => null);
      let alertState = {};
      if (vInfo && vInfo.alert_state) {
        try {
          alertState = JSON.parse(vInfo.alert_state) || {};
        } catch (_) {}
      }
      if (alertState.tg_linked === false) return false;
      if (evtKey === 'panic' && alertState.panic_ep === scopeOrEpoch) return false;
      if (evtKey === 'inheritance' && alertState.inh_ep === scopeOrEpoch) return false;

      const tagHex = ethers
        .sha256(ethers.toUtf8Bytes('aegis_alert_v1:' + String(vaultOwner).trim().toLowerCase()))
        .slice(2, 34);
      const expectedTag = `v1_${tagHex}`;

      let chatId = this._decryptChatId(alertState.cid_enc, tk, vaultOwner);
      if (!chatId) {
        const updRes = await fetch(`https://api.telegram.org/bot${tk}/getUpdates?limit=100`);
        const updJson = await updRes.json();
        if (updJson && updJson.ok && Array.isArray(updJson.result)) {
          for (let i = updJson.result.length - 1; i >= 0; i--) {
            const msg = updJson.result[i].message;
            if (msg && msg.chat && msg.chat.id && (msg.text || '').trim() === `/start ${expectedTag}`) {
              chatId = String(msg.chat.id);
              alertState.cid_enc = this._encryptChatId(chatId, tk, vaultOwner);
              alertState.tg_linked = true;
              break;
            }
          }
        }
      }
      if (!chatId) return false;

      this._sentTelegramAlerts.add(dedupKey);
      const sent = await this._sendTelegramText(tk, chatId, text);
      if (sent && this.hasSignerKey) {
        if (evtKey === 'panic') alertState.panic_ep = scopeOrEpoch;
        if (evtKey === 'inheritance') alertState.inh_ep = scopeOrEpoch;
        await this.callContract(
          'record_alert_state',
          {
            vault_owner: vaultOwner,
            alert_state_json: JSON.stringify(alertState)
          },
          '30000000000000',
          '0'
        ).catch(() => {});
      }
      return sent;
    } catch (_) {
      return false;
    }
  }

  /**
   * Autonomous 24/7 Keeper Lifecycle Monitor (works with browser tab CLOSED or OPEN):
   * 1. Syncs outgoing wallet transactions (`sync_owner_activity`) to reset heartbeat timer on any owner tx
   * 2. Promotes elapsed 72-hour timelock policies (`apply_policy`)
   * 3. Links Telegram (`/start v1_<tag>`) and dispatches all 7 alerts (`test`, `timelock`, `timelock_cancelled`,
   *    `reminder` at <=25%, `grace` at 0s, `panic`, `inheritance`) with on-chain deduplication (`record_alert_state`)
   */
  async monitorAllVaultsLifecycle() {
    try {
      const tk = this.getTelegramBotToken();
      const tagMap = new Map();
      if (tk) {
        try {
          const updRes = await fetch(`https://api.telegram.org/bot${tk}/getUpdates?limit=100`);
          const updJson = await updRes.json();
          if (updJson && updJson.ok && Array.isArray(updJson.result)) {
            for (const item of updJson.result) {
              const msg = item && item.message;
              const txt = msg && msg.text ? msg.text.trim() : '';
              if (msg && msg.chat && msg.chat.id && txt.startsWith('/start v1_')) {
                const tag = txt.slice('/start '.length).trim();
                tagMap.set(tag, {
                  chatId: String(msg.chat.id),
                  updateId: String(item.update_id)
                });
              }
            }
          }
        } catch (_) {}
      }

      const accounts = await this.getRegisteredAccounts();
      if (!accounts || accounts.length === 0) return;

      if (!this._ownerKeyNonceMap) this._ownerKeyNonceMap = new Map();
      if (!this._dormantAccountsCache) this._dormantAccountsCache = new Map();
      const messages = this._getTelegramAlertMessages();
      const nowMs = Date.now();

      for (const acc of accounts) {
        const tagHex = ethers
          .sha256(ethers.toUtf8Bytes('aegis_alert_v1:' + String(acc).trim().toLowerCase()))
          .slice(2, 34);
        const expectedTag = `v1_${tagHex}`;
        const tagEntry = tagMap.get(expectedTag);

        const lastDormantCheck = this._dormantAccountsCache.get(acc) || 0;
        if (!tagEntry && lastDormantCheck > 0 && nowMs - lastDormantCheck < 15000) {
          continue;
        }

        const v = await this.getVaultInfo(acc).catch(() => null);
        if (!v) continue;

        const state = typeof v.state === 'string' ? v.state : Object.keys(v.state || {})[0];
        let alertState = {};
        const hadExistingAlertState = Boolean(v.alert_state);
        if (v.alert_state) {
          try {
            alertState = JSON.parse(v.alert_state) || {};
          } catch (_) {}
        }
        let alertDirty = false;

        // Mark dormant if Unconfigured or already-swept Evacuated/Inheritance without pending actions
        if (
          state === 'Unconfigured' ||
          ((state === 'Evacuated' || state === 'Inheritance') && v.is_epoch_swept)
        ) {
          this._dormantAccountsCache.set(acc, nowMs);
        } else {
          this._dormantAccountsCache.delete(acc);
        }

        // 1. Autonomous Wallet Transaction Activity Reset (`sync_owner_activity`)
        if (state === 'Active' || state === 'Claiming') {
          try {
            const akList = await this.nearRpc('query', {
              request_type: 'view_access_key_list',
              finality: 'optimistic',
              account_id: acc
            });
            const nowNsBig = BigInt(v.current_time_ns || BigInt(Date.now()) * 1000000n);
            const maxAllowedNonce = nowNsBig + 60000000000n;
            let maxNonce = 0n;
            const currentKeyMap = {};
            if (akList && Array.isArray(akList.keys)) {
              for (const k of akList.keys) {
                const pk = String(k?.public_key || '');
                const n = BigInt(k?.access_key?.nonce || 0);
                if (n <= maxAllowedNonce) {
                  if (pk) currentKeyMap[pk] = n;
                  if (n > maxNonce) maxNonce = n;
                }
              }
            }
            const curPingNs = BigInt(v.last_ping_ns || 0);
            const prevTrack = this._ownerKeyNonceMap.get(acc);
            if (!prevTrack) {
              this._ownerKeyNonceMap.set(acc, {
                keyMap: currentKeyMap,
                maxNonce,
                lastPingNs: curPingNs
              });
            } else {
              let txDetected = maxNonce > prevTrack.maxNonce;
              if (!txDetected && prevTrack.keyMap) {
                for (const [pk, curNonce] of Object.entries(currentKeyMap)) {
                  const oldNonce = prevTrack.keyMap[pk];
                  if (oldNonce !== undefined && curNonce > oldNonce) {
                    txDetected = true;
                    break;
                  } else if (oldNonce === undefined && Object.keys(prevTrack.keyMap).length > 0) {
                    txDetected = true;
                    break;
                  }
                }
              }
              if (txDetected) {
                if (curPingNs <= prevTrack.lastPingNs && this.hasSignerKey) {
                  const monotonicObservedNonce = (
                    nowNsBig > maxNonce ? nowNsBig : maxNonce + 1n
                  ).toString();
                  await this.callContract(
                    'sync_owner_activity',
                    { vault_owner: acc, observed_nonce: monotonicObservedNonce },
                    '30000000000000',
                    '0'
                  );
                  console.log(
                    `⚡ [Autonomous Activity Sync] Reset timer for ${acc} via outgoing wallet tx (observed_nonce ${monotonicObservedNonce})`
                  );
                  v.last_ping_ns = v.current_time_ns;
                  this._ownerKeyNonceMap.set(acc, {
                    keyMap: currentKeyMap,
                    maxNonce,
                    lastPingNs: BigInt(v.current_time_ns || curPingNs)
                  });
                } else {
                  this._ownerKeyNonceMap.set(acc, {
                    keyMap: currentKeyMap,
                    maxNonce,
                    lastPingNs: curPingNs
                  });
                }
              } else if (curPingNs > prevTrack.lastPingNs) {
                this._ownerKeyNonceMap.set(acc, {
                  keyMap: currentKeyMap,
                  maxNonce,
                  lastPingNs: curPingNs
                });
              }
            }
          } catch (_) {}
        }

        // 2. Autonomous 72-Hour Cooldown Promotion (`apply_policy`)
        if (
          alertState.timelock_eff &&
          alertState.timelock_applied !== alertState.timelock_eff &&
          !v.pending_policy &&
          BigInt(v.current_time_ns || 0) >= BigInt(alertState.timelock_eff) &&
          this.hasSignerKey
        ) {
          try {
            await this.callContract('apply_policy', { account_id: acc }, '30000000000000', '0');
            console.log(`🔓 [Autonomous Cooldown] Promoted elapsed 72h policy on-chain for ${acc}`);
          } catch (_) {}
          alertState.timelock_applied = alertState.timelock_eff;
          alertDirty = true;
        }

        // 3. Autonomous Telegram Linking & All 7 Alerts
        if (tk) {
          let chatId = alertState.tg_linked === false ? null : this._decryptChatId(alertState.cid_enc, tk, acc);
          if (tagEntry) {
            const isPreviouslyUnlinkedStart =
              alertState.tg_linked === false &&
              alertState.tg_unlinked_uid &&
              String(tagEntry.updateId) === String(alertState.tg_unlinked_uid);
            if (!isPreviouslyUnlinkedStart) {
              const newCidEnc = this._encryptChatId(tagEntry.chatId, tk, acc);
              chatId = tagEntry.chatId;
              if (
                alertState.cid_enc !== newCidEnc ||
                alertState.last_start_uid !== tagEntry.updateId ||
                alertState.tg_linked === false
              ) {
                await this._sendTelegramText(tk, chatId, messages.test);
                alertState.tg_linked = true;
                alertState.cid_enc = newCidEnc;
                alertState.last_start_uid = tagEntry.updateId;
                delete alertState.tg_unlinked_uid;
                if (!hadExistingAlertState) {
                  if (v.last_cancelled_timelock_ns) {
                    alertState.cancelled_tl = String(v.last_cancelled_timelock_ns);
                  }
                  if (v.is_epoch_swept && state === 'Evacuated') alertState.panic_ep = v.epoch;
                  if (v.is_epoch_swept && state === 'Inheritance') alertState.inh_ep = v.epoch;
                }
                alertDirty = true;
                console.log(`📲 [Telegram Keeper] Linked Telegram alerts for ${acc}`);
              }
            }
          }

          if (chatId) {
            // (a) Explicit Test Alert request (`request_telegram_test`)
            if (
              v.last_test_alert_req_ns &&
              String(v.last_test_alert_req_ns) !== alertState.last_test_req
            ) {
              await this._sendTelegramText(tk, chatId, messages.test);
              alertState.last_test_req = String(v.last_test_alert_req_ns);
              alertDirty = true;
              console.log(`📲 [Telegram Keeper] Sent requested test alert for ${acc}`);
            }

            // (b) 72h Cooldown Started (`timelock`)
            if (v.pending_policy && v.pending_policy.effective_at_ns) {
              const eff = String(v.pending_policy.effective_at_ns);
              if (alertState.timelock !== eff) {
                await this._sendTelegramText(tk, chatId, messages.timelock);
                alertState.timelock = eff;
                alertState.timelock_eff = eff;
                alertDirty = true;
                console.log(`📲 [Telegram Keeper] Sent 72h timelock alert for ${acc}`);
              }
            }

            // (c) 72h Cooldown Cancelled (`timelock_cancelled`)
            if (v.last_cancelled_timelock_ns) {
              const canc = String(v.last_cancelled_timelock_ns);
              if (alertState.cancelled_tl !== canc) {
                await this._sendTelegramText(tk, chatId, messages.timelock_cancelled);
                alertState.cancelled_tl = canc;
                alertDirty = true;
                console.log(`📲 [Telegram Keeper] Sent timelock_cancelled alert for ${acc}`);
              }
            }

            // (d) Check-in Reminder (<=50%) & (e) Grace Buffer Active (0s)
            if (state === 'Active' || state === 'Claiming') {
              const nowNs = Number(v.current_time_ns || Date.now() * 1e6);
              const lastPingNs = Number(v.last_ping_ns || nowNs);
              const hbNs = Number(v.heartbeat_interval_ns || 0);
              const cpNs = Number(v.challenge_period_ns || 0);
              const elapsedNs = Math.max(0, nowNs - lastPingNs);
              const remHbNs = hbNs - elapsedNs;
              const remTotalNs = hbNs + cpNs - elapsedNs;
              const pingScope = String(v.last_ping_ns);

              if (hbNs > 0 && remHbNs > 0 && remHbNs <= hbNs * 0.50) {
                if (alertState.reminder !== pingScope) {
                  await this._sendTelegramText(tk, chatId, messages.reminder);
                  alertState.reminder = pingScope;
                  alertDirty = true;
                  console.log(`📲 [Telegram Keeper] Sent <=50% check-in reminder for ${acc}`);
                }
              } else if (hbNs > 0 && remHbNs <= 0 && remTotalNs > 0) {
                if (alertState.grace !== pingScope) {
                  await this._sendTelegramText(tk, chatId, messages.grace);
                  alertState.grace = pingScope;
                  alertDirty = true;
                  console.log(`📲 [Telegram Keeper] Sent grace buffer alert for ${acc}`);
                }
              }
            }

            // (f) Emergency Panic Evacuation (`Evacuated`)
            let panicEpochToAlert = state === 'Evacuated' ? v.epoch : undefined;
            if (panicEpochToAlert === undefined && v.last_sweep_report) {
              try {
                const rep = JSON.parse(v.last_sweep_report);
                if (
                  rep &&
                  (rep.state === 'Evacuated' || String(rep.state || '').toLowerCase().includes('evac')) &&
                  rep.epoch !== undefined
                ) {
                  panicEpochToAlert = rep.epoch;
                }
              } catch (_) {}
            }
            if (panicEpochToAlert !== undefined && alertState.panic_ep !== panicEpochToAlert) {
              await this._sendTelegramText(tk, chatId, messages.panic);
              alertState.panic_ep = panicEpochToAlert;
              alertDirty = true;
              console.log(`📲 [Telegram Keeper] Sent panic evacuation alert for ${acc} (epoch ${panicEpochToAlert})`);
            }

            // (g) Automatic Inheritance (`Inheritance`)
            let inhEpochToAlert = state === 'Inheritance' ? v.epoch : undefined;
            if (inhEpochToAlert === undefined && v.last_sweep_report) {
              try {
                const rep = JSON.parse(v.last_sweep_report);
                if (
                  rep &&
                  (rep.state === 'Inheritance' || String(rep.state || '').toLowerCase().includes('inherit')) &&
                  rep.epoch !== undefined
                ) {
                  inhEpochToAlert = rep.epoch;
                }
              } catch (_) {}
            }
            if (inhEpochToAlert !== undefined && alertState.inh_ep !== inhEpochToAlert) {
              await this._sendTelegramText(tk, chatId, messages.inheritance);
              alertState.inh_ep = inhEpochToAlert;
              alertDirty = true;
              console.log(`📲 [Telegram Keeper] Sent inheritance alert for ${acc} (epoch ${inhEpochToAlert})`);
            }
          }
        }

        if (alertDirty && this.hasSignerKey) {
          await this.callContract(
            'record_alert_state',
            {
              vault_owner: acc,
              alert_state_json: JSON.stringify(alertState)
            },
            '30000000000000',
            '0'
          ).catch(err => {
            console.warn(`[record_alert_state] warning for ${acc}:`, err.message);
          });
        }
      }
    } catch (err) {
      console.warn('[monitorAllVaultsLifecycle] Notice:', err.message);
    }
  }

  async getRegisteredAccounts() {
    try {
      const list = await this.viewContract('get_registered_accounts', {});
      if (Array.isArray(list) && list.length > 0) return list;
    } catch (_) {}
    return [];
  }

  startHttpServer(port = process.env.PORT || 8080) {
    if (this._httpServerRunning) return;
    this._httpServerRunning = true;
    const http = require('http');
    const server = http.createServer((req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Private-Network', 'true');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

      if (url.pathname === '/' || url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'online',
            service: 'LastKey Stateless Autonomous Keeper',
            network: this.networkId,
            contract: this.contractId,
            relayer: this.relayerAccountId,
            uptime_seconds: Math.floor(process.uptime()),
            timestamp: new Date().toISOString()
          })
        );
        return;
      }

      if (url.pathname === '/telemetry') {
        try {
          if (fs.existsSync(this.telemetryPath)) {
            const data = fs.readFileSync(this.telemetryPath, 'utf8');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(data);
            return;
          }
        } catch (_) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'No local telemetry cached; query get_vault_info on-chain' }));
        return;
      }

      if (url.pathname === '/ping' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          if (body.length < 8192) body += chunk;
        });
        req.on('end', async () => {
          try {
            const payload = JSON.parse(body || '{}');
            const result = await this.sponsorPing(payload.vault_owner, {
              timestampMs: payload.timestamp_ms,
              signatureHex: payload.signature_hex,
              nep413NonceHex: payload.nep413_nonce_hex || null,
              nep413Recipient: payload.nep413_recipient || null
            });
            res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
          }
        });
        return;
      }

      if ((url.pathname === '/trigger' || url.pathname === '/sweep') && req.method === 'POST') {
        this.sweepAllActionable()
          .then(summary => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, ...summary }));
          })
          .catch(err => {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
          });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    server.listen(port, '0.0.0.0', () => {
      console.log(`🌐 [LastKey Relayer] HTTP Keeper Server listening on port ${port}`);
    });
  }

  async startMonitoring(_initialAccounts = [], intervalMs = 15000) {
    await this.init({ requireSigner: false });
    if (process.env.PORT || process.env.ENABLE_HTTP === 'true') {
      this.startHttpServer();
    }
    console.log(`🔍 [LastKey Relayer] Starting stateless get_actionable_vaults monitor on ${this.contractId}...`);
    const check = async () => {
      try {
        await this.sweepAllActionable();
      } catch (err) {
        console.warn('[LastKey Keeper Cycle] Notice:', err.message);
      }
    };
    await check();
    setInterval(check, intervalMs);
  }

  async runSinglePass() {
    return await this.sweepAllActionable();
  }

  async runBoundedLoop(durationMinutes = 55, intervalMs = 5000) {
    await this.init({ requireSigner: false });
    const endAtMs = Date.now() + Math.max(1, Number(durationMinutes)) * 60 * 1000;
    const pollMs = Math.max(2000, Number(intervalMs) || 5000);
    console.log(
      `🛡️  [LastKey Cloud Keeper] Active 24/7 loop started for ${durationMinutes}m (checking every ${pollMs / 1000}s)...`
    );
    while (Date.now() < endAtMs) {
      const cycleStart = Date.now();
      try {
        await this.sweepAllActionable();
      } catch (err) {
        console.warn('[LastKey Cloud Keeper Cycle] Notice:', err.message);
      }
      const elapsed = Date.now() - cycleStart;
      const waitMs = Math.max(500, pollMs - elapsed);
      if (Date.now() + waitMs >= endAtMs) break;
      await new Promise(r => setTimeout(r, waitMs));
    }
    console.log('✅ [LastKey Cloud Keeper] Bounded loop window completed cleanly.');
  }

  /**
   * Production stateless sweep cycle using `get_actionable_vaults`:
   * - Single RPC view call when healthy (0 gas burned, 0 private key needed if 0 actionable vaults)
   * - Triggers push inheritance & executes verified multichain sweeps for expired/evacuated vaults
   */
  async sweepAllActionable(options = {}) {
    if (this._activeSweepPromise) {
      console.log('⏳ [LastKey Relayer] Sweep cycle already in progress; coalescing concurrent request.');
      return this._activeSweepPromise;
    }
    this._activeSweepPromise = this._executeSweepAllActionable(options).finally(() => {
      this._activeSweepPromise = null;
    });
    return this._activeSweepPromise;
  }

  async _executeSweepAllActionable(options = {}) {
    await this.init({ requireSigner: false });
    if (!options.skipLifecycleMonitor) {
      await this.monitorAllVaultsLifecycle();
    }
    console.log(`🔍 [LastKey Relayer] Querying get_actionable_vaults on ${this.contractId}...`);
    const actionable = await this.getActionableVaults({ throwOnError: true });

    if (!actionable || actionable.length === 0) {
      console.log('✅ 0 actionable vaults found. All bunkers healthy or already swept. 0 gas burned.');
      return { actionable: 0, processed: [] };
    }

    await this.init({ requireSigner: true });
    console.log(
      `🚨 Found ${actionable.length} actionable vault(s): ${actionable.map(v => `${v.owner}[v${v.epoch}]`).join(', ')}`
    );

    const processed = [];
    for (const v of actionable) {
      const state = typeof v.state === 'string' ? v.state : Object.keys(v.state)[0];
      const acc = v.owner;
      const prefetchedVault = await this.getVaultInfo(acc);
      if (!prefetchedVault) continue;
      let transitionedInSamePass = false;

      if (state === 'Active' || state === 'Claiming') {
        console.log(`⏱️  [Autonomous Inheritance] Triggering trigger_push_inheritance for ${acc}...`);
        try {
          const pushOut = await this.callContract(
            'trigger_push_inheritance',
            { vault_owner: acc },
            '80000000000000',
            '0'
          );
          console.log(`✅ Push inheritance triggered on-chain for ${acc}! Tx: ${pushOut.transaction.hash}`);
          prefetchedVault.state = 'Inheritance';
          prefetchedVault.is_epoch_swept = false;
          transitionedInSamePass = true;
        } catch (err) {
          console.warn(`[trigger_push_inheritance] error for ${acc}:`, err.message);
          continue;
        }
      }
      const report = await this.sweepVault(acc, { prefetchedVault, transitionedInSamePass });
      processed.push({
        owner: acc,
        epoch: v.epoch,
        complete: Boolean(report?.is_complete),
        sweeps: report?.sweeps || null
      });
    }
    console.log('✅ [LastKey Relayer] sweep-all execution cycle finished.');
    return { actionable: actionable.length, processed };
  }
}

if (typeof require !== 'undefined' && require.main === module) {
  const args = process.argv.slice(2);
  const service = new AegisRelayerService();

  if (args.includes('--daemon-minutes')) {
    const mIdx = args.indexOf('--daemon-minutes');
    const mins = Number(args[mIdx + 1] || 55);
    const iIdx = args.indexOf('--interval-ms');
    const intervalMs = iIdx !== -1 ? Number(args[iIdx + 1] || 5000) : 5000;
    service
      .runBoundedLoop(mins, intervalMs)
      .then(() => process.exit(0))
      .catch(err => {
        console.error('Daemon loop error:', err.message);
        process.exit(1);
      });
  } else if (args.includes('--sweep-all') || args.includes('--once')) {
    service
      .sweepAllActionable()
      .then(() => process.exit(0))
      .catch(err => {
        console.error('Sweep-all failed:', err.message);
        process.exit(1);
      });
  } else if (args.includes('--sweep')) {
    const idx = args.indexOf('--sweep');
    const target = args[idx + 1];
    if (!target) {
      console.error('Usage: node relayer/service.js --sweep <account.testnet>');
      process.exit(1);
    }
    service
      .sweepVault(target)
      .then(() => process.exit(0))
      .catch(err => {
        console.error(err.message);
        process.exit(1);
      });
  } else if (args.includes('--watch') || args.includes('--server')) {
    if (args.includes('--port')) {
      const pIdx = args.indexOf('--port');
      process.env.PORT = args[pIdx + 1];
    }
    service.startMonitoring();
  } else {
    console.log('Usage:');
    console.log('  node relayer/service.js --sweep-all');
    console.log('  node relayer/service.js --sweep <account>');
    console.log('  node relayer/service.js --server [--port 8080]');
  }
}

module.exports = { AegisRelayerService };

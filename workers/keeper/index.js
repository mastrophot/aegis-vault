/**
 * Aegis Cloudflare Worker: 24/7 Stateless Autonomous Keeper (`nodejs_compat`)
 *
 * - Lazy-loads heavy multichain crypto libraries (`ethers`, `bitcoinjs-lib`, `@solana/web3.js`, `chainsig.js`)
 *   inside request/cron handlers so Worker cold-start CPU stays <5ms
 * - Uses restricted `FunctionCall` key on `keeper.aegis.okgoogleok.testnet`
 * - Executes real NEAR MPC threshold sweeps (`v1.signer-prod.testnet`) and broadcasts to BTC, EVM, Solana & NEAR
 * - Persists verified telemetry on-chain via `record_sweep_telemetry` (+ optional Cloudflare KV mirror)
 */

import './shims/workerd-init.js';

let CachedRelayerService = null;
let CachedKeeperInstance = null;
let CachedKeeperConfigKey = '';

async function getRelayerServiceClass() {
  if (!CachedRelayerService) {
    const mod = await import('../../relayer/service.js');
    CachedRelayerService = mod.AegisRelayerService || (mod.default && mod.default.AegisRelayerService);
  }
  return CachedRelayerService;
}

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Private-Network': 'true'
};

async function createKeeperService(env) {
  const configKey = [
    env.NEAR_NETWORK || 'testnet',
    env.CONTRACT_ID || 'aegis.okgoogleok.testnet',
    env.RELAYER_ACCOUNT_ID || 'keeper.aegis.okgoogleok.testnet',
    Boolean(env.RELAYER_PRIVATE_KEY)
  ].join('|');

  if (CachedKeeperInstance && CachedKeeperConfigKey === configKey) {
    return CachedKeeperInstance;
  }

  const AegisRelayerService = await getRelayerServiceClass();
  CachedKeeperInstance = new AegisRelayerService({
    networkId: env.NEAR_NETWORK || 'testnet',
    contractId: env.CONTRACT_ID || 'aegis.okgoogleok.testnet',
    relayerAccountId: env.RELAYER_ACCOUNT_ID || 'keeper.aegis.okgoogleok.testnet',
    privateKey: env.RELAYER_PRIVATE_KEY || '',
    nearRpcUrl: env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
    solanaRpcUrl: env.SOLANA_RPC_URL || 'https://solana-devnet.api.onfinality.io/public',
    evmRpcUrl: env.EVM_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
    disableLocalFileCache: true
  });
  CachedKeeperConfigKey = configKey;
  return CachedKeeperInstance;
}

async function executeSweepCycle(env) {
  const keeper = await createKeeperService(env);
  const summary = await keeper.sweepAllActionable();

  if (env.AEGIS_TELEMETRY_KV && summary.processed && summary.processed.length > 0) {
    for (const item of summary.processed) {
      const info = await keeper.getVaultInfo(item.owner);
      if (info && info.last_sweep_report) {
        await env.AEGIS_TELEMETRY_KV.put(`telemetry:${item.owner}:${item.epoch}`, info.last_sweep_report);
        await env.AEGIS_TELEMETRY_KV.put(`telemetry:${item.owner}`, info.last_sweep_report);
      }
    }
  }

  return {
    success: true,
    timestamp: new Date().toISOString(),
    ...summary
  };
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(executeSweepCycle(env));
  },

  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    if (url.pathname === '/health' || url.pathname === '/') {
      return new Response(
        JSON.stringify({
          status: 'online',
          worker: 'aegis-keeper',
          contract: env.CONTRACT_ID || 'aegis.okgoogleok.testnet',
          relayer: env.RELAYER_ACCOUNT_ID || 'keeper.aegis.okgoogleok.testnet',
          signerConfigured: Boolean(env.RELAYER_PRIVATE_KEY)
        }),
        { status: 200, headers: CORS_HEADERS }
      );
    }

    if (url.pathname === '/trigger' || url.pathname === '/sweep') {
      if (request.method !== 'POST') {
        return new Response(
          JSON.stringify({ success: false, error: 'Method Not Allowed: use POST /trigger' }),
          { status: 405, headers: CORS_HEADERS }
        );
      }
      try {
        const result = await executeSweepCycle(env);
        return new Response(JSON.stringify(result), { status: 200, headers: CORS_HEADERS });
      } catch (err) {
        return new Response(
          JSON.stringify({ success: false, error: err.message }),
          { status: 500, headers: CORS_HEADERS }
        );
      }
    }

    if (url.pathname === '/ping' && request.method === 'POST') {
      try {
        const body = await request.json();
        const keeper = await createKeeperService(env);
        const res = await keeper.sponsorPing(body.vault_owner, {
          timestampMs: body.timestamp_ms,
          signatureHex: body.signature_hex,
          nep413NonceHex: body.nep413_nonce_hex || null,
          nep413Recipient: body.nep413_recipient || null
        });
        return new Response(JSON.stringify(res), {
          status: res.success ? 200 : 400,
          headers: CORS_HEADERS
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ success: false, error: err.message }),
          { status: 500, headers: CORS_HEADERS }
        );
      }
    }

    if (url.pathname === '/telemetry') {
      const owner = url.searchParams.get('owner');
      if (owner && env.AEGIS_TELEMETRY_KV) {
        const cached = await env.AEGIS_TELEMETRY_KV.get(`telemetry:${owner}`);
        if (cached) {
          return new Response(cached, { status: 200, headers: CORS_HEADERS });
        }
      }
      if (owner) {
        const keeper = await createKeeperService(env);
        const info = await keeper.getVaultInfo(owner);
        if (info && info.last_sweep_report) {
          return new Response(info.last_sweep_report, { status: 200, headers: CORS_HEADERS });
        }
      }
      return new Response(JSON.stringify({ message: 'No sweep report found' }), {
        status: 404,
        headers: CORS_HEADERS
      });
    }

    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: CORS_HEADERS });
  }
};

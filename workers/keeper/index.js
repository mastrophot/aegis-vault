/**
 * Aegis Cloudflare Worker: 24/7 Stateless Autonomous Keeper (`nodejs_compat`)
 *
 * - Runs on 1-minute Cron (`* * * * *`) + HTTP `/sweep` & `/ping` endpoints
 * - Uses restricted `FunctionCall` key on `keeper.aegis.okgoogleok.testnet` (injected via `wrangler secret put RELAYER_PRIVATE_KEY`)
 * - Executes real NEAR MPC threshold sweeps (`v1.signer-prod.testnet`) and broadcasts to BTC, EVM, Solana & NEAR
 * - Persists verified telemetry on-chain via `record_sweep_telemetry` (+ optional Cloudflare KV mirror)
 */

import { Buffer } from 'node:buffer';
if (!globalThis.Buffer) {
  globalThis.Buffer = Buffer;
}

import relayerPkg from '../../relayer/service.js';
const { AegisRelayerService } = relayerPkg;

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

function createKeeperService(env) {
  return new AegisRelayerService({
    networkId: env.NEAR_NETWORK || 'testnet',
    contractId: env.CONTRACT_ID || 'aegis.okgoogleok.testnet',
    relayerAccountId: env.RELAYER_ACCOUNT_ID || 'keeper.aegis.okgoogleok.testnet',
    privateKey: env.RELAYER_PRIVATE_KEY || '',
    nearRpcUrl: env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
    solanaRpcUrl: env.SOLANA_RPC_URL || 'https://api.devnet.solana.com',
    evmRpcUrl: env.EVM_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
    disableLocalFileCache: true
  });
}

async function executeSweepCycle(env) {
  const keeper = createKeeperService(env);
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

    if ((url.pathname === '/trigger' || url.pathname === '/sweep') && (request.method === 'POST' || request.method === 'GET')) {
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
        const keeper = createKeeperService(env);
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
        const keeper = createKeeperService(env);
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

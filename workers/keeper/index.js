/**
 * Aegis Cloudflare Worker: 24/7 Stateless Keeper & Webhook Runner
 * Executes on 1-minute cron + instant HTTP Webhook trigger for hackathon live demo
 */

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleSweepCycle(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', worker: 'aegis-keeper' }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    if (url.pathname === '/trigger' || url.pathname === '/sweep') {
      const result = await handleSweepCycle(env);
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    return new Response('Aegis Autonomous Keeper Worker', { status: 200 });
  }
};

async function handleSweepCycle(env) {
  const rpcUrl = env.NEAR_RPC_URL || 'https://rpc.testnet.near.org';
  const contractId = env.CONTRACT_ID || 'aegis.okgoogleok.testnet';

  // 1. Query actionable vaults in 1 call
  try {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'aegis-keeper',
        method: 'query',
        params: {
          request_type: 'call_function',
          finality: 'final',
          account_id: contractId,
          method_name: 'get_actionable_vaults',
          args_base64: 'e30='
        }
      })
    });

    const json = await res.json();
    if (!json.result || !json.result.result) {
      return { success: false, error: 'Failed to query get_actionable_vaults', details: json };
    }

    const rawStr = new TextDecoder().decode(new Uint8Array(json.result.result));
    const actionable = JSON.parse(rawStr);

    if (!Array.isArray(actionable) || actionable.length === 0) {
      return { success: true, actionable: 0, message: 'All bunkers healthy and armed. 0 gas burned.' };
    }

    // Process actionable vaults...
    return {
      success: true,
      actionable: actionable.length,
      owners: actionable.map(v => v.owner)
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

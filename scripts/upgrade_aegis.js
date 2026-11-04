const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

async function upgrade() {
  const credPath = path.resolve(__dirname, '../.credentials/aegis.okgoogleok.testnet.json');
  const cred = JSON.parse(fs.readFileSync(credPath, 'utf8'));
  
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(cred.privateKey || cred.private_key);
  await keyStore.setKey('testnet', cred.accountId || cred.account_id, keyPair);

  const near = await nearAPI.connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://archival-rpc.testnet.near.org'
  });

  const account = await near.account(cred.accountId || cred.account_id);
  const wasmPath = path.resolve(__dirname, '../contracts/vault/target/wasm32-unknown-unknown/release/lastkey_vault.wasm');
  const wasmBytes = fs.readFileSync(wasmPath);

  console.log(`📦 Deploying updated WASM (${wasmBytes.length} bytes) to ${cred.accountId}...`);
  const outcome = await account.deployContract(wasmBytes);
  console.log(`✅ Deployed! Tx: ${outcome.transaction.hash}`);

  console.log(`🔄 Calling migrate() on ${cred.accountId}...`);
  const migrateOutcome = await account.functionCall({
    contractId: cred.accountId,
    methodName: 'migrate',
    args: {},
    gas: '30000000000000'
  });
  console.log(`✅ Migrated! Tx: ${migrateOutcome.transaction.hash}`);
}

upgrade().catch(console.error);

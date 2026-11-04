const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

async function upgrade() {
  const credPath = path.resolve(__dirname, '../.credentials/aegis.okgoogleok.testnet.json');
  const cred = JSON.parse(fs.readFileSync(credPath, 'utf8'));
  
  const parentCredPath = path.resolve(__dirname, '../.credentials/okgoogleok.testnet.json');
  const parentCred = JSON.parse(fs.readFileSync(parentCredPath, 'utf8'));

  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(cred.privateKey || cred.private_key);
  await keyStore.setKey('testnet', cred.accountId || cred.account_id, keyPair);

  const parentKeyPair = nearAPI.KeyPair.fromString(parentCred.privateKey || parentCred.private_key);
  await keyStore.setKey('testnet', parentCred.accountId || parentCred.account_id, parentKeyPair);

  const near = await nearAPI.connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://archival-rpc.testnet.near.org'
  });

  const parentAccount = await near.account(parentCred.accountId || parentCred.account_id);
  console.log(`💸 Topping up ${cred.accountId} with 1 NEAR for storage...`);
  try {
    await parentAccount.sendMoney(cred.accountId, '1000000000000000000000000'); // 1 NEAR
    console.log(`✅ Topped up 1 NEAR!`);
  } catch (e) {
    console.log(`Notice on top-up:`, e.message);
  }

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

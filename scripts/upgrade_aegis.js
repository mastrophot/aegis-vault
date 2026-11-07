const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

async function upgrade() {
  const credPath = path.resolve(__dirname, '../.credentials/aegis.okgoogleok.testnet.json');
  const cred = JSON.parse(fs.readFileSync(credPath, 'utf8'));

  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(cred.privateKey || cred.private_key);
  await keyStore.setKey('testnet', cred.accountId || cred.account_id, keyPair);
  
  if (process.argv.includes('--topup')) {
    const parentCredPath = path.resolve(__dirname, '../.credentials/okgoogleok.testnet.json');
    if (fs.existsSync(parentCredPath)) {
      const parentCred = JSON.parse(fs.readFileSync(parentCredPath, 'utf8'));
      const parentKeyPair = nearAPI.KeyPair.fromString(parentCred.privateKey || parentCred.private_key);
      await keyStore.setKey('testnet', parentCred.accountId || parentCred.account_id, parentKeyPair);
      const nearParent = await nearAPI.connect({
        networkId: 'testnet',
        keyStore,
        nodeUrl: 'https://test.rpc.fastnear.com'
      });
      const parentAccount = await nearParent.account(parentCred.accountId || parentCred.account_id);
      console.log(`💸 Topping up ${cred.accountId} with 1 NEAR for storage...`);
      await parentAccount.sendMoney(cred.accountId, '1000000000000000000000000');
      console.log(`✅ Topped up 1 NEAR!`);
    }
  }

  const near = await nearAPI.connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://test.rpc.fastnear.com'
  });

  const account = await near.account(cred.accountId || cred.account_id);
  const wasmPath = path.resolve(__dirname, '../contracts/vault/target/wasm32-unknown-unknown/release/lastkey_vault.wasm');
  const wasmBytes = fs.readFileSync(wasmPath);

  console.log(`📦 Deploying updated WASM (${wasmBytes.length} bytes) to ${cred.accountId}...`);
  const outcome = await account.deployContract(wasmBytes);
  console.log(`✅ Deployed! Tx: ${outcome.transaction.hash}`);
}

upgrade().catch(err => {
  console.error('❌ Upgrade failed:', err.message);
  process.exit(1);
});

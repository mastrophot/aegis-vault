const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

async function main() {
  const target = process.argv[2] || 'mastrophot.testnet';
  const parentCredPath = path.resolve(__dirname, '../.credentials/okgoogleok.testnet.json');
  const parentCred = JSON.parse(fs.readFileSync(parentCredPath, 'utf8'));

  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(parentCred.privateKey || parentCred.private_key);
  await keyStore.setKey('testnet', parentCred.accountId || parentCred.account_id, keyPair);

  const near = await nearAPI.connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://test.rpc.fastnear.com'
  });

  const account = await near.account(parentCred.accountId || parentCred.account_id);
  console.log(`Resetting vault for ${target} on aegis.okgoogleok.testnet...`);
  const outcome = await account.functionCall({
    contractId: 'aegis.okgoogleok.testnet',
    methodName: 'admin_reset_vault',
    args: { target_account: target },
    gas: '100000000000000'
  });

  console.log(`✅ Reset confirmed! Tx: ${outcome.transaction.hash}`);
}

main().catch(console.error);

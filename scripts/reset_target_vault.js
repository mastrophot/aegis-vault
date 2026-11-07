const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

async function main() {
  const target = process.argv[2] || 'mastrophot.testnet';
  const contractCredPath = path.resolve(__dirname, '../.credentials/aegis.okgoogleok.testnet.json');
  const contractCred = JSON.parse(fs.readFileSync(contractCredPath, 'utf8'));
  const contractAccountId = contractCred.accountId || contractCred.account_id || 'aegis.okgoogleok.testnet';

  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(contractCred.privateKey || contractCred.private_key);
  await keyStore.setKey('testnet', contractAccountId, keyPair);

  const near = await nearAPI.connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://test.rpc.fastnear.com'
  });

  const account = await near.account(contractAccountId);
  console.log(`Resetting vault for ${target} on ${contractAccountId} (self-call)...`);
  const outcome = await account.functionCall({
    contractId: contractAccountId,
    methodName: 'admin_reset_vault',
    args: { target_account: target },
    gas: '100000000000000'
  });

  console.log(`✅ Reset confirmed! Tx: ${outcome.transaction.hash}`);
}

main().catch(err => {
  console.error('❌ Reset failed:', err.message);
  process.exit(1);
});

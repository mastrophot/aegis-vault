/**
 * LastKey Vault Testnet Deployment Script
 * 
 * 1. Generates an Ed25519 KeyPair
 * 2. Creates a unique testnet account via NEAR Testnet Faucet
 * 3. Deploys lastkey_vault.wasm to NEAR Testnet
 * 4. Initializes the vault contract with owner, guardian, and backup addresses
 */

const fs = require('fs');
const path = require('path');
const nearAPI = require('near-api-js');

const { connect, keyStores, KeyPair } = nearAPI;

async function createTestnetAccount(accountId, publicKey) {
  console.log(`📡 Requesting testnet account creation: ${accountId}...`);
  
  // Try official NEAR testnet helper faucet
  const endpoints = [
    'https://helper.testnet.near.org/account',
    'https://testnet-api.kitwallet.app/account'
  ];

  for (const endpoint of endpoints) {
    try {
      console.log(`   Trying faucet endpoint: ${endpoint}`);
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          newAccountId: accountId,
          newAccountPublicKey: publicKey.toString()
        })
      });

      if (response.ok) {
        console.log(`   ✅ Account ${accountId} funded successfully!`);
        return true;
      } else {
        const text = await response.text();
        console.log(`   ⚠️ Faucet response: ${response.status} - ${text}`);
      }
    } catch (e) {
      console.log(`   ⚠️ Faucet fetch failed: ${e.message}`);
    }
  }

  throw new Error('All testnet faucets failed or rate limited');
}

async function deploy() {
  console.log('====================================================');
  console.log('🚀 LASTKEY TESTNET DEPLOYMENT ENGINE');
  console.log('====================================================\n');

  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const accountId = `lastkey-vault-${randomSuffix}.testnet`;
  const wasmPath = path.resolve(__dirname, '../contracts/vault/target/wasm32-unknown-unknown/release/lastkey_vault.wasm');

  if (!fs.existsSync(wasmPath)) {
    throw new Error(`WASM not found at: ${wasmPath}`);
  }

  const wasmSize = (fs.statSync(wasmPath).size / 1024).toFixed(1);
  console.log(`📦 Loaded WASM: ${wasmPath} (${wasmSize} KB)\n`);

  // 1. Generate KeyPair
  const keyPair = KeyPair.fromRandom('ed25519');
  console.log(`🔑 Generated Local Deployment Key:`);
  console.log(`   • Account ID:  ${accountId}`);
  console.log(`   • Public Key:  ${keyPair.getPublicKey().toString()}`);

  // 2. Fund via Faucet
  await createTestnetAccount(accountId, keyPair.getPublicKey());

  // 3. Connect to NEAR Testnet
  const keyStore = new keyStores.InMemoryKeyStore();
  await keyStore.setKey('testnet', accountId, keyPair);

  const config = {
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://rpc.testnet.near.org',
    walletUrl: 'https://testnet.mynearwallet.com',
    helperUrl: 'https://helper.testnet.near.org',
    explorerUrl: 'https://testnet.nearblocks.io'
  };

  const near = await connect(config);
  const account = await near.account(accountId);
  const balance = await account.getAccountBalance();
  console.log(`💰 Account Balance: ${(BigInt(balance.available) / 10n**24n).toString()} NEAR\n`);

  // 4. Deploy Contract
  console.log(`🚀 Deploying WASM binary to ${accountId}...`);
  const wasmBinary = fs.readFileSync(wasmPath);
  const deployResult = await account.deployContract(wasmBinary);
  console.log(`✅ Contract deployed! Transaction: ${deployResult.transaction.hash}`);

  // 5. Initialize Contract (LastKeyVault::new)
  console.log(`⚙️  Initializing Vault contract...`);
  const owner = 'mastrophot.testnet';
  const mpcContract = 'v1.signer-prod.testnet';

  const initArgs = {
    owner,
    mpc_contract: mpcContract,
    backup: {
      btc: 'tb1qug7ge5vzhslcywjqs62k5392uy7ta5klvd2f7c',
      evm: '0xbaF34172995c3a00bbA2Df888257c8d74E11E96e',
      sol: 'b3VPfLqD97c8o5K6hYgQB4kit7Z3tnWBnZK8wWU66G1',
      near: null
    },
    heirs: {
      btc: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
      evm: '0x1111111111111111111111111111111111111111',
      sol: '11111111111111111111111111111111',
      near: null
    },
    heartbeat_interval_ns: null, // default 90 days
    challenge_period_ns: null,   // default 7 days
    policy_timelock_ns: null     // default 72 hours
  };

  const initTx = await account.functionCall({
    contractId: accountId,
    methodName: 'new',
    args: initArgs,
    gas: '30000000000000', // 30 TGas
    attachedDeposit: '0'
  });

  console.log(`✅ Vault initialized! Tx: ${initTx.transaction.hash}\n`);

  // 6. Query State via View Method
  const vaultInfo = await account.viewFunction({
    contractId: accountId,
    methodName: 'get_vault_info',
    args: {}
  });

  console.log('====================================================');
  console.log('🎉 DEPLOYMENT & VERIFICATION COMPLETE!');
  console.log('====================================================');
  console.log(`Contract Account:   ${accountId}`);
  console.log(`State:              ${JSON.stringify(vaultInfo.state)}`);
  console.log(`Owner:              ${vaultInfo.owner}`);
  console.log(`Explorer Link:      https://testnet.nearblocks.io/address/${accountId}`);
  console.log('====================================================');

  // Save credentials locally for reference
  const credsDir = path.resolve(__dirname, '../.credentials');
  if (!fs.existsSync(credsDir)) fs.mkdirSync(credsDir);
  fs.writeFileSync(
    path.join(credsDir, `${accountId}.json`),
    JSON.stringify({ accountId, private_key: keyPair.toString(), publicKey: keyPair.getPublicKey().toString() }, null, 2)
  );
  console.log(`💾 Deployment credentials saved to: .credentials/${accountId}.json`);
}

deploy().catch(err => {
  console.error('❌ Deployment Failed:', err);
  process.exit(1);
});

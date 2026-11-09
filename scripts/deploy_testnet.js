/**
 * LastKey Bunker Testnet Deployment Script
 * 
 * 1. Generates an Ed25519 KeyPair
 * 2. Creates a unique testnet account via NEAR Testnet Faucet
 * 3. Deploys lastkey_vault.wasm to NEAR Testnet
 * 4. Initializes the multi-tenant vault contract with mpc_contract and default_relayer
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
  console.log('🚀 LASTKEY BUNKER TESTNET DEPLOYMENT ENGINE');
  console.log('====================================================\n');

  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const accountId = process.env.CONTRACT_ID || `lastkey-bunker-${randomSuffix}.testnet`;
  const wasmPath = path.resolve(__dirname, '../contracts/vault/target/wasm32-unknown-unknown/release/lastkey_vault.wasm');

  if (!fs.existsSync(wasmPath)) {
    throw new Error(`WASM not found at: ${wasmPath}`);
  }

  const wasmSize = (fs.statSync(wasmPath).size / 1024).toFixed(1);
  console.log(`📦 Loaded WASM: ${wasmPath} (${wasmSize} KB)\n`);

  // 1. Generate KeyPair & Persist Credentials Immediately (prevents key loss on RPC failure)
  const keyPair = KeyPair.fromRandom('ed25519');
  const credsDir = path.resolve(__dirname, '../.credentials');
  if (!fs.existsSync(credsDir)) fs.mkdirSync(credsDir, { recursive: true });
  fs.writeFileSync(
    path.join(credsDir, `${accountId}.json`),
    JSON.stringify({ accountId, private_key: keyPair.toString(), publicKey: keyPair.getPublicKey().toString() }, null, 2)
  );
  console.log(`🔑 Generated & Saved Local Deployment Key (.credentials/${accountId}.json):`);
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
    nodeUrl: process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
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
  console.log(`⚙️  Initializing Multi-Tenant Vault contract...`);
  const mpcContract = 'v1.signer-prod.testnet';
  const defaultRelayer = process.env.RELAYER_ACCOUNT_ID || `keeper.${accountId}`;

  const initArgs = {
    mpc_contract: mpcContract,
    default_relayer: defaultRelayer
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
  const registeredAccounts = await account.viewFunction({
    contractId: accountId,
    methodName: 'get_registered_accounts',
    args: {}
  });

  console.log('====================================================');
  console.log('🎉 DEPLOYMENT & VERIFICATION COMPLETE!');
  console.log('====================================================');
  console.log(`Contract Account:   ${accountId}`);
  console.log(`MPC Signer:         ${mpcContract}`);
  console.log(`Default Relayer:    ${defaultRelayer}`);
  console.log(`Registered Vaults:  ${registeredAccounts.length}`);
  console.log(`Explorer Link:      https://testnet.nearblocks.io/address/${accountId}`);
  console.log('====================================================');
}

deploy().catch(err => {
  console.error('❌ Deployment Failed:', err);
  process.exit(1);
});

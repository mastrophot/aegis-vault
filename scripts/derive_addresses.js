/**
 * Aegis — Multi-Chain Address Derivation Engine
 * Verifies deterministic foreign address derivation for Bitcoin, EVM, and Solana
 * via NEAR Chain Signatures MPC (v1.signer-prod.testnet)
 */

const { contracts, chainAdapters } = require('chainsig.js');
const { Connection } = require('@solana/web3.js');

async function deriveAllVaultAddresses(accountId = 'aegis.okgoogleok.testnet', path = 'aegis/v0', networkId = 'testnet') {
  console.log(`\n🔑 Deriving Vault Addresses via NEAR MPC (${networkId.toUpperCase()})`);
  console.log(`• NEAR Vault Contract: ${accountId}`);
  console.log(`• Derivation Path:     ${path}\n`);

  const contract = new contracts.ChainSignatureContract({
    networkId,
    contractId: networkId === 'mainnet' ? 'v1.signer' : 'v1.signer-prod.testnet',
    fallbackRpcUrls: [networkId === 'mainnet' ? 'https://free.rpc.fastnear.com' : 'https://test.rpc.fastnear.com']
  });

  // 1. EVM (Ethereum / Base / Arbitrum / Polygon)
  const evmAdapter = new chainAdapters.evm.EVM({ contract });
  const evm = await evmAdapter.deriveAddressAndPublicKey(accountId, path);

  // 2. Bitcoin (Native SegWit P2WPKH)
  const btcAdapter = new chainAdapters.btc.Bitcoin({
    network: networkId === 'mainnet' ? 'mainnet' : 'testnet',
    contract,
    btcRpcAdapter: new chainAdapters.btc.BTCRpcAdapter({ network: networkId === 'mainnet' ? 'mainnet' : 'testnet' })
  });
  const btc = await btcAdapter.deriveAddressAndPublicKey(accountId, path);

  // 3. Solana (Ed25519 Native)
  const solAdapter = new chainAdapters.solana.Solana({
    contract,
    solanaConnection: new Connection(networkId === 'mainnet' ? 'https://api.mainnet-beta.solana.com' : 'https://api.devnet.solana.com')
  });
  const sol = await solAdapter.deriveAddressAndPublicKey(accountId, path);

  const result = {
    evm: { address: evm.address, publicKey: evm.publicKey },
    btc: { address: btc.address, publicKey: btc.publicKey },
    sol: { address: sol.address, publicKey: sol.publicKey }
  };

  console.log('✅ EVM Address (Base / Sepolia / ETH):', result.evm.address);
  console.log('✅ Bitcoin Address (P2WPKH SegWit):  ', result.btc.address);
  console.log('✅ Solana Address (Ed25519 Native):  ', result.sol.address);
  console.log('\n🔒 Private keys for these addresses do not exist anywhere — only NEAR MPC threshold consensus can sign for them.');

  return result;
}

if (require.main === module) {
  const accountId = process.argv[2] || 'aegis.okgoogleok.testnet';
  const path = process.argv[3] || 'aegis/v0';
  const networkId = process.argv[4] || 'testnet';
  deriveAllVaultAddresses(accountId, path, networkId)
    .then(() => process.exit(0))
    .catch(err => {
      console.error('❌ Derivation error:', err);
      process.exit(1);
    });
}

module.exports = { deriveAllVaultAddresses };

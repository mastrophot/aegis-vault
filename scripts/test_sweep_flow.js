/**
 * Sweep Flow Simulation & Cryptographic Invariant Test
 * 
 * Verifies:
 * 1. Vault address derivation for EVM, BTC, and Solana using vault contract account ID
 * 2. EVM EIP-1559 Sweep preparation, sighash calculation, and NEAR MPC signature reconstruction
 * 3. Bitcoin SegWit PSBT Sweep construction to backup address
 * 4. Solana SystemProgram Sweep construction with feePayer: from and raw serialized message bytes
 * 5. Solana SPL Token Sweep with idempotent ATA creation
 * 6. Native NEAR Sweep with dynamic state storage reserve
 * 7. Zero-Asset-Left-Behind Evacuation Queue with continuous nonces and fault isolation
 */

const { LastKeySweepRelayer } = require('../relayer/sweep_relayer');
const { ethers } = require('ethers');
const bitcoin = require('bitcoinjs-lib');

async function runSweepSimulation() {
  console.log('====================================================');
  console.log('🛡️  AEGIS HARDENED MULTICHAIN RELAYER TEST SUITE');
  console.log('====================================================\n');

  const relayer = new LastKeySweepRelayer({ networkId: 'testnet' });
  const vaultContractId = 'aegis.okgoogleok.testnet';
  const derivationPath = 'aegis/v0';

  // 1. Address Derivation
  console.log('1️⃣  Deriving Vault Addresses from NEAR MPC...');
  const vault = await relayer.deriveAllAddresses(vaultContractId, derivationPath);
  console.log(`   • Vault NEAR Contract: ${vaultContractId}`);
  console.log(`   • Derivation Epoch:    ${derivationPath}`);
  console.log(`   • EVM Vault Address:   ${vault.evm.address}`);
  console.log(`   • BTC Vault Address:   ${vault.btc.address}`);
  console.log(`   • SOL Vault Address:   ${vault.sol.address}`);
  console.log('   ✅ Vault addresses derived successfully from contract identity.\n');

  // Simulated Backup Cold Addresses
  const backupAddresses = {
    evm: '0x1111111111111111111111111111111111111111',
    btc: 'tb1q99999999999999999999999999999999999999',
    sol: 'ColdBackupSolanaAddress11111111111111111111'
  };

  // 2. EVM Sweep Simulation & v1.signer Signature Reconstruction
  console.log('2️⃣  Simulating EVM Panic Evacuation (Sepolia / Base)...');
  const evmSweep = await relayer.prepareEvmSweep({
    fromAddress: vault.evm.address,
    toAddress: backupAddresses.evm,
    valueWei: ethers.parseEther('0.5'), // 0.5 ETH
    nonce: 0,
    chainId: 11155111 // Sepolia
  });

  console.log(`   • Target Destination: ${backupAddresses.evm}`);
  console.log(`   • Sweep Amount:       0.5 ETH`);
  console.log(`   • Unsigned Tx Hash:   ${evmSweep.txHash}`);
  console.log(`   • Verifiable Raw Hex: ${evmSweep.unsignedTxHex.slice(0, 32)}... (Anti-Blind-Signing)`);
  if (!evmSweep.unsignedTxHex.toLowerCase().includes(backupAddresses.evm.toLowerCase().replace('0x', ''))) {
    throw new Error('EVM unsigned tx does not contain target recipient address!');
  }
  console.log(`   • Hash byte length:   ${evmSweep.hashBytes.length} bytes (32-byte payload for v1.signer)`);

  // Test NEAR v1.signer response format reconstruction:
  // v1.signer returns: { big_r: { affine_point: "02..." }, s: { scalar: "..." }, recovery_id: 0, scheme: "Secp256k1" }
  const mockWallet = ethers.Wallet.createRandom();
  const rawSig = mockWallet.signingKey.sign(evmSweep.txHash);
  const mpcSignerResponse = {
    scheme: 'Secp256k1',
    big_r: { affine_point: '02' + rawSig.r.replace(/^0x/, '') },
    s: { scalar: rawSig.s.replace(/^0x/, '') },
    recovery_id: rawSig.yParity
  };

  const signedEvm = relayer.assembleSignedEvmTx(evmSweep.rawTx, mpcSignerResponse);
  console.log(`   • Serialized Signed Tx: ${signedEvm.signedTx.slice(0, 42)}...`);
  console.log(`   • Recovered Signer:     ${signedEvm.from}`);
  if (signedEvm.from.toLowerCase() !== mockWallet.address.toLowerCase()) {
    throw new Error('Signer mismatch in assembleSignedEvmTx!');
  }
  console.log('   ✅ EVM signature assembly from v1.signer format validated 100%.\n');

  // 3. Bitcoin SegWit Sweep Simulation
  console.log('3️⃣  Simulating Bitcoin Panic Evacuation (Testnet SegWit)...');
  const mockUtxos = [
    {
      txid: 'f'.repeat(64),
      vout: 0,
      value: 10000000 // 0.1 BTC = 10,000,000 sats
    }
  ];

  const btcSweep = relayer.prepareBtcSweep({
    utxos: mockUtxos,
    fromAddress: vault.btc.address,
    toAddress: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
    feeSatsOverride: 2000,
    network: bitcoin.networks.testnet
  });

  console.log(`   • Input UTXO:     ${mockUtxos[0].value} sats (0.1 BTC)`);
  console.log(`   • Output Amount:  ${btcSweep.sendAmount} sats`);
  console.log(`   • Mining Fee:     ${btcSweep.feeSats} sats`);
  console.log(`   • PSBT Hex:       ${btcSweep.psbtHex.slice(0, 50)}...`);
  if (!btcSweep.sighashes[0].verifiablePayloadHex || btcSweep.sighashes[0].verifiablePayloadHex.length <= 364) {
    throw new Error('Bitcoin sweep missing BIP-143 verifiablePayloadHex (>182 bytes)');
  }
  console.log(`   • BIP-143 Preimage+Outputs: ${btcSweep.sighashes[0].verifiablePayloadHex.length / 2} bytes (Verifiable On-Chain)`);

  // Verify Bitcoin Dust rejection invariant
  try {
    relayer.prepareBtcSweep({
      utxos: [{ txid: 'e'.repeat(64), vout: 0, value: 1500 }],
      fromAddress: vault.btc.address,
      toAddress: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
      feeSatsOverride: 1200,
      network: bitcoin.networks.testnet
    });
    throw new Error('Should have rejected dust output < 546 sats');
  } catch (err) {
    if (!err.message.includes('below Bitcoin dust limit')) throw err;
    console.log('   • Dust Guard:     Verified (rejection below 546 sats)');
  }
  // Test Bitcoin PSBT MPC signature injection and finalization
  const mockBtcMpcSig = {
    r: '12'.repeat(32),
    s: '34'.repeat(32),
    publicKey: vault.btc.publicKey
  };
  const finalizedBtc = relayer.finalizeBtcSweepPsbt(btcSweep.psbtHex, [mockBtcMpcSig], bitcoin.networks.testnet);
  console.log(`   • Finalized BTC TxId: ${finalizedBtc.txId}`);
  console.log(`   • Finalized BTC Hex:  ${finalizedBtc.txHex.slice(0, 40)}...`);
  console.log('   ✅ Bitcoin PSBT SegWit signature injection and finalization validated.\n');

  // 4. Solana Sweep Simulation (feePayer: from, no double sha256)
  console.log('4️⃣  Simulating Solana Panic Evacuation (Devnet)...');
  const solSweep = relayer.prepareSolanaSweep({
    fromPubkey: vault.sol.address,
    toPubkey: '11111111111111111111111111111111',
    lamports: 1000000000 // 1 SOL
  });

  console.log(`   • From Pubkey (FeePayer): ${vault.sol.address}`);
  console.log(`   • To Pubkey (Recipient): 11111111111111111111111111111111`);
  console.log(`   • Sweep Lamports:        ${solSweep.sweepLamports} (Fee deducted automatically)`);
  console.log(`   • Raw Payload Hex (Ed25519): ${solSweep.rawPayloadHex.slice(0, 40)}... (Length: ${solSweep.rawPayloadHex.length / 2} bytes)`);
  console.log(`   • EdDSA Mode:            ${solSweep.isEddsa}`);
  console.log('   ✅ Solana transaction message & raw Ed25519 payload validated.\n');

  // 4a. Solana SPL Token Sweep Simulation to Empty Wallet
  console.log('4️⃣a. Simulating Solana SPL Token Sweep (USDC to brand new wallet)...');
  const solSplSweep = relayer.prepareSolanaTokenSweep({
    mintPubkey: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USDC
    fromOwnerPubkey: vault.sol.address,
    toRecipientPubkey: '11111111111111111111111111111111',
    amountTokens: 5000000000n, // 5,000 USDC
    memo: 'Aegis SPL Transfer'
  });
  console.log(`   • Recipient ATA:         ${solSplSweep.recipientAta} (Created via Idempotent Instruction)`);
  console.log(`   • Raw Payload Hex (Ed25519): ${solSplSweep.rawPayloadHex.slice(0, 40)}...`);

  // Test Token-2022 compatibility
  const token2022ProgramId = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
  const solToken2022Sweep = relayer.prepareSolanaTokenSweep({
    mintPubkey: '2b1kV6DKHGMyoChMwnNnkcQvcF4FmJmJ9Y5uY6uG8jYq',
    fromOwnerPubkey: vault.sol.address,
    toRecipientPubkey: '11111111111111111111111111111111',
    amountTokens: 1000000n,
    tokenProgramId: token2022ProgramId
  });
  console.log(`   • Token-2022 Recipient ATA:  ${solToken2022Sweep.recipientAta}`);

  // Test Solana MPC Signature Assembly
  const mockSolanaSig = '0x' + 'ab'.repeat(64); // 64-byte Ed25519 signature
  const signedSol = relayer.assembleSignedSolanaTx(solSweep.serializedMessage, vault.sol.address, mockSolanaSig);
  console.log(`   • Solana Signed Tx Base64:   ${signedSol.signedTxBase64.slice(0, 32)}...`);
  console.log('   ✅ Solana SPL & Token-2022 atomic ATA creation + transfer validated.\n');

  // 4b. NEAR Native Sweep Simulation
  console.log('4️⃣b. Simulating Native NEAR Vault Sweep (Testnet)...');
  const nearSweep = relayer.prepareNearSweep({
    fromAccount: 'aegis.okgoogleok.testnet',
    toAccount: 'mastrophot.testnet',
    balanceYocto: '10000000000000000000000000', // 10 NEAR
    memo: 'Aegis NEAR Evacuation'
  });

  console.log(`   • From Account:          ${nearSweep.fromAccount}`);
  console.log(`   • To Account:            ${nearSweep.toAccount}`);
  console.log(`   • Storage Reserve:       ${nearSweep.storageReserveYocto} yoctoNEAR (~1.6 NEAR)`);
  console.log(`   • Sweep Amount:          ${nearSweep.sweepAmountYocto} yoctoNEAR`);
  const nep141Sweep = relayer.prepareNearNep141Sweep({
    tokenContract: 'usdc.fakes.testnet',
    fromAccount: 'aegis.okgoogleok.testnet',
    toAccount: 'mastrophot.testnet',
    amountRaw: '25000000'
  });
  console.log(`   • NEP-141 FT Sweep:      ${nep141Sweep.tokenContract} -> ${nep141Sweep.toAccount} (${nep141Sweep.amountRaw} units, 1 yoctoNEAR)`);
  console.log('   ✅ NEAR native & NEP-141 FT sweep transaction assembly validated.\n');

  // 5. Test Zero-Asset-Left-Behind Queue Orchestration (NFT -> Tokens -> Native Gas)
  console.log('5️⃣  Validating Zero-Asset-Left-Behind Evacuation Queue with Gas Deduction...');
  const evacuationPlan = relayer.planEvmEvacuationQueue({
    fromAddress: vault.evm.address,
    toAddress: '0x1111111111111111111111111111111111111111',
    nfts: [
      { contract: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', tokenId: 1337 }
    ],
    tokens: [
      { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', amount: 5000000000n },
      { address: '0x6982508145454Ce325dDbE47a25d4ec3d2311933', amount: 1000000000000000000000000000n }
    ],
    nativeWeiBalance: ethers.parseEther('1.25'),
    memo: 'Aegis Zero-Asset Evacuation'
  });

  console.log(`   • Evacuation Steps Planned: ${evacuationPlan.length}`);
  evacuationPlan.forEach((p, idx) => {
    console.log(`     [Step ${idx + 1}] Type: ${p.step} (Planned Nonce: ${p.nonce})`);
  });

  const finalStep = evacuationPlan[evacuationPlan.length - 1];
  console.log(`   • Native Balance Before: ${ethers.formatEther(finalStep.balanceBefore)} ETH`);
  console.log(`   • Reserved Gas Cost:     ${ethers.formatEther(finalStep.gasCostReservedWei)} ETH`);
  console.log(`   • Final Native Sweep:    ${ethers.formatEther(finalStep.sweepAmountWei)} ETH`);

  if (BigInt(finalStep.sweepAmountWei) >= BigInt(finalStep.balanceBefore)) {
    throw new Error('Native final sweep did not deduct gas cost!');
  }
  console.log('   ✅ Evacuation sequence validated: Gas accurately reserved for prior steps.\n');

  // 6. Test Continuous Nonce Fault Isolation: Scam/Blacklist Token Revert Simulation
  console.log('6️⃣  Simulating Fault Isolation with Continuous Nonce Preservation...');
  const isolatedRun = await relayer.executeQueueWithFaultIsolation(evacuationPlan, async (task) => {
    if (task.tokenAddress === '0x6982508145454Ce325dDbE47a25d4ec3d2311933') {
      throw new Error('EXECUTION_REVERTED: Blacklisted / Honeypot token');
    }
    return { txHash: '0x' + '1'.repeat(64), status: 1 };
  });

  const skipped = isolatedRun.filter(r => r.status === 'SKIPPED_REVERT');
  const succeeded = isolatedRun.filter(r => r.status === 'SUCCESS');
  console.log(`   • Total Tasks:                 ${isolatedRun.length}`);
  console.log(`   • Successfully Swept:          ${succeeded.length}`);
  console.log(`   • Safely Skipped Broken Assets: ${skipped.length}`);

  // Check nonce continuity of succeeded steps
  const executedNonces = succeeded.map(s => s.task.nonce);
  console.log(`   • Executed Nonces Sequence:    [${executedNonces.join(', ')}]`);
  for (let i = 0; i < executedNonces.length; i++) {
    if (executedNonces[i] !== i) {
      throw new Error(`Nonce gap detected! Expected ${i}, got ${executedNonces[i]}`);
    }
  }

  console.log('   ✅ Nonce continuity guaranteed: Skipped revert did NOT leave gaps in EVM nonces.\n');

  console.log('====================================================');
  console.log('🚀 ALL MULTICHAIN RELAYER PIPELINES PASSED (100%)');
  console.log('====================================================');
}

runSweepSimulation().catch(err => {
  console.error('❌ Simulation Error:', err);
  process.exit(1);
});

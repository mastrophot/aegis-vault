#!/usr/bin/env node
/**
 * Offline Zero-Server CLI Decryption Helper for Aegis E2EE Heir Testaments
 *
 * Supports:
 * 1) `enc:x25519:<base64>` — decrypts using Heir's Solana / NEAR Ed25519 secret key
 *    (Base58 private key, Solana `id.json` 64-byte array, `ed25519:...`, or 64-char hex seed)
 * 2) `enc:aes256:<base64>` — decrypts using PBKDF2-SHA256 + AES-256-GCM passphrase
 *
 * Usage:
 *   node scripts/decrypt_testament.js "<enc:x25519:...>" "<solana_secret_key_or_json>"
 *   node scripts/decrypt_testament.js "<enc:aes256:...>" "<passphrase>"
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const bs58Pkg = require('bs58');
const { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } = require('@noble/curves/ed25519');

const bs58Decode = bs58Pkg.decode || (bs58Pkg.default && bs58Pkg.default.decode);

function parseEd25519PubKey(pubKeyStr) {
  const clean = String(pubKeyStr || '').trim().replace(/^ed25519:/i, '');
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    return Uint8Array.from(Buffer.from(clean, 'hex'));
  }
  const decoded = bs58Decode(clean);
  if (decoded.length !== 32) {
    throw new Error('Recipient Ed25519 public key must decode to 32 bytes');
  }
  return new Uint8Array(decoded);
}

function parseEd25519SecretSeed(secretInput) {
  const raw = String(secretInput || '').trim().replace(/^ed25519:/i, '').replace(/^0x/i, '');
  if (raw.startsWith('[') && raw.endsWith(']')) {
    const arr = JSON.parse(raw);
    return new Uint8Array(arr.slice(0, 32));
  }
  if (/^[0-9a-fA-F]{64}$/.test(raw) || /^[0-9a-fA-F]{128}$/.test(raw)) {
    return Uint8Array.from(Buffer.from(raw.slice(0, 64), 'hex'));
  }
  const decoded = bs58Decode(raw);
  if (decoded.length === 64 || decoded.length === 32) {
    return new Uint8Array(decoded.slice(0, 32));
  }
  throw new Error('Invalid Ed25519 secret key format');
}

function encryptTestamentX25519(plainText, recipientEd25519Pub) {
  const edPub = parseEd25519PubKey(recipientEd25519Pub);
  const x25519Pub = edwardsToMontgomeryPub(edPub);
  const ephem = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const cipher = nacl.box(Buffer.from(String(plainText), 'utf8'), nonce, x25519Pub, ephem.secretKey);
  return 'enc:x25519:' + Buffer.concat([
    Buffer.from(ephem.publicKey),
    Buffer.from(nonce),
    Buffer.from(cipher)
  ]).toString('base64');
}

function decryptTestamentX25519(envelope, secretInput) {
  const packed = Buffer.from(String(envelope).trim().slice('enc:x25519:'.length), 'base64');
  const ephemPub = new Uint8Array(packed.subarray(0, 32));
  const nonce = new Uint8Array(packed.subarray(32, 56));
  const cipher = new Uint8Array(packed.subarray(56));
  const seed32 = parseEd25519SecretSeed(secretInput);
  const x25519Sec = edwardsToMontgomeryPriv(seed32);
  const opened = nacl.box.open(cipher, nonce, ephemPub, x25519Sec);
  if (!opened) throw new Error('Decryption failed: wrong secret key or corrupted ciphertext');
  return Buffer.from(opened).toString('utf8');
}

async function encryptTestamentPassphrase(plainText, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(String(passphrase), salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'enc:aes256:' + Buffer.concat([salt, iv, enc, tag]).toString('base64');
}

async function decryptTestamentPassphrase(envelope, passphrase) {
  const packed = Buffer.from(String(envelope).trim().slice('enc:aes256:'.length), 'base64');
  const salt = packed.subarray(0, 16);
  const iv = packed.subarray(16, 28);
  const body = packed.subarray(28, packed.length - 16);
  const tag = packed.subarray(packed.length - 16);
  const key = crypto.pbkdf2Sync(String(passphrase), salt, 100000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(body), decipher.final()]);
  return dec.toString('utf8');
}

if (require.main === module) {
  const [envelope, secret] = process.argv.slice(2);
  if (!envelope || !secret) {
    console.log('Usage: node scripts/decrypt_testament.js "<enc:x25519:... | enc:aes256:...>" "<secretKey_or_passphrase>"');
    process.exit(1);
  }
  (async () => {
    if (envelope.startsWith('enc:x25519:')) {
      console.log(decryptTestamentX25519(envelope, secret));
    } else if (envelope.startsWith('enc:aes256:')) {
      console.log(await decryptTestamentPassphrase(envelope, secret));
    } else {
      throw new Error('Unsupported ciphertext prefix');
    }
  })().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

module.exports = {
  encryptTestamentX25519,
  decryptTestamentX25519,
  encryptTestamentPassphrase,
  decryptTestamentPassphrase
};

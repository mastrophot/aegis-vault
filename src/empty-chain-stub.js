// Lightweight browser stub for unused chains (Cosmos, Aptos, Sui, XRP) and viem shim in chainsig.js
import { keccak256 as ethersKeccak256, getAddress as ethersGetAddress } from "ethers";

export const keccak256 = (data) => ethersKeccak256(Uint8Array.from(data));
export const getAddress = (addr) => ethersGetAddress(addr);
export const concatHex = () => "0x";
export const numberToHex = () => "0x0";
export const serializeTransaction = () => "0x";
export const parseTransaction = () => ({});
export const toBytes = () => new Uint8Array();
export const hashMessage = () => "0x";
export const hashTypedData = () => "0x";
export const encodeAbiParameters = () => "0x";
export const hexToBigInt = (h) => BigInt(h || 0);
export const concat = () => new Uint8Array();
export const pad = () => new Uint8Array();
export const isAddress = () => true;
export const hashAuthorization = () => "0x";

export const chains = [];
export const assets = [];
export const encodeSecp256k1Pubkey = () => ({});
export const sha256 = () => new Uint8Array();
export const ripemd160 = () => new Uint8Array();
export const fromHex = () => new Uint8Array();
export const toBase64 = () => "";
export const fromBase64 = () => new Uint8Array();
export class Registry {}
export const encodePubkey = () => ({});
export const makeAuthInfoBytes = () => new Uint8Array();
export const makeSignDoc = () => ({});
export const makeSignBytes = () => new Uint8Array();
export const calculateFee = () => ({ amount: [], gas: "0" });
export const GasPrice = { fromString: () => ({}) };
export const StargateClient = { connect: async () => ({}) };
export const SignMode = { SIGN_MODE_DIRECT: 1 };
export const TxRaw = { encode: () => ({ finish: () => new Uint8Array() }), decode: () => ({}), fromPartial: () => ({}) };
export class Ed25519PublicKey {}
export class Deserializer {}
export const MultiAgentTransaction = { deserialize: () => ({}) };
export const SimpleTransaction = { deserialize: () => ({}) };
export const generateSigningMessageForTransaction = () => new Uint8Array();
export class AccountAuthenticatorEd25519 {}
export class Ed25519Signature {}
export const generateSignedTransaction = () => new Uint8Array();
export const SignedTransaction = { deserialize: () => ({}) };
export const postAptosFullNode = async () => ({ data: {} });
export const MimeType = { BCS_SIGNED_TRANSACTION: "" };
export class KeylessPublicKey {}
export class FederatedKeylessPublicKey {}
export const AbstractKeylessAccount = { fetchJWK: async () => {} };
export class SuiHTTPTransport {}
export const messageWithIntent = () => new Uint8Array();
export const toSerializedSignature = () => "";
export const encodeAccountID = () => "";
export const encode = () => "";
export class Client {}
export default {};

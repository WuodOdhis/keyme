/**
 * BIP32 for the signer's paired account.
 *
 * Only what PSCT needs: master from seed, hardened and normal private derivation, public
 * derivation, and xpub serialization (Base58Check). Validated against the BIP32 test vectors.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, concat, hexToBytes } from "./bytes.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const N = secp256k1.CURVE.n;
const HARDENED = 0x80000000;

export interface Node {
  privateKey?: bigint;
  publicKey: Uint8Array;
  chainCode: Uint8Array;
  depth: number;
  parentFingerprint: number;
  childNumber: number;
}

function bytesToNumber(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function numberToBytes(n: bigint, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

export function fingerprint(publicKey: Uint8Array): number {
  const h = hash160(publicKey);
  return ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
}

export function masterFromSeed(seed: Uint8Array): Node {
  const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), seed);
  const privateKey = bytesToNumber(I.slice(0, 32));
  if (privateKey === 0n || privateKey >= N) throw new Error("invalid master key");
  return {
    privateKey,
    publicKey: secp256k1.getPublicKey(numberToBytes(privateKey), true),
    chainCode: I.slice(32),
    depth: 0,
    parentFingerprint: 0,
    childNumber: 0,
  };
}

function derivePrivateNode(parent: Node, index: number): Node {
  if (parent.privateKey === undefined) throw new Error("private derivation requires a private parent");
  if (index < 0 || index > 0xffffffff) throw new Error("bad child index");
  const data =
    index >= HARDENED
      ? concat(Uint8Array.of(0), numberToBytes(parent.privateKey), numberToBytes(BigInt(index), 4))
      : concat(parent.publicKey, numberToBytes(BigInt(index), 4));
  const I = hmac(sha512, parent.chainCode, data);
  const il = bytesToNumber(I.slice(0, 32));
  if (il >= N) throw new Error("invalid child key");
  const child = (il + parent.privateKey) % N;
  if (child === 0n) throw new Error("invalid child key");
  return {
    privateKey: child,
    publicKey: secp256k1.getPublicKey(numberToBytes(child), true),
    chainCode: I.slice(32),
    depth: parent.depth + 1,
    parentFingerprint: fingerprint(parent.publicKey),
    childNumber: index,
  };
}

function derivePublicNode(parent: Node, index: number): Node {
  if (index >= HARDENED) throw new Error("cannot derive hardened children from a public key");
  const data = concat(parent.publicKey, numberToBytes(BigInt(index), 4));
  const I = hmac(sha512, parent.chainCode, data);
  const il = bytesToNumber(I.slice(0, 32));
  if (il >= N) throw new Error("invalid child key");
  const point = secp256k1.ProjectivePoint.fromHex(parent.publicKey).add(
    secp256k1.ProjectivePoint.fromPrivateKey(numberToBytes(il)),
  );
  return {
    publicKey: point.toRawBytes(true),
    chainCode: I.slice(32),
    depth: parent.depth + 1,
    parentFingerprint: fingerprint(parent.publicKey),
    childNumber: index,
  };
}

export function parsePath(path: string): number[] {
  if (path === "m" || path === "") return [];
  const parts = path.replace(/^m\//, "").split("/");
  return parts.map((p) => {
    const hardened = p.endsWith("'") || p.endsWith("h");
    const n = Number(hardened ? p.slice(0, -1) : p);
    if (!Number.isInteger(n) || n < 0 || n >= HARDENED) throw new Error(`bad path element ${p}`);
    return hardened ? n + HARDENED : n;
  });
}

export function derivePrivate(node: Node, path: string): Node {
  return parsePath(path).reduce((n, i) => derivePrivateNode(n, i), node);
}

export function derivePublic(node: Node, path: string): Node {
  return parsePath(path).reduce((n, i) => derivePublicNode(n, i), node);
}

// ---------------------------------------------------------------- xpub

const VERSION = { mainnet: 0x0488b21e, testnet: 0x043587cf };

function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).slice(0, 4);
}

function base58Encode(bytes: Uint8Array): string {
  let n = bytesToNumber(bytes);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out || "1";
}

function base58Decode(text: string): Uint8Array {
  let n = 0n;
  for (const c of text) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 character ${c}`);
    n = n * 58n + BigInt(i);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const c of text) {
    if (c !== "1") break;
    zeros++;
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...body]);
}

export function encodeXpub(node: Node, network: "mainnet" | "testnet" = "mainnet"): string {
  if (node.privateKey !== undefined) throw new Error("refusing to serialize a private node as xpub");
  const payload = concat(
    numberToBytes(BigInt(VERSION[network]), 4),
    Uint8Array.of(node.depth),
    numberToBytes(BigInt(node.parentFingerprint), 4),
    numberToBytes(BigInt(node.childNumber), 4),
    node.chainCode,
    node.publicKey,
  );
  return base58Encode(concat(payload, checksum(payload)));
}

export function decodeXpub(text: string): Node {
  const raw = base58Decode(text.trim());
  if (raw.length !== 82) throw new Error(`xpub must be 82 bytes, got ${raw.length}`);
  const payload = raw.slice(0, 78);
  const check = raw.slice(78);
  const expected = checksum(payload);
  for (let i = 0; i < 4; i++) if (check[i] !== expected[i]) throw new Error("xpub checksum mismatch");
  const version = Number(bytesToNumber(payload.slice(0, 4)));
  if (version !== VERSION.mainnet && version !== VERSION.testnet) throw new Error("unknown xpub version");
  return {
    publicKey: payload.slice(45, 78),
    chainCode: payload.slice(13, 45),
    depth: payload[4]!,
    parentFingerprint: Number(bytesToNumber(payload.slice(5, 9))),
    childNumber: Number(bytesToNumber(payload.slice(9, 13))),
  };
}

export function privateKeyHex(node: Node): string {
  if (node.privateKey === undefined) throw new Error("no private key");
  return bytesToHex(numberToBytes(node.privateKey));
}

export function toPublic(node: Node): Node {
  const { privateKey, ...rest } = node;
  void privateKey;
  return rest;
}

export function seedFromHex(hex: string): Uint8Array {
  return hexToBytes(hex.startsWith("0x") ? hex : `0x${hex}`);
}

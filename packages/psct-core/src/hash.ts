/** CKB hashing: blake2b-256 with the "ckb-default-hash" personalisation. */

import { blake2b } from "@noble/hashes/blake2b";
import { encodeRawTransaction, encodeScript, type Script, type Transaction } from "./ckb.js";
import { bytesToHex } from "./bytes.js";

const PERSONAL = new TextEncoder().encode("ckb-default-hash");

export function ckbHash(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32, personalization: PERSONAL });
}

export function blake160(data: Uint8Array): Uint8Array {
  return ckbHash(data).slice(0, 20);
}

/** tx_hash = blake2b(molecule(RawTransaction)) — witnesses are not part of it. */
export function txHash(tx: Transaction): string {
  return bytesToHex(ckbHash(encodeRawTransaction(tx)));
}

export function scriptHash(s: Script): string {
  return bytesToHex(ckbHash(encodeScript(s)));
}

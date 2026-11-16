/** secp256k1 helpers shared by the single-key and multisig profiles. */

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, concat } from "./bytes.js";
import { blake160 } from "./hash.js";

export function recoverPubkey(message: Uint8Array, sig65: Uint8Array): Uint8Array {
  if (sig65.length !== 65) throw new Error(`expected 65-byte signature, got ${sig65.length}`);
  const compact = concat(sig65.slice(0, 32), sig65.slice(32, 64));
  const recid = sig65[64]!;
  const sig = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recid);
  return sig.recoverPublicKey(message).toRawBytes(true);
}

/** blake160 of the compressed public key, as hex. */
export function pubkeyHash(sig65: Uint8Array, message: Uint8Array): string {
  return bytesToHex(blake160(recoverPubkey(message, sig65)));
}

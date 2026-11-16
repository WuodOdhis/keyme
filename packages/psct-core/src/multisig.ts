/**
 * Legacy secp256k1-blake160 multisig lock (`secp256k1_blake160_multisig_all.c`).
 *
 * Rules derived from the lock source, not from documentation:
 *
 *   script args  = blake160(multisig_script) [20 bytes] + optional since [8 bytes LE]
 *   multisig_script = [0][require_first_n][threshold][pubkeys_cnt][pubkey_hash × n]
 *   witness lock = multisig_script + [signature × threshold]      (exactly, no padding)
 *
 * The signing message is the sighash-all framing, but the placeholder is not 65 zero bytes:
 * the trailing `65 * threshold` bytes of the lock field are zeroed in place, so the witness
 * length and every table offset stay unchanged.
 *
 * Signatures are not required to be in pubkey order. The script recovers each one, matches it
 * against the first unused pubkey hash, then requires the first `require_first_n` positions to be
 * used. Canonical finalization should still order by pubkey position for determinism.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { blake160 } from "./hash.js";
import { sighashMessage, witnessLock, zeroSignatureRegion } from "./sighash.js";
import { pubkeyHash } from "./secp.js";
import type { Transaction } from "./ckb.js";

const SIGNATURE_SIZE = 65;
const BLAKE160_SIZE = 20;
const FLAGS_SIZE = 4;
const SINCE_VALUE_BITS = 56n;
const SINCE_VALUE_MASK = (1n << SINCE_VALUE_BITS) - 1n;
const SINCE_EPOCH_FLAG = 1n;

export interface MultisigScript {
  requireFirstN: number;
  threshold: number;
  pubkeys: string[];
  /** blake160 of the script part, as committed by the lock args. */
  scriptHash: string;
  since?: bigint;
}

export interface MultisigLock extends MultisigScript {
  signatures: Uint8Array[];
}

export function decodeMultisigArgs(argsHex: string): { scriptHash: string; since?: bigint } | null {
  const b = hexToBytes(argsHex);
  if (b.length !== BLAKE160_SIZE && b.length !== BLAKE160_SIZE + 8) return null;
  const scriptHash = bytesToHex(b.slice(0, BLAKE160_SIZE));
  if (b.length === BLAKE160_SIZE) return { scriptHash };
  let since = 0n;
  for (let i = 7; i >= 0; i--) since = (since << 8n) | BigInt(b[BLAKE160_SIZE + i]!);
  return { scriptHash, since };
}

export function decodeMultisigLock(lock: Uint8Array): MultisigLock | null {
  if (lock.length < FLAGS_SIZE) return null;
  const reserved = lock[0]!;
  const requireFirstN = lock[1]!;
  const threshold = lock[2]!;
  const count = lock[3]!;
  if (reserved !== 0 || count === 0 || threshold === 0) return null;
  if (threshold > count || requireFirstN > threshold) return null;

  const scriptLen = FLAGS_SIZE + BLAKE160_SIZE * count;
  const expected = scriptLen + SIGNATURE_SIZE * threshold;
  if (lock.length !== expected) return null;

  const pubkeys: string[] = [];
  for (let i = 0; i < count; i++) {
    pubkeys.push(bytesToHex(lock.slice(FLAGS_SIZE + i * BLAKE160_SIZE, FLAGS_SIZE + (i + 1) * BLAKE160_SIZE)));
  }
  const signatures: Uint8Array[] = [];
  for (let i = 0; i < threshold; i++) {
    const from = scriptLen + i * SIGNATURE_SIZE;
    signatures.push(lock.slice(from, from + SIGNATURE_SIZE));
  }
  return {
    requireFirstN,
    threshold,
    pubkeys,
    scriptHash: bytesToHex(blake160(lock.slice(0, scriptLen))),
    signatures,
  };
}

/** RFC-0017 epoch-with-fraction comparison, as implemented by the lock's utils.h. */
export function epochFractionCmp(a: bigint, b: bigint): number {
  const epoch = (v: bigint) => (v >> 0n) & ((1n << 24n) - 1n);
  const index = (v: bigint) => (v >> 24n) & ((1n << 16n) - 1n);
  const len = (v: bigint) => (v >> 40n) & ((1n << 16n) - 1n);
  const ae = epoch(a);
  const be = epoch(b);
  if (ae < be) return -1;
  if (ae > be) return 1;
  const al = len(a);
  const bl = len(b);
  const left = index(a) * bl;
  const right = index(b) * al;
  return left < right ? -1 : left > right ? 1 : 0;
}

/** The lock requires every group input's since to share the constraint's flags and be >= it. */
export function checkSince(tx: Transaction, groupIndices: number[], since: bigint): string | null {
  const flags = since >> SINCE_VALUE_BITS;
  const value = since & SINCE_VALUE_MASK;
  for (const idx of groupIndices) {
    const inputSince = tx.inputs[idx]!.since;
    const iFlags = inputSince >> SINCE_VALUE_BITS;
    const iValue = inputSince & SINCE_VALUE_MASK;
    if (iFlags !== flags) return `input ${idx}: since flags ${iFlags} != required ${flags}`;
    if (flags === SINCE_EPOCH_FLAG) {
      if (epochFractionCmp(iValue, value) < 0) return `input ${idx}: since epoch is earlier than required`;
    } else if (iValue < value) {
      return `input ${idx}: since ${iValue} is earlier than required ${value}`;
    }
  }
  return null;
}

export interface MultisigCheck {
  ok: boolean;
  reason?: string;
  script?: MultisigScript;
  /** Pubkey hashes whose signatures were present and matched. */
  signers?: string[];
}

/** Verify one multisig group against its real witness and the lock args. */
export function verifyMultisigGroup(
  tx: Transaction,
  groupIndices: number[],
  lockArgsHex: string,
): MultisigCheck {
  const args = decodeMultisigArgs(lockArgsHex);
  if (!args) return { ok: false, reason: "lock args are not 20 or 28 bytes" };

  const first = Math.min(...groupIndices);
  const lock = witnessLock(tx.witnesses[first] ?? "0x");
  if (!lock) return { ok: false, reason: `input ${first} carries no WitnessArgs lock` };

  const parsed = decodeMultisigLock(lock);
  if (!parsed) return { ok: false, reason: "witness lock is not a well-formed multisig script" };
  if (parsed.scriptHash.toLowerCase() !== args.scriptHash.toLowerCase()) {
    return { ok: false, reason: `script hash ${parsed.scriptHash} does not match lock args ${args.scriptHash}` };
  }

  if (args.since !== undefined) {
    const sinceError = checkSince(tx, groupIndices, args.since);
    if (sinceError) return { ok: false, reason: sinceError };
  }

  let message: Uint8Array;
  try {
    message = sighashMessage(tx, groupIndices, (w) =>
      zeroSignatureRegion(w, SIGNATURE_SIZE * parsed.threshold),
    );
  } catch (e) {
    return { ok: false, reason: `cannot build signing message: ${(e as Error).message}` };
  }

  const used = new Array(parsed.pubkeys.length).fill(false);
  const signers: string[] = [];
  for (const sig of parsed.signatures) {
    let hash: string;
    try {
      hash = pubkeyHash(sig, message);
    } catch (e) {
      return { ok: false, reason: `signature does not recover: ${(e as Error).message}` };
    }
    const i = parsed.pubkeys.findIndex((p, idx) => !used[idx] && p.toLowerCase() === hash);
    if (i < 0) return { ok: false, reason: `signature from ${hash} is not an unused signer` };
    used[i] = true;
    signers.push(hash);
  }

  for (let i = 0; i < parsed.requireFirstN; i++) {
    if (!used[i]) return { ok: false, reason: `require_first_n: signer ${i} did not sign` };
  }

  const script: MultisigScript = {
    requireFirstN: parsed.requireFirstN,
    threshold: parsed.threshold,
    pubkeys: parsed.pubkeys,
    scriptHash: parsed.scriptHash,
    since: args.since,
  };
  return { ok: true, script, signers };
}

/**
 * Assemble a witness lock from partial signatures.
 *
 * Signatures are placed by pubkey position, which is deterministic and satisfies
 * `require_first_n`. Callers pass signatures keyed by signer hash.
 */
export function assembleMultisigLock(
  script: MultisigScript,
  signaturesBySigner: Record<string, Uint8Array>,
): Uint8Array | null {
  const slots: (Uint8Array | null)[] = script.pubkeys.map(
    (p) => signaturesBySigner[p.toLowerCase()] ?? signaturesBySigner[p] ?? null,
  );
  const chosen = slots.filter((s): s is Uint8Array => s !== null);
  if (chosen.length < script.threshold) return null;
  for (let i = 0; i < script.requireFirstN; i++) if (!slots[i]) return null;

  const out = new Uint8Array(FLAGS_SIZE + BLAKE160_SIZE * script.pubkeys.length + SIGNATURE_SIZE * script.threshold);
  out[0] = 0;
  out[1] = script.requireFirstN;
  out[2] = script.threshold;
  out[3] = script.pubkeys.length;
  script.pubkeys.forEach((p, i) => out.set(hexToBytes(p), FLAGS_SIZE + i * BLAKE160_SIZE));
  chosen.slice(0, script.threshold).forEach((s, i) => out.set(s, FLAGS_SIZE + BLAKE160_SIZE * script.pubkeys.length + i * SIGNATURE_SIZE));
  return out;
}

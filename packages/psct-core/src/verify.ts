/** Signature verification: recover pubkey, compare blake160 to lock args. */

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, concat, hexToBytes } from "./bytes.js";
import { blake160 } from "./hash.js";
import { sighashAllMessage, witnessLock } from "./sighash.js";
import { classifyLock } from "./profiles.js";
import type { Script, Transaction } from "./ckb.js";

export function recoverPubkey(message: Uint8Array, sig65: Uint8Array): Uint8Array {
  if (sig65.length !== 65) throw new Error(`expected 65-byte signature, got ${sig65.length}`);
  const compact = concat(sig65.slice(0, 32), sig65.slice(32, 64));
  const recid = sig65[64]!;
  const sig = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recid);
  return sig.recoverPublicKey(message).toRawBytes(true);
}

export interface SigCheck {
  ok: boolean;
  lockArgs: string;
  recovered: string;
}

export function verifySighashAll(
  message: Uint8Array,
  sig65Hex: string,
  lockArgsHex: string,
): SigCheck {
  const sig = hexToBytes(sig65Hex);
  const pub = recoverPubkey(message, sig);
  const got = bytesToHex(blake160(pub));
  const want = lockArgsHex.toLowerCase();
  return { ok: got === want, lockArgs: want, recovered: got };
}

export type GroupVerdict =
  | "verified"
  | "no-profile"
  | "infrastructure"
  | "unknown-lock"
  | "no-signature"
  | "bad-signature";

export interface GroupResult {
  group: "lock" | "type";
  scriptHash: string;
  name: string;
  inputs: number[];
  profile: string | null;
  verdict: GroupVerdict;
  reason?: string;
}

/**
 * Verify every lock group. Unknown locks are refused, never guessed.
 * A group is "ok" only when its signature was actually recovered and matched.
 */
export function verifyTx(
  tx: Transaction,
  bound: { cellOutput: { lock: Script; type: Script | null } }[],
): GroupResult[] {
  const results: GroupResult[] = [];
  const groups = new Map<string, { indices: number[]; lock: Script }>();
  bound.forEach((b, i) => {
    const l = b.cellOutput.lock;
    const key = `${l.codeHash}|${l.hashType}|${l.args}`;
    const g = groups.get(key) ?? { indices: [], lock: l };
    g.indices.push(i);
    groups.set(key, g);
  });

  for (const [, { indices, lock }] of groups) {
    const uniq = [...new Set(indices)].sort((a, b) => a - b);
    const first = uniq[0]!;
    const p = classifyLock(lock);
    const base = {
      group: "lock" as const,
      scriptHash: lock.codeHash,
      name: p.name,
      inputs: uniq,
      profile: p.profile,
    };

    if (p.kind === "infrastructure") {
      results.push({ ...base, verdict: "infrastructure", reason: p.note ?? "L2 lock" });
      continue;
    }
    if (p.kind === "unknown") {
      results.push({ ...base, verdict: "unknown-lock", reason: "not in the registry" });
      continue;
    }
    if (p.profile === null) {
      results.push({ ...base, verdict: "no-profile", reason: p.note ?? "no verification profile" });
      continue;
    }

    const sig = witnessLock(tx.witnesses[first] ?? "0x");
    if (!sig || sig.length !== 65) {
      results.push({
        ...base,
        verdict: "no-signature",
        reason: `input ${first} carries no 65-byte lock field`,
      });
      continue;
    }
    const msg = sighashAllMessage(tx, uniq);
    const check = verifySighashAll(msg, bytesToHex(sig), lock.args);
    results.push(
      check.ok
        ? { ...base, verdict: "verified" }
        : { ...base, verdict: "bad-signature", reason: `recovered ${check.recovered}` },
    );
  }
  return results;
}

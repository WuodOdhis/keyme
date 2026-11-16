/** Signature verification: per lock group, one verdict each. Unknown locks are refused. */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { recoverPubkey } from "./secp.js";
import { blake160 } from "./hash.js";
import { sighashAllMessage, witnessLock } from "./sighash.js";
import { classifyLock, MULTISIG_PROFILE, MULTISIG_V2_PROFILE, SECP_PROFILE } from "./profiles.js";
import { verifyMultisigGroup } from "./multisig.js";
import type { Script, Transaction } from "./ckb.js";

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
  /** For multisig: signer pubkey hashes that were present. */
  signers?: string[];
}

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

    if (p.kind === "unknown") {
      results.push({ ...base, verdict: "unknown-lock", reason: "not in the registry" });
      continue;
    }
    if (p.profile === null) {
      results.push({ ...base, verdict: "no-profile", reason: p.note ?? "no verification profile" });
      continue;
    }

    if (p.profile === MULTISIG_PROFILE || p.profile === MULTISIG_V2_PROFILE) {
      const r = verifyMultisigGroup(tx, uniq, lock.args);
      results.push({
        ...base,
        verdict: r.ok ? "verified" : "bad-signature",
        reason: r.reason,
        signers: r.signers,
      });
      continue;
    }

    if (p.profile !== SECP_PROFILE) {
      results.push({ ...base, verdict: "no-profile", reason: `unimplemented profile ${p.profile}` });
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
    try {
      const msg = sighashAllMessage(tx, uniq);
      const check = verifySighashAll(msg, bytesToHex(sig), lock.args);
      results.push(
        check.ok
          ? { ...base, verdict: "verified", signers: [check.recovered] }
          : { ...base, verdict: "bad-signature", reason: `recovered ${check.recovered}` },
      );
    } catch (e) {
      results.push({
        ...base,
        verdict: "bad-signature",
        reason: `invalid signature: ${(e as Error).message}`,
      });
    }
  }
  return results;
}

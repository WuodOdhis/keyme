/**
 * Offline software signer.
 *
 *   signer show <file.psct.b64>
 *   signer sign <in.psct.b64> --privkey-file key.hex --out out.psct.b64 [--yes]
 *
 * The signer binds every input before displaying anything, refuses unsupported locks, and adds one
 * signature per script group it controls. It never trusts the hints in the file.
 */

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { secp256k1 } from "@noble/curves/secp256k1";

import { bytesToHex, concat, fmtCkb, hexToBytes } from "../bytes.js";
import { decodeRawTransaction, type Script, type Transaction } from "../ckb.js";
import { blake160, ckbHash, scriptHash } from "../hash.js";
import { classifyLock, classifyType, MULTISIG_PROFILE, MULTISIG_V2_PROFILE, SECP_PROFILE } from "../profiles.js";
import { bindAll } from "../psct/bind.js";
import { inspect } from "../psct/inspect.js";
import { encodeWitnessArgs, sighashMessage, zeroSignatureRegion, withZeroedLock } from "../sighash.js";
import { decodeMultisigLock } from "../multisig.js";
import { pubkeyHash } from "../secp.js";
import { encodeAddress } from "../address.js";
import {
  psctFingerprint,
  psctTransaction,
  psctTxHash,
  type Psct,
} from "../psct/container.js";
import { readPsctFile, writePsctFile } from "../psct/file.js";
import { accountFromXpub, defaultPathPrefix, pairingFor } from "../pairing.js";
import type { Account } from "../account.js";

interface Group {
  key: string;
  indices: number[];
  lock: Script;
  profile: string | null;
}

function groupsOf(psct: Psct, bound: ReturnType<typeof bindAll>): Group[] {
  const map = new Map<string, Group>();
  bound.forEach((b, i) => {
    const lock = b.cellOutput.lock;
    const key = scriptHash(lock);
    const g = map.get(key) ?? { key, indices: [], lock, profile: classifyLock(lock).profile };
    g.indices.push(i);
    map.set(key, g);
  });
  return [...map.values()];
}

function headersMap(psct: Psct): Map<string, string> {
  return new Map(psct.headers.map((h) => [bytesToHex(ckbHash(h)), bytesToHex(h)]));
}

/** The transaction as the signer will assemble it: templates carry the non-signature witness fields. */
function reviewTransaction(tx: Transaction, psct: Psct): Transaction {
  return {
    ...tx,
    witnesses: psct.witnessTemplates.map((t) =>
      bytesToHex(
        encodeWitnessArgs({
          lock: null,
          inputType: t.inputType ?? null,
          outputType: t.outputType ?? null,
        }),
      ),
    ),
  };
}

export function describePsct(
  psct: Psct,
  account?: Account,
): { lines: string[]; warnings: string[] } {
  const tx = psctTransaction(psct);
  const bound = bindAll(
    tx,
    psct.inputProofs.map((p) => ({
      prevTx: decodeRawTransaction(p.prevTx),
      index: p.index,
      blockHash: p.blockHash ? bytesToHex(p.blockHash) : undefined,
    })),
  );
  const inspection = inspect(reviewTransaction(tx, psct), bound, { headers: headersMap(psct) });
  const groups = groupsOf(psct, bound);
  const pairingWarnings: string[] = [];
  let pairing: ReturnType<typeof pairingFor> | undefined;
  if (account) {
    try {
      pairing = pairingFor(psct, account, {
        inputLocks: bound.map((b) => b.cellOutput.lock),
        outputLocks: tx.outputs.map((o) => o.lock),
        fee: inspection.fee,
      });
      pairingWarnings.push(...pairing.warnings);
    } catch (e) {
      pairingWarnings.push(`pairing: ${(e as Error).message}`);
    }
  } else {
    pairingWarnings.push("no paired account: change is not certified");
  }

  const lines: string[] = [];
  lines.push(`network      ${psct.network}`);
  lines.push(`fingerprint  ${psctFingerprint(psct)}`);
  lines.push(`tx hash      ${psctTxHash(psct)}`);
  if (account) lines.push(`account      ${bytesToHex(account.fingerprint)}`);
  lines.push(`inputs       ${tx.inputs.length}`);
  lines.push(`fee          ${inspection.feeCkb} CKB${inspection.interestKnown ? "" : " (lower bound)"}`);

  lines.push("outputs");
  tx.outputs.forEach((o, i) => {
    const addr = (() => {
      try {
        return encodeAddress(o.lock, psct.network === "ckb" ? "ckb" : "ckt");
      } catch {
        return `${o.lock.codeHash.slice(0, 10)}…`;
      }
    })();
    const own = pairing?.changeOutputs.includes(i) ? "CHANGE" : "payment";
    lines.push(`  ${i}  ${fmtCkb(o.capacity).padStart(14)} CKB  ${own.padEnd(8)} ${addr}`);
  });

  lines.push("groups");
  for (const g of groups) {
    const sigs = psct.sigs[g.key]?.length ?? 0;
    const p = classifyLock(g.lock);
    lines.push(`  ${p.name.padEnd(28)} inputs=[${g.indices.join(",")}] sigs=${sigs}`);
  }

  const baseWarnings = inspection.warnings.filter(
    (w) =>
      !(
        pairing &&
        pairing.changeOutputs.length > 0 &&
        w.includes("no change output recognised")
      ),
  );

  return { lines, warnings: [...baseWarnings, ...pairingWarnings] };
}

export interface SignResult {
  psct: Psct;
  signedGroups: string[];
  signer: string;
}

export function signPsct(psct: Psct, privkeyHex: string, account?: Account): SignResult {
  const priv = hexToBytes(privkeyHex.startsWith("0x") ? privkeyHex : `0x${privkeyHex}`);
  if (priv.length !== 32) throw new Error("private key must be 32 bytes");
  const pubkey = secp256k1.getPublicKey(priv, true);
  const signer = bytesToHex(blake160(pubkey));

  const tx = psctTransaction(psct);
  const bound = bindAll(
    tx,
    psct.inputProofs.map((p) => ({
      prevTx: decodeRawTransaction(p.prevTx),
      index: p.index,
      blockHash: p.blockHash ? bytesToHex(p.blockHash) : undefined,
    })),
  );
  const groups = groupsOf(psct, bound);

  // Refuse the whole transaction if any lock is outside the modelled profiles.
  for (const g of groups) {
    if (g.profile !== SECP_PROFILE && g.profile !== MULTISIG_PROFILE && g.profile !== MULTISIG_V2_PROFILE) {
      throw new Error(`unsupported lock ${classifyLock(g.lock).name}; refusing to sign any part of it`);
    }
  }

  // Type scripts have no signing profile, but an unknown one can implement any rule. Under the
  // strict model an unmodelled contract is not certifiable, so it is refused, not just warned about.
  const unknownType = [...bound.map((b) => b.cellOutput.type), ...tx.outputs.map((o) => o.type)].find(
    (t) => t && classifyType(t) === "unknown type",
  );
  if (unknownType) {
    throw new Error(
      `unknown type script ${unknownType.codeHash.slice(0, 18)}…; refusing to sign an uncertifiable contract`,
    );
  }
  const inspection = inspect(reviewTransaction(tx, psct), bound, { headers: headersMap(psct) });
  const daoProblem = inspection.dao.find((d) => d.issues.length > 0);
  if (daoProblem) throw new Error(`DAO input ${daoProblem.input}: ${daoProblem.issues.join("; ")}`);

  // With a paired account, a claim that an output is change must be true.
  if (account) {
    const pairing = pairingFor(psct, account, {
      inputLocks: bound.map((b) => b.cellOutput.lock),
      outputLocks: tx.outputs.map((o) => o.lock),
      fee: inspection.fee,
    });
    if (pairing.lies.length) throw new Error(pairing.lies.join("; "));
  }

  // Witness layout: every group's first input carries its placeholder lock.
  const firstLock = new Map<number, Uint8Array>();
  for (const g of groups) {
    const first = Math.min(...g.indices);
    const template = psct.witnessTemplates[first]?.lockTemplate;
    if (g.profile === SECP_PROFILE) {
      firstLock.set(first, new Uint8Array(65));
    } else {
      if (!template) throw new Error(`missing multisig lock template for ${g.key}`);
      firstLock.set(first, template);
    }
  }
  const placeholder: Transaction = {
    ...tx,
    witnesses: psct.witnessTemplates.map((t, i) =>
      bytesToHex(
        encodeWitnessArgs({
          lock: firstLock.get(i) ?? null,
          inputType: t.inputType ?? null,
          outputType: t.outputType ?? null,
        }),
      ),
    ),
  };

  const signed: string[] = [];
  for (const g of groups) {
    const first = Math.min(...g.indices);
    if (g.profile === SECP_PROFILE) {
      if (g.lock.args.toLowerCase() !== signer.toLowerCase()) continue;
      const msg = sighashMessage(placeholder, g.indices, (w) => withZeroedLock(w, 65));
      const sig = secp256k1.sign(msg, priv, { lowS: true });
      const sig65 = concat(sig.toCompactRawBytes(), Uint8Array.of(sig.recovery ?? 0));
      if (pubkeyHash(sig65, msg) !== signer) throw new Error("self-check failed for secp signature");
      psct.sigs[g.key] = [{ signer: hexToBytes(signer), signature: sig65, profile: SECP_PROFILE }];
      signed.push(g.key);
      continue;
    }

    const template = psct.witnessTemplates[first]?.lockTemplate;
    if (!template) throw new Error(`missing multisig template for ${g.key}`);
    const parsed = decodeMultisigLock(template);
    if (!parsed) throw new Error("malformed multisig template");
    const position = parsed.pubkeys.findIndex((p) => p.toLowerCase() === signer.toLowerCase());
    if (position < 0) continue;

    const msg = sighashMessage(placeholder, g.indices, (w) =>
      zeroSignatureRegion(w, 65 * parsed.threshold),
    );
    const sig = secp256k1.sign(msg, priv, { lowS: true });
    const sig65 = concat(sig.toCompactRawBytes(), Uint8Array.of(sig.recovery ?? 0));
    if (pubkeyHash(sig65, msg) !== signer) throw new Error("self-check failed for multisig signature");

    const list = psct.sigs[g.key] ?? [];
    const without = list.filter((s) => bytesToHex(s.signer) !== signer);
    without.push({ signer: hexToBytes(signer), signature: sig65, profile: g.profile! });
    psct.sigs[g.key] = without;
    signed.push(g.key);
  }

  if (signed.length === 0) {
    throw new Error(`this key (${signer}) does not control any input in this transaction`);
  }
  return { psct, signedGroups: signed, signer };
}

export function requiresConfirmation(): boolean {
  return process.stdin.isTTY === true;
}

async function confirm(): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question("Approve and sign? [y/N] ");
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

function loadAccount(text: string, network: "ckb" | "ckt"): Account {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) {
    const j = JSON.parse(trimmed) as { xpub: string; pathPrefix?: string; fingerprint?: string };
    const base = accountFromXpub(j.xpub, j.pathPrefix ?? defaultPathPrefix(network));
    return {
      ...base,
      fingerprint: j.fingerprint ? hexToBytes(j.fingerprint) : base.fingerprint,
    };
  }
  return accountFromXpub(trimmed, defaultPathPrefix(network));
}

function parseArgs(argv: string[]) {  const args: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        args[key] = next;
        i++;
      } else {
        args[key] = "true";
      }
    } else {
      positional.push(a);
    }
  }
  return { args, positional };
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const { args, positional } = parseArgs(rest);
  if (!cmd) {
    console.error("usage: signer <show|sign> <file.psct.b64> ...");
    process.exit(2);
  }

  if (cmd === "show" || cmd === "sign") {
    const psct = readPsctFile(positional[0]!);
    const account = args["account-file"]
      ? loadAccount(readFileSync(args["account-file"], "utf8"), psct.network)
      : undefined;
    const { lines, warnings } = describePsct(psct, account);
    for (const l of lines) console.log(l);
    if (warnings.length) {
      console.log("warnings");
      for (const w of warnings) console.log(`  - ${w}`);
    }

    if (cmd === "show") return;

    if (!args["privkey-file"]) throw new Error("--privkey-file is required");
    const key = readFileSync(args["privkey-file"], "utf8").trim();

    if (!args.yes) {
      if (!requiresConfirmation()) throw new Error("not a terminal; pass --yes to confirm signing");
      const ok = await confirm();
      if (!ok) {
        console.error("cancelled");
        process.exit(1);
      }
    }

    const result = signPsct(psct, key, account);
    console.log(`signer       ${result.signer}`);

    const out = args.out ?? "signed.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`signed       ${result.signedGroups.length} group(s)`);
    console.log(`wrote        ${out}`);
    return;
  }

  console.error(`unknown command ${cmd}`);
  process.exit(2);
}

const isMain = process.argv[1]?.replace(/\\/g, "/").endsWith("apps/signer.ts");
if (isMain) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}


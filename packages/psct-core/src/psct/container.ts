/**
 * PSCT v0 container.
 *
 *   magic "psct" (70 73 63 74) | version byte 0 | canonical CBOR
 *
 * The envelope carries the *raw* molecule transaction (witnesses emptied), the non-signature parts
 * of each witness as a template, every input's creating transaction, any headers its proofs need,
 * account hints, and partial signatures.
 *
 * Why witness templates: witnesses are not only signatures. DAO stores a header index in
 * `input_type`; xUDT stores extension data in `output_type`. Emptying witnesses would make the
 * signed message unreconstructable. The template is the witness minus its lock field.
 *
 * Required: signatures are keyed by script hash and signer, and never by input. CKB signs per
 * script group, so a per-input slot model is wrong.
 */

import { bytesEqual, bytesToHex, hexToBytes } from "../bytes.js";
import { decodeRawTransaction, encodeRawTransaction, type Script, type Transaction } from "../ckb.js";
import { ckbHash, scriptHash, txHash } from "../hash.js";
import { encodeCbor, decodeCbor, type CborValue } from "../cbor.js";
import { bindAll, type BoundCell } from "./bind.js";
import { classifyLock, MULTISIG_PROFILE, MULTISIG_V2_PROFILE, SECP_PROFILE } from "../profiles.js";
import { assembleMultisigLock, decodeMultisigLock } from "../multisig.js";
import { verifyTx } from "../verify.js";
import { decodeWitnessArgs, sighashMessage, witnessLock, encodeWitnessArgs, zeroSignatureRegion } from "../sighash.js";
import { pubkeyHash } from "../secp.js";

export const PSCT_MAGIC = Uint8Array.of(0x70, 0x73, 0x63, 0x74);
export const PSCT_VERSION = 0;

export interface WitnessTemplate {
  /** Non-signature `input_type` payload (DAO header index, xUDT extension data, ...). */
  inputType?: Uint8Array;
  /** Non-signature `output_type` payload. */
  outputType?: Uint8Array;
  /** For multisig: the lock field with its signature region zeroed, so finalize can assemble. */
  lockTemplate?: Uint8Array;
}

export interface InputProofRaw {
  /** Creating transaction, witness-free, as RawTransaction molecule bytes. */
  prevTx: Uint8Array;
  index: number;
  blockHash?: Uint8Array;
}

export interface PsctSignature {
  /** Public key hash or lock arg, 20 bytes for the profiles we support. */
  signer: Uint8Array;
  signature: Uint8Array;
  profile: string;
}

export interface PsctAccount {
  xpub: string;
  fingerprint: Uint8Array;
  pathPrefix: string;
}

export interface Psct {
  network: "ckb" | "ckt";
  /** RawTransaction molecule, witnesses emptied. */
  tx: Uint8Array;
  witnessTemplates: WitnessTemplate[];
  inputProofs: InputProofRaw[];
  /** Raw 208-byte headers, indexed by their own hash. */
  headers: Uint8Array[];
  account?: PsctAccount;
  inputHints: { derivation?: string }[];
  outputHints: { role?: string }[];
  /** script hash (hex) -> signatures. Order-independent. */
  sigs: Record<string, PsctSignature[]>;
  meta?: CborValue;
  /** Unknown top-level keys, preserved verbatim (BIP-174's lesson). */
  extra?: Record<string, CborValue>;
}

const KNOWN_KEYS = new Set([
  "psct",
  "network",
  "tx",
  "witness_templates",
  "input_proofs",
  "headers",
  "account",
  "inputs",
  "outputs",
  "sigs",
  "meta",
]);

function asBytes(v: CborValue | undefined, where: string): Uint8Array {
  if (!(v instanceof Uint8Array)) throw new Error(`${where}: expected bytes`);
  return v;
}

function asString(v: CborValue | undefined, where: string): string {
  if (typeof v !== "string") throw new Error(`${where}: expected string`);
  return v;
}

function asArray(v: CborValue | undefined, where: string): CborValue[] {
  if (!Array.isArray(v)) throw new Error(`${where}: expected array`);
  return v;
}

function asMap(v: CborValue | undefined, where: string): { [k: string]: CborValue } {
  if (!v || typeof v !== "object" || v instanceof Uint8Array || Array.isArray(v)) {
    throw new Error(`${where}: expected map`);
  }
  return v as { [k: string]: CborValue };
}

function asUint(v: CborValue | undefined, where: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new Error(`${where}: expected unsigned integer`);
  }
  return v;
}

// ---------------------------------------------------------------- encode

export function encodePsct(p: Psct): Uint8Array {
  const templates = p.witnessTemplates.map((t) => {
    const m: { [k: string]: CborValue } = {};
    if (t.lockTemplate) m["lock_template"] = t.lockTemplate;
    if (t.inputType) m["input_type"] = t.inputType;
    if (t.outputType) m["output_type"] = t.outputType;
    return m;
  });

  const proofs = p.inputProofs.map((ip) => {
    const m: { [k: string]: CborValue } = { prev_tx: ip.prevTx, index: ip.index };
    if (ip.blockHash) m["block_hash"] = ip.blockHash;
    return m;
  });

  const sigs: { [k: string]: CborValue } = {};
  for (const [key, list] of Object.entries(p.sigs)) {
    sigs[key] = list.map((s) => ({
      signer: s.signer,
      signature: s.signature,
      profile: s.profile,
    }));
  }

  const obj: { [k: string]: CborValue } = {
    psct: PSCT_VERSION,
    network: p.network,
    tx: p.tx,
    witness_templates: templates,
    input_proofs: proofs,
    // Deterministic regardless of how the caller collected them.
    headers: [...p.headers].sort((x, y) => {
      const hx = bytesToHex(ckbHash(x));
      const hy = bytesToHex(ckbHash(y));
      return hx < hy ? -1 : hx > hy ? 1 : 0;
    }),
    inputs: p.inputHints.map((h) => {
      const m: { [k: string]: CborValue } = {};
      if (h.derivation) m["derivation"] = h.derivation;
      return m;
    }),
    outputs: p.outputHints.map((h) => {
      const m: { [k: string]: CborValue } = {};
      if (h.role) m["role"] = h.role;
      return m;
    }),
    sigs,
  };
  if (p.account) {
    obj["account"] = {
      xpub: p.account.xpub,
      fingerprint: p.account.fingerprint,
      path_prefix: p.account.pathPrefix,
    };
  }
  if (p.meta !== undefined) obj["meta"] = p.meta;
  for (const [k, v] of Object.entries(p.extra ?? {})) {
    if (KNOWN_KEYS.has(k)) throw new Error(`extra key ${k} collides with a known field`);
    obj[k] = v;
  }

  const body = encodeCbor(obj);
  const out = new Uint8Array(PSCT_MAGIC.length + 1 + body.length);
  out.set(PSCT_MAGIC, 0);
  out[PSCT_MAGIC.length] = PSCT_VERSION;
  out.set(body, PSCT_MAGIC.length + 1);
  return out;
}

// ---------------------------------------------------------------- decode

export function decodePsct(bytes: Uint8Array): Psct {
  if (bytes.length < PSCT_MAGIC.length + 1) throw new Error("PSCT too short");
  for (let i = 0; i < PSCT_MAGIC.length; i++) {
    if (bytes[i] !== PSCT_MAGIC[i]) throw new Error("bad PSCT magic");
  }
  const version = bytes[PSCT_MAGIC.length]!;
  if (version !== PSCT_VERSION) throw new Error(`unsupported PSCT version ${version}`);

  const obj = asMap(decodeCbor(bytes.slice(PSCT_MAGIC.length + 1)), "psct");
  if (asUint(obj["psct"], "psct.psct") !== PSCT_VERSION) throw new Error("psct version mismatch");

  const network = asString(obj["network"], "network");
  if (network !== "ckb" && network !== "ckt") throw new Error(`unknown network ${network}`);

  const witnessTemplates = asArray(obj["witness_templates"], "witness_templates").map((t, i) => {
    const m = asMap(t, `witness_templates[${i}]`);
    const out: WitnessTemplate = {};
    if (m["input_type"] !== undefined) out.inputType = asBytes(m["input_type"], `templates[${i}].input_type`);
    if (m["output_type"] !== undefined) out.outputType = asBytes(m["output_type"], `templates[${i}].output_type`);
    if (m["lock_template"] !== undefined) out.lockTemplate = asBytes(m["lock_template"], `templates[${i}].lock_template`);
    return out;
  });

  const inputProofs = asArray(obj["input_proofs"], "input_proofs").map((p, i) => {
    const m = asMap(p, `input_proofs[${i}]`);
    const proof: InputProofRaw = {
      prevTx: asBytes(m["prev_tx"], `proofs[${i}].prev_tx`),
      index: asUint(m["index"], `proofs[${i}].index`),
    };
    if (m["block_hash"] !== undefined) proof.blockHash = asBytes(m["block_hash"], `proofs[${i}].block_hash`);
    return proof;
  });

  const headers = asArray(obj["headers"], "headers").map((h, i) => asBytes(h, `headers[${i}]`));

  const accountRaw = obj["account"];
  const account = accountRaw
    ? (() => {
        const m = asMap(accountRaw, "account");
        return {
          xpub: asString(m["xpub"], "account.xpub"),
          fingerprint: asBytes(m["fingerprint"], "account.fingerprint"),
          pathPrefix: asString(m["path_prefix"], "account.path_prefix"),
        };
      })()
    : undefined;

  const inputHints = asArray(obj["inputs"] ?? [], "inputs").map((h) => {
    const m = asMap(h, "inputs[]");
    return m["derivation"] !== undefined
      ? { derivation: asString(m["derivation"], "inputs[].derivation") }
      : {};
  });
  const outputHints = asArray(obj["outputs"] ?? [], "outputs").map((h) => {
    const m = asMap(h, "outputs[]");
    return m["role"] !== undefined ? { role: asString(m["role"], "outputs[].role") } : {};
  });

  const sigs: Record<string, PsctSignature[]> = {};
  for (const [key, list] of Object.entries(asMap(obj["sigs"], "sigs"))) {
    sigs[key] = asArray(list, `sigs[${key}]`).map((s, i) => {
      const m = asMap(s, `sigs[${key}][${i}]`);
      return {
        signer: asBytes(m["signer"], `sigs[${key}][${i}].signer`),
        signature: asBytes(m["signature"], `sigs[${key}][${i}].signature`),
        profile: asString(m["profile"], `sigs[${key}][${i}].profile`),
      };
    });
  }

  const extra: Record<string, CborValue> = {};
  for (const [k, v] of Object.entries(obj)) if (!KNOWN_KEYS.has(k)) extra[k] = v;

  return {
    network,
    tx: asBytes(obj["tx"], "tx"),
    witnessTemplates,
    inputProofs,
    headers,
    account,
    inputHints,
    outputHints,
    sigs,
    meta: obj["meta"],
    extra: Object.keys(extra).length ? extra : undefined,
  };
}

// ---------------------------------------------------------------- extraction

/**
 * Import the signatures that already exist in a transaction into the PSCT, and record the multisig
 * lock template. Used when turning a known transaction into a conformance vector.
 */
export function extractExistingSignatures(p: Psct, tx: Transaction, bound: BoundCell[]): void {
  const groups = new Map<string, number[]>();
  bound.forEach((b, i) => {
    const key = scriptHash(b.cellOutput.lock);
    groups.set(key, [...(groups.get(key) ?? []), i]);
  });

  for (const [key, indices] of groups) {
    const lock = bound[indices[0]!]!.cellOutput.lock;
    const profile = classifyLock(lock);
    const first = Math.min(...indices);
    const raw = witnessLock(tx.witnesses[first] ?? "0x");
    if (!raw) continue;

    if (profile.profile === SECP_PROFILE) {
      p.sigs[key] = [{ signer: hexToBytes(lock.args), signature: raw, profile: SECP_PROFILE }];
      continue;
    }

    if (profile.profile === MULTISIG_PROFILE || profile.profile === MULTISIG_V2_PROFILE) {
      const parsed = decodeMultisigLock(raw);
      if (!parsed) continue;
      const scriptLen = 4 + 20 * parsed.pubkeys.length;
      const template = raw.slice(0, scriptLen + 65 * parsed.threshold);
      template.fill(0, scriptLen);
      p.witnessTemplates[first] = { ...p.witnessTemplates[first], lockTemplate: template };

      const msg = sighashMessage(tx, indices, (w) => zeroSignatureRegion(w, 65 * parsed.threshold));
      p.sigs[key] = parsed.signatures.map((sig) => ({
        signer: hexToBytes(pubkeyHash(sig, msg)),
        signature: sig,
        profile: profile.profile!,
      }));
    }
  }
}

// ---------------------------------------------------------------- helpers

export function psctTransaction(p: Psct): Transaction {
  return decodeRawTransaction(p.tx);
}

export function psctTxHash(p: Psct): string {
  return txHash(psctTransaction(p));
}

/** Short display form of the tx hash. Covers inputs/outputs/deps, not witnesses or proofs. */
export function psctFingerprint(p: Psct): string {
  const h = psctTxHash(p);
  return `${h.slice(0, 10)}…${h.slice(-4)}`;
}

export function witnessTemplateFromHex(hex: string): WitnessTemplate {
  if (hex === "0x" || hex === "") return {};
  const args = decodeWitnessArgs(hexToBytes(hex));
  const t: WitnessTemplate = {};
  if (args.inputType) t.inputType = args.inputType;
  if (args.outputType) t.outputType = args.outputType;
  return t;
}

export interface BuildOptions {
  network: "ckb" | "ckt";
  proofs: { prevTx: Transaction; index: number; blockHash?: string }[];
  headers?: Map<string, string>;
  account?: PsctAccount;
  inputHints?: { derivation?: string }[];
  outputHints?: { role?: string }[];
}

export function buildPsct(tx: Transaction, opts: BuildOptions): Psct {
  const headers = [...(opts.headers?.values() ?? [])].map((h) => hexToBytes(h));
  return {
    network: opts.network,
    tx: encodeRawTransaction(tx),
    witnessTemplates: tx.witnesses.map(witnessTemplateFromHex),
    inputProofs: opts.proofs.map((p) => ({
      prevTx: encodeRawTransaction({ ...p.prevTx, witnesses: [] }),
      index: p.index,
      blockHash: p.blockHash ? hexToBytes(p.blockHash) : undefined,
    })),
    headers,
    account: opts.account,
    inputHints: opts.inputHints ?? [],
    outputHints: opts.outputHints ?? [],
    sigs: {},
  };
}

/** Merge two PSCTs. Commutative, associative, and lossless for unknown fields. */
export function combinePsct(a: Psct, b: Psct): Psct {
  if (a.network !== b.network) throw new Error("cannot combine different networks");
  if (!bytesEqual(a.tx, b.tx)) throw new Error("cannot combine different transactions");
  if (a.witnessTemplates.length !== b.witnessTemplates.length) {
    throw new Error("witness template count differs");
  }
  for (let i = 0; i < a.witnessTemplates.length; i++) {
    if (!sameTemplate(a.witnessTemplates[i]!, b.witnessTemplates[i]!)) {
      throw new Error(`witness template ${i} differs`);
    }
  }
  if (a.inputProofs.length !== b.inputProofs.length) throw new Error("input proof count differs");
  for (let i = 0; i < a.inputProofs.length; i++) {
    const x = a.inputProofs[i]!;
    const y = b.inputProofs[i]!;
    if (x.index !== y.index || !bytesEqual(x.prevTx, y.prevTx)) {
      throw new Error(`input proof ${i} differs`);
    }
  }

  const headers = new Map<string, Uint8Array>();
  for (const h of [...a.headers, ...b.headers]) headers.set(bytesToHex(ckbHash(h)), h);
  const sortedHeaders = [...headers.entries()].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)).map(([, h]) => h);

  const sigs: Record<string, PsctSignature[]> = {};
  for (const src of [a.sigs, b.sigs]) {
    for (const [script, list] of Object.entries(src)) {
      const target = (sigs[script] ??= []);
      for (const s of list) {
        const existing = target.find((t) => bytesEqual(t.signer, s.signer));
        if (existing) {
          if (!bytesEqual(existing.signature, s.signature)) {
            throw new Error(`conflicting signature from ${bytesToHex(s.signer)} for ${script}`);
          }
        } else {
          target.push(s);
        }
      }
    }
  }

  const extra: Record<string, CborValue> = { ...(a.extra ?? {}) };
  for (const [k, v] of Object.entries(b.extra ?? {})) {
    if (extra[k] !== undefined && encodeCbor(extra[k]!).toString() !== encodeCbor(v).toString()) {
      throw new Error(`conflicting unknown field ${k}`);
    }
    extra[k] = v;
  }

  return {
    network: a.network,
    tx: a.tx,
    witnessTemplates: a.witnessTemplates,
    inputProofs: a.inputProofs,
    headers: sortedHeaders,
    account: a.account ?? b.account,
    inputHints: a.inputHints.length ? a.inputHints : b.inputHints,
    outputHints: a.outputHints.length ? a.outputHints : b.outputHints,
    sigs,
    meta: a.meta ?? b.meta,
    extra: Object.keys(extra).length ? extra : undefined,
  };
}

function sameTemplate(a: WitnessTemplate, b: WitnessTemplate): boolean {
  return (
    bytesEqual(a.inputType ?? new Uint8Array(), b.inputType ?? new Uint8Array()) &&
    bytesEqual(a.outputType ?? new Uint8Array(), b.outputType ?? new Uint8Array()) &&
    bytesEqual(a.lockTemplate ?? new Uint8Array(), b.lockTemplate ?? new Uint8Array())
  );
}

export interface FinalizeOptions {
  /** Optional headers by hash, for DAO interest display. Not needed for finalization. */
  headers?: Map<string, string>;
}

/**
 * Assemble signatures into witnesses and prove the result verifies.
 *
 * Throws rather than returning a half-signed transaction: a finalize that produces something the
 * verifier rejects is a bug, not a result.
 */
export function finalizePsct(p: Psct, opts: FinalizeOptions = {}): Transaction {
  const tx = psctTransaction(p);
  const bound: BoundCell[] = bindAll(
    tx,
    p.inputProofs.map((ip) => ({
      prevTx: decodeRawTransaction(ip.prevTx),
      index: ip.index,
      blockHash: ip.blockHash ? bytesToHex(ip.blockHash) : undefined,
    })),
  );

  const groups = new Map<string, { indices: number[]; lock: Script }>();
  bound.forEach((b, i) => {
    const lock = b.cellOutput.lock;
    const key = `${scriptHash(lock)}`;
    const g = groups.get(key) ?? { indices: [], lock };
    g.indices.push(i);
    groups.set(key, g);
  });

  const locks = new Map<number, Uint8Array>();
  for (const [key, { indices, lock }] of groups) {
    const first = Math.min(...indices);
    const p2 = classifyLock(lock);
    const signatures = p.sigs[key] ?? [];

    if (p2.profile === SECP_PROFILE) {
      const sig = signatures.find((s) => s.profile === SECP_PROFILE);
      if (!sig) throw new Error(`missing secp256k1 signature for ${key}`);
      locks.set(first, sig.signature);
      continue;
    }

    if (p2.profile === MULTISIG_PROFILE || p2.profile === MULTISIG_V2_PROFILE) {
      const template = p.witnessTemplates[first]?.lockTemplate;
      if (!template) throw new Error(`missing multisig lock template for ${key}`);
      const parsed = decodeMultisigLock(template);
      if (!parsed) throw new Error("multisig lock template is malformed");
      const bySigner: Record<string, Uint8Array> = {};
      for (const s of signatures) bySigner[bytesToHex(s.signer)] = s.signature;
      const assembled = assembleMultisigLock(
        {
          requireFirstN: parsed.requireFirstN,
          threshold: parsed.threshold,
          pubkeys: parsed.pubkeys,
          scriptHash: parsed.scriptHash,
        },
        bySigner,
      );
      if (!assembled) throw new Error(`not enough signatures for multisig ${key}`);
      locks.set(first, assembled);
      continue;
    }

    throw new Error(`no finalize profile for lock ${p2.name}`);
  }

  tx.witnesses = p.witnessTemplates.map((t, i) =>
    bytesToHex(
      encodeWitnessArgs({
        lock: locks.get(i) ?? null,
        inputType: t.inputType ?? null,
        outputType: t.outputType ?? null,
      }),
    ),
  );

  const results = verifyTx(tx, bound);
  const failed = results.filter((r) => r.verdict !== "verified");
  if (failed.length) {
    throw new Error(
      `finalized transaction does not verify: ${failed.map((f) => `${f.name}:${f.verdict}`).join(", ")}`,
    );
  }
  return tx;
}

/**
 * Watch-only coordinator.
 *
 * Builds a transaction from live cells, resolves every input's creating transaction, and emits a
 * PSCT. It never holds or asks for a private key.
 *
 *   coordinator transfer --network devnet --from <addr> --to <addr> --amount 10 --out out.psct.b64
 *   coordinator transfer ... --signers a,b,c --threshold 2 [--multisig v2]
 *   coordinator combine a.psct.b64 b.psct.b64 --out c.psct.b64
 *   coordinator finalize c.psct.b64 --out tx.json
 *   coordinator send tx.json --network devnet
 */

import { readFileSync, writeFileSync } from "node:fs";
import { bytesToHex, fmtCkb, hexToBytes } from "../bytes.js";
import { decodeAddress, encodeAddress } from "../address.js";
import { blake160, scriptHash } from "../hash.js";
import { occupiedCapacity } from "../capacity.js";
import { decodeXpub, derivePublic } from "../bip32.js";
import { lockForNode } from "../account.js";
import { accountFromXpub, defaultPathPrefix } from "../pairing.js";
import type { HashType, Script, Transaction } from "../ckb.js";
import { fromRpcScript } from "../ckb.js";
import { buildPsct, combinePsct, finalizePsct, psctFingerprint, psctTxHash, type Psct } from "../psct/container.js";
import { readPsctFile, writePsctFile } from "../psct/file.js";
import { resolveProofs } from "../psct/proofs.js";
import { Rpc } from "../rpc.js";
import { networkByName, type Network, type NetworkName } from "../network.js";
import { toRpcTx } from "../ckb.js";

export const LEGACY_MULTISIG = "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8";
export const V2_MULTISIG = "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29";
const CKB = 100_000_000n;
const CHANGE_MIN = 61n * CKB;

export interface MultisigSpec {
  signers: string[];
  threshold: number;
  requireFirstN: number;
  version: "legacy" | "v2";
}

export function multisigLock(spec: MultisigSpec): { lock: Script; lockTemplate: Uint8Array } {
  const hashes = spec.signers.map((a) => decodeAddress(a).script.args);
  const scriptPart = new Uint8Array([
    0,
    spec.requireFirstN,
    spec.threshold,
    hashes.length,
    ...hashes.flatMap((h) => [...hexToBytes(h)]),
  ]);
  const args = bytesToHex(blake160(scriptPart));
  const lock: Script =
    spec.version === "v2"
      ? { codeHash: V2_MULTISIG, hashType: "data1", args }
      : { codeHash: LEGACY_MULTISIG, hashType: "type", args };
  const template = new Uint8Array(scriptPart.length + 65 * spec.threshold);
  template.set(scriptPart, 0);
  return { lock, lockTemplate: template };
}

export function parseCkb(value: string): bigint {
  const [whole, frac = ""] = value.split(".");
  if (!/^\d+$/.test(whole ?? "")) throw new Error(`bad CKB amount ${value}`);
  if (frac.length > 8 || !/^\d*$/.test(frac)) throw new Error(`bad CKB amount ${value}`);
  return BigInt(whole!) * CKB + BigInt((frac + "00000000").slice(0, 8));
}

interface LiveCell {
  outPoint: { txHash: string; index: number };
  capacity: bigint;
  type: Script | null;
}

async function liveCells(rpc: Rpc, lock: Script): Promise<LiveCell[]> {
  const res = await rpc.call<{
    objects: { out_point: { tx_hash: string; index: string }; output: { capacity: string; type: { code_hash: string; hash_type: HashType; args: string } | null } }[];
  }>("get_cells", [
    {
      script: { code_hash: lock.codeHash, hash_type: lock.hashType, args: lock.args },
      script_type: "lock",
    },
    "asc",
    "0x40",
    null,
  ]);
  return res.objects.map((o) => ({
    outPoint: { txHash: o.out_point.tx_hash, index: Number(BigInt(o.out_point.index)) },
    capacity: BigInt(o.output.capacity),
    type: o.output.type ? fromRpcScript(o.output.type) : null,
  }));
}

export interface TransferOptions {
  network: NetworkName;
  from?: string;
  to: string;
  amount: bigint;
  fee?: bigint;
  multisig?: MultisigSpec;
  /** Paired account; when present the coordinator derives from/change instead of using an address. */
  account?: { xpub: string; index?: number };
}

export interface TransferResult {
  psct: Psct;
  tx: Transaction;
  fee: bigint;
  change: bigint;
  multisigAddress?: string;
  fromAddress?: string;
}

export interface Source {
  fromLock: Script;
  changeLock: Script;
  accountHint?: Psct["account"];
  derivation?: string;
}

export function resolveSource(opts: {
  from?: string;
  account?: { xpub: string; index?: number };
  network: Network;
}): Source {
  if (opts.account) {
    const node = decodeXpub(opts.account.xpub);
    const index = opts.account.index ?? 0;
    const fromLock = lockForNode(derivePublic(node, `0/${index}`));
    const changeLock = lockForNode(derivePublic(node, `1/${index}`));
    const account = accountFromXpub(opts.account.xpub, defaultPathPrefix(opts.network.prefix));
    if (opts.from) {
      const given = decodeAddress(opts.from).script;
      if (scriptHash(given) !== scriptHash(fromLock)) {
        throw new Error("--from does not match the paired account's external address");
      }
    }
    return {
      fromLock,
      changeLock,
      accountHint: {
        xpub: account.xpub,
        fingerprint: account.fingerprint,
        pathPrefix: account.pathPrefix,
      },
      derivation: `0/${index}`,
    };
  }
  if (!opts.from) throw new Error("--from or --account is required");
  const lock = decodeAddress(opts.from).script;
  return { fromLock: lock, changeLock: lock };
}

export async function buildTransfer(opts: TransferOptions): Promise<TransferResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const toLock = decodeAddress(opts.to).script;

  let fromLock: Script;
  let changeLock: Script;
  let dep = network.secpDep;
  let lockTemplate: Uint8Array | undefined;
  let multisigAddress: string | undefined;
  let accountHint: Psct["account"];
  let derivation: string | undefined;

  if (opts.multisig) {
    const built = multisigLock(opts.multisig);
    fromLock = built.lock;
    changeLock = built.lock;
    lockTemplate = built.lockTemplate;
    dep = opts.multisig.version === "v2" ? network.multisigV2Dep : network.multisigDep;
    multisigAddress = encodeAddress(fromLock, network.prefix, "full");
    if (opts.from) {
      const given = decodeAddress(opts.from).script;
      if (scriptHash(given) !== scriptHash(fromLock)) {
        throw new Error(`--from does not match the multisig config; expected ${multisigAddress}`);
      }
    }
  } else {
    const src = resolveSource({ from: opts.from, account: opts.account, network });
    fromLock = src.fromLock;
    changeLock = src.changeLock;
    accountHint = src.accountHint;
    derivation = src.derivation;
  }

  const fee = opts.fee ?? 1000n;
  // Plain CKB inputs only: spending a typed cell needs that type script's semantics.
  const cells = (await liveCells(rpc, fromLock)).filter((c) => c.type === null);
  const fromAddress = encodeAddress(fromLock, network.prefix);
  if (cells.length === 0) throw new Error(`no live cells for ${fromAddress}`);

  const selected: LiveCell[] = [];
  let total = 0n;
  for (const cell of cells) {
    selected.push(cell);
    total += cell.capacity;
    const change = total - opts.amount - fee;
    if (change === 0n || change >= CHANGE_MIN) break;
  }
  const change = total - opts.amount - fee;
  if (change < 0n) throw new Error("not enough capacity");
  if (change > 0n && change < CHANGE_MIN) {
    throw new Error(
      `change ${fmtCkb(change)} CKB is below the ${fmtCkb(CHANGE_MIN)} CKB minimum; fund the address or lower the amount`,
    );
  }

  const outputs = [{ capacity: opts.amount, lock: toLock, type: null }];
  const outputsData = ["0x"];
  if (change > 0n) {
    outputs.push({ capacity: change, lock: changeLock, type: null });
    outputsData.push("0x");
  }

  outputs.forEach((o, i) => {
    const need = occupiedCapacity(o, outputsData[i] ?? "0x");
    if (o.capacity < need) {
      throw new Error(
        `output ${i} is ${fmtCkb(o.capacity)} CKB, below the ${fmtCkb(need)} CKB cell minimum`,
      );
    }
  });

  const tx: Transaction = {
    version: 0,
    cellDeps: [dep],
    headerDeps: [],
    inputs: selected.map((c) => ({ since: 0n, previousOutput: c.outPoint })),
    outputs,
    outputsData,
    witnesses: selected.map(() => "0x"),
  };

  const proofs = await resolveProofs(tx, rpc);
  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs: proofs.map((p) => ({ prevTx: p.prevTx, index: p.index, blockHash: p.blockHash })),
    headers: new Map(),
    account: accountHint,
    inputHints: selected.map(() => ({ derivation })),
    outputHints: outputs.map((_, i) => ({ role: i === 0 ? "payment" : "change" })),
  });
  if (lockTemplate) psct.witnessTemplates[0] = { lockTemplate };

  return { psct, tx, fee, change, multisigAddress, fromAddress };
}

function parseArgs(argv: string[]) {
  const args: Record<string, string> = {};
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
    console.error(
      "usage: coordinator <transfer|dao-deposit|dao-prepare|dao-withdraw|xudt-mint|xudt-transfer|combine|finalize|send> ...",
    );
    process.exit(2);
  }

  if (cmd === "transfer") {
    const network = (args.network ?? "devnet") as NetworkName;
    const signers = args.signers?.split(",").map((s) => s.trim()).filter(Boolean);
    const multisig: MultisigSpec | undefined = signers
      ? {
          signers,
          threshold: Number(args.threshold ?? 2),
          requireFirstN: Number(args["require-first-n"] ?? 0),
          version: (args.multisig ?? "legacy") as "legacy" | "v2",
        }
      : undefined;
    const amount = parseCkb(args.amount!);
    const result = await buildTransfer({
      network,
      from: args.from,
      to: args.to!,
      amount,
      fee: args.fee ? BigInt(args.fee) : undefined,
      multisig,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "tx.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    if (result.fromAddress) console.log(`from        ${result.fromAddress}`);
    if (result.multisigAddress) console.log(`multisig    ${result.multisigAddress}`);
    console.log(`inputs      ${result.tx.inputs.length}`);
    console.log(`amount      ${fmtCkb(amount)} CKB`);
    console.log(`change      ${fmtCkb(result.change)} CKB`);
    console.log(`fee         ${fmtCkb(result.fee)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "dao-deposit") {
    const { buildDaoDeposit } = await import("./dao.js");
    const result = await buildDaoDeposit({
      network: (args.network ?? "devnet") as NetworkName,
      from: args.from,
      amount: parseCkb(args.amount!),
      fee: args.fee ? BigInt(args.fee) : undefined,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "dao-deposit.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    console.log(`deposit     ${fmtCkb(parseCkb(args.amount!))} CKB`);
    console.log(`change      ${fmtCkb(result.change)} CKB`);
    console.log(`fee         ${fmtCkb(result.fee)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "dao-prepare") {
    const { buildDaoPrepare } = await import("./dao.js");
    const result = await buildDaoPrepare({
      network: (args.network ?? "devnet") as NetworkName,
      from: args.from,
      fee: args.fee ? BigInt(args.fee) : undefined,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "dao-prepare.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    console.log(result.detail);
    console.log(`fee         ${fmtCkb(result.fee)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "dao-withdraw") {
    const { buildDaoWithdraw } = await import("./dao.js");
    const result = await buildDaoWithdraw({
      network: (args.network ?? "devnet") as NetworkName,
      from: args.from,
      to: args.to!,
      amount: args.amount ? parseCkb(args.amount) : undefined,
      fee: args.fee ? BigInt(args.fee) : undefined,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "dao-withdraw.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    console.log(result.detail);
    console.log(`change      ${fmtCkb(result.change)} CKB`);
    console.log(`fee         ${fmtCkb(result.fee)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "xudt-mint") {
    const { buildXudtMint } = await import("./xudt.js");
    const result = await buildXudtMint({
      network: (args.network ?? "devnet") as NetworkName,
      from: args.from,
      amount: BigInt(args.amount!),
      capacity: args.capacity ? parseCkb(args.capacity) : undefined,
      fee: args.fee ? BigInt(args.fee) : undefined,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "xudt-mint.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    console.log(`type        ${result.typeScript.codeHash}:${result.typeScript.hashType}:${result.typeScript.args}`);
    console.log(result.detail);
    console.log(`change      ${fmtCkb(result.change)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "xudt-transfer") {
    const { buildXudtTransfer } = await import("./xudt.js");
    const [codeHash, hashType, typeArgs] = (args.type ?? "").split(":");
    if (!codeHash || !hashType || !typeArgs) {
      throw new Error("--type must be <code_hash>:<hash_type>:<args>");
    }
    const result = await buildXudtTransfer({
      network: (args.network ?? "devnet") as NetworkName,
      from: args.from,
      to: args.to!,
      typeScript: { codeHash, hashType: hashType as "type" | "data1" | "data", args: typeArgs },
      amount: BigInt(args.amount!),
      outputCapacity: args.capacity ? parseCkb(args.capacity) : undefined,
      fee: args.fee ? BigInt(args.fee) : undefined,
      account: args.account ? { xpub: args.account, index: args.index ? Number(args.index) : 0 } : undefined,
    });
    const out = args.out ?? "xudt-transfer.psct.b64";
    writePsctFile(out, result.psct);
    console.log(`psct        ${psctFingerprint(result.psct)}`);
    console.log(`tx          ${psctTxHash(result.psct)}`);
    console.log(result.detail);
    console.log(`change      ${fmtCkb(result.change)} CKB`);
    console.log(`fee         ${fmtCkb(result.fee)} CKB`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "combine") {
    if (positional.length < 2) throw new Error("combine needs two files");
    const out = args.out ?? "combined.psct.b64";
    writePsctFile(out, combinePsct(readPsctFile(positional[0]!), readPsctFile(positional[1]!)));
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "finalize") {
    const p = readPsctFile(positional[0]!);
    const tx = finalizePsct(p);
    const out = args.out ?? "tx.json";
    writeFileSync(out, JSON.stringify(toRpcTx(tx), null, 2));
    console.log(`tx          ${psctTxHash(p)}`);
    console.log(`witnesses   ${tx.witnesses.length}`);
    console.log(`wrote       ${out}`);
    return;
  }

  if (cmd === "send") {
    const network = networkByName(args.network ?? "devnet");
    const rpc = new Rpc(network.rpc);
    const tx = JSON.parse(readFileSync(positional[0]!, "utf8"));
    const hash = await rpc.call<string>("send_transaction", [tx]);
    console.log(`sent        ${hash}`);
    return;
  }

  console.error(`unknown command ${cmd}`);
  process.exit(2);
}

const isMain = process.argv[1]?.replace(/\\/g, "/").endsWith("apps/coordinator.ts");
if (isMain) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

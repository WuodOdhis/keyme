/**
 * Spore (NFTs on CKB), from sporeprotocol/spore-contract.
 *
 * Cell data is a molecule `SporeData` table:
 *   content_type: Bytes      (MIME string)
 *   content:      Bytes
 *   cluster_id:   BytesOpt
 *
 * Type args = 32-byte spore id. A transfer requires the input and output SporeData to be
 * byte-identical ("no field was modified"); the lock may change and the capacity may change.
 * No output with the same id means the NFT is melted and its capacity returns to the lock owner.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { readBytesOpt, tableOffsets } from "./molecule.js";
import { ckbHash, scriptHash } from "./hash.js";
import type { Script, Transaction } from "./ckb.js";
import type { BoundCell } from "./psct/bind.js";

export const SPORE_V2_CODE_HASH = "0x4a4dce1df3dffff7f8b2cd7dff7303df3b6150c9788cb75dcf6747247132b9f5";
export const SPORE_CLUSTER_V2_CODE_HASH = "0x7366a61534fa7c7e6225ecc0d828ea3b5366adec2b58206f2ee84995fe030075";
export const SPORE_DID_CODE_HASH = "0xcfba73b58b6f30e70caed8a999748781b164ef9a1e218424a6fb55ebf641cb33";

export type SporeKind = "spore" | "cluster" | "did";

export function sporeKind(script: Script | null): SporeKind | null {
  if (!script) return null;
  const h = script.codeHash.toLowerCase();
  if (h === SPORE_V2_CODE_HASH) return "spore";
  if (h === SPORE_CLUSTER_V2_CODE_HASH) return "cluster";
  if (h === SPORE_DID_CODE_HASH) return "did";
  return null;
}

export interface SporeData {
  contentType: string | null;
  contentBytes: number;
  contentHash: string;
  clusterId: string | null;
}

/** Parse a SporeData / ClusterData table. Returns null when the data is not a valid table. */
export function parseSporeData(dataHex: string): SporeData | null {
  const b = hexToBytes(dataHex);
  if (b.length < 16) return null;
  try {
    const offs = tableOffsets(b, 0, 3);
    const size = b.length;
    const end = (i: number) => (i + 1 < offs.length ? offs[i + 1]! : size);
    const field = (i: number) => b.slice(offs[i]!, end(i));

    const ctRaw = field(0);
    const ctLen = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offs[0]!, true);
    const contentTypeBytes = ctRaw.slice(4, 4 + ctLen);
    const contentRaw = field(1);
    const contentLen = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offs[1]!, true);
    const content = contentRaw.slice(4, 4 + contentLen);
    const cluster = readBytesOpt(b, offs[2]!, end(2));

    let contentType: string | null = null;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(contentTypeBytes);
      if (/^[\x20-\x7e]+$/.test(text)) contentType = text;
    } catch {
      contentType = null;
    }

    return {
      contentType,
      contentBytes: content.length,
      contentHash: bytesToHex(ckbHash(content)),
      clusterId: cluster ? bytesToHex(cluster) : null,
    };
  } catch {
    return null;
  }
}

export interface SporeFinding {
  id: string;
  kind: "transfer" | "melt" | "mint";
  input?: number;
  output?: number;
  data?: SporeData;
  toLock?: Script;
  capacityBefore?: bigint;
  capacityAfter?: bigint;
  issues: string[];
}

/**
 * Compare Spore cells between inputs and outputs.
 *
 * A transfer must keep the data identical; a capacity reduction is allowed by the script but is
 * exactly the "strip value from the NFT" pattern a signer should surface.
 */
export function inspectSpore(tx: Transaction, bound: BoundCell[]): SporeFinding[] {
  const findings: SporeFinding[] = [];
  const key = (s: Script) => `${scriptHash(s)}`;

  const inputById = new Map<string, number>();
  bound.forEach((b, i) => {
    const t = b.cellOutput.type;
    if (!t || sporeKind(t) !== "spore") return;
    inputById.set(key(t), i);
  });

  const pairedOutputs = new Set<number>();
  for (const [id, i] of inputById) {
    const input = bound[i]!;
    const outIndex = tx.outputs.findIndex((o, j) => o.type && key(o.type) === id);
    const data = parseSporeData(input.data);
    const issues: string[] = [];
    if (!data) issues.push("input data is not a valid SporeData table");

    if (outIndex < 0) {
      findings.push({
        id,
        kind: "melt",
        input: i,
        data: data ?? undefined,
        capacityBefore: input.cellOutput.capacity,
        issues,
      });
      continue;
    }

    pairedOutputs.add(outIndex);
    const out = tx.outputs[outIndex]!;
    const outData = tx.outputsData[outIndex] ?? "0x";
    const outParsed = parseSporeData(outData);
    if (input.data.toLowerCase() !== outData.toLowerCase()) {
      issues.push("SporeData changed during transfer; the type script rejects any modification");
    }
    if (!outParsed) issues.push("output data is not a valid SporeData table");
    const before = input.cellOutput.capacity;
    const after = out.capacity;
    if (after < before) {
      issues.push(`capacity reduced by ${((before - after) / 100_000_000n).toString()} CKB during transfer`);
    }

    findings.push({
      id,
      kind: "transfer",
      input: i,
      output: outIndex,
      data: outParsed ?? data ?? undefined,
      toLock: out.lock,
      capacityBefore: before,
      capacityAfter: after,
      issues,
    });
  }

  // Outputs with a spore id that no input carries are mints.
  tx.outputs.forEach((o, j) => {
    const t = o.type;
    if (!t || sporeKind(t) !== "spore" || pairedOutputs.has(j)) return;
    const id = key(t);
    if (inputById.has(id)) return;
    const data = parseSporeData(tx.outputsData[j] ?? "0x");
    findings.push({
      id,
      kind: "mint",
      output: j,
      data: data ?? undefined,
      toLock: o.lock,
      capacityAfter: o.capacity,
      issues: data ? [] : ["output data is not a valid SporeData table"],
    });
  });

  return findings;
}

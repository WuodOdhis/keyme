/**
 * Hostile corpus — executable acceptance criteria for the strict trust model (D1).
 *
 * Every test here is a way a malicious coordinator could try to make the signer approve something
 * other than what the bytes say. All of them must fail closed.
 *
 * Run: npx tsx --test src/hostile.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { bindAll, BindError } from "./psct/bind.js";
import { inspect } from "./psct/inspect.js";
import { verifyTx } from "./verify.js";
import { witnessLock, decodeWitnessArgs, encodeWitnessArgs } from "./sighash.js";
import { decodeMultisigLock } from "./multisig.js";
import { occupiedBytes } from "./capacity.js";
import { DAO_CODE_HASH, classifyDaoCell } from "./dao.js";
import { decodeXudtArgs, ownerMode, tokenAmount, tokenKind } from "./xudt.js";
import { SPORE_V2_CODE_HASH, inspectSpore, parseSporeData } from "./spore.js";
import { bytesVec, option, table } from "./molecule.js";
import { decodeOmnilockArgs } from "./omnilock.js";
import { decodeSinceInfo } from "./since.js";
import { txHash } from "./hash.js";
import { hexToBytes, bytesToHex } from "./bytes.js";
import { loadFixture, loadManifest } from "./fixtures.js";
import { SECP_PROFILE } from "./profiles.js";
import type { CellOutput } from "./ckb.js";

const manifest = loadManifest();

// Select by class, never by shape: a 2-input multisig fixture is not a "plain payment".
const plain = (() => {
  for (const e of [...manifest].sort((a, b) => a.inputs - b.inputs)) {
    const f = loadFixture(e.hash);
    const bound = bindAll(f.tx, f.proofs);
    const r = verifyTx(f.tx, bound);
    const insp = inspect(f.tx, bound, { headers: f.headers });
    // "Plain" = every lock group is verified single-key secp AND nothing is minted (no DAO).
    // A DAO cell also has a secp lock; it is not a plain payment.
    if (
      r.length > 0 &&
      r.every((x) => x.profile === SECP_PROFILE && x.verdict === "verified") &&
      insp.dao.length === 0
    ) {
      return f;
    }
  }
  throw new Error("no plain secp256k1 fixture");
})();

// A multi-input fixture made only of supported user locks (no L2 witnesses).
const multi = (() => {
  for (const e of manifest) {
    const f = loadFixture(e.hash);
    if (f.tx.inputs.length < 3) continue;
    const r = verifyTx(f.tx, bindAll(f.tx, f.proofs));
    if (r.some((x) => x.verdict === "verified")) {
      return f;
    }
  }
  throw new Error("no suitable multi-input fixture");
})();

function clone<T>(x: T): T {
  return structuredClone(x);
}

const boundOutput = (f: typeof plain, i: number): CellOutput =>
  f.proofs[i]!.prevTx.outputs[f.proofs[i]!.index]!;

describe("binding", () => {
  it("accepts an honest proof set", () => {
    assert.doesNotThrow(() => bindAll(plain.tx, plain.proofs));
  });

  it("rejects an inflated input capacity (the fee-theft attack)", () => {
    const proofs = clone(plain.proofs);
    proofs[0]!.cellOutput = { ...boundOutput(plain, 0), capacity: 10_000_000_000_000n };
    assert.throws(() => bindAll(plain.tx, proofs), BindError);
  });

  it("rejects a previous transaction that does not hash to the outpoint", () => {
    const bad = clone(plain.proofs[0]!.prevTx);
    bad.outputs[0] = { ...bad.outputs[0]!, capacity: bad.outputs[0]!.capacity + 1n };
    const proofs = clone(plain.proofs);
    proofs[0] = { prevTx: bad, index: plain.proofs[0]!.index };
    assert.throws(() => bindAll(plain.tx, proofs), /hash mismatch/);
  });

  it("rejects an index that does not match the outpoint", () => {
    const proofs = clone(plain.proofs);
    proofs[0] = { ...proofs[0]!, index: proofs[0]!.index + 1 };
    assert.throws(() => bindAll(plain.tx, proofs), BindError);
  });

  it("rejects a mutated data claim", () => {
    const proofs = clone(plain.proofs);
    proofs[0]!.data = "0xdeadbeef";
    assert.throws(() => bindAll(plain.tx, proofs), /data claim/);
  });

  it("rejects a swapped output claim", () => {
    const prev = plain.proofs[0]!.prevTx;
    if (prev.outputs.length < 2) return; // nothing to swap in this fixture
    const proofs = clone(plain.proofs);
    const other = plain.proofs[0]!.index === 0 ? 1 : 0;
    proofs[0]!.cellOutput = prev.outputs[other]!;
    assert.throws(() => bindAll(plain.tx, proofs), BindError);
  });

  it("rejects a proof count mismatch", () => {
    assert.throws(() => bindAll(plain.tx, plain.proofs.slice(1)), /expected/);
  });

  it("never reaches inspect() with a forged claim", () => {
    const forged = clone(plain.proofs);
    forged[0]!.cellOutput = { ...boundOutput(plain, 0), capacity: 999n * 100_000_000n };
    assert.throws(() => inspect(plain.tx, bindAll(plain.tx, forged)), BindError);
  });
});

describe("signed bytes", () => {
  it("a changed output invalidates the signature", () => {
    const tx = clone(multi.tx);
    tx.outputs[0] = { ...tx.outputs[0]!, capacity: tx.outputs[0]!.capacity - 1n };
    const results = verifyTx(tx, bindAll(tx, multi.proofs));
    assert.ok(
      results.some((r) => r.verdict === "bad-signature"),
      JSON.stringify(results.map((r) => [r.name, r.verdict])),
    );
  });

  it("a changed cell_dep invalidates the signature", () => {
    const tx = clone(multi.tx);
    const cur = tx.cellDeps[0]!.depType;
    tx.cellDeps[0] = { ...tx.cellDeps[0]!, depType: cur === "code" ? "dep_group" : "code" };
    const results = verifyTx(tx, bindAll(tx, multi.proofs));
    assert.ok(results.some((r) => r.verdict === "bad-signature"));
  });

  it("reordering inputs invalidates the signature", () => {
    const tx = clone(multi.tx);
    [tx.inputs[0], tx.inputs[1]] = [tx.inputs[1]!, tx.inputs[0]!];
    const proofs = clone(multi.proofs);
    [proofs[0], proofs[1]] = [proofs[1]!, proofs[0]!];
    const results = verifyTx(tx, bindAll(tx, proofs));
    assert.ok(results.every((r) => r.verdict !== "verified"));
  });

  it("a perturbed signature does not verify", () => {
    const tx = clone(multi.tx);
    const before = verifyTx(multi.tx, bindAll(multi.tx, multi.proofs));
    const secp = before.find((r) => r.verdict === "verified");
    assert.ok(secp, "fixture has no verified group");
    const i = secp.inputs[0]!;
    const w = hexToBytes(tx.witnesses[i]!);
    w[20] = w[20]! ^ 0xff; // first byte of the signature (header 16 + length 4)
    tx.witnesses[i] = bytesToHex(w);
    const results = verifyTx(tx, bindAll(tx, multi.proofs));
    assert.ok(results.some((r) => r.verdict === "bad-signature"));
  });

  it("tx_hash changes when any signed field changes", () => {
    const tx = clone(multi.tx);
    const before = txHash(tx);
    tx.outputsData[0] = "0x00";
    assert.notEqual(txHash(tx), before);
  });
});

describe("lock policy", () => {
  it("refuses an unknown lock instead of guessing", () => {
    const bound = bindAll(plain.tx, plain.proofs).map((b) => ({
      ...b,
      cellOutput: { ...b.cellOutput, lock: { ...b.cellOutput.lock, codeHash: "0x" + "11".repeat(32) } },
    }));
    assert.equal(verifyTx(plain.tx, bound)[0]!.verdict, "unknown-lock");
  });

  it("names a known lock but still refuses it without a profile", () => {
    const OMNI = "0x9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26";
    const bound = bindAll(plain.tx, plain.proofs).map((b) => ({
      ...b,
      cellOutput: { ...b.cellOutput, lock: { ...b.cellOutput.lock, codeHash: OMNI } },
    }));
    const r = verifyTx(plain.tx, bound)[0]!;
    assert.equal(r.verdict, "no-profile");
    assert.equal(r.name, "OmniLock");
  });
});

describe("multisig", () => {
  const ms = (() => {
    for (const e of manifest) {
      const f = loadFixture(e.hash);
      const r = verifyTx(f.tx, bindAll(f.tx, f.proofs));
      if (r.some((x) => x.profile?.includes("multisig") && x.verdict === "verified")) return f;
    }
    throw new Error("no verified multisig fixture");
  })();

  const msGroup = () => {
    const results = verifyTx(ms.tx, bindAll(ms.tx, ms.proofs));
    const g = results.find((r) => r.profile?.includes("multisig"));
    assert.ok(g, "no multisig group");
    return g!;
  };

  const replaceLock = (txIndex: number, lock: Uint8Array) => {
    const args = decodeWitnessArgs(hexToBytes(ms.tx.witnesses[txIndex]!));
    return bytesToHex(encodeWitnessArgs({ ...args, lock }));
  };

  it("verifies a real on-chain multisig spend", () => {
    const g = msGroup();
    assert.equal(g.verdict, "verified");
    assert.ok((g.signers?.length ?? 0) >= 2);
  });

  it("is order-independent over signatures", () => {
    const g = msGroup();
    const i = g.inputs[0]!;
    const lock = witnessLock(ms.tx.witnesses[i]!)!;
    const parsed = decodeMultisigLock(lock)!;
    assert.ok(parsed.signatures.length >= 2, "need two signatures to swap");

    const scriptLen = 4 + 20 * parsed.pubkeys.length;
    const swapped = lock.slice();
    swapped.set(parsed.signatures[1]!, scriptLen);
    swapped.set(parsed.signatures[0]!, scriptLen + 65);

    const tx = clone(ms.tx);
    tx.witnesses[i] = replaceLock(i, swapped);
    const results = verifyTx(tx, bindAll(tx, ms.proofs));
    assert.ok(results.some((r) => r.profile?.includes("multisig") && r.verdict === "verified"));
  });

  it("rejects a zeroed signature", () => {
    const g = msGroup();
    const i = g.inputs[0]!;
    const lock = witnessLock(ms.tx.witnesses[i]!)!;
    const parsed = decodeMultisigLock(lock)!;
    const scriptLen = 4 + 20 * parsed.pubkeys.length;
    const broken = lock.slice();
    broken.fill(0, scriptLen, scriptLen + 65);

    const tx = clone(ms.tx);
    tx.witnesses[i] = replaceLock(i, broken);
    const results = verifyTx(tx, bindAll(tx, ms.proofs));
    assert.ok(results.some((r) => r.verdict === "bad-signature"));
  });

  it("rejects a truncated lock field", () => {
    const g = msGroup();
    const i = g.inputs[0]!;
    const lock = witnessLock(ms.tx.witnesses[i]!)!;
    const tx = clone(ms.tx);
    tx.witnesses[i] = replaceLock(i, lock.slice(0, lock.length - 1));
    const results = verifyTx(tx, bindAll(tx, ms.proofs));
    assert.ok(results.some((r) => r.verdict === "bad-signature"));
  });
});

describe("nervos dao", () => {
  const dao = (() => {
    for (const e of manifest) {
      const f = loadFixture(e.hash);
      const r = inspect(f.tx, bindAll(f.tx, f.proofs), { headers: f.headers });
      if (r.dao.some((x) => x.kind === "withdrawing")) return { f, r };
    }
    throw new Error("no DAO withdraw fixture");
  })();

  it("verifies the withdraw's lock signature", () => {
    const bound = bindAll(dao.f.tx, dao.f.proofs);
    assert.ok(verifyTx(dao.f.tx, bound).some((x) => x.verdict === "verified"));
  });

  it("computes interest and reconciles the fee", () => {
    const w = dao.r.dao.find((x) => x.kind === "withdrawing")!;
    assert.ok(w.interest !== undefined, "interest should be computable from the supplied headers");
    assert.ok(w.interest! > 0n);
    assert.equal(dao.r.interestKnown, true);
    // fee = inputs + interest - outputs, and must be positive
    assert.equal(dao.r.fee, dao.r.inputCapacity + dao.r.daoInterest - dao.r.outputCapacity);
    assert.ok(dao.r.fee > 0n, `fee should be positive, got ${dao.r.fee}`);
    assert.ok(w.mature === true);
  });

  it("refuses to invent interest when a header is missing", () => {
    const r = inspect(dao.f.tx, bindAll(dao.f.tx, dao.f.proofs), { headers: new Map() });
    assert.equal(r.interestKnown, false);
    assert.ok(r.warnings.some((w) => /interest is unknown/.test(w)));
  });

  it("uses the flat occupied-capacity formula", () => {
    const cell = bindAll(dao.f.tx, dao.f.proofs)[0]!;
    // 8 (capacity) + 8 (data) + 20+33 (lock) + 0+33 (DAO type) = 102
    assert.equal(occupiedBytes(cell.cellOutput, cell.data), 102);
  });

  it("identifies the cell as a withdrawing cell, not a token", () => {
    const cell = bindAll(dao.f.tx, dao.f.proofs)[0]!;
    assert.equal(cell.cellOutput.type!.codeHash.toLowerCase(), DAO_CODE_HASH);
    const parsed = classifyDaoCell(cell.data);
    assert.equal(parsed?.kind, "withdrawing");
    // and the inspector must not report a token delta for it
    assert.equal(dao.r.deltas.filter((d) => d.kind === "token").length, 0);
  });
});

describe("xudt", () => {
  const token = (() => {
    for (const e of manifest) {
      const f = loadFixture(e.hash);
      const r = inspect(f.tx, bindAll(f.tx, f.proofs), { headers: f.headers });
      if (r.tokens.length > 0) return { f, r, t: r.tokens[0]! };
    }
    throw new Error("no xUDT fixture");
  })();

  it("recognises xUDT and totals the amount across cells", () => {
    assert.equal(token.t.kind, "xudt");
    assert.ok(token.t.delta > 0n);
  });

  it("owner mode follows the flags, not just input locks", () => {
    const bound = bindAll(token.f.tx, token.f.proofs);
    const xudtCell = bound.find((b) => tokenKind(b.cellOutput.type) === "xudt");
    assert.ok(xudtCell, "no xUDT input");
    const info = decodeXudtArgs(xudtCell!.cellOutput.type!.args)!;
    // What the chain says: owner mode is satisfied.
    assert.equal(ownerMode(info, token.f.tx, bound), true);
    // Drop the flag that points at input type scripts: input locks alone do not satisfy it.
    assert.equal(ownerMode({ ...info, flags: 0 }, token.f.tx, bound), false);
  });

  it("reads the first 16 bytes and ignores extension data", () => {
    const data = "0x" + "01".padStart(2, "0") + "00".repeat(15) + "deadbeef";
    assert.equal(tokenAmount(data), 1n);
  });

  it("refuses data shorter than 16 bytes", () => {
    assert.equal(tokenAmount("0x" + "00".repeat(15)), null);
  });
});

describe("spore", () => {
  const enc = new TextEncoder();
  const sporeData = (contentType: string, content: string, clusterId?: string) =>
    "0x" +
    Buffer.from(
      table(
        bytesVec(enc.encode(contentType)),
        bytesVec(enc.encode(content)),
        option(clusterId ? bytesVec(hexToBytes(clusterId)) : null),
      ),
    ).toString("hex");

  const id = "0x" + "ab".repeat(32);
  const type = { codeHash: SPORE_V2_CODE_HASH, hashType: "data1" as const, args: id };
  const lock = {
    codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hashType: "type" as const,
    args: "0x" + "11".repeat(20),
  };
  const otherLock = { ...lock, args: "0x" + "22".repeat(20) };
  const data = sporeData("image/png", "hello-spore");
  const cell = (cap: bigint, l = lock) => ({ capacity: cap, lock: l, type });

  it("parses SporeData", () => {
    const d = parseSporeData(data)!;
    assert.equal(d.contentType, "image/png");
    assert.equal(d.contentBytes, 11);
    assert.equal(d.clusterId, null);
  });

  it("detects a transfer and reports the new lock", () => {
    const tx = {
      outputs: [cell(100_000_000_000n, otherLock)],
      outputsData: [data],
    } as any;
    const bound = [{ cellOutput: cell(100_000_000_000n), data, outPointTxHash: "0x", index: 0 }] as any;
    const [f] = inspectSpore(tx, bound);
    assert.equal(f!.kind, "transfer");
    assert.equal(f!.issues.length, 0);
    assert.equal(f!.toLock!.args, otherLock.args);
  });

  it("rejects a modified SporeData", () => {
    const tx = { outputs: [cell(100_000_000_000n)], outputsData: [sporeData("image/png", "tampered")] } as any;
    const bound = [{ cellOutput: cell(100_000_000_000n), data, outPointTxHash: "0x", index: 0 }] as any;
    const [f] = inspectSpore(tx, bound);
    assert.ok(f!.issues.some((i) => /changed during transfer/.test(i)));
  });

  it("flags a capacity reduction during transfer", () => {
    const tx = { outputs: [cell(70_000_000_000n)], outputsData: [data] } as any;
    const bound = [{ cellOutput: cell(100_000_000_000n), data, outPointTxHash: "0x", index: 0 }] as any;
    const [f] = inspectSpore(tx, bound);
    assert.ok(f!.issues.some((i) => /capacity reduced by 300 CKB/.test(i)));
  });

  it("detects a melt when no output carries the id", () => {
    const tx = { outputs: [], outputsData: [] } as any;
    const bound = [{ cellOutput: cell(100_000_000_000n), data, outPointTxHash: "0x", index: 0 }] as any;
    const [f] = inspectSpore(tx, bound);
    assert.equal(f!.kind, "melt");
    assert.equal(f!.capacityBefore, 100_000_000_000n);
  });
});

describe("lock descriptors", () => {
  it("describes OmniLock auth schemes and modes", () => {
    const eth = "0x" + "01" + "22".repeat(20) + "03";
    const info = decodeOmnilockArgs(eth)!;
    assert.equal(info.authFlag, 0x01);
    assert.equal(info.authName, "Ethereum");
    assert.deepEqual(info.modes, ["administrator", "anyone-can-pay"]);
  });

  it("rejects truncated OmniLock args", () => {
    assert.equal(decodeOmnilockArgs("0x" + "01".repeat(10)), null);
  });
});

describe("since", () => {
  it("decodes absolute block", () => {
    const s = decodeSinceInfo(12345n);
    assert.equal(s.kind, "absolute-block");
    assert.equal(s.text, "block 12345");
  });

  it("decodes absolute epoch with fraction", () => {
    const value = 15125n | (568n << 24n) | (1702n << 40n);
    const s = decodeSinceInfo(0x20n << 56n | value);
    assert.equal(s.kind, "absolute-epoch");
    assert.equal(s.text, "epoch 15125.568/1702");
  });

  it("decodes relative timestamp", () => {
    const s = decodeSinceInfo(0xc0n << 56n | 3600n * 1000n);
    assert.equal(s.kind, "relative-timestamp");
    assert.equal(s.text, "3600s after");
    assert.equal(s.relative, true);
  });

  it("treats zero as no constraint", () => {
    assert.equal(decodeSinceInfo(0n).kind, "unknown");
    assert.equal(decodeSinceInfo(0n).text, "none");
  });
});

describe("inspection", () => {
  it("fee is inputs minus outputs, computed from bound cells", () => {
    const r = inspect(plain.tx, bindAll(plain.tx, plain.proofs));
    assert.equal(r.fee.toString(), plain.fee);
    assert.equal(r.inputCapacity - r.outputCapacity, r.fee);
  });

  it("never invents a token delta from unknown data", () => {
    const bound = bindAll(plain.tx, plain.proofs).map((b) => ({
      ...b,
      cellOutput: {
        ...b.cellOutput,
        type: { codeHash: "0x" + "22".repeat(32), hashType: "type" as const, args: "0x01" },
      },
      data: "0x00112233445566778899", // 10 bytes, not an xUDT amount
    }));
    const r = inspect(plain.tx, bound);
    assert.equal(r.deltas.filter((d) => d.kind === "token").length, 0);
    assert.ok(r.warnings.some((w) => /semantics unknown/.test(w)));
  });
});

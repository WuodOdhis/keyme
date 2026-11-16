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
    const r = verifyTx(f.tx, bindAll(f.tx, f.proofs));
    // Every group must be a verified single-key secp256k1 group — "contains one" is not enough.
    if (r.length > 0 && r.every((x) => x.profile === SECP_PROFILE && x.verdict === "verified")) {
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

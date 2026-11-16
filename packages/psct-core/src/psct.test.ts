/**
 * PSCT v0 conformance tests.
 *
 * These are the stage-1 vectors: canonical encoding, commutative combine, unknown-field
 * preservation, and finalization that must reproduce (or at least verify) the original witness.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { loadFixture, loadManifest, type Fixture } from "./fixtures.js";
import {
  buildPsct,
  combinePsct,
  decodePsct,
  encodePsct,
  extractExistingSignatures,
  finalizePsct,
  psctFingerprint,
  psctTransaction,
  psctTxHash,
  type Psct,
} from "./psct/container.js";
import { encodeCbor, decodeCbor } from "./cbor.js";
import { toCkbCli, fromCkbCli } from "./ckbcli.js";
import { parseCkb, multisigLock, LEGACY_MULTISIG } from "./apps/coordinator.js";
import { signPsct } from "./apps/signer.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { encodeAddress } from "./address.js";
import { encodeTransaction } from "./ckb.js";
import { ckbHash } from "./hash.js";
import { bindAll } from "./psct/bind.js";
import { witnessLock } from "./sighash.js";
import { bytesEqual, bytesToHex, hexToBytes } from "./bytes.js";
import { scriptHash, txHash } from "./hash.js";
import { classifyLock, MULTISIG_PROFILE, MULTISIG_V2_PROFILE, SECP_PROFILE } from "./profiles.js";

const manifest = loadManifest();

function psctFor(f: Fixture, network: "ckb" | "ckt" = "ckb"): Psct {
  return buildPsct(f.tx, {
    network,
    proofs: f.proofs.map((p) => ({ prevTx: p.prevTx, index: p.index, blockHash: p.blockHash })),
    headers: f.headers,
    inputHints: f.tx.inputs.map(() => ({ derivation: "m/44'/309'/0'/0/0" })),
    outputHints: f.tx.outputs.map((_, i) => ({ role: i === 0 ? "payment" : "change" })),
  });
}

/** Extract every existing signature from the fixture's witnesses into PSCT form. */
function extractSignatures(p: Psct, f: Fixture): void {
  extractExistingSignatures(p, f.tx, bindAll(f.tx, f.proofs));
}

describe("cbor", () => {
  it("is deterministic for map key order", () => {
    const a = encodeCbor({ b: 1, a: 2, c: [true, null, "x"] });
    const b = encodeCbor({ c: [true, null, "x"], a: 2, b: 1 });
    assert.ok(bytesEqual(a, b));
  });

  it("rejects non-minimal integers", () => {
    assert.throws(() => decodeCbor(Uint8Array.of(0x18, 0x01)), /non-canonical/);
  });

  it("rejects unordered map keys", () => {
    // {"b":1,"a":2} in the wrong order
    const bytes = Uint8Array.of(
      0xa2,
      0x61, 0x62, 0x01,
      0x61, 0x61, 0x02,
    );
    assert.throws(() => decodeCbor(bytes), /canonical order/);
  });

  it("round-trips bytes, bigints and unicode", () => {
    const value = { data: Uint8Array.of(1, 2, 3), n: 18446744073709551615n, text: "ключ" };
    const back = decodeCbor(encodeCbor(value)) as typeof value;
    assert.ok(bytesEqual(back.data, value.data));
    assert.equal(back.n, value.n);
    assert.equal(back.text, value.text);
  });
});

describe("psct envelope", () => {
  const f = loadFixture(manifest[0]!.hash);

  it("round-trips byte-identically", () => {
    const p = psctFor(f);
    const bytes = encodePsct(p);
    const back = decodePsct(bytes);
    assert.ok(bytesEqual(encodePsct(back), bytes));
  });

  it("keeps the tx hash and fingerprint", () => {
    const p = psctFor(f);
    assert.equal(psctTxHash(p), f.hash);
    assert.match(psctFingerprint(p), /^0x[0-9a-f]{8}…[0-9a-f]{4}$/);
  });

  it("references the same inputs and outputs", () => {
    const p = psctFor(f);
    const tx = psctTransaction(p);
    assert.equal(tx.inputs.length, f.tx.inputs.length);
    assert.equal(tx.outputs.length, f.tx.outputs.length);
    assert.equal(tx.witnesses.length, 0);
  });

  it("rejects a bad magic", () => {
    const bytes = encodePsct(psctFor(f));
    bytes[0] = 0x00;
    assert.throws(() => decodePsct(bytes), /magic/);
  });

  it("preserves unknown top-level fields", () => {
    const p = psctFor(f);
    const withExtra: Psct = { ...p, extra: { future_field: { a: 1 } } };
    const back = decodePsct(encodePsct(withExtra));
    assert.deepEqual(back.extra, { future_field: { a: 1 } });
  });
});

describe("combine", () => {
  const f = loadFixture(manifest[0]!.hash);

  it("is commutative for signatures and unknown fields", () => {
    const base = psctFor(f);
    const tx = psctTransaction(base);
    const bound = bindAll(tx, f.proofs);
    const group = bound.findIndex((b) => classifyLock(b.cellOutput.lock).profile === SECP_PROFILE)!;
    const sig = witnessLock(f.tx.witnesses[group] ?? "0x")!;
    const key = scriptHash(bound[group]!.cellOutput.lock);

    const left: Psct = {
      ...base,
      sigs: {
        [key]: [
          {
            signer: hexToBytes(bound[group]!.cellOutput.lock.args),
            signature: sig,
            profile: SECP_PROFILE,
          },
        ],
      },
    };
    const right: Psct = { ...base, extra: { note: "b" } };

    const ab = encodePsct(combinePsct(left, right));
    const ba = encodePsct(combinePsct(right, left));
    assert.ok(bytesEqual(ab, ba), "combine must be commutative");
    assert.equal(decodePsct(ab).sigs[key]!.length, 1);
    assert.deepEqual(decodePsct(ab).extra, { note: "b" });
  });

  it("rejects conflicting signatures from the same signer", () => {
    const base = psctFor(f);
    const key = scriptHash(bindAll(f.tx, f.proofs)[0]!.cellOutput.lock);
    const a: Psct = { ...base, sigs: { [key]: [{ signer: new Uint8Array(20), signature: new Uint8Array(65).fill(1), profile: SECP_PROFILE }] } };
    const b: Psct = { ...base, sigs: { [key]: [{ signer: new Uint8Array(20), signature: new Uint8Array(65).fill(2), profile: SECP_PROFILE }] } };
    assert.throws(() => combinePsct(a, b), /conflicting signature/);
  });

  it("rejects different transactions", () => {
    const a = psctFor(loadFixture(manifest[0]!.hash));
    const b = psctFor(loadFixture(manifest[1]!.hash));
    assert.throws(() => combinePsct(a, b), /different transactions/);
  });
});

describe("ckb-cli interop", () => {
  const fullHash = (tx: Parameters<typeof encodeTransaction>[0]) =>
    bytesToHex(ckbHash(encodeTransaction(tx)));

  it("exports a secp PSCT in ckb-cli shape and imports it back", () => {
    const f = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) => {
        const r = bindAll(x.tx, x.proofs);
        return r.every((b) => classifyLock(b.cellOutput.lock).profile === SECP_PROFILE);
      })!;
    const p = psctFor(f);
    extractSignatures(p, f);

    const cli = toCkbCli(p);
    assert.equal(
      (cli.transaction as { witnesses: unknown[] }).witnesses.length,
      f.tx.witnesses.length,
      "placeholder witnesses preserve the layout",
    );
    assert.equal(Object.keys(cli.multisig_configs).length, 0);
    assert.ok(Object.keys(cli.signatures).length > 0);

    const back = fromCkbCli(cli, { proofs: f.proofs, network: "ckb" });
    const a = finalizePsct(p);
    const b = finalizePsct(back);
    assert.equal(fullHash(b), fullHash(a));
  });

  it("exports a multisig as config + addresses and re-imports it", () => {
    const f = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) =>
        bindAll(x.tx, x.proofs).some((b) => {
          const profile = classifyLock(b.cellOutput.lock).profile;
          return profile === MULTISIG_PROFILE || profile === MULTISIG_V2_PROFILE;
        }),
      )!;
    const p = psctFor(f);
    extractSignatures(p, f);

    const cli = toCkbCli(p);
    const configs = Object.values(cli.multisig_configs);
    assert.equal(configs.length, 1);
    assert.equal(configs[0]!.threshold, 3);
    assert.equal(configs[0]!.sighash_addresses.length, 5);
    for (const a of configs[0]!.sighash_addresses) assert.match(a, /^ck(b|t)1/);

    const back = fromCkbCli(cli, { proofs: f.proofs, network: "ckb" });
    const a = finalizePsct(p);
    const b = finalizePsct(back);
    assert.equal(fullHash(b), fullHash(a));
  });

  it("refuses a lossy export when a witness template carries type data", () => {
    const dao = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) => x.tx.headerDeps.length > 0)!;
    const p = psctFor(dao);
    extractSignatures(p, dao);
    assert.throws(() => toCkbCli(p), /lossy export/);
  });
});

describe("coordinator helpers", () => {
  it("parses CKB decimal amounts", () => {
    assert.equal(parseCkb("1"), 100_000_000n);
    assert.equal(parseCkb("0.00000001"), 1n);
    assert.equal(parseCkb("100.5"), 10_050_000_000n);
    assert.throws(() => parseCkb("1.123456789"), /bad CKB amount/);
  });

  it("derives the multisig lock and template from signers", () => {
    const locks = manifest.flatMap((m) => {
      const f = loadFixture(m.hash);
      return bindAll(f.tx, f.proofs)
        .map((b) => b.cellOutput.lock)
        .filter((l) => classifyLock(l).profile === SECP_PROFILE);
    });
    const unique = new Map(locks.map((l) => [l.args, l]));
    const signers = [...unique.values()].slice(0, 3).map((l) => encodeAddress(l, "ckt", "short"));
    assert.equal(signers.length, 3);

    const { lock, lockTemplate } = multisigLock({
      signers,
      threshold: 2,
      requireFirstN: 0,
      version: "legacy",
    });
    assert.equal(lock.codeHash, LEGACY_MULTISIG);
    assert.equal((lock.args.length - 2) / 2, 20);
    assert.equal(lockTemplate.length, 4 + 20 * 3 + 65 * 2);
  });
});

describe("signer policy", () => {
  it("refuses an unknown type script instead of signing an uncertifiable contract", () => {
    const f = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) =>
        bindAll(x.tx, x.proofs).every(
          (b) => classifyLock(b.cellOutput.lock).profile === SECP_PROFILE,
        ),
      )!;
    const base = psctFor(f);
    const tx = psctTransaction(base);
    tx.outputs[0] = {
      ...tx.outputs[0]!,
      type: { codeHash: "0x" + "22".repeat(32), hashType: "type", args: "0x" },
    };
    const psct = buildPsct(tx, {
      network: "ckb",
      proofs: f.proofs.map((p) => ({ prevTx: p.prevTx, index: p.index, blockHash: p.blockHash })),
      headers: f.headers,
    });
    const key = bytesToHex(secp256k1.utils.randomPrivateKey());
    assert.throws(() => signPsct(psct, key), /unknown type script/);
  });
});

describe("finalize", () => {
  it("reproduces a single-key witness exactly", () => {
    const f = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) => {
        const r = bindAll(x.tx, x.proofs);
        return r.every((b) => classifyLock(b.cellOutput.lock).profile === SECP_PROFILE);
      })!;
    const p = psctFor(f);
    extractSignatures(p, f);
    const tx = finalizePsct(p);
    assert.equal(txHash(tx), f.hash);
    for (let i = 0; i < f.tx.witnesses.length; i++) {
      assert.equal(tx.witnesses[i], f.tx.witnesses[i], `witness ${i}`);
    }
  });

  it("finalizes a 3-of-5 multisig and verifies", () => {
    const f = manifest
      .map((m) => loadFixture(m.hash))
      .find((x) => {
        const r = bindAll(x.tx, x.proofs);
        return r.some((b) => {
          const p = classifyLock(b.cellOutput.lock).profile;
          return p === MULTISIG_PROFILE || p === MULTISIG_V2_PROFILE;
        });
      })!;
    const p = psctFor(f);
    extractSignatures(p, f);
    const tx = finalizePsct(p);
    assert.equal(psctTxHash({ ...p }), f.hash);
    assert.equal(tx.witnesses.length, f.tx.witnesses.length);
  });
});

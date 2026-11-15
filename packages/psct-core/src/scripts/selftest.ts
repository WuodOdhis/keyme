/**
 * Self-test: recompute real mainnet transaction hashes and recover real signatures.
 *
 * Validates the whole stack in one shot:
 *   molecule encoding -> tx_hash -> sighash message -> secp256k1 recovery -> blake160 lock match
 *
 * tx_hash mismatch  => transaction/molecule encoding is wrong.
 * tx_hash ok, sig fails => witness (WitnessArgs) encoding or sighash framing is wrong.
 */

import { txHash } from "../hash.js";
import { sighashAllMessage, witnessLock } from "../sighash.js";
import { verifySighashAll } from "../verify.js";
import { MAINNET } from "../rpc.js";
import type { Transaction } from "../ckb.js";
import { bytesToHex } from "../bytes.js";

const SECP_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

interface Case {
  hash: string;
  inputs: number;
  hashOk: boolean;
  sigs: number;
  sigsOk: number;
  failures: string[];
}

const prevCache = new Map<string, Transaction>();

async function resolveLocks(tx: Transaction) {
  const locks = new Map<string, { codeHash: string; hashType: string; args: string }>();
  for (const input of tx.inputs) {
    const op = input.previousOutput;
    let prev = prevCache.get(op.txHash);
    if (!prev) {
      prev = await MAINNET.tx(op.txHash);
      prevCache.set(op.txHash, prev);
    }
    const out = prev.outputs[op.index];
    if (!out) throw new Error(`missing output ${op.txHash}[${op.index}]`);
    locks.set(`${op.txHash}:${op.index}`, {
      codeHash: out.lock.codeHash,
      hashType: out.lock.hashType,
      args: out.lock.args,
    });
  }
  return locks;
}

async function main() {
  const cases: Case[] = [];
  const tip = Number(await MAINNET.tip());
  let scanned = 0;

  for (let d = 1; d < 100 && cases.length < 25; d++) {
    const txs = await MAINNET.blockTxs(tip - d);
    scanned++;
    for (const { hash, tx } of txs) {
      if (tx.witnesses.length === 0) continue;
      // Cellbase transactions have a null outpoint and no real signatures; skip them.
      if (tx.inputs.some((i) => /^0x0+$/.test(i.previousOutput.txHash))) continue;

      const computed = txHash(tx);
      const hashOk = computed === hash;
      const locks = await resolveLocks(tx);

      const groups = new Map<string, number[]>();
      tx.inputs.forEach((input, i) => {
        const op = input.previousOutput;
        const l = locks.get(`${op.txHash}:${op.index}`)!;
        const key = `${l.codeHash}|${l.hashType}|${l.args}`;
        groups.set(key, [...(groups.get(key) ?? []), i]);
      });

      let groupCount = 0;
      let groupsOk = 0;
      const failures: string[] = [];

      for (const [key, indices] of groups) {
        const [codeHash, hashType, args] = key.split("|");
        if (codeHash !== SECP_CODE_HASH || hashType !== "type" || args!.length !== 42) continue;
        groupCount++;

        // One signature per lock group, carried on the group's first input.
        const first = Math.min(...indices);
        let msg: Uint8Array;
        try {
          msg = sighashAllMessage(tx, indices);
        } catch (e) {
          failures.push(`group ${args!.slice(0, 10)}…: ${(e as Error).message}`);
          continue;
        }
        const sig = witnessLock(tx.witnesses[first] ?? "0x");
        if (!sig || sig.length !== 65) {
          failures.push(`group ${args!.slice(0, 10)}…: input ${first} has no 65-byte lock field`);
          continue;
        }
        const res = verifySighashAll(msg, bytesToHex(sig), args!);
        if (res.ok) groupsOk++;
        else failures.push(`group ${args!.slice(0, 10)}…: recovered ${res.recovered} != ${args}`);
      }

      if (groupCount > 0) cases.push({ hash, inputs: tx.inputs.length, hashOk, sigs: groupCount, sigsOk: groupsOk, failures });
      if (cases.length >= 25) break;
    }
  }

  const hashFails = cases.filter((c) => !c.hashOk);
  const sigFails = cases.filter((c) => c.sigsOk !== c.sigs);

  console.log(`scanned blocks:                    ${scanned}`);
  console.log(`cases with secp256k1 lock groups:   ${cases.length}`);
  console.log(`tx_hash mismatches:                ${hashFails.length}`);
  console.log(`signature failures:                ${sigFails.length}`);
  console.log("");
  for (const c of cases) {
    const mark = c.hashOk && c.sigsOk === c.sigs ? "ok  " : "FAIL";
    console.log(
      `${mark} ${c.hash.slice(0, 18)}… inputs=${c.inputs} groups=${c.sigsOk}/${c.sigs}` +
        (c.failures.length ? `\n      ${c.failures.slice(0, 2).join("\n      ")}` : ""),
    );
  }
  if (hashFails.length || sigFails.length) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

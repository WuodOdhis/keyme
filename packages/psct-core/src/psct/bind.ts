/**
 * Input proof binding.
 *
 * CKB's sighash commits to the *outpoint*, not to the spent cell's capacity/lock/type/data.
 * Therefore a supplied CellOutput is a claim, not a fact, until it is bound to the outpoint by
 * the creating transaction's hash. This module is the only place allowed to turn a claim into a
 * fact.
 */

import { bytesEqual, hexToBytes } from "../bytes.js";
import type { CellOutput, Transaction } from "../ckb.js";
import { txHash } from "../hash.js";

export interface InputProof {
  /** The creating transaction, witness-free. Its blake2b hash must equal the outpoint's tx_hash. */
  prevTx: Transaction;
  index: number;
  /** Optional claims. If present they must match the bound output exactly. */
  cellOutput?: CellOutput;
  data?: string;
  /** Block that contains the creating transaction. Needed for DAO interest and since checks. */
  blockHash?: string;
}

export interface BoundCell {
  outPointTxHash: string;
  index: number;
  cellOutput: CellOutput;
  data: string;
  blockHash?: string;
}

export class BindError extends Error {
  constructor(
    message: string,
    public readonly inputIndex: number,
  ) {
    super(message);
    this.name = "BindError";
  }
}

function sameScript(a: CellOutput["lock"], b: CellOutput["lock"]): boolean {
  return (
    a.codeHash.toLowerCase() === b.codeHash.toLowerCase() &&
    a.hashType === b.hashType &&
    a.args.toLowerCase() === b.args.toLowerCase()
  );
}

/**
 * Bind one input to its creating transaction.
 *
 * Checks, in order:
 *   1. blake2b(raw(prevTx)) == input.previous_output.tx_hash
 *   2. proof.index < prevTx.outputs.length
 *   3. if a CellOutput claim was supplied, it equals prevTx.outputs[index]
 *   4. if a data claim was supplied, it equals prevTx.outputsData[index]
 */
export function bindInput(tx: Transaction, inputIndex: number, proof: InputProof): BoundCell {
  const input = tx.inputs[inputIndex];
  if (!input) throw new BindError(`no input at index ${inputIndex}`, inputIndex);

  const op = input.previousOutput;
  const computed = txHash(proof.prevTx);
  if (computed.toLowerCase() !== op.txHash.toLowerCase()) {
    throw new BindError(
      `prev tx hash mismatch: computed ${computed}, outpoint says ${op.txHash}`,
      inputIndex,
    );
  }
  if (proof.index !== op.index) {
    throw new BindError(`proof index ${proof.index} != outpoint index ${op.index}`, inputIndex);
  }

  const out = proof.prevTx.outputs[proof.index];
  if (!out) throw new BindError(`prev tx has no output at ${proof.index}`, inputIndex);
  const data = proof.prevTx.outputsData[proof.index] ?? "0x";

  if (proof.cellOutput) {
    if (proof.cellOutput.capacity !== out.capacity) {
      throw new BindError(
        `capacity claim ${proof.cellOutput.capacity} != bound ${out.capacity}`,
        inputIndex,
      );
    }
    if (!sameScript(proof.cellOutput.lock, out.lock)) {
      throw new BindError(`lock claim does not match bound output`, inputIndex);
    }
    if (Boolean(proof.cellOutput.type) !== Boolean(out.type)) {
      throw new BindError(`type presence claim does not match bound output`, inputIndex);
    }
    if (out.type && proof.cellOutput.type && !sameScript(proof.cellOutput.type, out.type)) {
      throw new BindError(`type claim does not match bound output`, inputIndex);
    }
  }

  if (proof.data !== undefined && !bytesEqual(hexToBytes(proof.data), hexToBytes(data))) {
    throw new BindError(`data claim does not match bound output`, inputIndex);
  }

  return { outPointTxHash: op.txHash, index: proof.index, cellOutput: out, data, blockHash: proof.blockHash };
}

/** Bind every input; throws on the first failure. */
export function bindAll(tx: Transaction, proofs: InputProof[]): BoundCell[] {
  if (proofs.length !== tx.inputs.length) {
    throw new Error(`expected ${tx.inputs.length} input proofs, got ${proofs.length}`);
  }
  return proofs.map((p, i) => bindInput(tx, i, p));
}

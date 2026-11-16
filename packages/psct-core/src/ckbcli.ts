/**
 * ckb-cli interop.
 *
 * ckb-cli's `tx` file is `{ transaction, multisig_configs, signatures }`:
 *   - `transaction` is a full JSON transaction (witnesses may be empty)
 *   - `multisig_configs` is keyed by the 20-byte lock arg (H160) and holds the signers as short
 *     secp addresses plus `require_first_n` / `threshold`
 *   - `signatures` is keyed by the 20-byte lock arg and holds 65-byte signatures
 *
 * The file carries no input cells, so importing one requires proofs. Export is lossless only for
 * profiles ckb-cli understands (secp and multisig); DAO/xUDT witness templates have nowhere to go
 * and are refused rather than silently dropped.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { decodeRawTransaction, fromRpcTx, toRpcTx, type RpcTransaction, type Transaction } from "./ckb.js";
import { blake160, scriptHash } from "./hash.js";
import { decodeAddress, encodeAddress } from "./address.js";
import { classifyLock, MULTISIG_PROFILE, MULTISIG_V2_PROFILE, SECP_PROFILE } from "./profiles.js";
import { decodeMultisigLock } from "./multisig.js";
import { encodeWitnessArgs, sighashMessage, zeroSignatureRegion } from "./sighash.js";
import { pubkeyHash } from "./secp.js";
import { bindAll, type InputProof } from "./psct/bind.js";
import {
  buildPsct,
  psctTransaction,
  type Psct,
  type PsctSignature,
} from "./psct/container.js";

export interface CkbCliMultisigConfig {
  lock_code_hash: string;
  sighash_addresses: string[];
  require_first_n: number;
  threshold: number;
}

export interface CkbCliTxFile {
  transaction: unknown;
  multisig_configs: Record<string, CkbCliMultisigConfig>;
  signatures: Record<string, string[]>;
}

const SECP_CODE = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

export function toCkbCli(psct: Psct): CkbCliTxFile {
  const tx = psctTransaction(psct);
  const network = psct.network;

  for (const t of psct.witnessTemplates) {
    if (t.inputType || t.outputType) {
      throw new Error(
        "ckb-cli has no field for witness type data (DAO/xUDT); refusing a lossy export",
      );
    }
  }

  const bound = bindAll(
    tx,
    psct.inputProofs.map((p) => ({
      prevTx: decodeRawTransaction(p.prevTx),
      index: p.index,
      blockHash: p.blockHash ? bytesToHex(p.blockHash) : undefined,
    })),
  );

  const groups = new Map<string, number[]>();
  bound.forEach((b, i) => {
    const key = scriptHash(b.cellOutput.lock);
    groups.set(key, [...(groups.get(key) ?? []), i]);
  });

  const multisig_configs: Record<string, CkbCliMultisigConfig> = {};
  const signatures: Record<string, string[]> = {};

  for (const [script, indices] of groups) {
    const lock = bound[indices[0]!]!.cellOutput.lock;
    const profile = classifyLock(lock);
    const args = lock.args;

    if (profile.profile === SECP_PROFILE) {
      const list = psct.sigs[script] ?? [];
      if (list.length) signatures[args] = list.map((s) => bytesToHex(s.signature));
      continue;
    }

    if (profile.profile === MULTISIG_PROFILE || profile.profile === MULTISIG_V2_PROFILE) {
      const template = psct.witnessTemplates[Math.min(...indices)]?.lockTemplate;
      if (!template) throw new Error(`missing multisig lock template for ${script}`);
      const parsed = decodeMultisigLock(template);
      if (!parsed) throw new Error("malformed multisig lock template");

      multisig_configs[args] = {
        lock_code_hash: lock.codeHash,
        sighash_addresses: parsed.pubkeys.map((p) =>
          encodeAddress(
            { codeHash: SECP_CODE, hashType: "type", args: p },
            network === "ckb" ? "ckb" : "ckt",
            "short",
          ),
        ),
        require_first_n: parsed.requireFirstN,
        threshold: parsed.threshold,
      };
      const list = psct.sigs[script] ?? [];
      if (list.length) signatures[args] = list.map((s) => bytesToHex(s.signature));
      continue;
    }

    throw new Error(`ckb-cli interop does not support ${profile.name}`);
  }

  // ckb-cli rebuilds the lock fields from the signature map, but the *number* of witnesses is part
  // of the signing message. Export placeholders so the layout survives the round trip.
  const unsigned: Transaction = {
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
  return {
    transaction: toRpcTx(unsigned),
    multisig_configs,
    signatures,
  };
}


export interface ImportOptions {
  /** ckb-cli carries no input cells; the caller must supply them. */
  proofs: InputProof[];
  network?: "ckb" | "ckt";
}

export function fromCkbCli(file: CkbCliTxFile, opts: ImportOptions): Psct {
  const tx = fromRpcTx(file.transaction as RpcTransaction);
  const network = opts.network ?? "ckb";
  const psct = buildPsct(tx, { network, proofs: opts.proofs });

  const bound = bindAll(tx, opts.proofs);
  const byArgs = new Map<string, { script: string; indices: number[] }>();
  bound.forEach((b, i) => {
    const lock = b.cellOutput.lock;
    const entry = byArgs.get(lock.args) ?? { script: scriptHash(lock), indices: [] };
    entry.indices.push(i);
    byArgs.set(lock.args, entry);
  });

  // Rebuild multisig lock templates from the configs.
  for (const [args, cfg] of Object.entries(file.multisig_configs)) {
    const group = byArgs.get(args);
    if (!group) throw new Error(`multisig config ${args} has no input`);
    const pubkeys = cfg.sighash_addresses.map((a) => {
      const decoded = decodeAddress(a);
      if (decoded.script.codeHash.toLowerCase() !== SECP_CODE) {
        throw new Error(`multisig signer ${a} is not a secp256k1 address`);
      }
      return decoded.script.args;
    });
    const scriptPart = new Uint8Array([
      0,
      cfg.require_first_n,
      cfg.threshold,
      pubkeys.length,
      ...pubkeys.flatMap((p) => [...hexToBytes(p)]),
    ]);
    const derived = bytesToHex(blake160(scriptPart));
    if (derived !== args.toLowerCase()) {
      throw new Error(`multisig config does not hash to ${args} (got ${derived})`);
    }
    const template = new Uint8Array(scriptPart.length + 65 * cfg.threshold);
    template.set(scriptPart, 0);
    psct.witnessTemplates[Math.min(...group.indices)] = {
      ...psct.witnessTemplates[Math.min(...group.indices)],
      lockTemplate: template,
    };
  }

  // Place signatures: secp by lock arg, multisig by recovering the signer.
  const placeholder = psctTransaction(psct);
  const groupList = new Map<string, number[]>();
  bound.forEach((b, i) => {
    const key = scriptHash(b.cellOutput.lock);
    groupList.set(key, [...(groupList.get(key) ?? []), i]);
  });

  for (const [args, sigs] of Object.entries(file.signatures)) {
    const group = byArgs.get(args);
    if (!group) throw new Error(`signatures for ${args} have no input`);
    const lock = bound[group.indices[0]!]!.cellOutput.lock;
    const profile = classifyLock(lock);

    if (profile.profile === SECP_PROFILE) {
      if (sigs.length !== 1) throw new Error(`expected one secp signature for ${args}`);
      psct.sigs[group.script] = [
        { signer: hexToBytes(args), signature: hexToBytes(sigs[0]!), profile: SECP_PROFILE },
      ];
      continue;
    }

    if (profile.profile === MULTISIG_PROFILE || profile.profile === MULTISIG_V2_PROFILE) {
      const template = psct.witnessTemplates[Math.min(...group.indices)]?.lockTemplate;
      if (!template) throw new Error(`missing multisig template for ${args}`);
      const parsed = decodeMultisigLock(template);
      if (!parsed) throw new Error("malformed multisig template");

      // Recover signers from the same message the signer would have signed.
      const withPlaceholder = {
        ...placeholder,
        witnesses: psct.witnessTemplates.map((t) =>
          bytesToHex(
            encodeWitnessArgs({
              lock: t.lockTemplate ?? null,
              inputType: t.inputType ?? null,
              outputType: t.outputType ?? null,
            }),
          ),
        ),
      };
      const indices = groupList.get(group.script)!;
      const msg = sighashMessage(withPlaceholder, indices, (w) =>
        zeroSignatureRegion(w, 65 * parsed.threshold),
      );
      psct.sigs[group.script] = sigs.map((hex) => {
        const sig = hexToBytes(hex);
        return {
          signer: hexToBytes(pubkeyHash(sig, msg)),
          signature: sig,
          profile: profile.profile!,
        };
      });
    }
  }

  return psct;
}


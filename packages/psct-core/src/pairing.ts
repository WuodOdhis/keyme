/**
 * Account pairing check.
 *
 * The signer is configured with an account xpub before it sees any PSCT. From that it derives its
 * own external and change locks, and then:
 *   - the PSCT's account must match the paired one (xpub and fingerprint);
 *   - an output claiming to be change must actually derive from the account;
 *   - outputs that derive from the account are change even if the file calls them payments;
 *   - if no output returns to the account, the fee is the whole difference and is surfaced.
 *
 * This turns "change is probably mine" into a check.
 */

import { hexToBytes } from "./bytes.js";
import { scriptHash } from "./hash.js";
import { deriveAddresses, sameFingerprint, type Account } from "./account.js";
import { decodeXpub, fingerprint } from "./bip32.js";
import type { Script } from "./ckb.js";
import type { Psct } from "./psct/container.js";

export interface PairingResult {
  account: Account;
  ownInputs: boolean[];
  changeOutputs: number[];
  /** Outputs that claim to be change but are not derived from the account. */
  lies: string[];
  warnings: string[];
}

export interface PairingContext {
  inputLocks: Script[];
  outputLocks: Script[];
  fee: bigint;
}

export function accountFromXpub(xpub: string, pathPrefix: string): Account {
  const node = decodeXpub(xpub);
  const fp = fingerprint(node.publicKey);
  return {
    xpub: xpub.trim(),
    fingerprint: hexToBytes(`0x${fp.toString(16).padStart(8, "0")}`),
    pathPrefix,
    coinType: pathPrefix.includes("/1'/") ? 1 : 309,
  };
}

export function defaultPathPrefix(network: "ckb" | "ckt"): string {
  return network === "ckb" ? "m/44'/309'/0'" : "m/44'/1'/0'";
}

function checkAccount(psct: Psct, account: Account): void {
  if (!psct.account) {
    throw new Error("PSCT has no account; cannot certify change against a paired account");
  }
  if (psct.account.xpub !== account.xpub) {
    throw new Error("paired account xpub does not match the PSCT account");
  }
  if (!sameFingerprint(psct.account.fingerprint, account.fingerprint)) {
    throw new Error("paired account fingerprint does not match the PSCT account");
  }
}

export function pairingFor(psct: Psct, account: Account, ctx: PairingContext): PairingResult {
  checkAccount(psct, account);

  const derived = deriveAddresses(account.xpub, 20);
  const own = new Set<string>();
  for (const a of [...derived.external, ...derived.change]) own.add(scriptHash(a.script));

  const ownInputs = ctx.inputLocks.map((l) => own.has(scriptHash(l)));
  const lies: string[] = [];
  const warnings: string[] = [];
  const changeOutputs: number[] = [];

  ctx.outputLocks.forEach((lock, i) => {
    const isOwn = own.has(scriptHash(lock));
    const claim = psct.outputHints[i]?.role;
    if (isOwn) changeOutputs.push(i);
    if (claim === "change" && !isOwn) {
      lies.push(`output ${i} is claimed as change but does not derive from the paired account`);
    }
    if (isOwn && claim === "payment") {
      warnings.push(`output ${i} is labelled a payment but returns to your account (change)`);
    }
  });

  if (changeOutputs.length === 0 && ctx.fee > 100_000_000n) {
    warnings.push(`no output returns to your account; the fee is ${ctx.fee} shannons`);
  }
  if (!ownInputs.some(Boolean)) {
    warnings.push("none of the inputs derive from the paired account");
  }

  return { account, ownInputs, changeOutputs, lies, warnings };
}

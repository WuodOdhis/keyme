/**
 * Paired account: the signer knows the xpub before it ever sees a PSCT, so change and inputs are
 * derived rather than trusted.
 *
 * Account layout: m/44'/coin'/0' (coin 309 mainnet, 1 testnet), then /0/i external and /1/i change.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import type { Script } from "./ckb.js";
import { blake160 } from "./hash.js";
import {
  decodeXpub,
  derivePrivate,
  derivePublic,
  encodeXpub,
  fingerprint,
  masterFromSeed,
  seedFromHex,
  toPublic,
  type Node,
} from "./bip32.js";

export const SECP_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

export interface Account {
  xpub: string;
  /** First 4 bytes of hash160(account public key). Identifies the account, not the master. */
  fingerprint: Uint8Array;
  pathPrefix: string;
  coinType: number;
}

export function accountPath(coinType: number): string {
  return `m/44'/${coinType}'/0'`;
}

export function accountFromSeed(
  seedHex: string,
  network: "mainnet" | "testnet" = "mainnet",
  coinType = network === "mainnet" ? 309 : 1,
): { account: Account; node: Node; master: Node } {
  const master = masterFromSeed(seedFromHex(seedHex));
  const node = derivePrivate(master, accountPath(coinType));
  const account: Account = {
    xpub: encodeXpub(toPublic(node), network),
    fingerprint: hexToBytes(
      `0x${fingerprint(node.publicKey).toString(16).padStart(8, "0")}`,
    ),
    pathPrefix: accountPath(coinType),
    coinType,
  };
  return { account, node, master };
}

export function lockForNode(node: Node): Script {
  return {
    codeHash: SECP_CODE_HASH,
    hashType: "type",
    args: bytesToHex(blake160(node.publicKey)),
  };
}

export interface DerivedAddresses {
  external: { script: Script; path: string }[];
  change: { script: Script; path: string }[];
}

/** Derive a look-ahead window of external and change locks from an account xpub. */
export function deriveAddresses(xpub: string, count = 20): DerivedAddresses {
  const node = decodeXpub(xpub);
  const external: { script: Script; path: string }[] = [];
  const change: { script: Script; path: string }[] = [];
  for (let i = 0; i < count; i++) {
    external.push({ script: lockForNode(derivePublic(node, `0/${i}`)), path: `0/${i}` });
    change.push({ script: lockForNode(derivePublic(node, `1/${i}`)), path: `1/${i}` });
  }
  return { external, change };
}

export function sameFingerprint(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

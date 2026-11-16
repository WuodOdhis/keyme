/**
 * Lock/type script registry.
 *
 * Two jobs, deliberately separate:
 *   1. name a script, so the UI can say "OmniLock" instead of a hash;
 *   2. decide whether this signer can *verify* it.
 *
 * Naming is not trust. A script with a name and no profile is still refused.
 *
 * Entries are keyed by `codeHash|hashType`, not by code hash alone: the same code hash means
 * different things under `type`, `data` and `data1`, so hash_type is part of the identity.
 */

import type { Script } from "./ckb.js";
import { tokenKind } from "./xudt.js";
import { sporeKind } from "./spore.js";

export type LockKind = "signable" | "unknown";

export interface LockProfile {
  name: string;
  kind: LockKind;
  /** null = known lock, no verification profile yet. Refuse, do not guess. */
  profile: string | null;
  note?: string;
}

export const SECP_PROFILE = "sighash-all/secp256k1-blake160/v1";
export const MULTISIG_PROFILE = "sighash-all/multisig-legacy/v1";
export const MULTISIG_V2_PROFILE = "sighash-all/multisig-v2/v1";

const key = (codeHash: string, hashType: string) => `${codeHash.toLowerCase()}|${hashType}`;

const REGISTRY: Record<string, LockProfile> = {
  // --- signable, profile implemented
  [key("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "type")]: {
    name: "Secp256k1Blake160",
    kind: "signable",
    profile: SECP_PROFILE,
  },
  [key("0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8", "type")]: {
    name: "Secp256k1Multisig (legacy)",
    kind: "signable",
    profile: MULTISIG_PROFILE,
  },
  [key("0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29", "data1")]: {
    name: "Secp256k1MultisigV2",
    kind: "signable",
    profile: MULTISIG_V2_PROFILE,
    note: "same signing rules as legacy; validated against the fiber-scripts 3-of-5 upgrade",
  },

  // --- signable in principle, profile not implemented yet
  [key("0xd1a9f877aed3f5e07cb9c52b61ab96d06f250ae6883cc7f0a2423db0976fc821", "type")]: {
    name: "Secp256k1MultisigV2Beta",
    kind: "signable",
    profile: null,
    note: "no evidence for its placeholder yet",
  },
  [key("0x9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26", "type")]: {
    name: "OmniLock",
    kind: "signable",
    profile: null,
    note: "multi-curve auth structure; needs its own profile",
  },
  [key("0x641a89ad2f77721b803cd50d01351c1f308444072d5fa20088567196c0574c68", "type")]: {
    name: "NostrLock",
    kind: "signable",
    profile: null,
    note: "schnorr; not implemented",
  },
  [key("0xd00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323", "type")]: {
    name: "JoyId",
    kind: "signable",
    profile: null,
    note: "passkey/WebAuthn; not implemented",
  },
  [key("0xbf43c3602455798c1a61a596e0d95278864c552fafe231c063b3fabf97a8febc", "type")]: {
    name: "PWLock",
    kind: "signable",
    profile: null,
  },

  // --- dangerous by design: never sign without an explicit policy
  [key("0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354", "type")]: {
    name: "AnyoneCanPay",
    kind: "signable",
    profile: null,
    note: "permissionless lock: third parties can take capacity",
  },
};

const TYPE_REGISTRY: Record<string, string> = {
  [key("0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95", "type")]: "xUDT",
  [key("0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5", "type")]: "sUDT",
  [key("0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e", "type")]: "NervosDAO",
  [key("0x00000000000000000000000000000000000000000000000000545950455f4944", "type")]: "TypeId",
};

export function classifyLock(script: Script): LockProfile {
  const known = REGISTRY[key(script.codeHash, script.hashType)];
  if (known) return known;
  return { name: "unknown lock", kind: "unknown", profile: null };
}

export function classifyType(script: Script): string {
  const kind = tokenKind(script);
  if (kind === "xudt") return "xUDT";
  if (kind === "sudt") return "sUDT";
  const spore = sporeKind(script);
  if (spore === "spore") return "Spore";
  if (spore === "cluster") return "Spore Cluster";
  if (spore === "did") return "Spore DID";
  return TYPE_REGISTRY[key(script.codeHash, script.hashType)] ?? "unknown type";
}

export function isSupportedLock(script: Script): boolean {
  const p = classifyLock(script);
  return p.kind === "signable" && p.profile !== null;
}

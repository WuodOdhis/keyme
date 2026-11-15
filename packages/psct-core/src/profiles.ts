/**
 * Lock/type script registry.
 *
 * Two jobs, deliberately separate:
 *   1. name a script, so the UI can say "OmniLock" instead of a hash;
 *   2. decide whether this signer can *verify* it.
 *
 * Naming is not trust. A script with a name and no profile is still refused.
 *
 * Code hashes for the standard deployment set come from CCC's mainnet registry
 * (packages/core/src/client/clientPublicMainnet.advanced.ts), cross-checked against chain data.
 */

import type { Script } from "./ckb.js";

export type LockKind = "signable" | "infrastructure" | "unknown";

export interface LockProfile {
  name: string;
  kind: LockKind;
  /** null = known lock, no verification profile yet. Refuse, do not guess. */
  profile: string | null;
  note?: string;
}

const SECP_PROFILE = "sighash-all/secp256k1-blake160/v1";

const REGISTRY: Record<string, LockProfile> = {
  // --- signable, profile implemented
  "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8": {
    name: "Secp256k1Blake160",
    kind: "signable",
    profile: SECP_PROFILE,
  },

  // --- signable in principle, profile not implemented yet
  "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8": {
    name: "Secp256k1Multisig (legacy)",
    kind: "signable",
    profile: null,
    note: "placeholder and signature ordering differ from secp256k1; not implemented",
  },
  "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29": {
    name: "Secp256k1MultisigV2",
    kind: "signable",
    profile: null,
    note: "enhanced since handling; not implemented",
  },
  "0xd1a9f877aed3f5e07cb9c52b61ab96d06f250ae6883cc7f0a2423db0976fc821": {
    name: "Secp256k1MultisigV2Beta",
    kind: "signable",
    profile: null,
  },
  "0x9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26": {
    name: "OmniLock",
    kind: "signable",
    profile: null,
    note: "multi-curve auth structure; needs its own profile",
  },
  "0x641a89ad2f77721b803cd50d01351c1f308444072d5fa20088567196c0574c68": {
    name: "NostrLock",
    kind: "signable",
    profile: null,
    note: "schnorr; not implemented",
  },
  "0xd00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323": {
    name: "JoyId",
    kind: "signable",
    profile: null,
    note: "passkey/WebAuthn; not implemented",
  },
  "0xbf43c3602455798c1a61a596e0d95278864c552fafe231c063b3fabf97a8febc": {
    name: "PWLock",
    kind: "signable",
    profile: null,
  },

  // --- dangerous by design: never sign without an explicit policy
  "0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354": {
    name: "AnyoneCanPay",
    kind: "signable",
    profile: null,
    note: "permissionless lock: third parties can take capacity",
  },

  // --- L2 / infrastructure: a signer has no business authorising these
  "0xede199745fbd9e9f339f1dd2e92a586020d111432bfb81a6c2b12ddc9856f0ba": {
    name: "Godwoken lock (L2)",
    kind: "infrastructure",
    profile: null,
    note: "gw-utils custodian/stake lock family",
  },
  "0x1c04df09d9adede5bfc40ff1a39a3a17fc8e29f15c56f16b7e48680c600ee5ac": {
    name: "Godwoken lock (L2)",
    kind: "infrastructure",
    profile: null,
    note: "gw-utils custodian/stake lock family",
  },
  "0xff022d5512d3d5fd9614cc6ead110925d7a39e8916b6b1c8d5967846e4d32733": {
    name: "Godwoken lock (L2)",
    kind: "infrastructure",
    profile: null,
    note: "gw-utils custodian/stake lock family",
  },
  "0x45c112df97daece27c4afa02b24b15f64403bdfd45ab2e0e88c9fb2a24796b1d": {
    name: "Godwoken lock (L2)",
    kind: "infrastructure",
    profile: null,
    note: "gw-utils custodian/stake lock family",
  },
};

const TYPE_REGISTRY: Record<string, string> = {
  "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95": "xUDT",
  "0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5": "sUDT",
  "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e": "NervosDAO",
  "0x00000000000000000000000000000000000000000000000000545950455f4944": "TypeId",
  "0x2c8c11c985da60b0a330c61a85507416d6382c130ba67f0c47ab071e00aec628": "UniqueType",
  "0x4a06164dc34dccade5afe3e847a97b6db743e79f5477fa3295acf02849c5984a": "DidCkb",
  "0xaba4430cc7110d699007095430a1faa72973edf2322ddbfd4d1d219cacf237af": "EasyToDiscoverType",
};

export function classifyLock(script: Script): LockProfile {
  const known = REGISTRY[script.codeHash.toLowerCase()];
  if (known) return known;
  return { name: "unknown lock", kind: "unknown", profile: null };
}

export function classifyType(script: Script): string {
  return TYPE_REGISTRY[script.codeHash.toLowerCase()] ?? "unknown type";
}

export function isSupportedLock(script: Script): boolean {
  const p = classifyLock(script);
  return p.kind === "signable" && p.profile !== null;
}

/**
 * OmniLock (RFC-0042).
 *
 * Args: <21-byte auth> <omnilock args>
 *   auth = <1-byte flag> <20-byte content>
 *   omnilock args = <1-byte flags> <optional fields...>
 *
 * The flags select the verification scheme; the modes add admin / anyone-can-pay / time-lock /
 * supply checks. We never verify OmniLock signatures here — we only describe the lock honestly and
 * refuse to sign for it.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import type { Script } from "./ckb.js";

export const OMNI_LOCK_CODE_HASH = "0x9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26";

const AUTH_NAMES: Record<number, string> = {
  0x00: "CKB secp256k1",
  0x01: "Ethereum",
  0x02: "EOS",
  0x03: "Tron",
  0x04: "Bitcoin",
  0x05: "Dogecoin",
  0x06: "CKB multisig",
  0x12: "EOS (variant)",
  0xfc: "lock-script delegation",
  0xfd: "preimage lock",
  0xfe: "dynamic preimage lock",
};

export interface OmnilockInfo {
  authFlag: number;
  authName: string;
  auth: string;
  /** Omnilock mode flags, if present. */
  modeFlags: number | null;
  modes: string[];
}

export function decodeOmnilockArgs(argsHex: string): OmnilockInfo | null {
  const b = hexToBytes(argsHex);
  if (b.length < 21) return null;
  const authFlag = b[0]!;
  const auth = bytesToHex(b.slice(1, 21));
  const modeFlags = b.length > 21 ? b[21]! : null;
  const modes: string[] = [];
  if (modeFlags !== null) {
    if (modeFlags & 0x01) modes.push("administrator");
    if (modeFlags & 0x02) modes.push("anyone-can-pay");
    if (modeFlags & 0x04) modes.push("time-lock");
    if (modeFlags & 0x08) modes.push("supply");
  }
  return {
    authFlag,
    authName: AUTH_NAMES[authFlag] ?? `unknown auth 0x${authFlag.toString(16)}`,
    auth,
    modeFlags,
    modes,
  };
}

export function describeOmnilock(script: Script): string | null {
  if (script.codeHash.toLowerCase() !== OMNI_LOCK_CODE_HASH) return null;
  const info = decodeOmnilockArgs(script.args);
  if (!info) return "OmniLock (malformed args)";
  const modes = info.modes.length ? `, modes: ${info.modes.join("+")}` : "";
  return `OmniLock (auth: ${info.authName} ${info.auth.slice(0, 10)}…${modes})`;
}

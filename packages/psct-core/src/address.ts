/**
 * CKB addresses (RFC-0021): bech32m, two payload formats.
 *
 *   short: [0x00][code_hash_index][args]        index 0 = secp256k1-blake160, 1 = multisig, 2 = ACP
 *   full:  [0x01][code_hash:32][hash_type:1][args]
 *
 * The signer needs this to derive its own addresses and to check change outputs itself, rather
 * than trusting an address string from the coordinator.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import type { Script } from "./ckb.js";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;
const HASH_TYPE_CODE: Record<string, number> = { data: 0, type: 1, data1: 2, data2: 4 };
const CODE_HASH_INDEX: Record<string, number> = {
  "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8": 0,
  "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8": 1,
  "0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354": 2,
};

function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i]!;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data: number[], from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from !== 0) throw new Error("invalid data range");
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw new Error("invalid padding");
  }
  return out;
}

export function encodeAddress(
  script: Script,
  prefix: "ckb" | "ckt" = "ckb",
  format: "auto" | "short" | "full" = "auto",
): string {
  const index = CODE_HASH_INDEX[script.codeHash.toLowerCase()];
  const useShort = format !== "full" && index !== undefined && script.hashType === "type";
  const payload = useShort
    ? [0x01, index, ...hexToBytes(script.args)]
    : [
        0x00,
        ...hexToBytes(script.codeHash),
        HASH_TYPE_CODE[script.hashType] ?? 1,
        ...hexToBytes(script.args),
      ];

  const hrp = prefix;
  const data = convertBits(payload, 8, 5, true);
  const constant = useShort ? BECH32_CONST : BECH32M_CONST;
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const check = polymod(values) ^ constant;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((check >> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map((v) => CHARSET[v]).join("");
}

export interface DecodedAddress {
  prefix: "ckb" | "ckt";
  script: Script;
}

export function decodeAddress(address: string): DecodedAddress {
  const lower = address.toLowerCase();
  if (lower !== address && address.toUpperCase() !== address) {
    throw new Error("mixed-case address");
  }
  const sep = lower.lastIndexOf("1");
  if (sep < 1) throw new Error("no separator");
  const prefix = lower.slice(0, sep) as "ckb" | "ckt";
  if (prefix !== "ckb" && prefix !== "ckt") throw new Error(`unknown prefix ${prefix}`);
  const data: number[] = [];
  for (const c of lower.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error(`invalid character ${c}`);
    data.push(v);
  }
  const check = polymod([...hrpExpand(prefix), ...data]);
  if (check !== BECH32_CONST && check !== BECH32M_CONST) {
    throw new Error("bad checksum");
  }
  const payload = convertBits(data.slice(0, -6), 5, 8, false);
  if (payload[0] === 0x00) {
    const codeHash = bytesToHex(new Uint8Array(payload.slice(1, 33)));
    const hashTypeNum = payload[33]!;
    const hashType = (Object.keys(HASH_TYPE_CODE).find(
      (k) => HASH_TYPE_CODE[k] === hashTypeNum,
    ) ?? "type") as Script["hashType"];
    return { prefix, script: { codeHash, hashType, args: bytesToHex(new Uint8Array(payload.slice(34))) } };
  }
  if (payload[0] === 0x01) {
    const index = payload[1]!;
    const args = bytesToHex(new Uint8Array(payload.slice(2)));
    const codeHash = Object.keys(CODE_HASH_INDEX).find((k) => CODE_HASH_INDEX[k] === index);
    if (!codeHash) throw new Error(`unknown code hash index ${index}`);
    return { prefix, script: { codeHash, hashType: "type", args } };
  }
  throw new Error(`unknown address format ${payload[0]}`);
}

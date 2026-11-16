/** PSCT file I/O: base64 text, hex, or raw bytes. Always written as base64. */

import { readFileSync, writeFileSync } from "node:fs";
import { decodePsct, encodePsct, type Psct } from "./container.js";

export function decodePsctBytes(bytes: Uint8Array): Psct {
  return decodePsct(bytes);
}

export function readPsctFile(path: string): Psct {
  const raw = readFileSync(path);
  // Try text first: base64 or hex.
  const text = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F\s]+$/.test(text) && text.replace(/\s/g, "").startsWith("70")) {
    const hex = text.replace(/\s/g, "");
    return decodePsct(Uint8Array.from(Buffer.from(hex, "hex")));
  }
  try {
    const decoded = Uint8Array.from(Buffer.from(text, "base64"));
    if (decoded.length > 0 && decoded[0] === 0x70) return decodePsct(decoded);
  } catch {
    // fall through to raw
  }
  return decodePsct(raw);
}

export function writePsctFile(path: string, psct: Psct): void {
  writeFileSync(path, Buffer.from(encodePsct(psct)).toString("base64") + "\n");
}

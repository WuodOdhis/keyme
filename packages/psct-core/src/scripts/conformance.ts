/**
 * Conformance: run the independent Rust implementation over every PSCT vector and compare with
 * the TypeScript-generated manifest.
 *
 * Build first: cd packages/psct-rs && cargo build --release
 * Run: npx tsx src/scripts/conformance.ts
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

interface VectorEntry {
  file: string;
  tx_hash: string;
  full_tx_hash: string;
  note: string;
}

interface RustReport {
  file: string;
  tx_hash: string;
  full_tx_hash: string;
  groups: { profile: string; verdict: string }[];
  ok: boolean;
}

function main() {
  const bin = process.platform === "win32" ? "psct-rs.exe" : "psct-rs";
  const binPath = join(process.cwd(), "..", "psct-rs", "target", "release", bin);
  if (!existsSync(binPath)) {
    console.error(`missing ${binPath}; run: cd packages/psct-rs && cargo build --release`);
    process.exit(1);
  }

  const manifest: VectorEntry[] = JSON.parse(
    readFileSync(join(process.cwd(), "vectors", "manifest.json"), "utf8"),
  );
  const files = manifest.map((m) => join(process.cwd(), "vectors", m.file));

  const out = execFileSync(binPath, files, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const reports: RustReport[] = out
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  let failures = 0;
  for (const entry of manifest) {
    const report = reports.find((r) => basename(r.file) === entry.file);
    const problems: string[] = [];
    if (!report) problems.push("no report");
    else {
      if (report.tx_hash !== entry.tx_hash) problems.push(`tx_hash ${report.tx_hash}`);
      if (report.full_tx_hash !== entry.full_tx_hash) problems.push(`full_tx_hash ${report.full_tx_hash}`);
      if (!report.ok) problems.push("not ok");
    }
    if (problems.length) {
      failures++;
      console.log(`FAIL ${entry.file}`);
      for (const p of problems) console.log(`     ${p}`);
    } else {
      console.log(`ok   ${entry.file.slice(0, 18)}… ${entry.note}`);
    }
  }

  console.log("");
  console.log(`vectors        ${manifest.length}`);
  console.log(`failures       ${failures}`);
  if (failures) process.exitCode = 1;
}

main();

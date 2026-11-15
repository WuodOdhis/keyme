import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MAINNET } from "../rpc.js";
import { ckbHash } from "../hash.js";
import { bytesToHex, hexToBytes, concat } from "../bytes.js";

const target = process.argv[2]!;
const dir = join(process.cwd(), "fixtures");
const m = JSON.parse(readFileSync(join(dir,"manifest.json"),"utf8"));
let txHash: string | null = null;
for (const e of m) {
  const f = JSON.parse(readFileSync(join(dir, e.hash+".json"),"utf8"));
  for (const p of f.proofs) {
    const out = p.prevTx.outputs[p.index];
    if (out?.lock?.codeHash === target) { txHash = e.hash; break; }
  }
  if (txHash) break;
}
console.log("tx", txHash);
const tx = await MAINNET.tx(txHash!);
console.log("deps", tx.cellDeps.map(d=>`${d.depType}:${d.outPoint.txHash.slice(0,10)}#${d.outPoint.index}`).join(" "));

async function cellAt(hash:string,index:number){
  const r = await MAINNET.call<any>("get_live_cell", [{tx_hash:hash,index:"0x"+index.toString(16)}, true]);
  return r.cell ?? null;
}
function ascii(b:Uint8Array){ let s=""; const out:string[]=[]; for(const x of b){ if(x>=32&&x<127){s+=String.fromCharCode(x);} else { if(s.length>=6) out.push(s); s=""; } } if(s.length>=6) out.push(s); return out; }

for (const d of tx.cellDeps) {
  let c = await cellAt(d.outPoint.txHash, d.outPoint.index);
  if (!c) { console.log("  dep missing", d.outPoint.txHash.slice(0,10)); continue; }
  let data = hexToBytes(c.data?.content ?? "0x");
  console.log(`dep ${d.depType} ${d.outPoint.txHash.slice(0,10)}#${d.outPoint.index} dataLen=${data.length} type=${c.output.type? c.output.type.code_hash.slice(0,10):"none"}`);
  console.log("   strings:", ascii(data).slice(0,6).join(" | ") || "-");
  if (d.depType === "dep_group") {
    // OutPointVec: count + 36-byte outpoints
    const n = new DataView(data.buffer,data.byteOffset,data.byteLength).getUint32(0,true);
    for (let i=0;i<Math.min(n,8);i++){
      const off = 4 + i*36;
      const hash = bytesToHex(data.slice(off, off+32));
      const idx = new DataView(data.buffer,data.byteOffset,data.byteLength).getUint32(off+32,true);
      const sub = await cellAt(hash, idx);
      if (!sub) { console.log(`   group[${i}] missing`); continue; }
      const sd = hexToBytes(sub.data?.content ?? "0x");
      console.log(`   group[${i}] dataLen=${sd.length} strings:`, ascii(sd).slice(0,6).join(" | ") || "-");
    }
  }
}

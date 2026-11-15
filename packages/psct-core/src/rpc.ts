/** Tiny CKB JSON-RPC client (mainnet / testnet). */

import { fromRpcTx, type RpcTransaction, type Transaction } from "./ckb.js";

export class Rpc {
  private blockCache = new Map<number, Map<string, Transaction>>();

  constructor(public readonly url: string) {}

  async call<T>(method: string, params: unknown[]): Promise<T> {
    const r = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }),
    });
    if (!r.ok) throw new Error(`${method}: HTTP ${r.status}`);
    const j = (await r.json()) as { result?: T; error?: { code: number; message: string } };
    if (j.error) throw new Error(`${method}: ${j.error.message} (${j.error.code})`);
    return j.result as T;
  }

  tip(): Promise<string> {
    return this.call<string>("get_tip_block_number", []);
  }

  async blockTxs(number: number): Promise<{ hash: string; tx: Transaction }[]> {
    const res = await this.call<{ block?: any } | any>("get_block_by_number", [
      `0x${number.toString(16)}`,
      "0x2",
      true,
    ]);
    const block = res.block ?? res;
    return (block.transactions ?? []).map((t: RpcTransaction) => ({
      hash: t.hash ?? "",
      tx: fromRpcTx(t),
    }));
  }

  async tx(hash: string): Promise<Transaction> {
    // get_transaction returns molecule hex; fetch the containing block for a JSON transaction.
    const res = await this.call<{
      tx_status: { block_number: string | null };
    }>("get_transaction", [hash, "0x0"]);
    const bnHex = res.tx_status.block_number;
    if (!bnHex) throw new Error(`tx ${hash} is not committed`);
    const bn = Number(BigInt(bnHex));

    let block = this.blockCache.get(bn);
    if (!block) {
      const txs = await this.blockTxs(bn);
      block = new Map(txs.map((t) => [t.hash, t.tx]));
      this.blockCache.set(bn, block);
    }
    const tx = block.get(hash);
    if (!tx) throw new Error(`tx ${hash} not found in block ${bn}`);
    return tx;
  }
}

export const MAINNET = new Rpc("https://mainnet.ckb.dev/rpc");
export const TESTNET = new Rpc("https://testnet.ckb.dev/rpc");

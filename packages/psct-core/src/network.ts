/** Network deployments the coordinator needs for cell deps. */

import type { CellDep } from "./ckb.js";

export type NetworkName = "mainnet" | "testnet" | "devnet";

export interface Network {
  name: NetworkName;
  prefix: "ckb" | "ckt";
  rpc: string;
  secpDep: CellDep;
  multisigDep: CellDep;
  multisigV2Dep: CellDep;
}

const dep = (txHash: string, index: number): CellDep => ({
  outPoint: { txHash, index },
  depType: "dep_group",
});

export const NETWORKS: Record<NetworkName, Network> = {
  mainnet: {
    name: "mainnet",
    prefix: "ckb",
    rpc: "https://mainnet.ckb.dev",
    secpDep: dep("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c", 0),
    multisigDep: dep("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c", 1),
    multisigV2Dep: dep("0x44be4f4feda80c0e41783ab10e191df3b2bb5c3731b0970c916dbec385dcdc60", 0),
  },
  testnet: {
    name: "testnet",
    prefix: "ckt",
    rpc: "https://testnet.ckb.dev",
    secpDep: dep("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", 0),
    multisigDep: dep("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", 1),
    multisigV2Dep: dep("0x2eefdeb21f3a3edf697c28a52601b4419806ed60bb427420455cc29a090b26d5", 0),
  },
  devnet: {
    name: "devnet",
    prefix: "ckt",
    rpc: "http://127.0.0.1:8114",
    secpDep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 0),
    multisigDep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 1),
    multisigV2Dep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 2),
  },
};

export function networkByName(name: string): Network {
  const n = NETWORKS[name as NetworkName];
  if (!n) throw new Error(`unknown network ${name}`);
  return n;
}

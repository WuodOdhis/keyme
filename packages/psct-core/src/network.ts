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
  daoDep: CellDep;
  xudtDep: CellDep;
  xudtCodeHash: string;
  xudtHashType: "type" | "data1";
}

const dep = (txHash: string, index: number): CellDep => ({
  outPoint: { txHash, index },
  depType: "dep_group",
});

const codeDep = (txHash: string, index: number): CellDep => ({
  outPoint: { txHash, index },
  depType: "code",
});

export const NETWORKS: Record<NetworkName, Network> = {
  mainnet: {
    name: "mainnet",
    prefix: "ckb",
    rpc: "https://mainnet.ckb.dev",
    secpDep: dep("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c", 0),
    multisigDep: dep("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c", 1),
    multisigV2Dep: dep("0x44be4f4feda80c0e41783ab10e191df3b2bb5c3731b0970c916dbec385dcdc60", 0),
    daoDep: codeDep("0xe2fb199810d49a4d8beec56718ba2593b665db9d52299a0f9e6e75416d73ff5c", 2),
    xudtDep: codeDep("0xc07844ce21b38e4b071dd0e1ee3b0e27afd8d7532491327f39b786343f558ab7", 0),
    xudtCodeHash: "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95",
    xudtHashType: "data1",
  },
  testnet: {
    name: "testnet",
    prefix: "ckt",
    rpc: "https://testnet.ckb.dev",
    secpDep: dep("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", 0),
    multisigDep: dep("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", 1),
    multisigV2Dep: dep("0x2eefdeb21f3a3edf697c28a52601b4419806ed60bb427420455cc29a090b26d5", 0),
    daoDep: codeDep("0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f", 2),
    xudtDep: codeDep("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f", 0),
    xudtCodeHash: "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb",
    xudtHashType: "type",
  },
  devnet: {
    name: "devnet",
    prefix: "ckt",
    rpc: "http://127.0.0.1:8114",
    secpDep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 0),
    multisigDep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 1),
    multisigV2Dep: dep("0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", 2),
    daoDep: codeDep("0x1bb87da347a776a927ab6593e1e10304ca195f8e24279f039008d5e3115b1bf7", 2),
    xudtDep: codeDep("0x1bb87da347a776a927ab6593e1e10304ca195f8e24279f039008d5e3115b1bf7", 6),
    xudtCodeHash: "0x1a1e4fef34f5982906f745b048fe7b1089647e82346074e0f32c2ece26cf6b1e",
    xudtHashType: "type",
  },
};

export function networkByName(name: string): Network {
  const n = NETWORKS[name as NetworkName];
  if (!n) throw new Error(`unknown network ${name}`);
  return n;
}

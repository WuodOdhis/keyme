# Prior work — WuodOdhis

BSc in Electrical Engineering; software and blockchain builder. Public CKB-ecosystem work. This page lists public repositories and merged pull requests only; private work and non-CKB projects are not listed. Last updated 2026-11-18.

## KeyMe — PSCT and the offline signer

Open standard for partially signed CKB transactions and a reference offline signer. The repository contains the PSCT v0 specification, the verifier, the coordinator, the signer, 68 tests, 13 offline fixtures, a second Rust implementation that reproduces `tx_hash` and `full_tx_hash` byte-for-byte on 3/3 vectors, and recorded testnet and devnet runs.

- Repository: https://github.com/WuodOdhis/keyme
- Testnet: transfer at block 23,084,406; 2-of-3 payout at block 23,086,201
- Devnet: DAO deposit → prepare → withdraw; xUDT mint → transfer
- Spec: https://github.com/WuodOdhis/keyme/blob/main/spec/psct-v0.md

## CKBuilders — CKB Dev Log

Public log from the CKBuilders program, focused on the Cell Model, transaction construction and CKB-VM script development. It covers CKB Academy, OffCKB, xUDT issuance and transfers with CCC, JoyID passkey integration, Spore DOB minting, Rust RISC-V scripts, weekly reports and a capstone.

- Repository: https://github.com/WuodOdhis/ckbuilders
- Structure: `logs/`, `concepts/`, `experiments/`, `weekly-reports/`, `ckb-scripts/`, `capstone/`

## Reflections of a CKBuilder — Nervos Education Hub

Three merged articles in the Nervos Education Hub's `EducationHubArticles` repository. The series translates CKB concepts through the eyes of a builder learning them: the cell model, builder semantics and transaction construction, and RGB++/Bitcoin interoperability.

| Part | Article | Date | Merge |
|---|---|---|---|
| 1 | Your Ethereum Account Doesn't Exist | 2026-06-02 | [PR #265](https://github.com/NervosEducationHub/EducationHubArticles/pull/265) |
| 2 | The Builder Is Not the Chain | 2026-06-23 | [PR #275](https://github.com/NervosEducationHub/EducationHubArticles/pull/275) |
| 3 | Bitcoin Doesn't Know It Has Smart Contracts | 2026-07-25 | [PR #275](https://github.com/NervosEducationHub/EducationHubArticles/pull/275) |

The article front matter credits `github:WuodOdhis`. The series was drafted in the [Reflections_of_CKBuilder](https://github.com/WuodOdhis/Reflections_of_CKBuilder) fork and merged upstream.

## CellScript swap builder

A local-devnet transaction builder for CellScript's `amm_pool.cell`. The repository documents what an off-chain builder needs to construct valid CellScript AMM transactions on CKB: resource identity, builder manifests and pre-sign checks. It is an experiment, not a finished swap implementation.

- Repository: https://github.com/WuodOdhis/cellscript-swap-builder
- Notes: `BUILDERS_NOTES.md`

## Fiber LSP

A prototype liquidity service for receive-first payments on the Fiber Network. It sits beside a funded Fiber node, sells a sender-facing Fiber invoice, provisions or reuses recipient liquidity, pays the recipient over Fiber, and settles the sender invoice. It uses real Fiber RPC calls and testnet channel state; it is an MVP, not a production LSP.

- Repository: https://github.com/WuodOdhis/fiber_pi

## CKB Agent Lock

A Web2-to-Web3 claim flow for DAO communities. Telegram identity is verified off-chain; recipients claim CKB from an on-chain reward pool secured by a custom RISC-V lock script running in CKB-VM. The repository includes the contract, server and portal.

- Repository: https://github.com/WuodOdhis/agentckblock

## ForecastCKB

A CKB pilot for auditable AI benchmark records. It explores whether CKB can preserve an independently verifiable record of a benchmark's trials, rules, predictions, outcomes and scores, with commit-reveal validation before outcomes are observed. The repository contains the contracts, docs, evidence and milestone-1 implementation.

- Repository: https://github.com/WuodOdhis/forecastckb

## Public record

- GitHub: https://github.com/WuodOdhis
- Merged CKB/Nervos pull requests: [NervosEducationHub #265](https://github.com/NervosEducationHub/EducationHubArticles/pull/265), [#275](https://github.com/NervosEducationHub/EducationHubArticles/pull/275)
- Other public work outside CKB (Arbitrum, Compound, Stellar, Logos, BOT Chain) is on the same GitHub profile but is not part of this CKB record.

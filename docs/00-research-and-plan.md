# KeyMe — research, gap analysis, and build plan

Status: research note, 2026-11-15
Scope: PSCT (partially signed CKB transaction) standard + air-gapped CKB signer
Sources checked: see §10

---

## 0. TL;DR

Your framing is directionally right and the opportunity is real. But three things need to change before we
write code:

1. **The gap is narrower and more specific than "CKB has no PSBT."** A partial-signing workflow already
   exists in `ckb-cli` (and in Neuron/CCC, incompatibly). What is missing is a *transport format with
   resolved cell data*, a *canonical signing profile*, and *any* open-source offline signer. Say that
   precisely; it is a much stronger grant pitch.
2. **Bitcoin's PSBT is the wrong blueprint in several places.** CKB has no scriptSig, no per-input
   signatures, and its sighash does **not** commit to the capacity or data of the cells being spent —
   which has a consequence most people miss (§3.1). It also has script-code dependencies a signer must
   whitelist. Copying BIP-174 field-by-field produces a format that cannot be safely verified.
3. **The build order is inverted.** Do not start with a spec document. Start with an *inspector + signature
   verifier* over real mainnet transactions. The spec should be extracted from that, with golden vectors,
   not the other way round. This also happens to be a standalone, grant-sized deliverable.

Recommended first builds: `psct inspect` / `psct verify` (§7, Phase 0).

---

## 0.5 The reframe (brief vs. research)

The original brief frames this as: *Bitcoin has PSBT + SeedSigner; CKB lacks both; port them.*
Research says the transferable part is much smaller — and the opportunity is different.

| # | Brief says | Research says | Consequence |
|---|---|---|---|
| 1 | "CKB has no BIP-174, so build one" | True, but a 2021 draft already specified the shape, RFC #406 was closed, and `ckb-cli` ships a de facto partial-signing file today | We are not inventing from zero; we are *finishing* something and making it safe. Cite the draft, absorb ckb-cli, don't reinvent. |
| 2 | "PSBT is the standard to copy" | Only the **roles** transfer (creator/updater/signer/combiner/finalizer/extractor). The **fields** do not: no per-input sig slots, no universal placeholder, and no segwit-style amount commitment (so the "witness UTXO only" shortcut is unsafe) | Port the process model, rebuild the data model. |
| 3 | "The hard part is QR + hardware" | QR (UR) and hardware are commodity. The hard part is the signing-message construction per lock script, the input-binding check, and byte-faithful verification | Engineering effort moves from transport to semantics. |
| 4 | "The offline device checks the math" | Only if it has **hash-bound** previous transactions, headers, code-dep identity, and token data — resolved cells alone can be forged | The format must carry *verification inputs*, not just a tx. |
| 5 | "Human-readable labels belong in the format" | That is the phishing vector | Labels live in the signer's trusted DB, never in the file. |
| 6 | "Air-gapped CKB doesn't exist" | SafePal S1 does it, closed | Differentiator is openness + standard + repairability. |
| 7 | "1→5, spec first" | The spec is the *output* of the verifier, not the input | Build the oracle first. |

### The one-sentence reframe

> The product is not "PSBT for CKB." It is: **a CKB transaction that a device with no network can
> independently prove is the transaction the user intended.** The container is a means; the proof is the
> product.

### Three load-bearing assumptions I would challenge

- **A1 — "PSBT is portable, therefore port it."** PSBT's portability comes from Bitcoin's uniform
  `scriptPubKey + amount` model. CKB has per-lock signing semantics and arbitrary type-script state, so
  portability here requires an explicit *profile registry*, not a universal field set.
- **A2 — "Transport is the risk."** Transport is the visible risk. The invisible risk is a signer that
  displays a summary it did not derive from the bytes it signed. That is the failure mode worth designing
  against first.
- **A3 — "Wallets are the customer."** The first paying user is the multisig/DAO operator pasting
  signatures into Telegram today (see ckb-msig). Wallet vendors adopt standards after operators demand
  them, not before.

### What I now believe (and would defend)

1. CKB can support **stronger** offline verification than Bitcoin PSBT — token deltas, DAO state, contract
   code identity, occupied-capacity accounting. That is the differentiator, not a consolation prize.
2. That strength is only reachable if the format is **closed-world**: unknown profile or unknown code dep
   means refuse, never "best effort."
3. The container should be **smaller** than PSBT in one sense and larger in another: no script/derivation
   sprawl, but every spent cell must come with its hash-bound creating transaction (§3.1).
4. Multisig ordering and per-lock placeholders are the two things that will silently break interop. They
   need vectors before they need prose.
5. The most valuable early artifact is a **verifier**, because it is simultaneously the test oracle, the
   grant deliverable, and the signer's core.
6. Hardware is a packaging decision. It should be the last thing we let constrain the design.

---

## 1. What actually exists today (verified)

| Thing | Status | Notes |
|---|---|---|
| Bitcoin BIP-174 PSBT | Deployed + actively maintained | v1.4.4 (2026-09-23) clarified combiner commutativity. BIP-370 = v2. |
| CKB equivalent (adopted) | **Does not exist** | No RFC, no cross-wallet file format, no npm/crate. |
| xxuejie, "CKB Offline Transaction Signing Scheme" (2021-05-31) | Draft forum post only | Molecule `UnsignedTransaction { signing_method, tx, input_txs, cell_dep_txs, headers }`. Never became an RFC. **This is the closest prior art and should be cited, not reinvented.** |
| RFC PR #406 "CKB Open Transaction" | **Closed, not merged** (opened 2023-02-20, closed 2024-01-09) | Different goal: collaborative/partial *construction* with allowed modifications. Prototype: `open-transaction-pool`. |
| CoBuild / `WitnessLayout` / OTX | Active | `cobuild-otx-contracts` reference implementation (2026-06). Goal is composable transactions + intent messages, **not** offline signer transport. Do not conflate. |
| `ckb-cli tx` JSON file | **In production, de facto** | Has `transaction`, `multisig_configs`, `signatures{lock_arg: [sig]}`, and `tx sign-inputs` → `tx add-signature` on separate machines. But: no resolved input cells, ckb-cli-only, no script metadata. |
| Lumos `TransactionSkeleton` | Library-level | No wire format. |
| Neuron multisig export | Tool-specific | Carries input txs (per ckb-msig), so it *is* offline-verifiable — but only in Neuron. |
| `@ile_labs/ckb-msig` 0.0.1 | Published 2026-11-08 | Converts/merges ckb-cli ↔ Neuron ↔ CCC multisig signatures. Proves the pain is live *right now*. Explicitly not a standard. |
| SafePal S1 | **Air-gapped QR hardware wallet that supports CKB** | Closed source, vendor app only, single-vendor format. |
| Ledger "Nervos" app | USB, Neuron only | Community-maintained; not in Ledger Live. |
| imKey Pro, OneKey | CKB support | Not QR-air-gapped in the SeedSigner sense. |
| Keystone / SeedSigner / Keycard Shell | Do **not** support CKB | Keystone = BTC/ETH/etc, UR/ERC-4527. |
| Any CKB QR/UR transport | Nothing found | No repo mentions CKB + `bc-ur`, CKB + animated QR, or CKB + PSBT. Confirmed empty. |

So: **closed, single-vendor, air-gapped CKB signing exists (SafePal S1). An open standard + open-source
signer does not.** That is the correct claim.

---

## 2. What in your brief holds up

- Air-gap rationale, threat model, and UX (two devices, QR in / QR out, trusted display) — correct.
- CKB inputs reference only an `OutPoint`; the spent `CellOutput` + `CellData` must be supplied — correct,
  and this is the core reason a PSBT-like wrapper is needed.
- CKB signs by **script group** (lock groups keyed by lock script hash), not per input — correct, and it
  changes the format design materially.
- Coin type 309 mainnet / 1 testnet, `m/44'/309'/0'/0/0` — correct.
- "No adopted PSCT RFC" — correct as of today.
- The product opportunity (DAO treasuries, multisig, cold storage, CKB-native assets) — correct.

---

## 3. Corrections that matter

### 3.1 Resolved cells alone are forgeable — the brief is right, my first pass was wrong

This is the most important correction in the document, and it came out of committing to the strict trust
model.

CKB's signing message is `blake2b256(tx_hash || witnesses…)`, and `tx_hash` covers **outpoints, outputs,
outputs_data, cell_deps, header_deps, since** — it does *not* cover the **capacity, lock, type, or data of
the cells being spent**. There is no CKB equivalent of BIP-143/BIP-341, where a segwit/taproot signature
commits to the spent amount.

Consequence: if the container carries only a resolved `CellOutput + CellData` supplied by the coordinator,
a malicious coordinator can lie about the input's capacity. The signer sees "fee 0.001 CKB" and approves,
the signature is valid (it never covered the capacity), and the network pays the difference — the entire
real input minus the outputs — to the miner. **That is a theft vector, not a usability bug.**

The fix is the one the original brief implied and the 2021 draft implemented: for every input, carry the
**creating transaction** (witnesses stripped, which is exactly what `tx_hash` covers), then have the signer:

1. recompute `blake2b256(molecule(prev_tx_without_witnesses))`;
2. compare it to `input.previous_output.tx_hash`;
3. read `prev_tx.outputs[index]` and `prev_tx.outputs_data[index]` and compare them to the claimed cell.

Preimage resistance makes that binding sound: an attacker cannot produce a different transaction with the
same hash. After this check the signer may compute fee and token deltas from data it proved, rather than
data it was handed. What it still cannot prove is that the cell is *unspent* — that is a liveness/DoS
property, not a custody property. Say so explicitly in the UI and in the spec.

What this means for the container:

- keep full previous transactions (witness-free) **per input**; do **not** ship only resolved cells;
- headers only where `header_deps` matter (Nervos DAO), and bind them by hash;
- `cell_deps` need their own binding, because they are code: for `hash_type: data`/`data1` verify
  `blake2b(dep_cell.data)` against `code_hash`; for `hash_type: type` bind the dep cell's output and hash its
  type script; expand `dep_group` cells (their data is a list of outpoints) before trusting anything.

Cost: a few hundred bytes per input, more for multi-input transactions. That cost is non-negotiable under
the strict model, so transport adapts to the format — never the reverse (§8).

Measured on mainnet (`docs/01-phase0-findings.md`): a 3-input transaction with an honest fee of 0.0003 CKB
displays as 399,600 CKB when one input claim is inflated 1000×, and the signature still verifies because
the signed bytes never changed.

### 3.2 "Signatures are appended one by one into slots" is wrong for CKB

Two separate problems:

- **Placeholder rule differs per lock script.** The sighash-all message is
  `blake2b256( tx_hash || u64le(len(w0')) || w0' || u64le(len(w1)) || w1 || ... )`, where `w0'` is the
  group's first witness with the lock field replaced by **65 zero bytes** — that length is
  secp256k1-specific. The multisig lock zeroes a *different, structured* blob. A format cannot define one
  universal "empty signature slot".
- **Multisig witness is an ordered value, not a set.** The final lock field encodes `flags + sigs` and the
  script enforces `require_first_n` / threshold semantics in pubkey order. Partial signatures must be
  stored *order-independently* and ordered deterministically at finalize time. This is exactly the bug
  class ckb-msig was written to fix.
- **There is exactly one signature per lock group**, on the group's first input. The other inputs in the
  group carry a 16-byte empty `WitnessArgs`, not a duplicate signature. Confirmed on mainnet (25/25 groups);
  my first test expected per-input signatures and was wrong.

Consequence: PSCT stores **partial signatures keyed by (script_hash, signer identity)** and a `finalize`
step that builds the witness. Never "fill the empty slot".

### 3.3 Human-readable metadata in the file is a phishing vector

Your Phase 1 lists "script registry / human-readable labels" as PSCT fields. If the signer *displays*
those, a malicious coordinator writes `"to": "Alice (my own savings)"` while the bytes say something else.

Rule: **the signer must render exclusively from the canonical bytes** (`tx` + `input_cells` + `headers`).
Any label/role/derivation field is advisory and must be visually marked as unverified, or dropped. This is
also the only way your "malware can't lie to the screen" claim is actually true.

### 3.4 Change verification needs a pre-paired account, not a field in the file

If the PSCT carries the xpub, the attacker supplies the xpub and "change" is trivially forged. The signer
must import/confirm the account (xpub + fingerprint + path prefix) **at setup**, out of band. The PSCT may
include derivation paths as hints; the signer re-derives and compares.

### 3.5 CKB has two extra attack surfaces Bitcoin PSBT doesn't

- **`cell_deps` are code.** A signer must whitelist `(code_hash, hash_type, dep_type)` for the locks/types
  it signs, and resolve `dep_group` expansion. Otherwise "my lock is secp256k1" is an unverified claim.
- **`outputs_data` is where the money is.** xUDT amounts (16-byte LE), Spore content, DAO state all live in
  data, not capacity. A signer that only shows capacity will happily sign a token drain. Same for unknown
  type scripts → hard warn, and `since`/relative locks → must be displayed (a hostile `since` can brick or
  time-lock funds).

### 3.6 The hardware plan is not buildable as written

"Raspberry Pi Zero 2 W with Wi-Fi/Bluetooth disabled/removed" — you cannot remove the radio from a 2 W.
SeedSigner deliberately uses the **Pi Zero v1.3**, which has no radio at all; that is the whole point of
its trust claim. Options that preserve "no radio exists":

- Pi Zero v1.3 (the SeedSigner path, supply is the risk),
- a radio-less RISC-V board (Luckfox / Milk-V Duo class),
- ESP32-S3/P4 (radio present, must never be initialised — weaker claim, see HexWallet),
- an old phone (radios exist; airplane mode is not verifiable).

Pick the trust claim first, then the board. Don't pick the board first.

### 3.7 "Air-gapped ecosystem doesn't exist" overstates it

SafePal S1 already does CKB over QR. Your differentiator is **openness + standard + DIY**, not "first".

### 3.8 Grant sizing

Spark is explicitly **≤ $1,000 typical, $2,000 max, 1–2 months**, paid 20/80, and requires
bilingual applications + reproducible verification. A 5-phase roadmap ending in a hardware signer is not a
Spark project. It is at minimum: Spark (spec + inspector) → Spark or CFDAO/Eco Fund (coordinator + software
signer) → larger track (hardware). Sequence proposals to match, and keep each one independently verifiable.

Also note the committee's published rejection reasons (Q2/Q3 2026): vague scope, unverifiable deliverables,
and proposals not grounded in the applicant's own experience. A tight, checkable Phase 0 is the best
antidote.

### 3.9 QR transport details

- Use **Blockchain Commons UR**, not a bespoke chunking scheme. It is what SeedSigner/Keystone/Sparrow use,
  and it gives you fountain-coded, order-independent frames for free.
- You need a UR type. `crypto-psbt` is taken. Options: register `crypto-psct`, or fall back to
  `bytes` with a self-describing CBOR envelope. Registering is a conversation with Blockchain Commons —
  start it early, ship `bytes` meanwhile.
- Measure early: a 6-input xUDT tx with hash-bound previous transactions is easily 4–10 KB. At realistic
  animated-QR throughput that's 15–50 s per direction. Budget for it in UX (progress, resumable frames), and
  consider a compact binary encoding *before* optimizing the QR layer. Do not trade proof data for frames.

---

## 4. The precise gap (what we would actually be building)

1. A **container** that carries `tx` + hash-bound previous transactions + headers + account hints + partial
   signatures, encodable as one file or a UR stream.
2. A **signing profile registry** that pins, per lock script, the exact sighash message construction and
   placeholder rule — with test vectors.
3. An **independent verifier/inspector** that a signer can trust: recompute fee, change, token deltas,
   policy warnings, and signature validity, from bytes only.
4. A **deterministic finalizer/combiner** that is commutative and preserves unknown fields (the lessons
   BIP-174 only wrote down in 2026 — build them in from day one).
5. An **open-source air-gapped signer** (software first, hardware later).

---

## 5. Architecture

```
            ┌──────────────── online ────────────────┐        ┌──── offline ────┐
  chain RPC │  coordinator (watch-only, CCC)         │  UR    │  signer          │
  ─────────▶│  - build tx, resolve cells, bind proofs │ ─────▶ │  - bind proofs    │
            │  - encode PSCT, render animated QR     │  QR    │  - verify bytes  │
            │  - receive sigs, finalize, broadcast   │ ◀───── │  - display       │
            └────────────────────────────────────────┘  UR    │  - sign          │
                                                                └──────────────────┘
                                      ▲
                                      │ shared: psct-core (schema, digest, profiles,
                                      │         inspect, combine, finalize) + vectors
```

Four artifacts:

- `spec/` — PSCT v0 + signing-profile registry + test vectors (JSON + binary fixtures).
- `psct-core` — TypeScript (on CCC) for the coordinator; **second independent implementation** (Rust or
  Python) for the signer. Two implementations or the spec is fiction.
- `coordinator` — web, watch-only, no private keys, no server-side state.
- `signer` — CLI (all platforms) → offline browser app → hardware image.

---

## 6. PSCT v0 — trust model, then data model

### 6.0 Decision D1 — strict trust (no compromise)

**The signer trusts nothing but canonical bytes and its own pre-paired account.** Not the coordinator, not
any field in the file, not any label, not any signature it did not verify, not any cell it did not hash-bind.

This is a design constraint with teeth. It forbids, permanently:

| Not allowed | Because | Replacement |
|---|---|---|
| Rendering a `label`/`role`/`memo` from the file | Attacker edits the field, screen lies | Labels live in the signer's trusted DB, shown as *its own* metadata |
| Taking the xpub/account from the file | Attacker supplies it, "change" is forged | Pair account at setup, out of band; file carries hints only |
| Trusting a supplied `CellOutput`/`CellData` | Fee and token deltas become attacker-chosen | Hash-bind to `previous_output.tx_hash` (§3.1) |
| Signing an unknown lock/type profile | Signer cannot know what it authorises | Refuse. Closed profile registry |
| Signing against an unwhitelisted `cell_dep` | The "lock" may be arbitrary code | Verify code hash/dep_type, refuse unknown |
| "Warn and continue" on unverifiable value | The warning is the attack surface | Refuse; offer a separate, explicit, visibly-degraded mode |
| Dropping verification data to fit a QR frame | Transport becomes the security boundary | Transport adapts (§8) |
| A network stack in the signer | "Disabled" is not "absent" | No-radio board, no network drivers linked |

Two nuances, because "strict" must still be usable:

- **Unknown *contract*, known *code*.** CKB type scripts are immutable code. If the code hash is pinned in
  the signer's database, the contract's behaviour is fixed and auditable even if this *instance* is new.
  If the code hash is unknown, the signer cannot know what the script does and must refuse.
- **Explicit downgrade.** A user may choose "sign for unknown contract anyway" as a per-session, visibly
  marked action. It must be a deliberate act with a different screen, never a default and never silent.

**What the signer provably cannot do** (state this in the UI, do not paper over it): prove a cell is
unspent, prove a previous transaction is canonical, or prove a header is on the best chain. Those are
liveness properties. A lying coordinator can therefore cause a failed broadcast or a delayed one. It cannot
cause a loss of funds once §3.1's binding is enforced.

### 6.1 Data model

Encoding: canonical CBOR (RFC 8949, deterministic) for transport; JSON for debugging and fixtures.
Magic: `psct` = `70 73 63 74`, then a u8 version. Base64 therefore starts `cHNjd…`.

```jsonc
{
  "psct": 0,
  "network": "ckb",                 // "ckb" | "ckt"
  "global": {
    // canonical, witnesses emptied. Signer renders from THIS.
    "tx": { "version": "0x0", "cell_deps": [...], "header_deps": [...],
            "inputs": [...], "outputs": [...], "outputs_data": [...] },

    // one entry per input, index-aligned with tx.inputs.
    // prev_tx is witness-free; hash(prev_tx) MUST equal inputs[i].previous_output.tx_hash.
    "input_proofs": [
      { "prev_tx": { ..., "witnesses": [] },
        "index": 3,
        "cell_output": { ... },      // MUST equal prev_tx.outputs[index]
        "data": "0x…",               // MUST equal prev_tx.outputs_data[index]
        "block_hash": "0x…", "block_number": 1234567 }   // for since/DAO checks
    ],

    // cell deps, likewise bound: data for hash_type=data/data1, output for type
    "cell_dep_proofs": [
      { "out_point": {...}, "cell_output": {...}, "data": "0x…",
        "prev_tx": { ... }, "index": 0 }        // or a dep_group expansion list
    ],

    // header deps, bound by hash; required for DAO withdraw and since
    "headers": [ { "hash": "0x…", "raw": "0x…" } ],

    // account the coordinator *claims*; signer must match against its own paired account
    "account": { "xpub": "...", "fingerprint": "0x…", "path_prefix": "m/44'/309'/0'" },

    // what the signer is expected to produce, per script group
    "signing": [
      { "group": "lock", "script_hash": "0x…",
        "profile": "sighash-all/secp256k1-blake160/v1",
        "expected": [ { "path": "m/44'/309'/0'/0/3", "pubkey": "0x…" } ] }
    ]
  },

  "inputs":  [ { "derivation": "m/44'/309'/0'/0/3" } ],       // index-aligned hints
  "outputs": [ { "role": "payment" }, { "role": "change" } ],  // advisory only
  "sigs": {
    "0x<script_hash>": [
      { "signer": "0x<pubkey-or-lock-arg>", "sig": "0x<65 bytes>", "profile": "…" }
    ]
  },
  "meta": { "note": "advisory; MUST NOT be rendered as fact" }
}
```

### Normative rules (the part that actually matters)

0. **Bind before you believe.** No capacity, token amount, fee, or code identity may be displayed until
   `input_proofs` / `cell_dep_proofs` have been hash-checked against the outpoints they claim (§3.1). A
   failed or missing proof is a hard refusal, not a warning.
1. **Determinism.** `tx` is serialized with an empty witness vector. `tx_hash` and the signing message are
   derived from that. Two encoders must produce byte-identical `tx`.
2. **Display = bytes.** Every screen field is computed from `global.tx` plus *verified* proofs.
   `meta`/`role`/`derivation` are hints and are rendered as "unverified" at most.
3. **Fee** = Σ verified input capacity − Σ output capacity. Signer computes it; never trusts a field. Also
   report occupied capacity per output so the user can see "you are burning 200 CKB to storage".
4. **Change** = output whose lock re-derives from the paired account + the hinted path. If the account does
   not match, the signer refuses or requires explicit approval.
5. **Token deltas** per type script: sum over inputs vs outputs using `outputs_data`. Unknown type script →
   hard warning with script hash, not a silent pass.
6. **Code identity.** For every lock/type the signer supports, the `cell_dep` must resolve to a whitelisted
   `(code_hash, hash_type, dep_type)` tuple. Unknown → refuse.
7. **Combine is commutative and lossless.** Merge `sigs` by key; conflicting values are an error; unknown
   keys are preserved verbatim. (BIP-174 1.4.3/1.4.4, retrofitted in 2026.)
8. **Finalize is deterministic.** Order signatures by the lock's own requirement (pubkey order,
   `require_first_n`, threshold), build the witness, verify locally, then emit a plain CKB transaction that
   `send_transaction` accepts.
9. **Profiles are closed.** No "best effort" signing. Unknown profile = refuse. v0 profiles:
   `sighash-all/secp256k1-blake160/v1`, `sighash-all/multisig-{legacy,2024}/v1`,
   `sighash-all/omnilock/v1`, `sighash-all/anyone-can-pay/v1` (warn-only).
10. **Interop.** Emit/consume the `ckb-cli tx` JSON shape as a lossy projection, so `ckb-cli tx send
    --tx-file` works today. This buys adoption and gives us a migration path for ckb-msig.

---

## 7. Corrected build order

Each phase ends with something a stranger can verify in under ten minutes. That is the grant currency.

### Phase 0 — Inspector + verifier (in progress)

Take real mainnet transactions, resolve inputs via RPC, and produce a trustworthy human summary; verify
existing signatures against your own re-implementation of the sighash.

Done so far (see `docs/01-phase0-findings.md`):
- molecule codec byte-identical to the node's serialization;
- `tx_hash` 25/25 and signatures 25/25 on live mainnet data;
- input binding + `inspect` + `verify` + CLI;
- the input-claim attack reproduced, and rejected by binding;
- 6 offline fixtures (max 11 inputs) re-verified with no network.

Remaining exit criteria:
- profiles for the four unknown lock code hashes in the fixtures;
- labelled fixtures: DAO deposit, DAO withdraw, xUDT transfer, Spore, 2-of-3 multisig;
- hostile corpus as assertions (forged capacity, wrong prev-tx hash, index mismatch, substituted
  `cell_dep`, mutated `outputs_data`, dark `since`, multisig under threshold).

Why first: it is the oracle every later phase is tested against; it is a useful standalone tool; it is Spark
sized; and it forces us to learn the exact sighash before freezing a spec.

### Phase 1 — PSCT v0 spec + `psct-core` (2 implementations) + vectors

Exit criteria: TS and (Python or Rust) produce identical bytes and identical signing messages on all
vectors; unknown-field preservation and commutative-combine tests pass; a hostile-fixture corpus is all
*detected*:

- inflated input capacity (the fee-theft attack)
- previous tx whose hash does not match the outpoint
- `prev_tx.outputs[index]` disagreeing with the claimed cell
- substituted `cell_dep` / fake `dep_group` expansion
- wrong change lock, swapped payment output, `outputs_data` mutated
- unknown type script, dark `since`, missing DAO header
- multisig signature set below threshold / out of order / duplicated signer

### Phase 2 — Coordinator + software signer (testnet end-to-end)

Watch-only web coordinator (CCC) + `psct sign` CLI. No QR yet: file handoff. This proves the format without
hardware or camera risk.

Under D1 the software signer is a **reference implementation and test harness, not the shippable product** —
a laptop has radios and a network stack, so it cannot meet the promise. Ship the claim only on the no-radio
board (Phase 5), and say so in the docs.

Exit: 2-of-3 multisig payout, DAO withdraw, and an xUDT transfer, each signed on a network-disabled machine
and broadcast from the coordinator.

### Phase 3 — UR transport

Encode PSCT as UR, register/choose the type, animated QR both directions. Reuse `bc-ur` implementations.
Exit: measure bytes/seconds per transaction class; a phone camera completes a 6-input tx without a dropped
frame stall.

### Phase 4 — Signer UX + verification policy

Trusted-display screens per operation type, driven only by verified bytes. Policy checks that fire *before*
the approve screen: Spore capacity stripping, unknown code hash, change mismatch, fee outlier relative to
the transaction class, unexplained `outputs_data` deltas, dark `since`. A failed check blocks the screen
rather than annotating it.

### Phase 5 — Hardware

Pick the no-radio board, build a reproducible image, strip network drivers, 3D case, assembly guide. Export
`psct-core` to the device or reimplement the small verifier in Rust.

---

## 8. Next 10 working days (concrete)

1. **Prove the §3.1 attack and the fix.** Take a real mainnet transaction, swap in an inflated input cell,
   and demonstrate that the signature still validates while the fee changes. That one script justifies the
   whole strict model and belongs verbatim in the grant application.
2. Pin the signing-message implementation against `ckb-system-scripts` source and the 2021 draft; write it
   down once, with the multisig variant. (Appendix A is the starting point.)
3. Build `psct bind` (proof hash-check), `psct inspect --tx <hash|file> --rpc <url>`, and `psct verify`.
4. Collect the 20-transaction corpus from mainnet; store fixtures as JSON + raw molecule bytes.
5. Write the hostile-fixture list (§7 Phase 1) *before* writing the verifier, so the tests can fail first.
6. Draft the PSCT v0 doc as a *description of what the verifier already does*.
7. Open the UR-type conversation with Blockchain Commons.
8. Decide: does Phase 2 target `ckb-cli` interop or CCC-native? (Recommend: both, ckb-cli as projection.)

---

## 9. Open questions for us to settle

- **Signer platform for v1.** D1 removes the laptop from the shipping path (radios + network stack), but it
  stays as the reference implementation. Hardware target: Pi Zero 1.3 (no radio, SeedSigner-proven, supply
  risk) vs a radio-less RISC-V board (better supply, less ecosystem). Decide before Phase 5, not before
  Phase 3.
- **Unknown-contract downgrade.** D1 forbids silent acceptance. Do we offer the explicit "sign for unknown
  code hash anyway" screen at all in v0, or defer it until real users hit the wall? Recommend: defer;
  measure how often it is actually needed on mainnet.
- **Multisig scope.** Legacy `multisig` only, or also the 2024 deployment? The 2024 one has tool gaps
  (ckb-cli/Neuron cannot sign it), which is both a risk and a differentiator.
- **Name.** `psct` (your term) is fine and unclaimed. Avoid `ckb-psbt` — it invites "why isn't it BIP-174"
  and it is *not* BIP-174. `crypto-psct` for the UR type.
- **Do we adopt CoBuild `WitnessLayout`** as the witness shape, or stay on `WitnessArgs`? CoBuild is where
  new scripts are going; but v0 signers must handle legacy `WitnessArgs` anyway. Suggest: support both,
  profile-per-lock, and do not require CoBuild for v0.
- **Grant sequence.** One Spark for Phase 0, then a second for Phase 1–2? Or CFDAO for the whole thing?
  Depends on how much you want to keep the scope tight.

---

## 10. Appendix A — CKB signing mechanics cheat-sheet

- Transaction: `version, cell_deps, header_deps, inputs, outputs, outputs_data, witnesses`.
- `tx_hash` = blake2b-256 of the molecule-serialized tx **with witnesses emptied**.
- **What `tx_hash` does *not* commit to:** the capacity, lock, type, or data of the cells being spent.
  Inputs commit only to `(previous_output, since)`. There is no BIP-143/BIP-341 equivalent. Therefore the
  fee is not committed either, and a supplied `CellOutput` must be hash-bound to its creating transaction
  before it is trusted. This is the single most security-relevant line in this document.
- `WitnessArgs` = table `{ lock: Bytes?, input_type: Bytes?, output_type: Bytes? }`.
- Sighash-all message (from `ckb-system-scripts/c/secp256k1_blake160_sighash_all.c`):
  1. `tx_hash`;
  2. witness at the **same index as the first input of this lock group**, parsed as `WitnessArgs`, with
     `lock` overwritten by 65 zero bytes (prefixed by its u64-LE length);
  3. witnesses at the same indices as remaining inputs sharing this lock script (each prefixed by u64-LE
     length);
  4. all witnesses with index ≥ number of inputs (each prefixed by u64-LE length);
  5. blake2b-256 with personalization `ckb-default-hash`.
  Signature = 65 bytes `r‖s‖recid`; recovered pubkey → blake160 → compare with lock args.
- Multisig: lock args carry `require_first_n`, `threshold`, pubkey hashes; the signed message zeroes a
  *structured* placeholder, and the final lock field is `flags + ordered signatures`. Do not assume the
  65-zero-byte rule.
- DAO withdraw: needs the deposit block header in `header_deps` and the deposit block number in the
  type-group witness `input_type` field. A signer without headers cannot verify a withdraw.
- xUDT: 16-byte LE amount in cell data; multiple cells per lock; type args encode owner mode.
- Spore: 32-byte type-id in args, content in data, capacity ≥ occupied; melting is a capacity event.
- Occupied capacity: `8 + molecule(CellOutput) + len(data)` bytes → shannons. Empty secp cell ≈ 61 CKB
  minimum.
- Addresses: bech32m, HRP `ckb` / `ckt`, checksum per RFC-0021.
- BIP-32: coin type 309 (mainnet), 1 (testnet); default path `m/44'/309'/0'/0/0`.

## 11. Appendix B — prior art, one line each

- **BIP-174 / BIP-370** — the model to learn from, not to copy.
- **xxuejie 2021 offline signing draft** — `UnsignedTransaction{signing_method, tx, input_txs,
  cell_dep_txs, headers}`; the direct ancestor of PSCT. Note it already carried `input_txs` — the binding
  requirement in §3.1 is not new, it was right and got dropped. Cite it.
- **RFC PR #406 / Open Transaction** — closed unmerged; different problem (mutable construction).
- **CoBuild / OTX** — witness layout + intent messages for composable txs; not a signer transport.
- **`ckb-cli tx` JSON** — de facto partial signing, no resolved cells, tool-specific.
- **Neuron multisig export** — offline-verifiable, Neuron-only.
- **`ckb-msig` (2026-11)** — proof the interop problem is current; potential partner, not competitor.
- **SafePal S1** — closed air-gapped CKB; the bar for UX, not for openness.
- **SeedSigner / Keystone / Keycard Shell** — the open-hardware patterns to copy (stateless signer, UR,
  QR-only, reproducible builds).

## 12. Sources

- BIP-174 (v1.4.4, 2026-09-23) and BIP-370.
- `nervosnetwork/rfcs` RFC-0022 (transaction structure), RFC-0021 (address), RFC-0023 (DAO), RFC-0042
  (OmniLock), RFC-0052 (xUDT).
- `nervosnetwork/ckb-system-scripts` — `secp256k1_blake160_sighash_all.c`, multisig lock.
- `nervosnetwork/ckb-cli` wiki "Handle Complex Transaction"; `tx` subcommand docs.
- Nervos Talk: RFC Draft "CKB Offline Transaction Signing Scheme" (2021-05-31); RFC PR #406;
  CoBuild overview (2024-02); `cobuild-otx-contracts` (2026-06); Spark Program Q2/Q3 2026 reports;
  ckb-msig (2026-11-08).
- docs.ckbccc.com (Transaction, Signer, compose-transactions).
- nervos.org/wallets; Ledger support page for Nervos (2026-05-13); SafePal CKB guide.
- CKB Eco Fund / Spark Program page (funding caps, 20/80, bilingual requirement).

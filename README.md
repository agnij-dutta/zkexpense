# zkExpense

**A verifiable expense report for AI agents.** After an agent makes a month of x402 micropayments, it produces one zero-knowledge proof for its principal or auditor:

> Every one of these N payments was made by this wallet, in USDC, on this chain, inside this period, to a vendor in the approved set, and the total is at most the budget (or exactly $X).

Individual vendors and amounts stay hidden. The auditor verifies one proof in milliseconds, or on-chain through `ExpenseAttestation.sol`.

zkExpense descends from Solva (ZK solvency on Starknet): same idea of proving an aggregate statement about private balances, applied to agent spend.

Real numbers from this repo (M4 under heavy load, see [BENCHMARKS.md](BENCHMARKS.md)): 347 payments prove in 11 s, the proof is 10,176 bytes, and it verifies in 8 ms in-process or for 2.68M gas on-chain. Verifier cost stays flat (2.56M to 2.86M gas) from 64 to 4096 payments.

## Quickstart

```bash
scripts/setup.sh                     # npm install, forge deps, compile circuits, generate verifiers

# a month of realistic x402 payments from one agent wallet (347 calls to 12 API vendors)
node cli/zkexpense.mjs sample --count 347 --out examples

# one proof: all 347 payments, approved vendors only, September, total <= $500
node cli/zkexpense.mjs prove examples/log-347.json --vendors examples/vendors.json --budget 500

# auditor side
node cli/zkexpense.mjs verify proof.json --vendor-root $(node cli/zkexpense.mjs vendor-root examples/vendors.json)
```

```
zkexpense report for agent:research-bot-7 (batch_512)
  payer     0x8fdb...e218 on chain 8453, asset 0x8335...2913
  period    2026-09-01T00:00:00Z .. 2026-09-30T23:59:59Z
  payments  347
  budget    $500.00, total hidden
  [ok] proof valid (bb, UltraHonk)
  [ok] report matches public inputs
  [ok] total within budget
  [ok] vendor root is the approved set
  verified in 7.9 ms [bb.js (in-process)]
```

Other commands:

| command                                          | what it does                                               |
| ------------------------------------------------ | ---------------------------------------------------------- |
| `prove ... --disclose-total`                     | reveal the exact total instead of only `total <= budget`   |
| `prove ... --prev last-month.json`               | chain this report onto the previous period's hash chain    |
| `prove ... --circuit agg_1024x4`                 | force a circuit (auto-picked by payment count otherwise)   |
| `disclose log.json --proof proof.json --tx 0x..` | open ONE payment (preimage + Merkle path), nothing else    |
| `check-disclosure d.json --proof proof.json`     | auditor checks that opening against the proven log root    |
| `vendor-root vendors.json`                       | the salted root a principal publishes for its approved set |
| `inspect log.json`                               | sanity summary of a log                                    |

A log that violates policy (unapproved vendor, payment outside the period) cannot be proven: the CLI refuses up front (exit 4) and the circuit has no satisfying witness anyway.

## Input format

A log is a list of x402 payments. Either flat rows:

```json
{
  "transaction": "0x<32-byte settlement tx hash>",
  "payer": "0x..",
  "payTo": "0x..",
  "amount": "12500",
  "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  "network": "base",
  "timestamp": 1788221000
}
```

or the raw pair an agent gets from x402, `{ paymentRequirements, settleResponse, timestamp }` (see `examples/x402-raw.json`). `amount` is in atomic units (USDC has 6 decimals), `network` is an x402 name (`base`, `base-sepolia`, `avalanche-fuji`, ...) or CAIP-2 (`eip155:8453`), `timestamp` is the settlement block time. One report covers one payer wallet, one asset and one chain; duplicates by settlement tx are rejected.

The vendor set is `{ "salt": "0x..", "vendors": [{ "name": "...", "address": "0x.." }] }`, up to 256 vendors. The salt keeps the published vendor root from being brute-forced against known addresses.

## What is proven

Each payment becomes a leaf

```
leaf = Poseidon2(payer, payTo, amount, asset, chainId, timestamp, txHash_hi, txHash_lo, salt)
```

with a per-payment salt derived from the agent's secret (`.zkexpense/secret`). The circuit (`circuits/lib/src/lib.nr`) proves, for the first `count` slots of a fixed-size batch (the rest is zero padding):

- payee is non-zero and equals `vendors[vendor_idx]` of the private vendor table whose salted Poseidon2 Merkle root is `vendorRoot`
- `periodStart <= ts_0 <= ts_1 <= ... <= periodEnd` (sorted, inside the period)
- `logRoot` is the Poseidon2 Merkle root of all leaves, `chainOut = H(..H(H(chainIn, leaf_0), leaf_1).., leaf_last)`
- `total = sum(amounts)`, `underBudget = total <= budget`, `totalCommit = H(total, blind)`, and `disclosedTotal = discloseTotal ? total : 0`

### Public inputs (15 fields, in this order)

| #   | name          |     | #   | name                                |
| --- | ------------- | --- | --- | ----------------------------------- |
| 0   | payer         |     | 8   | logRoot                             |
| 1   | asset         |     | 9   | vendorRoot                          |
| 2   | chainId       |     | 10  | count                               |
| 3   | periodStart   |     | 11  | underBudget                         |
| 4   | periodEnd     |     | 12  | disclosedTotal (0 unless disclosed) |
| 5   | budget        |     | 13  | totalCommit                         |
| 6   | discloseTotal |     | 14  | chainOut                            |
| 7   | chainIn       |     |     |                                     |

Revealed: payer wallet, asset, chain, period, budget, number of payments, roots. Hidden: every payee, every amount, every timestamp, every tx hash, the vendor list, and the total (unless disclosed).

## Proving approach: fixed batches + recursive aggregation

Two options were on the table: (a) a fixed-size batch circuit with padding plus recursive aggregation, or (b) folding one step per payment. zkExpense ships **(a)**, because it is what the installed toolchain actually supports end to end:

- A payment costs about **540 UltraHonk gates** (3 Poseidon2 permutations for the leaf, 1 for the hash chain, 1 for the Merkle tree, a ROM lookup for vendor membership, range checks). Vendor membership is a table lookup into the committed vendor array, not a Merkle path per payment, which is about 8x cheaper. A whole 1024-payment batch is 594k gates, so a month of agent spend fits in one proof with no recursion at all.
- For larger logs, Noir `std::verify_proof_with_type` with bb's `noir-recursive-no-zk` target works in nargo 1.0.0-beta.19 / bb 4.0.0-nightly. `agg_1024x4` verifies 4 batch proofs in-circuit (3.08M gates) and outputs one report over 4096 payments. Batch roots are combined so the aggregated `logRoot` equals the flat Merkle root over all 4096 slots, and the hash chain is threaded batch to batch. The inner verification key hash is pinned as a circuit constant, so a prover cannot substitute another circuit.
- Folding (b) is not a usable general-purpose path here: bb's folding is the Aztec `chonk` client-IVC scheme, which expects Aztec kernel-shaped circuits and produces a proof that is not verified by the generated Solidity verifier. Per-payment steps would also cost one prover step per payment instead of one proof per thousand.

Inner batch proofs are non-ZK (they never leave the prover); the final proof is ZK with a Keccak transcript for EVM verification. One gotcha worth knowing: recursive verification defers the pairing check to the final verifier, so `bb prove` happily produces an aggregate proof over a bad inner proof; it just never verifies. The CLI self-verifies every proof it writes.

## Contracts

`contracts/src/ExpenseAttestation.sol` records verified reports.

- A principal calls `registerAgent(agentId, payer, asset, chainId, vendorRoot, budgetCap)` (agentId can be an ERC-8004 id). `updateMandate` changes the vendor root and cap for future reports.
- Anyone calls `submitReport(agentId, circuitId, proof, publicInputs)`. It checks the public inputs against the mandate (payer, asset, chain, vendor root, budget <= cap), that the period is over, that periods are **contiguous** with the previous report, and that `chainIn` equals the previous report's `chainOut`. Then it calls the bb-generated verifier and stores `{logRoot, publicInputsHash, period, count, underBudget}`. Over-budget reports are recorded and emit `BudgetExceeded`.
- Verifiers are registered per circuit id (`keccak256("batch_512")` etc.), append-only. The owner can pause submissions.

`contracts/src/verifiers/*.sol` are generated by `bb write_solidity_verifier` (`scripts/build.sh`). They sit ~60 bytes over EIP-170 at 200 optimizer runs, so `foundry.toml` compiles them with `optimizer_runs = 1`.

## Tests

```bash
npm test     # node unit + e2e (real nargo/bb), nargo circuit tests, forge tests
```

- `circuits/lib`: 14 Noir tests (hash vectors, Merkle composition, every rejection path: unapproved vendor, lying vendor index, zero payee, before/after period, unsorted, count overflow, padding garbage ignored).
- `test/*.test.mjs`: JS/Noir hash parity, ingest validation, policy pre-checks, disclosure, and an end-to-end prove/verify/tamper run.
- `contracts/test`: 31 Foundry tests on real proofs (fixtures from `scripts/fixtures.mjs`), including a fuzz test that any change to any public input is rejected, chained Sep to Oct reports, replay, skipped chain, wrong payer/chain/vendor set, cap, pause, and an aggregated proof. `GasBench.t.sol` measures gas for the benchmark proofs.

## Caveats (read these)

1. **The agent writes its own log.** The proof shows that the payments _in the log_ satisfy the policy; it cannot see payments the agent left out. Mitigations, from cheapest to strongest:
   - _Dedicated payer wallet + count check._ `count` and `payer` are public. The auditor counts USDC transfers out of the payer wallet in the period (public Transfer / EIP-3009 `AuthorizationUsed` events) and compares. An omitted payment shows up as a mismatch.
   - _Spot-check disclosures._ The auditor picks random on-chain settlement txs from that wallet and asks for `zkexpense disclose`. The agent can only answer for payments that are really leaves of the proven root, and the opening reveals that one payment and nothing else. Swapping an omitted large payment for a fake small one fails as soon as either is sampled.
   - _On-chain anchoring (the sound fix, TODO)._ If payments go through a settlement contract that keeps the same Poseidon2 hash chain on-chain, the attestation contract can require `chainOut` to equal the on-chain head at period end, making omission impossible. The circuit already exposes `chainIn`/`chainOut` and the contract already enforces chain continuity between reports for this purpose. Note the leaf includes the settlement tx hash, which a contract cannot know mid-transaction; an anchored variant would use a per-payer nonce instead.
2. **Amounts and payees are as logged.** The same disclosure mechanism lets an auditor check any opened payment against its on-chain transfer.
3. **The payment count is public.** It is useful for the omission check above; a variant could make it private.
4. **Toolchain maturity.** bb 4.0.0 is a nightly; the Solidity verifiers are generated and unaudited. UltraHonk uses a KZG SRS (Aztec Ignition), so there is a universal trusted setup.
5. **Admin trust.** The attestation owner can add verifiers (never replace one) and pause submissions. Production should put this behind a timelock or multisig.
6. Timestamps are ordered within a batch and contiguous across reports, but the circuit does not check ordering across batches inside an aggregate (the hash chain still fixes the order).

## Layout

```
circuits/lib          core Noir library: hash, leaf, Merkle, prove_batch, aggregate, tests
circuits/batch_N      thin wrappers, N = 64 / 256 / 512 / 1024
circuits/agg_BxK      recursive aggregators (generated by scripts/build.sh with the pinned inner vk hash)
cli/                  zkexpense CLI (Node, ESM) and libraries
contracts/            Foundry: ExpenseAttestation.sol, generated verifiers, tests, fixtures
scripts/              setup, build, sample generator, fixtures, benchmarks
examples/             sample logs and vendor sets
```

Requires nargo 1.0.0-beta.19, bb 4.0.0-nightly.20260120, Foundry, Node 22. `@aztec/bb.js` (same bb version) is an optional dependency used for in-process verification; without it `verify` falls back to the bb CLI.

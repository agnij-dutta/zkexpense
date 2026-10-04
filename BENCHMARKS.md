# Benchmarks

All numbers are real runs of `node scripts/bench.mjs --runs 3` on the circuits at the commit that added this file (raw data: [`bench/results.json`](bench/results.json); the table is rendered by `node scripts/bench-table.mjs`). Every proof was also verified through the generated Solidity verifier in Foundry. Sample logs are synthetic (`generateSample`, seed 99), with realistic x402 micropayment amounts.

## Methodology

|               |                                                                                                                                                                                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Machine       | Apple M4 (10 cores: 4 performance + 6 efficiency), 16 GB RAM, macOS, on AC power                                                                                                                                                                                                     |
| Toolchain     | nargo 1.0.0-beta.19, bb 4.0.0-nightly.20260120, Node 22.14, Foundry 1.5.1, solc 0.8.30                                                                                                                                                                                               |
| Proof system  | UltraHonk, Keccak ZK transcript (`bb prove -t evm`), 15 public inputs                                                                                                                                                                                                                |
| Date          | 2026-10-05 01:25 to 01:27 IST (2026-10-04 19:55 to 19:57 UTC)                                                                                                                                                                                                                        |
| Repetitions   | 3 proving runs per single-batch case (best and every run reported), 1 run for the 4096-payment aggregate; verification is 1 warm-up plus 25 timed runs (median and min)                                                                                                              |
| Load          | 1-minute load average 15.8 to 21.9 during the run (sampled every 15 s). bb proves on all 10 cores, so about 10 of that is the benchmark itself; the rest was other work on the machine (other agent sessions, a browser). Treat prove times as noisy upper bounds on a quiet machine |
| Deterministic | gate counts, proof sizes and gas do not depend on load                                                                                                                                                                                                                               |

## Results

| payments | circuit                  |                        gates | prove (best) | prove (all runs)       | peak RAM |        proof | verify (median / min) | verify gas | submitReport gas |
| -------: | ------------------------ | ---------------------------: | -----------: | ---------------------- | -------: | -----------: | --------------------: | ---------: | ---------------: |
|       64 | `batch_64`               |                          80k |       0.81 s | 0.81 s, 0.90 s, 1.16 s |   248 MB |      9,408 B |        4.66 / 3.90 ms |  2,557,679 |        2,662,932 |
|      256 | `batch_256`              |                         196k |       2.23 s | 2.97 s, 2.23 s, 2.36 s |   517 MB |      9,792 B |        3.32 / 3.15 ms |  2,618,547 |        2,723,887 |
|  **347** | `batch_512`              |                         351k |   **3.09 s** | 3.09 s, 4.14 s, 3.28 s |   969 MB | **10,176 B** |    **3.69 / 3.28 ms** |  2,679,440 |        2,784,868 |
|      512 | `batch_512`              |                         351k |       3.24 s | 6.23 s, 3.96 s, 3.24 s |   970 MB |     10,176 B |        3.67 / 3.53 ms |  2,676,940 |        2,784,868 |
|     1024 | `batch_1024`             |                         660k |       7.40 s | 9.09 s, 7.40 s, 7.58 s | 1,586 MB |     10,560 B |        4.42 / 4.20 ms |  2,740,358 |        2,845,874 |
|     4096 | `agg_1024x4` (recursive) | 3.08M outer + 4 x 660k inner |      46.51 s | 46.51 s (1 run)        | 3,068 MB |     11,328 B |        3.21 / 3.17 ms |  2,862,272 |        2,967,967 |

### Column notes

- **prove**: `bb prove` wall time for the final proof, measured around the process. For 4096 payments it is the sum of 4 inner batch proofs (7.2 s, 5.5 s, 4.2 s, 4.2 s, non-ZK Poseidon2 transcript) plus the 3.08M-gate aggregation proof (25.4 s). Witness generation (`nargo execute`) is extra and small: 0.08 s at 64, 0.29 s at 347, 0.77 s at 1024, 3.0 s in total at 4096.
- **gates**: UltraHonk circuit size from `bb gates`. A payment costs about 600 gates ((660k - 80k) / 960); the fixed overhead is the 256-slot vendor table and its Merkle root (about 40k gates).
- **peak RAM**: max RSS of the final `bb prove` (`/usr/bin/time -l`).
- **proof**: bytes of the EVM proof. It grows with log2 of the circuit size (more sumcheck rounds), not with the payment count.
- **verify**: in-process `UltraHonkVerifierBackend.verifyProof` from `@aztec/bb.js` (same bb version), 1 thread, warm. Through the `bb verify` CLI it is about 20 to 50 ms wall, almost all of it process start-up.
- **verify gas**: gas used by the bb-generated verifier's `verify()` in Foundry (`contracts/test/GasBench.t.sol`), excluding calldata. **submitReport gas** is the whole `ExpenseAttestation.submitReport` execution (canonical-input and mandate checks, verify, storage, event). A real transaction adds intrinsic calldata (151k gas at 64 payments to 182k at 4096) and the 21k base.

## What scales how

- Prover time and memory grow roughly linearly with the batch size (about 600 gates per payment) and step at powers of two of the circuit size, so 347 and 512 payments cost the same.
- Verifier cost is essentially flat: 2.56M gas at 64 payments, 2.86M gas at 4096. The auditor's cost does not depend on how busy the agent was.
- Recursion works in this toolchain but costs about 700k gates per in-circuit verification, more than a full 1024-payment batch, so it only pays off beyond 1024 payments per period.

## History

An earlier run (2026-10-04, previous circuit version without strict tx ordering, 318k gates for `batch_512`) measured 11.09 s best-of-3 for 347 payments under a 1-minute load average of 17 to 69. The current circuit is about 10% larger; the faster time reflects a less contended machine, which is why these numbers should be read together with the load column above.

## Reproduce

```bash
scripts/setup.sh
npm run bench                                # all cases including the 4096 aggregate (a few minutes)
node scripts/bench.mjs --skip-agg            # single batches only
node scripts/bench.mjs --only n64,n347       # selected cases
node scripts/bench-table.mjs                 # render the table
```

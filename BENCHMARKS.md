# Benchmarks

All numbers are real runs of `node scripts/bench.mjs` (raw data: `bench/results.json`, table: `node scripts/bench-table.mjs`). Every proof was verified natively and through the generated Solidity verifier in Foundry.

**Important context:** the machine was shared with other heavy jobs during the run (load average 17 to 69 on 10 cores, against an ideal of under 10). Proving times are therefore pessimistic and noisy; on a quiet machine expect them to be meaningfully lower. As one data point, the same `batch_64` proof took 1.33 s wall earlier in the session at lower load, versus 3.28 s best-of-3 in the table. Gas, proof sizes and gate counts are deterministic and unaffected.

Setup: Apple M4, 10 cores, 16 GB RAM, nargo 1.0.0-beta.19, bb 4.0.0-nightly.20260120, UltraHonk with Keccak ZK transcript (`bb -t evm`), 15 public inputs.

| payments | circuit                  |                        gates | prove (best) | prove (all runs)          | peak RAM |        proof | verify (median / min) | verify gas | submitReport gas |
| -------: | ------------------------ | ---------------------------: | -----------: | ------------------------- | -------: | -----------: | --------------------: | ---------: | ---------------: |
|       64 | `batch_64`               |                          76k |       3.28 s | 3.61 s, 3.44 s, 3.28 s    |   226 MB |      9,408 B |        8.44 / 7.50 ms |  2,557,679 |        2,658,028 |
|      256 | `batch_256`              |                         180k |       6.13 s | 6.25 s, 6.13 s, 7.75 s    |   501 MB |      9,792 B |        7.97 / 7.61 ms |  2,618,547 |        2,718,983 |
|  **347** | `batch_512`              |                         318k |  **11.09 s** | 12.30 s, 12.54 s, 11.09 s |   868 MB | **10,176 B** |    **8.29 / 7.94 ms** |  2,679,440 |        2,779,964 |
|      512 | `batch_512`              |                         318k |       9.50 s | 12.80 s, 10.19 s, 9.50 s  |   872 MB |     10,176 B |        7.84 / 6.50 ms |  2,676,940 |        2,779,964 |
|     1024 | `batch_1024`             |                         594k |      13.52 s | 21.96 s, 18.49 s, 13.52 s | 1,576 MB |     10,560 B |        6.94 / 6.47 ms |  2,740,358 |        2,840,970 |
|     4096 | `agg_1024x4` (recursive) | 3.08M outer + 4 x 594k inner |      96.21 s | 96.21 s (1 run)           | 5,546 MB |     11,328 B |       17.45 / 8.84 ms |  2,862,272 |        2,963,063 |

## Column notes

- **prove**: `bb prove` wall time for the final proof. For 4096 payments it is the sum of 4 inner batch proofs (9.5 s, 7.5 s, 7.7 s, 11.2 s, non-ZK Poseidon2 transcript) plus the 3.08M-gate aggregation proof (60.2 s). Witness generation (`nargo execute`) is extra and small: 0.3 s at 64, 0.7 s at 347, 1.0 s at 1024, 4.3 s total at 4096.
- **gates**: UltraHonk circuit size from `bb gates`. A payment costs about 540 gates; the fixed overhead is the 256-slot vendor table and its Merkle root (about 40k gates).
- **peak RAM**: max RSS of the final `bb prove` (`/usr/bin/time -l`).
- **proof**: bytes of the EVM proof. It grows with log2 of the circuit size (more sumcheck/Gemini rounds), not with payment count.
- **verify**: in-process `UltraHonkVerifierBackend.verifyProof` from `@aztec/bb.js` (same bb version), 1 thread, warm, 25 runs. Via the `bb verify` CLI it is about 20 to 50 ms wall, almost all of it process start-up.
- **verify gas**: gas used by the bb-generated Solidity verifier's `verify()` in Foundry (`contracts/test/GasBench.t.sol`), excluding calldata. **submitReport gas** is the full `ExpenseAttestation.submitReport` execution (mandate checks + verify + 3 storage slots + event). Add intrinsic calldata for a real tx: 151k (64) to 182k (4096) gas, plus the 21k base.

## The tweet numbers

**347 payments, one proof: 11 s to prove on a busy laptop, 10 KB, verified in 8 ms (2.7M gas on-chain).**

The "verified in 9 ms" line holds: median in-process verification is 7 to 8.5 ms for every batch size, and the 9 ms figure sits inside the measured range. The aggregated 4096-payment proof verifies in 8.8 ms best case (17 ms median under load).

## What scales how

- Prover time and memory scale roughly linearly with payments inside a batch (~540 gates each), stepping at powers of two of the circuit size.
- Verifier cost is essentially flat: 2.56M gas at 64 payments, 2.86M gas at 4096. That is the whole point: the auditor's cost does not depend on how busy the agent was.
- Recursion works in this toolchain, but it is expensive: each in-circuit UltraHonk verification costs about 700k gates, more than a full 1024-payment batch. So recursion only pays off beyond 1024 payments per period; below that a single batch is strictly better.

## Reproduce

```bash
scripts/setup.sh
node scripts/bench.mjs --runs 3              # all cases, including the 4096 aggregate (~5 min)
node scripts/bench.mjs --skip-agg            # single batches only
node scripts/bench-table.mjs                 # render the table
```

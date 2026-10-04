# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-05

First public release. Unaudited.

### Added

- Noir batch circuits for 64, 256, 512 and 1024 payments: approved-vendor membership (salted vendor root), period and ordering checks, Poseidon2 log root, hash chain across periods, total under budget with an optional disclosed total.
- Recursive aggregation circuits (`agg_64x2`, `agg_1024x4`) that verify batch proofs in-circuit, with a pinned inner verification key hash and per-batch sub-periods.
- `zkexpense` CLI and TypeScript library (strict TypeScript, emitted to `dist/`): `prove`, `verify` (in-process bb.js or bb CLI), `disclose` by tx or by index, `check-disclosure`, `vendor-root`, `inspect`, `sample`.
- Raw x402 `{ paymentRequirements, settleResponse }` ingest.
- `ExpenseAttestation.sol`: mandates namespaced by principal, fixed first period, minimum period length, budget cap, contiguous periods, hash-chain continuity, canonical public inputs, append-only verifier registry, pause.
- bb-generated UltraHonk Solidity verifiers for every circuit.
- Tests: 27 Noir, 23 node (including real prove/verify through the CLI), 36 Foundry on real proofs, and an adversarial verification-key substitution test.
- Benchmarks with methodology (BENCHMARKS.md), CI workflow, contributing and security docs.

[Unreleased]: https://github.com/agnij-dutta/zkexpense/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agnij-dutta/zkexpense/releases/tag/v0.1.0

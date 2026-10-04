#!/usr/bin/env bash
# One-time setup: JS deps + TypeScript build, Foundry deps, then compile circuits and generate verifiers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
npm install
npm run build
cd "$ROOT/contracts"
[ -d lib/forge-std ] || forge install foundry-rs/forge-std@v1.17.0 --no-git
[ -d lib/openzeppelin-contracts ] || forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
"$ROOT/scripts/build.sh"

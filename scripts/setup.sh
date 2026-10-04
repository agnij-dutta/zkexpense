#!/usr/bin/env bash
# One-time setup: JS deps, Foundry deps, then compile circuits + generate verifiers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" && npm install
cd "$ROOT/contracts"
[ -d lib/forge-std ] || forge install foundry-rs/forge-std --no-git
[ -d lib/openzeppelin-contracts ] || forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
"$ROOT/scripts/build.sh"

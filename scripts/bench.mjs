#!/usr/bin/env node
// Benchmarks: proving time, memory, proof size, verification time and on-chain gas per circuit.
// usage: node scripts/bench.mjs [--runs 3] [--only batch_64,batch_256] [--skip-agg]
// Writes bench/results.json and contracts/test/fixtures/bench/<case>.json (for GasBench.t.sol).
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { cpus, totalmem, loadavg, tmpdir } from "node:os";
import { ROOT, ensureCompiled } from "../cli/lib/prover.mjs";
import { ingestLog, ingestVendors } from "../cli/lib/model.mjs";
import { proveReport } from "../cli/lib/report.mjs";
import { verifyProofJson } from "../cli/lib/verify.mjs";

const arg = (k, d) => {
  const i = process.argv.indexOf(`--${k}`);
  return i < 0 ? d : process.argv[i + 1] ?? true;
};
const RUNS = Number(arg("runs", 3));
const only = arg("only", null)?.split(",");
const CASES = [
  { id: "n64", circuit: "batch_64", payments: 64 },
  { id: "n256", circuit: "batch_256", payments: 256 },
  { id: "n347", circuit: "batch_512", payments: 347 },
  { id: "n512", circuit: "batch_512", payments: 512 },
  { id: "n1024", circuit: "batch_1024", payments: 1024 },
  { id: "n4096", circuit: "agg_1024x4", payments: 4096, runs: 1 },
].filter((c) => (!only || only.includes(c.id)) && !(process.argv.includes("--skip-agg") && c.circuit.startsWith("agg")));

const FIX = join(ROOT, "contracts/test/fixtures/bench");
mkdirSync(FIX, { recursive: true });
mkdirSync(join(ROOT, "bench"), { recursive: true });
const work = mkdtempSync(join(tmpdir(), "zkexpense-bench-"));

const gates = (pkg) => {
  const out = execFileSync("bb", ["gates", "-b", ensureCompiled(pkg)], { stdio: ["ignore", "pipe", "ignore"] }).toString();
  return Number(out.match(/"circuit_size":\s*(\d+)/)[1]);
};

const resultsPath = join(ROOT, "bench/results.json");
let previous = {};
try { previous = JSON.parse(readFileSync(resultsPath, "utf8")).cases ?? {}; } catch {}
const results = { ...previous };

for (const c of CASES) {
  execFileSync(process.execPath, [join(ROOT, "scripts/gen-sample.mjs"), "--count", String(c.payments), "--out", work, "--seed", "99"]);
  const log = ingestLog(JSON.parse(readFileSync(join(work, `log-${c.payments}.json`), "utf8")));
  const vendors = ingestVendors(JSON.parse(readFileSync(join(work, "vendors.json"), "utf8")));
  const opts = {
    budget: 500_000_000n, periodStart: Date.UTC(2026, 8, 1) / 1000, periodEnd: Date.UTC(2026, 9, 1) / 1000 - 1,
    discloseTotal: false, secret: 0xbe9cn, circuit: c.circuit,
  };
  const runs = c.runs ?? RUNS;
  const all = [];
  let pj;
  for (let r = 0; r < runs; r++) {
    pj = proveReport(log, vendors, opts);
    all.push(pj.meta.timings);
    console.error(`${c.id} run ${r + 1}/${runs}: prove ${(pj.meta.timings.proveMs / 1000).toFixed(2)}s`);
  }
  const best = all.reduce((a, b) => (b.proveMs < a.proveMs ? b : a));
  const v = await verifyProofJson(pj, { runs: 25 });
  if (!v.ok) throw new Error(`${c.id}: proof failed to verify`);
  writeFileSync(join(FIX, `${c.id}.json`), JSON.stringify(pj));
  results[c.id] = {
    circuit: c.circuit,
    payments: c.payments,
    gates: gates(c.circuit),
    innerGates: c.circuit.startsWith("agg") ? gates("batch_1024") : undefined,
    proveMsBest: best.proveMs,
    proveMsAll: all.map((t) => t.proveMs),
    innerProveMs: best.innerProveMs,
    aggregateProveMs: best.aggregateProveMs,
    witnessMs: best.witnessMs,
    peakRssMb: best.peakRssMb,
    proofBytes: pj.meta.proofBytes,
    publicInputs: pj.publicInputs.length,
    verifyMsMedian: Number(v.ms.toFixed(2)),
    verifyMsMin: Number(v.minMs.toFixed(2)),
    verifyEngine: v.engine,
  };
  console.error(JSON.stringify(results[c.id]));
}
rmSync(work, { recursive: true, force: true });

// On-chain gas: real proofs through the bb-generated Solidity verifiers (forge test).
const forge = execFileSync("forge", ["test", "--match-contract", "GasBench", "-vv"], { cwd: join(ROOT, "contracts") }).toString();
for (const m of forge.matchAll(/GAS (\w+) verify=(\d+) submit=(\d+) calldata=(\d+)/g)) {
  if (results[m[1]]) Object.assign(results[m[1]], { verifyGas: +m[2], submitReportGas: +m[3], calldataGas: +m[4] });
}

const env = {
  cpu: cpus()[0].model, cores: cpus().length, memGb: Math.round(totalmem() / 2 ** 30),
  loadAvgAtEnd: loadavg().map((x) => +x.toFixed(1)),
  nargo: execFileSync("nargo", ["--version"]).toString().split("\n")[0],
  bb: execFileSync("bb", ["--version"]).toString().trim(),
  date: new Date().toISOString(),
};
writeFileSync(resultsPath, JSON.stringify({ env, cases: results }, null, 2));
console.log(JSON.stringify({ env, cases: results }, null, 2));

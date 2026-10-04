#!/usr/bin/env node
// zkexpense: one zero-knowledge proof for a month of agent payments.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { ingestLog, ingestVendors, parseAmount, vendorRoot } from "./lib/model.mjs";
import { toHex } from "./lib/hash.mjs";
import { proveReport, PolicyViolation } from "./lib/report.mjs";
import { verifyProofJson } from "./lib/verify.mjs";
import { ROOT } from "./lib/prover.mjs";

const USAGE = `zkexpense: verifiable expense reports for AI agents

usage:
  zkexpense prove <log.json> --vendors <vendors.json> --budget <usd> [options]
      --period YYYY-MM          reporting period (default: month of the first payment)
      --from YYYY-MM-DD --to YYYY-MM-DD   explicit period (UTC, inclusive)
      --disclose-total          reveal the exact total (default: only total <= budget)
      --out <proof.json>        output file (default: proof.json)
      --circuit <name>          force batch_64 | batch_256 | batch_1024 | agg_64x2 | agg_1024x4
      --prev <proof.json>       previous period's proof; chains this report onto it
      --secret-file <path>      agent secret for salts/blinding (default: .zkexpense/secret, created)
  zkexpense verify <proof.json> [--vendor-root 0x..] [--payer 0x..] [--max-budget <usd>]
  zkexpense vendor-root <vendors.json>
  zkexpense inspect <log.json>
  zkexpense sample --count <n> [--out examples] [--rogue <n>]
`;

function parseArgs(argv) {
  const pos = [], flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) flags[k] = argv[++i];
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const usd = (atomic) => `$${(Number(atomic) / 1e6).toFixed(2)}`;
const day = (s, endOfDay) => {
  const t = Date.parse(`${s}T00:00:00Z`);
  if (Number.isNaN(t)) throw new Error(`bad date ${s}`);
  return t / 1000 + (endOfDay ? 86399 : 0);
};
const iso = (t) => new Date(t * 1000).toISOString().replace(".000Z", "Z");

function period(flags, log) {
  if (flags.from || flags.to) {
    if (!flags.from || !flags.to) throw new Error("--from and --to go together");
    return [day(flags.from, false), day(flags.to, true)];
  }
  let ym = flags.period;
  if (!ym) ym = new Date(log.payments[0].timestamp * 1000).toISOString().slice(0, 7);
  const [y, m] = ym.split("-").map(Number);
  return [Date.UTC(y, m - 1, 1) / 1000, Date.UTC(y, m, 1) / 1000 - 1];
}

function loadSecret(path) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "0x" + randomBytes(31).toString("hex") + "\n", { mode: 0o600 });
    console.error(`created agent secret at ${path} (keep it: it lets you disclose single payments later)`);
  }
  return BigInt(readFileSync(path, "utf8").trim());
}

function cmdProve({ pos, flags }) {
  if (!pos[0] || !flags.vendors || flags.budget === undefined) throw new Error("prove needs <log.json> --vendors <file> --budget <usd>");
  const log = ingestLog(readJson(pos[0]));
  const vendors = ingestVendors(readJson(flags.vendors));
  const budgetStr = String(flags.budget);
  const budget = parseAmount(budgetStr.includes(".") ? budgetStr : `${budgetStr}.0`);
  const [periodStart, periodEnd] = period(flags, log);
  const secret = loadSecret(resolve(flags["secret-file"] ?? ".zkexpense/secret"));
  const out = flags.out ?? "proof.json";

  console.error(`zkexpense: proving ${log.payments.length} payments, ${iso(periodStart)} .. ${iso(periodEnd)}, budget ${usd(budget)}`);
  const t0 = performance.now();
  const pj = proveReport(log, vendors, {
    budget, periodStart, periodEnd, discloseTotal: Boolean(flags["disclose-total"]), secret,
    chainIn: flags.prev ? BigInt(readJson(flags.prev).report.chainOut) : 0n,
    circuit: flags.circuit, log: (m) => console.error(m),
  });
  pj.meta.timings.totalMs = Math.round(performance.now() - t0);
  writeFileSync(out, JSON.stringify(pj, null, 2));
  const r = pj.report;
  console.log(`wrote ${out}`);
  console.log(`  circuit       ${pj.circuit}`);
  console.log(`  payments      ${r.count}`);
  console.log(`  under budget  ${r.underBudget}${r.discloseTotal ? ` (total ${usd(r.disclosedTotal)})` : " (total hidden)"}`);
  console.log(`  log root      ${r.logRoot}`);
  console.log(`  vendor root   ${r.vendorRoot}`);
  console.log(`  proof         ${pj.meta.proofBytes} bytes, proved in ${(pj.meta.timings.proveMs / 1000).toFixed(2)}s`);
  if (!r.underBudget) process.exitCode = 3;
}

function cmdVerify({ pos, flags }) {
  if (!pos[0]) throw new Error("verify needs <proof.json>");
  const pj = readJson(pos[0]);
  const res = verifyProofJson(pj);
  const r = res.report;
  const checks = [
    ["proof valid (bb, UltraHonk)", res.ok],
    ["report matches public inputs", res.consistent],
    ["total within budget", r.underBudget],
  ];
  if (flags["vendor-root"]) checks.push(["vendor root is the approved set", BigInt(flags["vendor-root"]) === BigInt(r.vendorRoot)]);
  if (flags.payer) checks.push(["payer is the agent wallet", flags.payer.toLowerCase() === r.payer]);
  if (flags["max-budget"]) {
    const b = String(flags["max-budget"]);
    checks.push(["budget is the agreed one", r.budget <= parseAmount(b.includes(".") ? b : `${b}.0`)]);
  }
  console.log(`zkexpense report for ${pj.agentId ?? "agent"} (${pj.circuit})`);
  console.log(`  payer     ${r.payer} on chain ${r.chainId}, asset ${r.asset}`);
  console.log(`  period    ${iso(r.periodStart)} .. ${iso(r.periodEnd)}`);
  console.log(`  payments  ${r.count}`);
  console.log(`  budget    ${usd(r.budget)}${r.discloseTotal ? `, total ${usd(r.disclosedTotal)}` : ", total hidden"}`);
  console.log(`  log root  ${r.logRoot}`);
  console.log(`  vendors   ${r.vendorRoot}`);
  for (const [name, ok] of checks) console.log(`  [${ok ? "ok" : "FAIL"}] ${name}`);
  console.log(`  verified in ${res.ms.toFixed(1)} ms`);
  if (!checks.every(([, ok]) => ok)) process.exitCode = 1;
}

function cmdVendorRoot({ pos }) {
  const v = ingestVendors(readJson(pos[0]));
  console.log(toHex(vendorRoot(v)));
}

function cmdInspect({ pos }) {
  const log = ingestLog(readJson(pos[0]));
  const total = log.payments.reduce((s, p) => s + p.amount, 0n);
  const payees = new Set(log.payments.map((p) => p.payTo));
  console.log(JSON.stringify({
    agentId: log.agentId, payer: log.payer, asset: log.asset, chainId: log.chainId,
    payments: log.payments.length, distinctPayees: payees.size, total: usd(total),
    first: iso(log.payments[0].timestamp), last: iso(log.payments.at(-1).timestamp),
  }, null, 2));
}

function cmdSample({ flags }) {
  const args = [resolve(ROOT, "scripts/gen-sample.mjs")];
  for (const [k, v] of Object.entries(flags)) args.push(`--${k}`, String(v));
  spawnSync(process.execPath, args, { stdio: "inherit" });
}

const { pos, flags } = parseArgs(process.argv.slice(2));
const cmd = pos.shift();
const table = { prove: cmdProve, verify: cmdVerify, "vendor-root": cmdVendorRoot, inspect: cmdInspect, sample: cmdSample };
try {
  if (!table[cmd]) { console.log(USAGE); process.exit(cmd ? 2 : 0); }
  table[cmd]({ pos, flags });
} catch (e) {
  console.error(e instanceof PolicyViolation ? e.message : `error: ${e.message}`);
  process.exit(e instanceof PolicyViolation ? 4 : 1);
}

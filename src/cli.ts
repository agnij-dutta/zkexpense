#!/usr/bin/env node
// zkexpense CLI: one zero-knowledge proof for a month of agent payments.
// Thin layer over the library in src/lib; every command reads and writes plain JSON files.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { toHex } from "./lib/hash.js";
import { ingestLog, ingestVendors, parseUsd, vendorRoot } from "./lib/model.js";
import { PolicyViolation, proveReport } from "./lib/report.js";
import { verifyProofJson, type VerifyEngine } from "./lib/verify.js";
import { checkDisclosure, disclose } from "./lib/disclose.js";
import { generateSample } from "./lib/sample.js";
import type { Disclosure, PaymentLog, ProofJson } from "./lib/types.js";

const USAGE = `zkexpense: verifiable expense reports for AI agents

usage:
  zkexpense prove <log.json> --vendors <vendors.json> --budget <usd> [options]
      --period YYYY-MM          reporting period (default: month of the first payment)
      --from YYYY-MM-DD --to YYYY-MM-DD   explicit period (UTC, inclusive)
      --disclose-total          reveal the exact total (default: only total <= budget)
      --out <proof.json>        output file (default: proof.json)
      --circuit <name>          force batch_64 | batch_256 | batch_512 | batch_1024 | agg_64x2 | agg_1024x4
      --prev <proof.json>       previous period's proof; chains this report onto it
      --secret-file <path>      agent secret for salts/blinding (default: .zkexpense/secret, created)
  zkexpense verify <proof.json> [--vendor-root 0x..] [--payer 0x..] [--max-budget <usd>] [--engine auto|js|cli]
  zkexpense disclose <log.json> --proof <proof.json> (--tx <hash> | --index <n>) [--out disclosure.json]
      open ONE payment (preimage + Merkle path to the log root), nothing else
  zkexpense check-disclosure <disclosure.json> --proof <proof.json>
  zkexpense vendor-root <vendors.json>
  zkexpense inspect <log.json>
  zkexpense sample --count <n> [--out examples] [--seed 42] [--month YYYY-MM] [--rogue <n>]
`;

/** Exit codes, documented in the README. */
const EXIT = { ok: 0, failed: 1, usage: 2, overBudget: 3, policyViolation: 4 } as const;

type Flags = Record<string, string | true>;
interface Args {
  pos: string[];
  flags: Flags;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): Args {
  const pos: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) flags[key] = argv[++i];
      else flags[key] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}

/** A flag that must carry a value (`--out x`, not a bare `--out`). */
function str(flags: Flags, key: string): string | undefined {
  const v = flags[key];
  if (v === true) throw new UsageError(`--${key} needs a value`);
  return v;
}

function readJson(path: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(`cannot read ${path}: ${(e as Error).message}`, { cause: e });
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${path} is not valid JSON: ${(e as Error).message}`, { cause: e });
  }
}

const readProof = (path: string): ProofJson => readJson(path) as ProofJson;
const usd = (atomic: bigint | string): string => `$${(Number(atomic) / 1e6).toFixed(2)}`;
const iso = (t: number): string => new Date(t * 1000).toISOString().replace(".000Z", "Z");

function day(s: string, endOfDay: boolean): number {
  const t = Date.parse(`${s}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s) || Number.isNaN(t)) throw new UsageError(`bad date "${s}" (expected YYYY-MM-DD)`);
  return t / 1000 + (endOfDay ? 86399 : 0);
}

/** Reporting period [start, end], inclusive, in unix seconds. */
function period(flags: Flags, log: PaymentLog): [number, number] {
  const from = str(flags, "from");
  const to = str(flags, "to");
  if (from || to) {
    if (!from || !to) throw new UsageError("--from and --to go together");
    return [day(from, false), day(to, true)];
  }
  const ym = str(flags, "period") ?? new Date(log.payments[0].timestamp * 1000).toISOString().slice(0, 7);
  const m = /^(\d{4})-(\d{2})$/.exec(ym);
  if (!m) throw new UsageError(`bad --period "${ym}" (expected YYYY-MM)`);
  const [y, mo] = [Number(m[1]), Number(m[2])];
  return [Date.UTC(y, mo - 1, 1) / 1000, Date.UTC(y, mo, 1) / 1000 - 1];
}

/** Load the agent secret, creating it (mode 0600) on first use. */
function loadSecret(path: string): bigint {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "0x" + randomBytes(31).toString("hex") + "\n", { mode: 0o600 });
    console.error(`created agent secret at ${path} (keep it: it lets you disclose single payments later)`);
  }
  const text = readFileSync(path, "utf8").trim();
  if (!/^0x[0-9a-fA-F]+$/.test(text)) throw new Error(`${path} does not contain a 0x hex secret`);
  return BigInt(text);
}

const secretPath = (flags: Flags): string => resolve(str(flags, "secret-file") ?? ".zkexpense/secret");

function cmdProve({ pos, flags }: Args): void {
  const vendorsPath = str(flags, "vendors");
  const budgetStr = str(flags, "budget");
  if (!pos[0] || !vendorsPath || budgetStr === undefined) {
    throw new UsageError("prove needs <log.json> --vendors <file> --budget <usd>");
  }
  const log = ingestLog(readJson(pos[0]));
  const vendors = ingestVendors(readJson(vendorsPath));
  const budget = parseUsd(budgetStr);
  const [periodStart, periodEnd] = period(flags, log);
  const secret = loadSecret(secretPath(flags));
  const out = str(flags, "out") ?? "proof.json";
  const prev = str(flags, "prev");

  console.error(
    `zkexpense: proving ${log.payments.length} payments, ${iso(periodStart)} .. ${iso(periodEnd)}, budget ${usd(budget)}`,
  );
  const t0 = performance.now();
  const pj = proveReport(log, vendors, {
    budget,
    periodStart,
    periodEnd,
    discloseTotal: flags["disclose-total"] === true,
    secret,
    chainIn: prev ? BigInt(readProof(prev).report.chainOut) : 0n,
    circuit: str(flags, "circuit"),
    log: (msg) => {
      console.error(msg);
    },
  });
  pj.meta.timings.totalMs = Math.round(performance.now() - t0);
  writeFileSync(out, JSON.stringify(pj, null, 2) + "\n");
  const r = pj.report;
  console.log(`wrote ${out}`);
  console.log(`  circuit       ${pj.circuit}`);
  console.log(`  payments      ${r.count}`);
  console.log(
    `  under budget  ${r.underBudget}${r.discloseTotal ? ` (total ${usd(r.disclosedTotal)})` : " (total hidden)"}`,
  );
  console.log(`  log root      ${r.logRoot}`);
  console.log(`  vendor root   ${r.vendorRoot}`);
  console.log(`  proof         ${pj.meta.proofBytes} bytes, proved in ${(pj.meta.timings.proveMs / 1000).toFixed(2)}s`);
  if (!r.underBudget) process.exitCode = EXIT.overBudget;
}

async function cmdVerify({ pos, flags }: Args): Promise<void> {
  if (!pos[0]) throw new UsageError("verify needs <proof.json>");
  const engine = (str(flags, "engine") ?? "auto") as VerifyEngine;
  if (!["auto", "js", "cli"].includes(engine)) throw new UsageError(`--engine must be auto, js or cli`);
  const pj = readProof(pos[0]);
  const res = await verifyProofJson(pj, { engine });
  const r = res.report;
  const checks: Array<[string, boolean]> = [
    ["proof valid (bb, UltraHonk)", res.ok],
    ["report matches public inputs", res.consistent],
    ["total within budget", r.underBudget],
  ];
  const root = str(flags, "vendor-root");
  if (root) {
    if (!/^0x[0-9a-fA-F]+$/.test(root)) throw new UsageError(`--vendor-root must be 0x hex`);
    checks.push(["vendor root is the approved set", BigInt(root) === BigInt(r.vendorRoot)]);
  }
  const payer = str(flags, "payer");
  if (payer) checks.push(["payer is the agent wallet", payer.toLowerCase() === r.payer]);
  const maxBudget = str(flags, "max-budget");
  if (maxBudget) checks.push(["budget is within the agreed cap", r.budget <= parseUsd(maxBudget)]);

  console.log(`zkexpense report for ${pj.agentId ?? "agent"} (${pj.circuit})`);
  console.log(`  payer     ${r.payer} on chain ${r.chainId}, asset ${r.asset}`);
  console.log(`  period    ${iso(r.periodStart)} .. ${iso(r.periodEnd)}`);
  console.log(`  payments  ${r.count}`);
  console.log(`  budget    ${usd(r.budget)}${r.discloseTotal ? `, total ${usd(r.disclosedTotal)}` : ", total hidden"}`);
  console.log(`  log root  ${r.logRoot}`);
  console.log(`  vendors   ${r.vendorRoot}`);
  for (const [name, ok] of checks) console.log(`  [${ok ? "ok" : "FAIL"}] ${name}`);
  console.log(`  verified in ${res.ms.toFixed(1)} ms [${res.engine}]`);
  if (!checks.every(([, ok]) => ok)) process.exitCode = EXIT.failed;
}

function cmdDisclose({ pos, flags }: Args): void {
  const proofPath = str(flags, "proof");
  const tx = str(flags, "tx");
  const index = str(flags, "index");
  if (!pos[0] || !proofPath || (tx === undefined) === (index === undefined)) {
    throw new UsageError("disclose needs <log.json> --proof <proof.json> and exactly one of --tx <hash> | --index <n>");
  }
  if (index !== undefined && !/^\d+$/.test(index)) throw new UsageError("--index must be a non-negative integer");
  const log = ingestLog(readJson(pos[0]));
  const secret = loadSecret(secretPath(flags));
  const d = disclose(log, readProof(proofPath), secret, tx ?? Number(index));
  const out = str(flags, "out") ?? "disclosure.json";
  writeFileSync(out, JSON.stringify(d, null, 2) + "\n");
  console.log(`wrote ${out}: payment #${d.index}, ${usd(d.payment.amount)} to ${d.payment.payTo}`);
}

async function cmdCheckDisclosure({ pos, flags }: Args): Promise<void> {
  const proofPath = str(flags, "proof");
  if (!pos[0] || !proofPath) throw new UsageError("check-disclosure needs <disclosure.json> --proof <proof.json>");
  const pj = readProof(proofPath);
  const d = readJson(pos[0]) as Disclosure;
  const proofOk = (await verifyProofJson(pj)).ok;
  const pathOk = checkDisclosure(d, pj);
  console.log(`  [${proofOk ? "ok" : "FAIL"}] report proof valid`);
  console.log(`  [${pathOk ? "ok" : "FAIL"}] payment ${d.payment.transaction} is leaf #${d.index} of the proven log`);
  console.log(`  ${usd(d.payment.amount)} to ${d.payment.payTo} at ${iso(d.payment.timestamp)}`);
  if (!proofOk || !pathOk) process.exitCode = EXIT.failed;
}

function cmdVendorRoot({ pos }: Args): void {
  if (!pos[0]) throw new UsageError("vendor-root needs <vendors.json>");
  console.log(toHex(vendorRoot(ingestVendors(readJson(pos[0])))));
}

function cmdInspect({ pos }: Args): void {
  if (!pos[0]) throw new UsageError("inspect needs <log.json>");
  const log = ingestLog(readJson(pos[0]));
  const total = log.payments.reduce((s, p) => s + p.amount, 0n);
  const summary = {
    agentId: log.agentId,
    payer: log.payer,
    asset: log.asset,
    chainId: log.chainId,
    payments: log.payments.length,
    distinctPayees: new Set(log.payments.map((p) => p.payTo)).size,
    total: usd(total),
    first: iso(log.payments[0].timestamp),
    last: iso(log.payments[log.payments.length - 1].timestamp),
  };
  console.log(JSON.stringify(summary, null, 2));
}

function intFlag(flags: Flags, key: string, fallback: number): number {
  const v = str(flags, key);
  if (v === undefined) return fallback;
  if (!/^\d+$/.test(v)) throw new UsageError(`--${key} must be a non-negative integer`);
  return Number(v);
}

function cmdSample({ flags }: Args): void {
  const count = intFlag(flags, "count", 347);
  const outDir = str(flags, "out") ?? "examples";
  const { log, vendors } = generateSample({
    count,
    month: str(flags, "month"),
    seed: intFlag(flags, "seed", 42),
    rogue: intFlag(flags, "rogue", 0),
  });
  mkdirSync(outDir, { recursive: true });
  const logPath = join(outDir, `log-${count}.json`);
  const vendorsPath = join(outDir, "vendors.json");
  writeFileSync(logPath, JSON.stringify(log, null, 2) + "\n");
  writeFileSync(vendorsPath, JSON.stringify(vendors, null, 2) + "\n");
  const total = log.payments.reduce((s, p) => s + BigInt(p.amount), 0n);
  console.log(`wrote ${logPath}: ${count} payments, ${usd(total)} total, period ${log.period} (synthetic data)`);
  console.log(`wrote ${vendorsPath}: ${vendors.vendors.length} approved vendors`);
}

const COMMANDS: Partial<Record<string, (args: Args) => void | Promise<void>>> = {
  prove: cmdProve,
  verify: cmdVerify,
  disclose: cmdDisclose,
  "check-disclosure": cmdCheckDisclosure,
  "vendor-root": cmdVendorRoot,
  inspect: cmdInspect,
  sample: cmdSample,
};

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args.pos.shift();
  if (cmd === undefined || cmd === "help" || args.flags.help === true) {
    console.log(USAGE);
    return;
  }
  const run = COMMANDS[cmd];
  if (!run) {
    console.error(`unknown command "${cmd}"\n\n${USAGE}`);
    process.exitCode = EXIT.usage;
    return;
  }
  try {
    await run(args);
  } catch (e) {
    if (e instanceof PolicyViolation) {
      console.error(e.message);
      process.exitCode = EXIT.policyViolation;
    } else if (e instanceof UsageError) {
      console.error(`usage error: ${e.message}\n\n${USAGE}`);
      process.exitCode = EXIT.usage;
    } else {
      console.error(`error: ${(e as Error).message}`);
      process.exitCode = EXIT.failed;
    }
  }
}

await main();

#!/usr/bin/env node
// Generates the real proofs used by the Foundry tests (contracts/test/fixtures/*.json) and the
// sample logs they are proven from (examples/fixtures/). Run `npm run build` first.
// usage: node scripts/fixtures.mjs [--no-agg]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT, generateSample, ingestLog, ingestVendors, proveReport } from "../dist/index.js";

const OUT = join(ROOT, "contracts/test/fixtures");
const DATA = join(ROOT, "examples/fixtures");
mkdirSync(OUT, { recursive: true });
mkdirSync(DATA, { recursive: true });

/** Synthetic log for one month, written to examples/fixtures/log-<tag>.json (seed 7 = one shared vendor set). */
function gen(count, month, tag) {
  const { log, vendors } = generateSample({ count, month, seed: 7 });
  writeFileSync(join(DATA, `log-${tag}.json`), JSON.stringify(log, null, 2) + "\n");
  writeFileSync(join(DATA, "vendors.json"), JSON.stringify(vendors, null, 2) + "\n");
  return ingestLog(log);
}

const month = (y, m) => [Date.UTC(y, m - 1, 1) / 1000, Date.UTC(y, m, 1) / 1000 - 1];
const usd = (x) => BigInt(Math.round(x * 1e6));
const SECRET = 0x5eed5eed5eedn; // also used by test/disclose.test.mjs
const write = (name, pj) => {
  writeFileSync(join(OUT, `${name}.json`), JSON.stringify(pj, null, 2) + "\n");
  console.log(`${name}: ${pj.circuit}, ${pj.report.count} payments, prove ${pj.meta.timings.proveMs} ms`);
};

const sep = gen(50, "2026-09", "sep");
const oct = gen(60, "2026-10", "oct");
const big = gen(120, "2026-09", "sep-120");
const vendors = ingestVendors(JSON.parse(readFileSync(join(DATA, "vendors.json"), "utf8")));
const [s0, s1] = month(2026, 9);
const [o0, o1] = month(2026, 10);
const base = { budget: usd(25), discloseTotal: false, secret: SECRET };

const pSep = proveReport(sep, vendors, { ...base, periodStart: s0, periodEnd: s1 });
write("sep", pSep);
write(
  "oct",
  proveReport(oct, vendors, { ...base, periodStart: o0, periodEnd: o1, chainIn: BigInt(pSep.report.chainOut) }),
);
write("sep_over_budget", proveReport(sep, vendors, { ...base, budget: usd(1), periodStart: s0, periodEnd: s1 }));
write("sep_disclosed", proveReport(sep, vendors, { ...base, discloseTotal: true, periodStart: s0, periodEnd: s1 }));
if (!process.argv.includes("--no-agg")) {
  write("sep_agg", proveReport(big, vendors, { ...base, periodStart: s0, periodEnd: s1, circuit: "agg_64x2" }));
}

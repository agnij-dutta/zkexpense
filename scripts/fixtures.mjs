#!/usr/bin/env node
// Generates real proofs used by the Foundry tests (contracts/test/fixtures/*.json).
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../cli/lib/prover.mjs";
import { ingestLog, ingestVendors } from "../cli/lib/model.mjs";
import { proveReport } from "../cli/lib/report.mjs";

const OUT = join(ROOT, "contracts/test/fixtures");
const DATA = join(ROOT, "examples/fixtures");
mkdirSync(OUT, { recursive: true });
mkdirSync(DATA, { recursive: true });

const gen = (count, month, tag) => {
  execFileSync(process.execPath, [join(ROOT, "scripts/gen-sample.mjs"), "--count", String(count), "--month", month, "--out", DATA, "--seed", "7"]);
  const f = join(DATA, `log-${tag}.json`);
  execFileSync("mv", [join(DATA, `log-${count}.json`), f]);
  return ingestLog(JSON.parse(readFileSync(f, "utf8")));
};
const vendors = () => ingestVendors(JSON.parse(readFileSync(join(DATA, "vendors.json"), "utf8")));
const month = (y, m) => [Date.UTC(y, m - 1, 1) / 1000, Date.UTC(y, m, 1) / 1000 - 1];
const SECRET = 0x5eed5eed5eedn;
const write = (name, pj) => {
  writeFileSync(join(OUT, `${name}.json`), JSON.stringify(pj, null, 2));
  console.log(`${name}: ${pj.circuit}, ${pj.report.count} payments, prove ${pj.meta.timings.proveMs} ms`);
};

const sep = gen(50, "2026-09", "sep");
const oct = gen(60, "2026-10", "oct");
const big = gen(120, "2026-09", "sep-120");
const v = vendors();
const [s0, s1] = month(2026, 9);
const [o0, o1] = month(2026, 10);
const usd = (x) => BigInt(Math.round(x * 1e6));

const pSep = proveReport(sep, v, { budget: usd(25), periodStart: s0, periodEnd: s1, discloseTotal: false, secret: SECRET });
write("sep", pSep);
write("oct", proveReport(oct, v, { budget: usd(25), periodStart: o0, periodEnd: o1, discloseTotal: false, secret: SECRET, chainIn: BigInt(pSep.report.chainOut) }));
write("sep_over_budget", proveReport(sep, v, { budget: usd(1), periodStart: s0, periodEnd: s1, discloseTotal: false, secret: SECRET }));
write("sep_disclosed", proveReport(sep, v, { budget: usd(25), periodStart: s0, periodEnd: s1, discloseTotal: true, secret: SECRET }));
if (!process.argv.includes("--no-agg")) {
  write("sep_agg", proveReport(big, v, { budget: usd(25), periodStart: s0, periodEnd: s1, discloseTotal: false, secret: SECRET, circuit: "agg_64x2" }));
}

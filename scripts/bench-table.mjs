#!/usr/bin/env node
// Renders bench/results.json as the markdown table used in BENCHMARKS.md.
import { readFileSync } from "node:fs";
const { env, cases } = JSON.parse(readFileSync(new URL("../bench/results.json", import.meta.url), "utf8"));
const s = (ms) => (ms / 1000).toFixed(2) + " s";
const k = (n) => (n >= 1e6 ? (n / 1e6).toFixed(2) + "M" : Math.round(n / 1e3) + "k");
const order = ["n64", "n256", "n347", "n512", "n1024", "n4096"].filter((x) => cases[x]);
console.log(
  `| payments | circuit | gates | prove (best) | prove (all runs) | peak RAM | proof | verify (median / min) | verify gas | submitReport gas |`,
);
console.log(`|---:|---|---:|---:|---|---:|---:|---:|---:|---:|`);
for (const id of order) {
  const c = cases[id];
  console.log(
    `| ${c.payments} | \`${c.circuit}\` | ${k(c.gates)} | ${s(c.proveMsBest)} | ${c.proveMsAll.map(s).join(", ")} | ${c.peakRssMb ?? "?"} MB | ${c.proofBytes} B | ${c.verifyMsMedian} / ${c.verifyMsMin} ms | ${c.verifyGas?.toLocaleString("en-US") ?? "?"} | ${c.submitReportGas?.toLocaleString("en-US") ?? "?"} |`,
  );
}
console.log(
  `\nEnvironment: ${env.cpu}, ${env.cores} cores, ${env.memGb} GB, ${env.nargo}, bb ${env.bb}, load average at end ${env.loadAvgAtEnd.join(" / ")}.`,
);

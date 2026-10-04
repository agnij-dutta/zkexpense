#!/usr/bin/env node
// Generates a realistic month of x402 micropayments from one agent wallet, plus a vendor set.
// usage: node scripts/gen-sample.mjs --count 347 [--out examples] [--seed 42] [--month 2026-09] [--rogue 0]
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => (a.startsWith("--") ? [...acc, [a.slice(2), arr[i + 1]]] : acc), []),
);
const count = Number(args.count ?? 347);
const outDir = args.out ?? "examples";
const month = args.month ?? "2026-09";
const rogue = Number(args.rogue ?? 0); // payments to a vendor NOT in the approved set
let seed = BigInt(args.seed ?? 42);

// Deterministic PRNG (sha256 counter mode) so sample logs are reproducible.
let ctr = 0n;
function rand() {
  const h = createHash("sha256").update(`${seed}:${ctr++}`).digest();
  return h.readUInt32BE(0) / 2 ** 32;
}
const hex = (bytes) => "0x" + createHash("sha256").update(`${seed}:hex:${ctr++}`).digest("hex").slice(0, bytes * 2);

// Typical x402 API sellers an autonomous research agent pays per call.
const VENDORS = [
  ["weather-api", 0.001, 0.01], ["llm-inference", 0.02, 0.4], ["web-search", 0.002, 0.02],
  ["news-feed", 0.005, 0.05], ["geo-coder", 0.001, 0.005], ["pdf-extract", 0.01, 0.15],
  ["price-oracle", 0.0005, 0.003], ["image-gen", 0.04, 0.5], ["vector-db", 0.001, 0.02],
  ["scraper-proxy", 0.003, 0.03], ["translation", 0.002, 0.06], ["sec-filings", 0.05, 0.25],
].map(([name, lo, hi]) => ({ name, address: hex(20), lo, hi, weight: 0.3 + rand() }));

const vendorSalt = hex(31);
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const payer = hex(20);
const [y, m] = month.split("-").map(Number);
const start = Date.UTC(y, m - 1, 1) / 1000;
const end = Date.UTC(y, m, 1) / 1000 - 1;

const totalW = VENDORS.reduce((s, v) => s + v.weight, 0);
function pickVendor() {
  let r = rand() * totalW;
  for (const v of VENDORS) if ((r -= v.weight) <= 0) return v;
  return VENDORS[VENDORS.length - 1];
}

const payments = [];
for (let i = 0; i < count; i++) {
  const v = pickVendor();
  const usd = v.lo + (v.hi - v.lo) * rand() ** 2; // skewed toward cheap calls
  const atomic = Math.max(1, Math.round(usd * 1e6));
  payments.push({
    transaction: hex(32), payer, payTo: v.address, amount: String(atomic),
    asset: USDC_BASE, network: "base", timestamp: start + Math.floor(rand() * (end - start)),
    resource: `https://${v.name}.example/x402`,
  });
}
for (let i = 0; i < rogue; i++) {
  payments[Math.floor(rand() * payments.length)].payTo = hex(20);
}
payments.sort((a, b) => a.timestamp - b.timestamp);

mkdirSync(outDir, { recursive: true });
const tag = `${count}`;
const log = { agentId: "agent:research-bot-7", period: month, payments };
const vendors = { name: "approved-vendors-2026Q3", salt: vendorSalt, vendors: VENDORS.map(({ name, address }) => ({ name, address })) };
writeFileSync(join(outDir, `log-${tag}.json`), JSON.stringify(log, null, 2));
writeFileSync(join(outDir, `vendors.json`), JSON.stringify(vendors, null, 2));
const total = payments.reduce((s, p) => s + Number(p.amount), 0) / 1e6;
console.log(`wrote ${join(outDir, `log-${tag}.json`)}: ${count} payments, $${total.toFixed(2)} total, period ${month}`);
console.log(`wrote ${join(outDir, "vendors.json")}: ${VENDORS.length} approved vendors`);

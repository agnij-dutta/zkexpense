// Deterministic sample data: a month of x402 micropayments from one agent wallet to typical
// pay-per-call API vendors. The data is SYNTHETIC (random addresses and tx hashes); it exists
// so the prover and benchmarks can run without a real agent.
import { createHash } from "node:crypto";

export interface SampleOptions {
  count: number;
  /** Reporting month, "YYYY-MM". */
  month?: string;
  seed?: number | bigint;
  /** Number of payments redirected to a vendor that is NOT in the approved set. */
  rogue?: number;
}

export interface SampleVendor {
  name: string;
  address: string;
}

export interface SampleData {
  log: {
    agentId: string;
    period: string;
    payments: Array<{
      transaction: string;
      payer: string;
      payTo: string;
      amount: string;
      asset: string;
      network: string;
      timestamp: number;
      resource: string;
    }>;
  };
  vendors: { name: string; salt: string; vendors: SampleVendor[] };
}

/** USDC on Base mainnet. */
export const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

// [name, min USD, max USD] per call
const VENDOR_PROFILES: Array<[string, number, number]> = [
  ["weather-api", 0.001, 0.01],
  ["llm-inference", 0.02, 0.4],
  ["web-search", 0.002, 0.02],
  ["news-feed", 0.005, 0.05],
  ["geo-coder", 0.001, 0.005],
  ["pdf-extract", 0.01, 0.15],
  ["price-oracle", 0.0005, 0.003],
  ["image-gen", 0.04, 0.5],
  ["vector-db", 0.001, 0.02],
  ["scraper-proxy", 0.003, 0.03],
  ["translation", 0.002, 0.06],
  ["sec-filings", 0.05, 0.25],
];

/** Generate a reproducible sample log and vendor set. Same seed gives the same payer and vendors. */
export function generateSample({ count, month = "2026-09", seed = 42, rogue = 0 }: SampleOptions): SampleData {
  if (!Number.isInteger(count) || count < 1) throw new Error(`--count must be a positive integer, got ${count}`);
  const ym = /^(\d{4})-(\d{2})$/.exec(month);
  if (!ym) throw new Error(`--month must be YYYY-MM, got ${month}`);
  const seedTag = BigInt(seed).toString();

  // sha256 counter-mode PRNG. The call order below is part of the output format: changing it
  // changes every generated address, which would invalidate the committed test fixtures.
  let counter = 0n;
  const rand = (): number => createHash("sha256").update(`${seedTag}:${counter++}`).digest().readUInt32BE(0) / 2 ** 32;
  const hex = (bytes: number): string =>
    "0x" +
    createHash("sha256")
      .update(`${seedTag}:hex:${counter++}`)
      .digest("hex")
      .slice(0, bytes * 2);

  const vendors = VENDOR_PROFILES.map(([name, lo, hi]) => {
    const address = hex(20);
    return { name, address, lo, hi, weight: 0.3 + rand() };
  });
  const vendorSalt = hex(31);
  const payer = hex(20);
  const start = Date.UTC(Number(ym[1]), Number(ym[2]) - 1, 1) / 1000;
  const end = Date.UTC(Number(ym[1]), Number(ym[2]), 1) / 1000 - 1;

  const totalWeight = vendors.reduce((s, v) => s + v.weight, 0);
  const pickVendor = () => {
    let r = rand() * totalWeight;
    for (const v of vendors) if ((r -= v.weight) <= 0) return v;
    return vendors[vendors.length - 1];
  };

  const payments: SampleData["log"]["payments"] = [];
  for (let i = 0; i < count; i++) {
    const v = pickVendor();
    const usd = v.lo + (v.hi - v.lo) * rand() ** 2; // skewed toward cheap calls
    payments.push({
      transaction: hex(32),
      payer,
      payTo: v.address,
      amount: String(Math.max(1, Math.round(usd * 1e6))),
      asset: USDC_BASE,
      network: "base",
      timestamp: start + Math.floor(rand() * (end - start)),
      resource: `https://${v.name}.example/x402`,
    });
  }
  for (let i = 0; i < rogue; i++) payments[Math.floor(rand() * payments.length)].payTo = hex(20);
  payments.sort((a, b) => a.timestamp - b.timestamp);

  return {
    log: { agentId: "agent:research-bot-7", period: month, payments },
    vendors: {
      name: "approved-vendors-2026Q3",
      salt: vendorSalt,
      vendors: vendors.map(({ name, address }) => ({ name, address })),
    },
  };
}

// Payment-log data model. Input rows mirror x402 settlement data:
//   flat:  { transaction, payer, payTo, amount, asset, network, timestamp }
//   raw:   { paymentRequirements, settleResponse, timestamp }   (what an x402 client sees)
// x402 spec: https://github.com/coinbase/x402
import { hash, merkleRoot } from "./hash.js";
import type { Payment, PaymentLog, Policy, VendorSet } from "./types.js";

/** Vendor table size. Must match `global V` in circuits/lib/src/lib.nr. */
export const V = 256;

/** x402 network names -> EVM chain id. CAIP-2 `eip155:<id>` is also accepted. */
const NETWORKS: Partial<Record<string, number>> = {
  base: 8453,
  "base-sepolia": 84532,
  ethereum: 1,
  mainnet: 1,
  sepolia: 11155111,
  avalanche: 43114,
  "avalanche-fuji": 43113,
  polygon: 137,
  "polygon-amoy": 80002,
  optimism: 10,
  arbitrum: 42161,
  iotex: 4689,
  sei: 1329,
  "sei-testnet": 1328,
};

/** Resolve an x402 network name, CAIP-2 id or numeric chain id to an EVM chain id. */
export function chainIdOf(network: unknown): number {
  if (typeof network === "number" && Number.isInteger(network) && network > 0) return network;
  const n = String(network).toLowerCase();
  if (n.startsWith("eip155:")) {
    const id = Number(n.slice(7));
    if (Number.isInteger(id) && id > 0) return id;
  } else {
    const id = NETWORKS[n];
    if (id !== undefined) return id;
  }
  throw new Error(`unknown network "${String(network)}" (use an EVM x402 network name or eip155:<chainId>)`);
}

const isAddr = (a: unknown): a is string => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
const isTx = (t: unknown): t is string => typeof t === "string" && /^0x[0-9a-fA-F]{64}$/.test(t);
const isObject = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;

/** Split a 32-byte tx hash into two 128-bit field elements (high, low). */
export function splitTx(tx: string): [bigint, bigint] {
  const h = tx.slice(2);
  return [BigInt("0x" + h.slice(0, 32)), BigInt("0x" + h.slice(32))];
}

/**
 * Parse an amount: integer atomic units ("1500", 1500) or a decimal with an optional
 * "$" prefix or " USDC" suffix ("$1.25", "0.000001 USDC") scaled by `decimals`.
 */
export function parseAmount(a: unknown, decimals = 6): bigint {
  if (typeof a === "number" && Number.isSafeInteger(a) && a >= 0) return BigInt(a);
  const s = String(a)
    .trim()
    .replace(/^\$/, "")
    .replace(/\s*usdc$/i, "");
  if (/^\d+$/.test(s)) return BigInt(s);
  const m = s.match(/^(\d+)\.(\d+)$/);
  if (!m) throw new Error(`bad amount "${String(a)}" (expected atomic units like "1500" or a decimal like "1.25")`);
  if (m[2].length > decimals) throw new Error(`amount "${String(a)}" has more than ${decimals} decimals`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(m[2].padEnd(decimals, "0"));
}

/** Parse a dollar budget like "500" or "12.5" into atomic units (whole numbers mean dollars here). */
export function parseUsd(x: string | number): bigint {
  const s = String(x);
  return parseAmount(s.includes(".") ? s : `${s}.0`);
}

/**
 * Flatten a raw x402 `{ paymentRequirements, settleResponse, timestamp }` record into a flat row.
 * Flat rows pass through unchanged. A settlement with `success: false` is an error, not a payment.
 */
export function flattenX402(r: Record<string, unknown>): Record<string, unknown> {
  const req = (r.paymentRequirements ?? r.requirements) as Record<string, unknown> | undefined;
  const set = (r.settleResponse ?? r.settlement) as Record<string, unknown> | undefined;
  if (!req && !set) return r;
  if (set && set.success === false) {
    const reason = typeof set.errorReason === "string" ? set.errorReason : "success=false";
    throw new Error(`unsettled payment in log (${reason})`);
  }
  return {
    transaction: set?.transaction,
    payer: set?.payer,
    payTo: req?.payTo,
    amount: r.amount ?? req?.amount ?? req?.maxAmountRequired,
    asset: req?.asset,
    network: set?.network ?? req?.network,
    timestamp: r.timestamp ?? set?.timestamp,
  };
}

/**
 * Validate and normalize a JSON log (an array of rows or `{ agentId, payments }`).
 * Rejects malformed rows, duplicate settlement txs, and mixed payer / asset / chain.
 * Returns payments sorted by (timestamp, tx hash), the order the circuit requires.
 */
export function ingestLog(raw: unknown): PaymentLog {
  const rows: unknown = Array.isArray(raw) ? raw : isObject(raw) ? raw.payments : undefined;
  if (!Array.isArray(rows) || rows.length === 0) throw new Error("log has no payments");
  const seen = new Set<string>();
  const payments: Payment[] = rows.map((row0: unknown, i: number) => {
    const where = `payment #${i}`;
    if (!isObject(row0)) throw new Error(`${where}: not an object`);
    const r = flattenX402(row0);
    const tx = r.transaction ?? r.txHash ?? r.tx;
    if (!isTx(tx)) throw new Error(`${where}: transaction must be a 32-byte 0x hex hash`);
    if (!isAddr(r.payer)) throw new Error(`${where}: payer must be a 20-byte 0x address`);
    if (!isAddr(r.payTo)) throw new Error(`${where}: payTo must be a 20-byte 0x address`);
    if (!isAddr(r.asset)) throw new Error(`${where}: asset must be a 20-byte 0x address`);
    const key = tx.toLowerCase();
    if (seen.has(key)) throw new Error(`${where}: duplicate settlement tx ${tx}`);
    seen.add(key);
    const amount = parseAmount(r.amount);
    if (amount >= 2n ** 64n) throw new Error(`${where}: amount exceeds u64`);
    const timestamp = Number(r.timestamp);
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error(`${where}: timestamp must be unix seconds`);
    return {
      transaction: key,
      payer: r.payer.toLowerCase(),
      payTo: r.payTo.toLowerCase(),
      amount,
      asset: r.asset.toLowerCase(),
      chainId: chainIdOf(r.network),
      timestamp,
    };
  });
  const { payer, asset, chainId } = payments[0];
  payments.forEach((p, i) => {
    if (p.payer !== payer) throw new Error(`payment #${i}: payer differs; one report covers one agent wallet`);
    if (p.asset !== asset) throw new Error(`payment #${i}: asset differs; one report covers one asset`);
    if (p.chainId !== chainId) throw new Error(`payment #${i}: network differs; one report covers one chain`);
  });
  payments.sort((a, b) => a.timestamp - b.timestamp || (a.transaction < b.transaction ? -1 : 1));
  const agentId = isObject(raw) && !Array.isArray(raw) && typeof raw.agentId === "string" ? raw.agentId : null;
  return { agentId, payer, asset, chainId, payments };
}

/** Validate a vendors file: `{ salt, vendors: ["0x..", { name, address }] }`. */
export function ingestVendors(raw: unknown): VendorSet {
  const list: unknown = Array.isArray(raw) ? raw : isObject(raw) ? raw.vendors : undefined;
  if (!Array.isArray(list)) throw new Error("vendors file needs a 'vendors' array");
  const addrs = list.map((v: unknown) => (isObject(v) ? v.address : v));
  if (addrs.length > V) throw new Error(`at most ${V} vendors per set, got ${addrs.length}`);
  for (const a of addrs) if (!isAddr(a)) throw new Error(`bad vendor address ${String(a)}`);
  const salt = isObject(raw) && !Array.isArray(raw) ? raw.salt : undefined;
  if (typeof salt !== "string" || !/^0x[0-9a-fA-F]+$/.test(salt)) {
    throw new Error(
      "vendors file needs a hex 'salt' so the published vendor root is stable and cannot be brute-forced",
    );
  }
  return { addrs: [...new Set((addrs as string[]).map((a) => a.toLowerCase()))], salt: BigInt(salt) };
}

/** Domain tags for 3-input hashes. Must match DOMAIN_* in circuits/lib/src/lib.nr. */
export const DOMAIN = { vendorLeaf: 1n, chain: 2n, total: 3n } as const;

/** One step of the payment hash chain: H(chain, leaf, DOMAIN.chain). */
export const chainStep = (chain: bigint, leaf: bigint): bigint => hash([chain, leaf, DOMAIN.chain]);

/** Hiding commitment to a total: H(total, blind, DOMAIN.total). */
export const commitTotal = (total: bigint, blind: bigint): bigint => hash([total, blind, DOMAIN.total]);

/** Salted Poseidon2 Merkle root over the V-slot vendor table (empty slots are 0). */
export function vendorRoot({ addrs, salt }: VendorSet): bigint {
  const leaves = Array.from({ length: V }, (_, i) =>
    i < addrs.length ? hash([BigInt(addrs[i]), salt, DOMAIN.vendorLeaf]) : 0n,
  );
  return merkleRoot(leaves);
}

/** The payment leaf. Field order must match `leaf_hash` in circuits/lib/src/lib.nr. */
export function leafHash(
  policy: Pick<Policy, "payer" | "asset" | "chainId">,
  p: Pick<Payment, "payTo" | "amount" | "timestamp" | "transaction">,
  salt: bigint,
): bigint {
  const [hi, lo] = splitTx(p.transaction);
  return hash([
    BigInt(policy.payer),
    BigInt(p.payTo),
    p.amount,
    BigInt(policy.asset),
    BigInt(policy.chainId),
    BigInt(p.timestamp),
    hi,
    lo,
    salt,
  ]);
}

/**
 * Deterministic per-payment salt from the agent's secret. Salting every leaf is what lets the
 * agent later open a single payment (preimage + Merkle path) without exposing its neighbours.
 */
export function paymentSalt(secret: bigint, tx: string): bigint {
  const [hi, lo] = splitTx(tx);
  return hash([secret, hi, lo]);
}

/** Blinding for the total commitment of one period. The trailing 7n is a domain tag. */
export const totalBlind = (secret: bigint, start: number, end: number): bigint =>
  hash([secret, BigInt(start), BigInt(end), 7n]);

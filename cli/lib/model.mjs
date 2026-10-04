// Payment-log data model. Input rows mirror x402 settlement receipts:
//   { transaction, payer, payTo, amount, asset, network, timestamp }
import { createHash, randomBytes } from "node:crypto";
import { hash, hash2, merkleRoot } from "./hash.mjs";

export const V = 256; // vendor table size, must match circuits/lib (global V)
export const BATCH_SIZES = [64, 256, 1024];

// x402 v1 network names and CAIP-2 ids -> EVM chain id
const NETWORKS = {
  base: 8453, "base-sepolia": 84532, ethereum: 1, mainnet: 1, sepolia: 11155111,
  avalanche: 43114, "avalanche-fuji": 43113, polygon: 137, "polygon-amoy": 80002,
  optimism: 10, arbitrum: 42161, iotex: 4689, sei: 1329, "sei-testnet": 1328,
};

export function chainIdOf(network) {
  if (typeof network === "number") return network;
  const n = String(network).toLowerCase();
  if (n.startsWith("eip155:")) return Number(n.slice(7));
  if (NETWORKS[n] === undefined) throw new Error(`unknown network "${network}" (use an EVM network or eip155:<id>)`);
  return NETWORKS[n];
}

const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(a);
const isTx = (t) => /^0x[0-9a-fA-F]{64}$/.test(t);

export function splitTx(tx) {
  const h = tx.slice(2);
  return [BigInt("0x" + h.slice(0, 32)), BigInt("0x" + h.slice(32))];
}

/** Parse amount: integer atomic units (string/number) or "$1.25"/"1.25 USDC" style with decimals. */
export function parseAmount(a, decimals = 6) {
  if (typeof a === "number" && Number.isInteger(a)) return BigInt(a);
  const s = String(a).trim().replace(/^\$/, "").replace(/\s*usdc$/i, "");
  if (/^\d+$/.test(s)) return BigInt(s);
  const m = s.match(/^(\d+)\.(\d+)$/);
  if (!m) throw new Error(`bad amount "${a}"`);
  const frac = m[2].padEnd(decimals, "0");
  if (frac.length > decimals) throw new Error(`amount "${a}" has more than ${decimals} decimals`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(frac);
}

/** Ingest a JSON log (array of x402 receipts or { payments: [...] }) into canonical form. */
export function ingestLog(raw) {
  const rows = Array.isArray(raw) ? raw : raw.payments;
  if (!Array.isArray(rows) || rows.length === 0) throw new Error("log has no payments");
  const seen = new Set();
  const out = rows.map((r, i) => {
    const where = `payment #${i}`;
    const tx = r.transaction ?? r.txHash ?? r.tx;
    if (!isTx(tx)) throw new Error(`${where}: transaction must be a 32-byte hex hash`);
    if (!isAddr(r.payer)) throw new Error(`${where}: bad payer`);
    if (!isAddr(r.payTo)) throw new Error(`${where}: bad payTo`);
    if (!isAddr(r.asset)) throw new Error(`${where}: bad asset`);
    const key = tx.toLowerCase();
    if (seen.has(key)) throw new Error(`${where}: duplicate settlement tx ${tx}`);
    seen.add(key);
    const amount = parseAmount(r.amount);
    if (amount >= 2n ** 64n) throw new Error(`${where}: amount exceeds u64`);
    const timestamp = Number(r.timestamp);
    if (!Number.isInteger(timestamp) || timestamp < 0) throw new Error(`${where}: bad timestamp`);
    return {
      transaction: key, payer: r.payer.toLowerCase(), payTo: r.payTo.toLowerCase(),
      amount, asset: r.asset.toLowerCase(), chainId: chainIdOf(r.network), timestamp,
    };
  });
  const { payer, asset, chainId } = out[0];
  for (const [i, p] of out.entries()) {
    if (p.payer !== payer) throw new Error(`payment #${i}: payer differs; one report covers one agent wallet`);
    if (p.asset !== asset) throw new Error(`payment #${i}: asset differs; one report covers one asset`);
    if (p.chainId !== chainId) throw new Error(`payment #${i}: network differs; one report covers one chain`);
  }
  // Canonical order: settlement time, then tx hash. The circuit enforces non-decreasing time.
  out.sort((a, b) => a.timestamp - b.timestamp || (a.transaction < b.transaction ? -1 : 1));
  return { agentId: raw.agentId ?? null, payer, asset, chainId, payments: out };
}

/** Vendors file: { salt, vendors: ["0x..", {name, address}] } */
export function ingestVendors(raw) {
  const list = (Array.isArray(raw) ? raw : raw.vendors).map((v) => (typeof v === "string" ? v : v.address));
  if (list.length > V) throw new Error(`at most ${V} vendors per set`);
  for (const a of list) if (!isAddr(a)) throw new Error(`bad vendor address ${a}`);
  const addrs = [...new Set(list.map((a) => a.toLowerCase()))];
  if (!raw.salt) throw new Error("vendors file needs a 'salt' (hex) so the vendor root is stable and unguessable");
  return { addrs, salt: BigInt(raw.salt) };
}

export function vendorRoot({ addrs, salt }) {
  const leaves = Array.from({ length: V }, (_, i) => (i < addrs.length ? hash2(BigInt(addrs[i]), salt) : 0n));
  return merkleRoot(leaves);
}

export function leafHash(policy, p, salt) {
  const [hi, lo] = splitTx(p.transaction);
  return hash([
    BigInt(policy.payer), BigInt(p.payTo), p.amount, BigInt(policy.asset), BigInt(policy.chainId),
    BigInt(p.timestamp), hi, lo, salt,
  ]);
}

// Deterministic per-payment salts from the agent's secret, so a single payment can be
// disclosed later (leaf preimage + Merkle path) without revealing any other.
export function paymentSalt(secret, tx) {
  const [hi, lo] = splitTx(tx);
  return hash([secret, hi, lo]);
}
export const totalBlind = (secret, start, end) => hash([secret, BigInt(start), BigInt(end), 7n]);

export function randomField() {
  return BigInt("0x" + randomBytes(31).toString("hex"));
}

export function sha256hex(s) {
  return createHash("sha256").update(s).digest("hex");
}

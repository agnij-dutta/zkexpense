// Circuit inputs (Prover.toml) and the expected public report, computed off-circuit.
// Every proof's public inputs are compared against this model, so a hash mismatch between
// TypeScript and Noir fails loudly instead of producing a report nobody can reproduce.
import { hash2, merkleRoot, toHex } from "./hash.js";
import { V, leafHash, paymentSalt, splitTx, totalBlind, vendorRoot } from "./model.js";
import type { DecodedReport, Payment, PaymentLog, Policy, Report, VendorSet } from "./types.js";

/** TOML string literal for a field element (hex) or a plain value. */
const tomlValue = (x: bigint | number | string): string => `"${typeof x === "bigint" ? toHex(x) : x}"`;

export interface BatchOptions {
  /** Circuit batch size (number of slots). */
  N: number;
  budget: bigint;
  periodStart: number;
  periodEnd: number;
  discloseTotal: boolean;
  /** Agent secret: derives per-payment salts and the total blinding. */
  secret: bigint;
  chainIn?: bigint;
  /** Override the total blinding (used for inner batches of an aggregate). */
  blind?: bigint;
}

export interface BatchWitness {
  toml: string;
  report: Report;
  total: bigint;
  blind: bigint;
  policy: Policy;
  leaves: bigint[];
  /** Policy violations found before proving. Non-empty means no proof can exist. */
  problems: string[];
}

function policyToml(policy: Policy): string[] {
  return [
    `[policy]`,
    `payer = ${tomlValue(BigInt(policy.payer))}`,
    `asset = ${tomlValue(BigInt(policy.asset))}`,
    `chain_id = "${policy.chainId}"`,
    `period_start = "${policy.periodStart}"`,
    `period_end = "${policy.periodEnd}"`,
    `budget = "${policy.budget}"`,
    `disclose_total = ${policy.discloseTotal ? "true" : "false"}`,
    `chain_in = ${tomlValue(policy.chainIn)}`,
  ];
}

/** Inputs for one batch circuit over `slice` (defaults to the whole log). */
export function buildBatch(
  log: PaymentLog,
  vendors: VendorSet,
  opts: BatchOptions,
  slice: Payment[] = log.payments,
): BatchWitness {
  const { N, budget, periodStart, periodEnd, discloseTotal, secret } = opts;
  const chainIn = opts.chainIn ?? 0n;
  if (slice.length > N) throw new Error(`batch of ${slice.length} payments exceeds circuit size ${N}`);

  const policy: Policy = {
    payer: log.payer,
    asset: log.asset,
    chainId: log.chainId,
    periodStart,
    periodEnd,
    budget,
    discloseTotal,
    chainIn,
  };
  const vendorIndex = new Map(vendors.addrs.map((a, i) => [a, i]));

  const leaves: bigint[] = new Array<bigint>(N).fill(0n);
  let total = 0n;
  let chain = chainIn;
  const problems: string[] = [];
  const slots: string[] = [];
  const slot = (payee: bigint, amount: bigint, ts: number, hi: bigint, lo: bigint, salt: bigint, vendorIdx: number) =>
    [
      ``,
      `[[payments]]`,
      `payee = ${tomlValue(payee)}`,
      `amount = "${amount}"`,
      `timestamp = "${ts}"`,
      `tx_hi = ${tomlValue(hi)}`,
      `tx_lo = ${tomlValue(lo)}`,
      `salt = ${tomlValue(salt)}`,
      `vendor_idx = "${vendorIdx}"`,
    ].join("\n");

  slice.forEach((p, i) => {
    const short = p.transaction.slice(0, 12);
    const vendorIdx = vendorIndex.get(p.payTo);
    if (vendorIdx === undefined) problems.push(`payTo ${p.payTo} (tx ${short}..) is not an approved vendor`);
    if (p.timestamp < periodStart || p.timestamp > periodEnd) {
      problems.push(`tx ${short}.. at ${p.timestamp} is outside the period ${periodStart}..${periodEnd}`);
    }
    const salt = paymentSalt(secret, p.transaction);
    const leaf = leafHash(policy, p, salt);
    leaves[i] = leaf;
    total += p.amount;
    chain = hash2(chain, leaf);
    const [hi, lo] = splitTx(p.transaction);
    slots.push(slot(BigInt(p.payTo), p.amount, p.timestamp, hi, lo, salt, vendorIdx ?? 0));
  });
  for (let i = slice.length; i < N; i++) slots.push(slot(0n, 0n, 0, 0n, 0n, 0n, 0));

  const blind = opts.blind ?? totalBlind(secret, periodStart, periodEnd);
  const report: Report = {
    logRoot: merkleRoot(leaves),
    vendorRoot: vendorRoot(vendors),
    count: slice.length,
    underBudget: total <= budget,
    disclosedTotal: discloseTotal ? total : 0n,
    totalCommit: hash2(total, blind),
    chainOut: chain,
  };

  const vendorTable = Array.from({ length: V }, (_, i) => (i < vendors.addrs.length ? BigInt(vendors.addrs[i]) : 0n));
  const toml = [
    `count = "${slice.length}"`,
    `vendor_salt = ${tomlValue(vendors.salt)}`,
    `total_blind = ${tomlValue(blind)}`,
    `vendors = [${vendorTable.map(tomlValue).join(", ")}]`,
    ``,
    ...policyToml(policy),
    ...slots,
  ].join("\n");
  return { toml: toml + "\n", report, total, blind, policy, leaves, problems };
}

/** Names of the 15 public inputs, in circuit order: Policy (8 fields) then Report (7 fields). */
export const PUBLIC_INPUT_NAMES = [
  "payer",
  "asset",
  "chainId",
  "periodStart",
  "periodEnd",
  "budget",
  "discloseTotal",
  "chainIn",
  "logRoot",
  "vendorRoot",
  "count",
  "underBudget",
  "disclosedTotal",
  "totalCommit",
  "chainOut",
] as const;

/** Public inputs the circuit must output for this policy and report. */
export function expectedPublicInputs(policy: Policy, report: Report): string[] {
  return [
    BigInt(policy.payer),
    BigInt(policy.asset),
    BigInt(policy.chainId),
    BigInt(policy.periodStart),
    BigInt(policy.periodEnd),
    policy.budget,
    policy.discloseTotal ? 1n : 0n,
    policy.chainIn,
    report.logRoot,
    report.vendorRoot,
    BigInt(report.count),
    report.underBudget ? 1n : 0n,
    report.disclosedTotal,
    report.totalCommit,
    report.chainOut,
  ].map(toHex);
}

/** Decode 15 public inputs (hex strings) into a human-readable report. */
export function decodePublicInputs(publicInputs: readonly string[]): DecodedReport {
  if (publicInputs.length !== PUBLIC_INPUT_NAMES.length) {
    throw new Error(`expected ${PUBLIC_INPUT_NAMES.length} public inputs, got ${publicInputs.length}`);
  }
  const field = (name: (typeof PUBLIC_INPUT_NAMES)[number]) => publicInputs[PUBLIC_INPUT_NAMES.indexOf(name)];
  const num = (name: (typeof PUBLIC_INPUT_NAMES)[number]) => BigInt(field(name));
  const address = (name: (typeof PUBLIC_INPUT_NAMES)[number]) => "0x" + num(name).toString(16).padStart(40, "0");
  return {
    payer: address("payer"),
    asset: address("asset"),
    chainId: Number(num("chainId")),
    periodStart: Number(num("periodStart")),
    periodEnd: Number(num("periodEnd")),
    budget: num("budget"),
    discloseTotal: num("discloseTotal") === 1n,
    chainIn: field("chainIn"),
    logRoot: field("logRoot"),
    vendorRoot: field("vendorRoot"),
    count: Number(num("count")),
    underBudget: num("underBudget") === 1n,
    disclosedTotal: num("disclosedTotal"),
    totalCommit: field("totalCommit"),
    chainOut: field("chainOut"),
  };
}

/** A proven inner batch plus the private openings the aggregator needs. */
export interface InnerBatch {
  proofFields: string[];
  report: Report;
  total: bigint;
  blind: bigint;
}

/** Inputs for an aggregation circuit over already-proven inner batches. */
export function buildAggregate(
  policy: Policy,
  vkFields: string[],
  vkHash: string,
  inners: InnerBatch[],
  totalBlindValue: bigint,
): { toml: string; report: Report; total: bigint } {
  let total = 0n;
  let count = 0;
  let chain = policy.chainIn;
  for (const inner of inners) {
    total += inner.total;
    count += inner.report.count;
    chain = inner.report.chainOut;
  }
  const report: Report = {
    logRoot: merkleRoot(inners.map((inner) => inner.report.logRoot)),
    vendorRoot: inners[0].report.vendorRoot,
    count,
    underBudget: total <= policy.budget,
    disclosedTotal: policy.discloseTotal ? total : 0n,
    totalCommit: hash2(total, totalBlindValue),
    chainOut: chain,
  };
  const lines = [
    `inner_vk = [${vkFields.map((f) => `"${f}"`).join(", ")}]`,
    `inner_vk_hash = "${vkHash}"`,
    `total_blind = ${tomlValue(totalBlindValue)}`,
    ``,
    ...policyToml(policy),
  ];
  for (const inner of inners) {
    const r = inner.report;
    lines.push(
      ``,
      `[[inners]]`,
      `proof = [${inner.proofFields.map((f) => `"${f}"`).join(", ")}]`,
      `total = "${inner.total}"`,
      `blind = ${tomlValue(inner.blind)}`,
      `[inners.report]`,
      `log_root = ${tomlValue(r.logRoot)}`,
      `vendor_root = ${tomlValue(r.vendorRoot)}`,
      `count = "${r.count}"`,
      `under_budget = ${r.underBudget ? "true" : "false"}`,
      `disclosed_total = "${r.disclosedTotal}"`,
      `total_commit = ${tomlValue(r.totalCommit)}`,
      `chain_out = ${tomlValue(r.chainOut)}`,
    );
  }
  return { toml: lines.join("\n") + "\n", report, total };
}

// Builds circuit inputs (Prover.toml) and the expected public report for one batch.
import { hash2, merkleRoot, toHex } from "./hash.mjs";
import { V, leafHash, paymentSalt, splitTx, totalBlind, vendorRoot } from "./model.mjs";

const q = (x) => `"${typeof x === "bigint" ? toHex(x) : x}"`;

/**
 * @param log      output of ingestLog
 * @param vendors  output of ingestVendors
 * @param opts     { N, budget (bigint atomic), periodStart, periodEnd, discloseTotal, chainIn, secret }
 * @param slice    payments for this batch (defaults to all)
 */
export function buildBatch(log, vendors, opts, slice = log.payments) {
  const { N, budget, periodStart, periodEnd, discloseTotal, secret } = opts;
  const chainIn = opts.chainIn ?? 0n;
  if (slice.length > N) throw new Error(`batch of ${slice.length} exceeds circuit size ${N}`);

  const policy = {
    payer: log.payer, asset: log.asset, chainId: log.chainId,
    periodStart, periodEnd, budget, discloseTotal, chainIn,
  };
  const vendorIndex = new Map(vendors.addrs.map((a, i) => [a, i]));

  const leaves = new Array(N).fill(0n);
  let total = 0n;
  let chain = chainIn;
  const rows = [];
  const problems = [];
  slice.forEach((p, i) => {
    const salt = paymentSalt(secret, p.transaction);
    const vi = vendorIndex.get(p.payTo);
    if (vi === undefined) problems.push(`payTo ${p.payTo} (tx ${p.transaction.slice(0, 12)}..) is not an approved vendor`);
    if (p.timestamp < periodStart || p.timestamp > periodEnd) problems.push(`tx ${p.transaction.slice(0, 12)}.. at ${p.timestamp} is outside the period`);
    const leaf = leafHash(policy, p, salt);
    leaves[i] = leaf;
    total += p.amount;
    chain = hash2(chain, leaf);
    const [hi, lo] = splitTx(p.transaction);
    rows.push({ payee: BigInt(p.payTo), amount: p.amount, timestamp: p.timestamp, hi, lo, salt, vi: vi ?? 0 });
  });
  while (rows.length < N) rows.push({ payee: 0n, amount: 0n, timestamp: 0, hi: 0n, lo: 0n, salt: 0n, vi: 0 });

  const blind = opts.blind ?? totalBlind(secret, periodStart, periodEnd);
  const report = {
    logRoot: merkleRoot(leaves),
    vendorRoot: vendorRoot(vendors),
    count: slice.length,
    underBudget: total <= budget,
    disclosedTotal: discloseTotal ? total : 0n,
    totalCommit: hash2(total, blind),
    chainOut: chain,
  };

  const vendorsArr = Array.from({ length: V }, (_, i) => (i < vendors.addrs.length ? BigInt(vendors.addrs[i]) : 0n));
  const lines = [
    `count = "${slice.length}"`,
    `vendor_salt = ${q(vendors.salt)}`,
    `total_blind = ${q(blind)}`,
    `vendors = [${vendorsArr.map(q).join(", ")}]`,
    ``,
    `[policy]`,
    `payer = ${q(BigInt(log.payer))}`,
    `asset = ${q(BigInt(log.asset))}`,
    `chain_id = "${log.chainId}"`,
    `period_start = "${periodStart}"`,
    `period_end = "${periodEnd}"`,
    `budget = "${budget}"`,
    `disclose_total = ${discloseTotal ? "true" : "false"}`,
    `chain_in = ${q(chainIn)}`,
  ];
  for (const r of rows) {
    lines.push(
      ``, `[[payments]]`,
      `payee = ${q(r.payee)}`, `amount = "${r.amount}"`, `timestamp = "${r.timestamp}"`,
      `tx_hi = ${q(r.hi)}`, `tx_lo = ${q(r.lo)}`, `salt = ${q(r.salt)}`, `vendor_idx = "${r.vi}"`,
    );
  }
  return { toml: lines.join("\n") + "\n", report, total, blind, policy, leaves, problems };
}

/** Public inputs in circuit order: Policy (8 fields) then Report (7 fields). */
export function expectedPublicInputs(policy, report) {
  return [
    BigInt(policy.payer), BigInt(policy.asset), BigInt(policy.chainId),
    BigInt(policy.periodStart), BigInt(policy.periodEnd), policy.budget,
    policy.discloseTotal ? 1n : 0n, policy.chainIn,
    report.logRoot, report.vendorRoot, BigInt(report.count), report.underBudget ? 1n : 0n,
    report.disclosedTotal, report.totalCommit, report.chainOut,
  ].map(toHex);
}

export const PUBLIC_INPUT_NAMES = [
  "payer", "asset", "chainId", "periodStart", "periodEnd", "budget", "discloseTotal", "chainIn",
  "logRoot", "vendorRoot", "count", "underBudget", "disclosedTotal", "totalCommit", "chainOut",
];

export function decodePublicInputs(pis) {
  const o = {};
  PUBLIC_INPUT_NAMES.forEach((k, i) => (o[k] = pis[i]));
  const n = (k) => BigInt(o[k]);
  return {
    payer: "0x" + n("payer").toString(16).padStart(40, "0"),
    asset: "0x" + n("asset").toString(16).padStart(40, "0"),
    chainId: Number(n("chainId")),
    periodStart: Number(n("periodStart")), periodEnd: Number(n("periodEnd")),
    budget: n("budget"), discloseTotal: n("discloseTotal") === 1n, chainIn: o.chainIn,
    logRoot: o.logRoot, vendorRoot: o.vendorRoot, count: Number(n("count")),
    underBudget: n("underBudget") === 1n, disclosedTotal: n("disclosedTotal"),
    totalCommit: o.totalCommit, chainOut: o.chainOut,
  };
}

/**
 * Aggregator inputs: K inner batch proofs (already proven) plus their private openings.
 * inners: [{ proofFields, report, total, blind }]
 */
export function buildAggregate(policy, vkFields, vkHash, inners, totalBlindValue) {
  let total = 0n, count = 0, chain = policy.chainIn;
  const roots = [];
  for (const inn of inners) {
    total += inn.total; count += inn.report.count; chain = inn.report.chainOut; roots.push(inn.report.logRoot);
  }
  const report = {
    logRoot: merkleRoot(roots),
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
    `total_blind = ${q(totalBlindValue)}`,
    ``, `[policy]`,
    `payer = ${q(BigInt(policy.payer))}`, `asset = ${q(BigInt(policy.asset))}`, `chain_id = "${policy.chainId}"`,
    `period_start = "${policy.periodStart}"`, `period_end = "${policy.periodEnd}"`, `budget = "${policy.budget}"`,
    `disclose_total = ${policy.discloseTotal ? "true" : "false"}`, `chain_in = ${q(policy.chainIn)}`,
  ];
  for (const inn of inners) {
    const r = inn.report;
    lines.push(
      ``, `[[inners]]`,
      `proof = [${inn.proofFields.map((f) => `"${f}"`).join(", ")}]`,
      `total = "${inn.total}"`, `blind = ${q(inn.blind)}`,
      `[inners.report]`,
      `log_root = ${q(r.logRoot)}`, `vendor_root = ${q(r.vendorRoot)}`, `count = "${r.count}"`,
      `under_budget = ${r.underBudget ? "true" : "false"}`, `disclosed_total = "${r.disclosedTotal}"`,
      `total_commit = ${q(r.totalCommit)}`, `chain_out = ${q(r.chainOut)}`,
    );
  }
  return { toml: lines.join("\n") + "\n", report, total };
}

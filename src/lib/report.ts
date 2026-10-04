// Payment log + vendor set + policy -> one zkExpense proof (single batch or aggregated).
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pickCircuit } from "./circuits.js";
import { hash } from "./hash.js";
import { totalBlind } from "./model.js";
import { ensureVk, execute, prove, toFields, verifyNative, type ProveResult } from "./toolchain.js";
import type { CircuitSpec, DecodedReportJson, PaymentLog, Policy, ProofJson, ProofTimings, Report, VendorSet } from "./types.js";
import {
  buildAggregate,
  buildBatch,
  decodePublicInputs,
  expectedPublicInputs,
  type BatchOptions,
  type InnerBatch,
} from "./witness.js";

export interface ProveOptions {
  /** Budget in atomic asset units. */
  budget: bigint;
  periodStart: number;
  periodEnd: number;
  /** Reveal the exact total instead of only `total <= budget`. */
  discloseTotal: boolean;
  /** Agent secret: derives per-payment salts and blinding. */
  secret: bigint;
  /** Previous report's chainOut; links consecutive periods into one hash chain. */
  chainIn?: bigint;
  /** Force a circuit by name; picked from the payment count otherwise. */
  circuit?: string;
  /** Progress messages. */
  log?: (msg: string) => void;
}

/** Thrown when the log breaks the policy, so no satisfying witness exists. */
export class PolicyViolation extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    const shown = problems.slice(0, 10).join("\n  - ");
    const more = problems.length > 10 ? `\n  ... and ${problems.length - 10} more` : "";
    super(`log violates policy; no proof is possible:\n  - ${shown}${more}`);
    this.name = "PolicyViolation";
    this.problems = problems;
  }
}

interface Proven {
  result: ProveResult;
  policy: Policy;
  report: Report;
}

/** Prove, check the fresh proof with bb, and clean up the bb output directory. */
function proveAndCheck(pkg: string, witness: string): ProveResult {
  const out = mkdtempSync(join(tmpdir(), "zkexpense-prove-"));
  try {
    const result = prove(pkg, witness, "evm", out);
    // Recursive verification defers the pairing check to the final verifier, so bb happily
    // proves an aggregate over a bad inner proof; it just never verifies. Always check.
    const check = verifyNative(ensureVk(pkg, "evm").vk, join(out, "proof"), join(out, "public_inputs"), "evm");
    if (!check.ok) throw new Error(`freshly generated ${pkg} proof does not verify; refusing to write it`);
    return result;
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

function proveSingle(spec: CircuitSpec, log: PaymentLog, vendors: VendorSet, base: BatchOptions, timings: ProofTimings) {
  const batch = buildBatch(log, vendors, base);
  if (batch.problems.length) throw new PolicyViolation(batch.problems);
  const witness = execute(spec.name, batch.toml, "zkexpense");
  timings.witnessMs = witness.ms;
  let result: ProveResult;
  try {
    result = proveAndCheck(spec.name, witness.witness);
  } finally {
    witness.discard();
  }
  timings.proveMs = result.ms;
  timings.peakRssMb = result.peakRssMb;
  return { result, policy: batch.policy, report: batch.report };
}

function proveAggregate(
  spec: CircuitSpec,
  log: PaymentLog,
  vendors: VendorSet,
  base: BatchOptions,
  timings: ProofTimings,
  say: (msg: string) => void,
): Proven {
  if (!spec.inner || !spec.k) throw new Error(`${spec.name} is not an aggregation circuit`);
  const innerVk = ensureVk(spec.inner, "noir-recursive-no-zk");
  const vkFields = toFields(readFileSync(innerVk.vk));
  const vkHash = toFields(readFileSync(innerVk.vkHash))[0];
  const inners: InnerBatch[] = [];
  const innerProveMs: number[] = [];
  // Inner batches are checked against sub-periods, so check the whole log against the outer
  // period up front; otherwise an out-of-period payment would only surface as a failed proof.
  const outside = log.payments
    .filter((p) => p.timestamp < base.periodStart || p.timestamp > base.periodEnd)
    .map((p) => `tx ${p.transaction.slice(0, 12)}.. at ${p.timestamp} is outside the period`);
  if (outside.length) throw new PolicyViolation(outside);

  // Batch i covers [boundaries[i-1], boundaries[i]]: its last payment's timestamp, or the previous
  // boundary when the batch is empty; the last batch always ends at the period end.
  const boundaries: number[] = [];
  let chainIn = base.chainIn ?? 0n;
  for (let i = 0; i < spec.k; i++) {
    const slice = log.payments.slice(i * spec.batch, (i + 1) * spec.batch);
    const start = i === 0 ? base.periodStart : boundaries[i - 1];
    const last = slice.at(-1);
    const end = i === spec.k - 1 ? base.periodEnd : last ? last.timestamp : start;
    boundaries.push(end);
    // Distinct blinding per inner batch (domain tag 100 + i), never revealed.
    const blind = hash([base.secret, BigInt(base.periodStart), BigInt(base.periodEnd), 100n + BigInt(i)]);
    const batch = buildBatch(
      log,
      vendors,
      { ...base, periodStart: start, periodEnd: end, discloseTotal: false, chainIn, blind },
      slice,
    );
    if (batch.problems.length) throw new PolicyViolation(batch.problems);
    const witness = execute(spec.inner, batch.toml, `inner_${i}`);
    timings.witnessMs += witness.ms;
    const out = mkdtempSync(join(tmpdir(), "zkexpense-inner-"));
    try {
      const result = prove(spec.inner, witness.witness, "noir-recursive-no-zk", out);
      innerProveMs.push(Math.round(result.ms));
      say(`  batch ${i + 1}/${spec.k}: ${slice.length} payments proven in ${(result.ms / 1000).toFixed(2)}s`);
      inners.push({ proofFields: toFields(result.proof), report: batch.report, total: batch.total, blind });
    } finally {
      witness.discard();
      rmSync(out, { recursive: true, force: true });
    }
    chainIn = batch.report.chainOut;
  }
  const policy: Policy = {
    payer: log.payer,
    asset: log.asset,
    chainId: log.chainId,
    periodStart: base.periodStart,
    periodEnd: base.periodEnd,
    budget: base.budget,
    discloseTotal: base.discloseTotal,
    chainIn: base.chainIn ?? 0n,
  };
  const agg = buildAggregate(
    policy,
    vkFields,
    vkHash,
    inners,
    boundaries,
    totalBlind(base.secret, base.periodStart, base.periodEnd),
  );
  const witness = execute(spec.name, agg.toml, "zkexpense");
  timings.witnessMs += witness.ms;
  say(`  aggregating ${spec.k} batch proofs (recursive UltraHonk verification in-circuit)`);
  let result: ProveResult;
  try {
    result = proveAndCheck(spec.name, witness.witness);
  } finally {
    witness.discard();
  }
  timings.innerProveMs = innerProveMs;
  timings.aggregateProveMs = Math.round(result.ms);
  timings.peakRssMb = result.peakRssMb;
  timings.proveMs = innerProveMs.reduce((s, x) => s + x, 0) + result.ms;
  return { result, policy, report: agg.report };
}

/** Prove a whole log under a policy and return the proof.json object. */
export function proveReport(log: PaymentLog, vendors: VendorSet, opts: ProveOptions): ProofJson {
  const say = opts.log ?? (() => {});
  const spec = pickCircuit(log.payments.length, opts.circuit);
  const timings: ProofTimings = { witnessMs: 0, proveMs: 0, peakRssMb: null };
  const base: BatchOptions = {
    N: spec.batch,
    budget: opts.budget,
    periodStart: opts.periodStart,
    periodEnd: opts.periodEnd,
    discloseTotal: opts.discloseTotal,
    secret: opts.secret,
    chainIn: opts.chainIn ?? 0n,
  };
  if (spec.kind === "single") {
    say(`circuit ${spec.name}: ${log.payments.length} payments, ${spec.batch - log.payments.length} padding slots`);
  }
  const proven =
    spec.kind === "single"
      ? proveSingle(spec, log, vendors, base, timings)
      : proveAggregate(spec, log, vendors, base, timings, say);

  const publicInputs = toFields(proven.result.publicInputs);
  const expected = expectedPublicInputs(proven.policy, proven.report);
  if (publicInputs.join() !== expected.join()) {
    throw new Error("circuit public outputs disagree with the TypeScript model (Poseidon2 or layout mismatch)");
  }
  return {
    version: 1,
    scheme: "ultra_honk/keccak-zk (bb -t evm)",
    circuit: spec.name,
    agentId: log.agentId,
    report: toJson(decodePublicInputs(publicInputs)) as DecodedReportJson,
    publicInputs,
    proof: "0x" + proven.result.proof.toString("hex"),
    meta: {
      payments: log.payments.length,
      proofBytes: proven.result.proof.length,
      timings: { ...timings, witnessMs: Math.round(timings.witnessMs), proveMs: Math.round(timings.proveMs) },
      createdAt: new Date().toISOString(),
    },
  };
}

/** JSON-safe copy: bigints become decimal strings. */
export function toJson(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v)));
}

// High-level: payment log + vendor set + policy -> one zkExpense proof (single batch or aggregated).
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { hash } from "./hash.mjs";
import { totalBlind } from "./model.mjs";
import { buildAggregate, buildBatch, decodePublicInputs, expectedPublicInputs } from "./witness.mjs";
import { ensureVk, execute, prove, toFields, verifyNative } from "./prover.mjs";

export const SINGLE = [64, 256, 1024].map((n) => ({ name: `batch_${n}`, kind: "single", capacity: n, batch: n }));
export const AGG = [
  { name: "agg_64x2", kind: "agg", inner: "batch_64", batch: 64, k: 2, capacity: 128 },
  { name: "agg_1024x4", kind: "agg", inner: "batch_1024", batch: 1024, k: 4, capacity: 4096 },
];
export const CIRCUITS = [...SINGLE, ...AGG];

export function pickCircuit(n, forced) {
  if (forced) {
    const c = CIRCUITS.find((c) => c.name === forced);
    if (!c) throw new Error(`unknown circuit ${forced}; one of ${CIRCUITS.map((c) => c.name).join(", ")}`);
    if (n > c.capacity) throw new Error(`${n} payments exceed ${c.name} capacity ${c.capacity}`);
    return c;
  }
  const c = SINGLE.find((c) => c.capacity >= n) ?? AGG.find((c) => c.name === "agg_1024x4" && c.capacity >= n);
  if (!c) throw new Error(`${n} payments exceed the largest supported report (4096); split the period`);
  return c;
}

const tmp = (tag) => join(tmpdir(), `zkexpense-${process.pid}-${tag}`);

/**
 * opts: { budget, periodStart, periodEnd, discloseTotal, secret, chainIn?, circuit?, log?: (msg)=>void }
 * chainIn links this report to the previous period's chainOut, so consecutive reports form one chain.
 * Returns a proof.json object.
 */
export function proveReport(log, vendors, opts) {
  const say = opts.log ?? (() => {});
  const c = pickCircuit(log.payments.length, opts.circuit);
  const timings = {};
  const base = { N: c.batch, budget: opts.budget, periodStart: opts.periodStart, periodEnd: opts.periodEnd, secret: opts.secret };

  let final;
  if (c.kind === "single") {
    const b = buildBatch(log, vendors, { ...base, discloseTotal: opts.discloseTotal, chainIn: opts.chainIn ?? 0n });
    if (b.problems.length) throw new PolicyViolation(b.problems);
    say(`circuit ${c.name}: ${log.payments.length} payments, ${c.batch - log.payments.length} padding slots`);
    const w = execute(c.name, b.toml, "zkexpense");
    timings.witnessMs = w.ms;
    const out = tmp("final");
    const p = prove(c.name, w.witness, "evm", out);
    selfVerify(c.name, out);
    timings.proveMs = p.ms;
    final = { p, policy: b.policy, report: b.report };
  } else {
    const innerVk = ensureVk(c.inner, "noir-recursive-no-zk");
    const vkFields = toFields(readFileSync(innerVk.vk));
    const vkHash = toFields(readFileSync(innerVk.vkHash))[0];
    const inners = [];
    let chainIn = opts.chainIn ?? 0n;
    timings.innerProveMs = [];
    timings.witnessMs = 0;
    for (let i = 0; i < c.k; i++) {
      const slice = log.payments.slice(i * c.batch, (i + 1) * c.batch);
      const blind = hash([opts.secret, BigInt(opts.periodStart), BigInt(opts.periodEnd), 100n + BigInt(i)]);
      const b = buildBatch(log, vendors, { ...base, discloseTotal: false, chainIn, blind }, slice);
      if (b.problems.length) throw new PolicyViolation(b.problems);
      const w = execute(c.inner, b.toml, `inner_${i}`);
      timings.witnessMs += w.ms;
      const out = tmp(`inner${i}`);
      const p = prove(c.inner, w.witness, "noir-recursive-no-zk", out);
      rmSync(out, { recursive: true, force: true });
      timings.innerProveMs.push(Math.round(p.ms));
      say(`  batch ${i + 1}/${c.k}: ${slice.length} payments proven in ${(p.ms / 1000).toFixed(2)}s`);
      inners.push({ proofFields: toFields(p.proof), report: b.report, total: b.total, blind });
      chainIn = b.report.chainOut;
    }
    const policy = {
      payer: log.payer, asset: log.asset, chainId: log.chainId, periodStart: opts.periodStart,
      periodEnd: opts.periodEnd, budget: opts.budget, discloseTotal: opts.discloseTotal, chainIn: opts.chainIn ?? 0n,
    };
    const a = buildAggregate(policy, vkFields, vkHash, inners, totalBlind(opts.secret, opts.periodStart, opts.periodEnd));
    const w = execute(c.name, a.toml, "zkexpense");
    timings.witnessMs += w.ms;
    const out = tmp("final");
    say(`  aggregating ${c.k} batch proofs (recursive UltraHonk verification in-circuit)`);
    const p = prove(c.name, w.witness, "evm", out);
    // Recursive verification defers the pairing check to the final verifier, so a bad inner
    // proof still yields an outer proof: it just never verifies. Always check before shipping.
    selfVerify(c.name, out);
    timings.aggregateProveMs = p.ms;
    timings.proveMs = timings.innerProveMs.reduce((s, x) => s + x, 0) + p.ms;
    final = { p, policy, report: a.report };
  }

  const publicInputs = toFields(final.p.publicInputs);
  const expected = expectedPublicInputs(final.policy, final.report);
  if (publicInputs.join() !== expected.join()) {
    throw new Error("internal: circuit public outputs disagree with the JS model (hash mismatch?)");
  }
  const decoded = decodePublicInputs(publicInputs);
  return {
    version: 1,
    scheme: "ultra_honk/keccak-zk (bb -t evm)",
    circuit: c.name,
    agentId: log.agentId,
    report: jsonable(decoded),
    publicInputs,
    proof: "0x" + final.p.proof.toString("hex"),
    meta: {
      payments: log.payments.length,
      proofBytes: final.p.proof.length,
      timings: Object.fromEntries(Object.entries(timings).map(([k, v]) => [k, Array.isArray(v) ? v : Math.round(v)])),
      createdAt: new Date().toISOString(),
    },
  };
}

function selfVerify(pkg, out) {
  const res = verifyNative(ensureVk(pkg, "evm").vk, join(out, "proof"), join(out, "public_inputs"), "evm");
  rmSync(out, { recursive: true, force: true });
  if (!res.ok) throw new Error(`internal: freshly generated ${pkg} proof does not verify`);
}

export class PolicyViolation extends Error {
  constructor(problems) {
    super(`log violates policy; no proof is possible:\n  - ${problems.slice(0, 10).join("\n  - ")}${problems.length > 10 ? `\n  ... and ${problems.length - 10} more` : ""}`);
    this.problems = problems;
  }
}

function jsonable(o) {
  return JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
}

export function ensureDir(d) {
  mkdirSync(d, { recursive: true });
}

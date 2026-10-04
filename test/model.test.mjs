import test from "node:test";
import assert from "node:assert/strict";
import {
  buildBatch,
  chainIdOf,
  chainStep,
  commitTotal,
  decodePublicInputs,
  expectedPublicInputs,
  hash2,
  ingestLog,
  ingestVendors,
  parseAmount,
  pickCircuit,
} from "../dist/index.js";

const A = (n) => "0x" + n.toString(16).padStart(40, "0");
const T = (n) => "0x" + n.toString(16).padStart(64, "0");
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const row = (i, over = {}) => ({
  transaction: T(1000 + i),
  payer: A(1),
  payTo: A(0xa0 + (i % 2)),
  amount: String(1000 * (i + 1)),
  asset: USDC,
  network: "base",
  timestamp: 1_788_220_800 + 3600 * (10 - i),
  ...over,
});

test("amount parsing: atomic, decimal, dollar", () => {
  assert.equal(parseAmount("1500"), 1500n);
  assert.equal(parseAmount("$1.25"), 1_250_000n);
  assert.equal(parseAmount("0.000001 USDC"), 1n);
  assert.throws(() => parseAmount("1.0000001"));
  assert.throws(() => parseAmount("-1"));
});

test("networks: x402 names and CAIP-2", () => {
  assert.equal(chainIdOf("base"), 8453);
  assert.equal(chainIdOf("base-sepolia"), 84532);
  assert.equal(chainIdOf("eip155:43113"), 43113);
  assert.throws(() => chainIdOf("solana"));
});

test("ingest sorts by settlement time and normalizes", () => {
  const log = ingestLog({ agentId: "a", payments: [row(0), row(1), row(2)] });
  assert.equal(log.chainId, 8453);
  assert.deepEqual(
    log.payments.map((p) => p.timestamp),
    [...log.payments.map((p) => p.timestamp)].sort((a, b) => a - b),
  );
});

test("ingest rejects duplicate settlement tx, mixed payer / asset / chain", () => {
  assert.throws(() => ingestLog([row(0), row(1, { transaction: T(1000) })]), /duplicate/);
  assert.throws(() => ingestLog([row(0), row(1, { payer: A(2) })]), /payer differs/);
  assert.throws(() => ingestLog([row(0), row(1, { asset: A(3) })]), /asset differs/);
  assert.throws(() => ingestLog([row(0), row(1, { network: "ethereum" })]), /network differs/);
  assert.throws(() => ingestLog([row(0, { transaction: "0x12" })]), /transaction/);
  assert.throws(() => ingestLog([]), /no payments/);
});

test("vendors file needs a salt", () => {
  assert.throws(() => ingestVendors({ vendors: [A(0xa0)] }), /salt/);
  const v = ingestVendors({ salt: "0x01", vendors: [{ name: "x", address: A(0xa0) }, A(0xa0)] });
  assert.equal(v.addrs.length, 1);
});

test("witness builder flags policy violations before proving", () => {
  const log = ingestLog([row(0), row(1), row(2, { payTo: A(0xdead) })]);
  const vendors = ingestVendors({ salt: "0x01", vendors: [A(0xa0), A(0xa1)] });
  const opts = {
    N: 64,
    budget: 10n ** 9n,
    periodStart: 1_788_220_800,
    periodEnd: 1_788_220_800 + 86400,
    discloseTotal: false,
    secret: 1n,
  };
  const b = buildBatch(log, vendors, opts);
  assert.equal(b.problems.length, 1);
  assert.match(b.problems[0], /not an approved vendor/);
  const late = buildBatch(log, vendors, { ...opts, periodEnd: opts.periodStart + 3600 });
  assert.ok(late.problems.some((p) => /outside the period/.test(p)));
});

test("public inputs round-trip through the decoder", () => {
  const log = ingestLog([row(0), row(1)]);
  const vendors = ingestVendors({ salt: "0x01", vendors: [A(0xa0), A(0xa1)] });
  const b = buildBatch(log, vendors, {
    N: 64,
    budget: 2500n,
    periodStart: 1_788_220_800,
    periodEnd: 1_790_812_799,
    discloseTotal: true,
    secret: 1n,
  });
  const d = decodePublicInputs(expectedPublicInputs(b.policy, b.report));
  assert.equal(d.count, 2);
  assert.equal(d.disclosedTotal, 3000n);
  assert.equal(d.underBudget, false);
  assert.equal(d.payer, A(1));
  assert.equal(d.chainId, 8453);
});

test("circuit selection", () => {
  assert.equal(pickCircuit(1).name, "batch_64");
  assert.equal(pickCircuit(64).name, "batch_64");
  assert.equal(pickCircuit(65).name, "batch_256");
  assert.equal(pickCircuit(347).name, "batch_512");
  assert.equal(pickCircuit(600).name, "batch_1024");
  assert.equal(pickCircuit(1025).name, "agg_1024x4");
  assert.throws(() => pickCircuit(4097));
  assert.throws(() => pickCircuit(200, "batch_64"));
});

test("raw x402 requirement/settlement pairs are accepted", () => {
  const r = row(0);
  const log = ingestLog([
    {
      paymentRequirements: {
        scheme: "exact",
        network: "base",
        maxAmountRequired: r.amount,
        payTo: r.payTo,
        asset: r.asset,
        resource: "https://x",
      },
      settleResponse: { success: true, transaction: r.transaction, network: "base", payer: r.payer },
      timestamp: r.timestamp,
    },
  ]);
  assert.equal(log.payments[0].amount, 1000n);
  assert.throws(
    () =>
      ingestLog([{ paymentRequirements: {}, settleResponse: { success: false, errorReason: "insufficient_funds" } }]),
    /unsettled/,
  );
});

test("witness builder flags out-of-order or repeated payments in a hand-built slice", () => {
  const log = ingestLog([row(0), row(1), row(2)]);
  const vendors = ingestVendors({ salt: "0x01", vendors: [A(0xa0), A(0xa1)] });
  const opts = {
    N: 64,
    budget: 10n ** 9n,
    periodStart: 1_788_220_800,
    periodEnd: 1_788_220_800 + 86400,
    discloseTotal: false,
    secret: 1n,
  };
  const [a, b] = log.payments;
  assert.equal(buildBatch(log, vendors, opts, [a, b]).problems.length, 0);
  assert.match(buildBatch(log, vendors, opts, [b, a]).problems[0], /strictly after/);
  assert.match(buildBatch(log, vendors, opts, [a, a]).problems[0], /strictly after/);
});

test("hash domains: vendor leaf, chain step and total commitment differ from a Merkle node", () => {
  const node = hash2(5n, 6n);
  assert.notEqual(chainStep(5n, 6n), node);
  assert.notEqual(commitTotal(5n, 6n), node);
  assert.notEqual(chainStep(5n, 6n), commitTotal(5n, 6n));
});

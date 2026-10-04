import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkDisclosure, disclose, ingestLog } from "../dist/index.js";

const root = new URL("..", import.meta.url).pathname;
const pj = JSON.parse(readFileSync(root + "contracts/test/fixtures/sep.json", "utf8"));
const aggPj = JSON.parse(readFileSync(root + "contracts/test/fixtures/sep_agg.json", "utf8"));
const log = ingestLog(JSON.parse(readFileSync(root + "examples/fixtures/log-sep.json", "utf8")));
const big = ingestLog(JSON.parse(readFileSync(root + "examples/fixtures/log-sep-120.json", "utf8")));
const SECRET = 0x5eed5eed5eedn; // scripts/fixtures.mjs

test("one payment opens against a real proof's log root", () => {
  const d = disclose(log, pj, SECRET, log.payments[13].transaction);
  assert.equal(d.index, 13);
  assert.ok(checkDisclosure(d, pj));
});

test("opening works for an aggregated (recursive) report too", () => {
  const d = disclose(big, aggPj, SECRET, big.payments[100].transaction);
  assert.equal(d.path.length, 7); // 128-leaf flat tree = 2 batches x 64
  assert.ok(checkDisclosure(d, aggPj));
});

test("a doctored opening is rejected", () => {
  const d = disclose(log, pj, SECRET, log.payments[3].transaction);
  for (const mutate of [
    (x) => (x.payment.amount = "1"),
    (x) => (x.payment.payTo = "0x" + "11".repeat(20)),
    (x) => (x.index = 4),
    (x) => (x.salt = "0x01"),
    (x) => x.path.pop(),
  ]) {
    const c = structuredClone(d);
    mutate(c);
    assert.equal(checkDisclosure(c, pj), false);
  }
});

test("wrong secret cannot reproduce the root", () => {
  assert.throws(() => disclose(log, pj, 1n, log.payments[0].transaction), /log root/);
});

test("an entry can be opened by leaf index (auditor samples the log, then checks the chain)", () => {
  const d = disclose(log, pj, SECRET, 7);
  assert.equal(d.index, 7);
  assert.equal(d.payment.transaction, log.payments[7].transaction);
  assert.ok(checkDisclosure(d, pj));
  assert.throws(() => disclose(log, pj, SECRET, log.payments.length), /not a payment/);
  assert.throws(() => disclose(log, pj, SECRET, -1), /not a payment/);
});

test("an opening is only valid against its own report", () => {
  const d = disclose(log, pj, SECRET, log.payments[0].transaction);
  assert.equal(checkDisclosure(d, aggPj), false);
});

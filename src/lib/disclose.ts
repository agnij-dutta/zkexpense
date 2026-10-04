// Selective disclosure: open ONE payment of a proven report (leaf preimage + Merkle path)
// without revealing any other. Lets an auditor spot-check on-chain transfers against the log.
import { circuitSpec } from "./circuits.js";
import { hash2, merklePath, merkleRoot, toHex } from "./hash.js";
import { leafHash, paymentSalt } from "./model.js";
import type { Disclosure, PaymentLog, ProofJson } from "./types.js";

/**
 * Open one payment of a proven log, chosen by settlement tx hash or by leaf index.
 *
 * Auditors sample in both directions: by tx (an on-chain transfer must be in the log, which
 * catches omissions) and by index (a log entry must be a real on-chain transfer, which catches
 * fabricated entries). Throws if the log and secret do not reproduce the proof's log root.
 */
export function disclose(log: PaymentLog, pj: ProofJson, secret: bigint, which: string | number): Disclosure {
  const r = pj.report;
  const policy = { payer: r.payer, asset: r.asset, chainId: r.chainId };
  const inPeriod = log.payments.filter((p) => p.timestamp >= r.periodStart && p.timestamp <= r.periodEnd);
  const leaves: bigint[] = new Array<bigint>(circuitSpec(pj.circuit).capacity).fill(0n);
  inPeriod.forEach((p, i) => (leaves[i] = leafHash(policy, p, paymentSalt(secret, p.transaction))));
  if (toHex(merkleRoot(leaves)) !== r.logRoot) {
    throw new Error("this log does not reproduce the proof's log root (wrong log or wrong secret file)");
  }
  let index: number;
  if (typeof which === "number") {
    if (!Number.isInteger(which) || which < 0 || which >= inPeriod.length) {
      throw new Error(`index ${which} is not a payment of the proven log (it has ${inPeriod.length})`);
    }
    index = which;
  } else {
    index = inPeriod.findIndex((p) => p.transaction === which.toLowerCase());
    if (index < 0) throw new Error(`tx ${which} is not in the proven log`);
  }
  const p = inPeriod[index];
  return {
    logRoot: r.logRoot,
    circuit: pj.circuit,
    index,
    payment: {
      transaction: p.transaction,
      payer: r.payer,
      payTo: p.payTo,
      amount: p.amount.toString(),
      asset: r.asset,
      chainId: r.chainId,
      timestamp: p.timestamp,
    },
    salt: toHex(paymentSalt(secret, p.transaction)),
    path: merklePath(leaves, index).map((x) => toHex(x)),
  };
}

/** Recompute the leaf from an opening and walk its path to the report's log root. */
export function checkDisclosure(d: Disclosure, pj?: ProofJson): boolean {
  const pay = d.payment;
  if (pj) {
    if (d.logRoot !== pj.report.logRoot || d.circuit !== pj.circuit) return false;
    if (pay.payer !== pj.report.payer || pay.asset !== pj.report.asset || pay.chainId !== pj.report.chainId) return false;
  }
  const leaf = leafHash(
    { payer: pay.payer, asset: pay.asset, chainId: pay.chainId },
    { payTo: pay.payTo, amount: BigInt(pay.amount), timestamp: pay.timestamp, transaction: pay.transaction },
    BigInt(d.salt),
  );
  let node = leaf;
  let i = d.index;
  for (const sibling of d.path) {
    node = i & 1 ? hash2(BigInt(sibling), node) : hash2(node, BigInt(sibling));
    i >>= 1;
  }
  return d.path.length === Math.log2(circuitSpec(d.circuit).capacity) && toHex(node) === d.logRoot;
}

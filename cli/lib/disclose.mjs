// Selective disclosure: open ONE payment of a proven report (leaf preimage + Merkle path),
// without revealing any other. Lets an auditor spot-check on-chain transfers against the log.
import { hash2, merklePath, merkleRoot, toHex } from "./hash.mjs";
import { leafHash, paymentSalt } from "./model.mjs";
import { CIRCUITS } from "./report.mjs";

const width = (circuit) => {
  const c = CIRCUITS.find((x) => x.name === circuit);
  if (!c) throw new Error(`unknown circuit ${circuit}`);
  return c.capacity;
};

export function disclose(log, pj, secret, tx) {
  const r = pj.report;
  const policy = { payer: r.payer, asset: r.asset, chainId: r.chainId };
  const inPeriod = log.payments.filter((p) => p.timestamp >= r.periodStart && p.timestamp <= r.periodEnd);
  const leaves = new Array(width(pj.circuit)).fill(0n);
  inPeriod.forEach((p, i) => (leaves[i] = leafHash(policy, p, paymentSalt(secret, p.transaction))));
  if (toHex(merkleRoot(leaves)) !== r.logRoot) throw new Error("this log does not reproduce the proof's log root (wrong log or secret)");
  const index = inPeriod.findIndex((p) => p.transaction === tx.toLowerCase());
  if (index < 0) throw new Error(`tx ${tx} is not in the proven log`);
  const p = inPeriod[index];
  return {
    logRoot: r.logRoot,
    circuit: pj.circuit,
    index,
    payment: {
      transaction: p.transaction, payer: r.payer, payTo: p.payTo, amount: p.amount.toString(),
      asset: r.asset, chainId: r.chainId, timestamp: p.timestamp,
    },
    salt: toHex(paymentSalt(secret, p.transaction)),
    path: merklePath(leaves, index).map(toHex),
  };
}

/** Recomputes the leaf from the opened payment and walks the path up to the log root. */
export function checkDisclosure(d, pj) {
  const pay = d.payment;
  if (pj && d.logRoot !== pj.report.logRoot) return false;
  if (pj && (pay.payer !== pj.report.payer || pay.asset !== pj.report.asset || pay.chainId !== pj.report.chainId)) return false;
  const leaf = leafHash(
    { payer: pay.payer, asset: pay.asset, chainId: pay.chainId },
    { payTo: pay.payTo, amount: BigInt(pay.amount), timestamp: pay.timestamp, transaction: pay.transaction },
    BigInt(d.salt),
  );
  let node = leaf;
  let i = d.index;
  for (const sib of d.path) {
    node = i & 1 ? hash2(BigInt(sib), node) : hash2(node, BigInt(sib));
    i >>= 1;
  }
  return d.path.length === Math.log2(width(d.circuit)) && toHex(node) === d.logRoot;
}

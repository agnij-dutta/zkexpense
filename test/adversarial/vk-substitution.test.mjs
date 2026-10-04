// Adversarial test: can a prover aggregate proofs of a DIFFERENT inner circuit (one without the
// vendor check) by feeding its verification key while claiming the pinned vk hash?
//
// The aggregator only asserts `inner_vk_hash == PINNED_VK_HASH`; soundness also needs the backend
// to bind `inner_vk` to that hash. This test builds the evil circuit, proves a batch that pays an
// unapproved vendor, and checks that the resulting aggregate proof does NOT verify.
// Slow (about a minute): run with `npm run test:adversarial`.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ROOT, buildAggregate, buildBatch, ensureVk, ingestLog, ingestVendors } from "../../dist/index.js";

const A = (n) => "0x" + n.toString(16).padStart(40, "0");
const T = (n) => "0x" + n.toString(16).padStart(64, "0");
const fields = (buf) => Array.from({ length: buf.length / 32 }, (_, i) => "0x" + buf.subarray(i * 32, i * 32 + 32).toString("hex"));
const sh = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] }).toString();

test("aggregator rejects inner proofs of a substituted circuit", { timeout: 900_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "zkexpense-adv-"));
  try {
    for (const pkg of ["lib", "batch_64", "agg_64x2"]) {
      cpSync(join(ROOT, "circuits", pkg, "src"), join(dir, pkg, "src"), { recursive: true });
      cpSync(join(ROOT, "circuits", pkg, "Nargo.toml"), join(dir, pkg, "Nargo.toml"));
    }
    // Evil library: identical except the vendor membership assertion is gone.
    cpSync(join(dir, "lib"), join(dir, "lib_evil"), { recursive: true });
    const libPath = join(dir, "lib_evil", "src", "lib.nr");
    const lib = readFileSync(libPath, "utf8");
    const check = 'assert(vendors[p.vendor_idx] == p.payee, "payee not in approved vendor set");';
    assert.ok(lib.includes(check), "vendor check not found; update this test");
    writeFileSync(libPath, lib.replace(check, "// vendor check removed"));
    cpSync(join(dir, "batch_64"), join(dir, "evil_64"), { recursive: true });
    const toml = readFileSync(join(dir, "evil_64", "Nargo.toml"), "utf8");
    writeFileSync(join(dir, "evil_64", "Nargo.toml"), toml.replace('"batch_64"', '"evil_64"').replace("../lib", "../lib_evil"));

    sh("nargo", ["compile", "--silence-warnings"], join(dir, "evil_64"));
    sh("nargo", ["compile", "--silence-warnings"], join(dir, "agg_64x2"));
    const evilJson = join(dir, "evil_64", "target", "evil_64.json");
    const evilVkDir = join(dir, "evil_64", "target", "vk");
    sh("bb", ["write_vk", "-b", evilJson, "-o", evilVkDir, "-t", "noir-recursive-no-zk"]);
    const pinned = fields(readFileSync(ensureVk("batch_64", "noir-recursive-no-zk").vkHash))[0];
    assert.notEqual(fields(readFileSync(join(evilVkDir, "vk_hash")))[0], pinned, "evil circuit must differ");

    // 66 payments, one of them to an unapproved vendor (in batch 2).
    const rows = Array.from({ length: 66 }, (_, i) => ({
      transaction: T(5000 + i),
      payer: A(1),
      payTo: i === 65 ? A(0xdead) : A(0xa0),
      amount: "1000",
      asset: A(0xc0),
      network: "base",
      timestamp: 1_788_220_900 + i,
    }));
    const log = ingestLog(rows);
    const vendors = ingestVendors({ salt: "0x01", vendors: [A(0xa0)] });
    const policyBase = { N: 64, budget: 10n ** 9n, discloseTotal: false, secret: 9n };
    const periodStart = 1_788_220_800;
    const periodEnd = 1_790_812_799;
    const boundaries = [log.payments[63].timestamp, periodEnd];

    const inners = [];
    let chainIn = 0n;
    for (let i = 0; i < 2; i++) {
      const slice = log.payments.slice(i * 64, (i + 1) * 64);
      const start = i === 0 ? periodStart : boundaries[0];
      const blind = 100n + BigInt(i);
      const b = buildBatch(log, vendors, { ...policyBase, periodStart: start, periodEnd: boundaries[i], chainIn, blind }, slice);
      writeFileSync(join(dir, "evil_64", `w${i}.toml`), b.toml);
      sh("nargo", ["execute", "--silence-warnings", "-p", `w${i}`, `w${i}`], join(dir, "evil_64"));
      const out = join(dir, `inner${i}`);
      sh("bb", ["prove", "-b", evilJson, "-w", join(dir, "evil_64", "target", `w${i}.gz`), "-k", join(evilVkDir, "vk"), "-o", out, "-t", "noir-recursive-no-zk"]);
      inners.push({ proofFields: fields(readFileSync(join(out, "proof"))), report: b.report, total: b.total, blind });
      chainIn = b.report.chainOut;
    }
    const verifyInner = spawnSync("bb", ["verify", "-k", join(evilVkDir, "vk"), "-p", join(dir, "inner1", "proof"), "-i", join(dir, "inner1", "public_inputs"), "-t", "noir-recursive-no-zk"]);
    assert.equal(verifyInner.status, 0, "sanity: the evil circuit proves a batch with an unapproved vendor");

    const policy = { payer: log.payer, asset: log.asset, chainId: log.chainId, periodStart, periodEnd, budget: 10n ** 9n, discloseTotal: false, chainIn: 0n };
    const evilVk = fields(readFileSync(join(evilVkDir, "vk")));
    const agg = buildAggregate(policy, evilVk, pinned, inners, boundaries, 77n);
    writeFileSync(join(dir, "agg_64x2", "attack.toml"), agg.toml);
    sh("nargo", ["execute", "--silence-warnings", "-p", "attack", "attack"], join(dir, "agg_64x2"));
    const aggJson = join(dir, "agg_64x2", "target", "agg_64x2.json");
    const aggVk = join(dir, "agg_vk");
    sh("bb", ["write_vk", "-b", aggJson, "-o", aggVk, "-t", "evm"]);
    const out = join(dir, "agg_out");
    // bb may refuse to prove, or prove something that does not verify; both mean the attack failed.
    const proved = spawnSync("bb", ["prove", "-b", aggJson, "-w", join(dir, "agg_64x2", "target", "attack.gz"), "-k", join(aggVk, "vk"), "-o", out, "-t", "evm"]);
    if (proved.status === 0) {
      const v = spawnSync("bb", ["verify", "-k", join(aggVk, "vk"), "-p", join(out, "proof"), "-i", join(out, "public_inputs"), "-t", "evm"]);
      assert.notEqual(v.status, 0, "an aggregate over a substituted inner circuit must not verify");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

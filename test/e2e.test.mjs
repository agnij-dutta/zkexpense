// End-to-end through the real CLI, nargo and bb. Uses the 64-payment circuit (a few seconds).
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const zk = (args, cwd) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });

test("prove -> verify, and tampering is caught", { timeout: 600_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "zkexpense-e2e-"));
  try {
    execFileSync(process.execPath, [CLI, "sample", "--count", "40", "--out", dir, "--seed", "3"]);
    const p = zk(
      [
        "prove",
        join(dir, "log-40.json"),
        "--vendors",
        join(dir, "vendors.json"),
        "--budget",
        "50",
        "--out",
        join(dir, "proof.json"),
      ],
      dir,
    );
    assert.equal(p.status, 0, p.stderr);
    const root = zk(["vendor-root", join(dir, "vendors.json")], dir).stdout.trim();

    const ok = zk(["verify", join(dir, "proof.json"), "--vendor-root", root], dir);
    assert.equal(ok.status, 0, ok.stdout);
    assert.match(ok.stdout, /\[ok\] proof valid/);

    // Wrong vendor root expectation
    const wrong = zk(["verify", join(dir, "proof.json"), "--vendor-root", "0x1234"], dir);
    assert.equal(wrong.status, 1);

    // Tamper with a public input: claim a bigger budget
    const pj = JSON.parse(readFileSync(join(dir, "proof.json"), "utf8"));
    pj.publicInputs[5] = "0x" + (10n ** 12n).toString(16).padStart(64, "0");
    pj.report.budget = (10n ** 12n).toString();
    writeFileSync(join(dir, "tampered.json"), JSON.stringify(pj));
    const bad = zk(["verify", join(dir, "tampered.json")], dir);
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /\[FAIL\] proof valid/);

    // Report text that disagrees with the public inputs is flagged
    const pj2 = JSON.parse(readFileSync(join(dir, "proof.json"), "utf8"));
    pj2.report.count = 1;
    writeFileSync(join(dir, "lying.json"), JSON.stringify(pj2));
    const lie = zk(["verify", join(dir, "lying.json")], dir);
    assert.match(lie.stdout, /\[FAIL\] report matches public inputs/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a payment to an unapproved vendor makes proving impossible", { timeout: 120_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "zkexpense-e2e-"));
  try {
    execFileSync(process.execPath, [CLI, "sample", "--count", "30", "--rogue", "1", "--out", dir, "--seed", "4"]);
    const p = zk(["prove", join(dir, "log-30.json"), "--vendors", join(dir, "vendors.json"), "--budget", "50"], dir);
    assert.equal(p.status, 4);
    assert.match(p.stderr, /not an approved vendor/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

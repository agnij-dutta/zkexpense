import { writeFileSync, readFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ensureVk, fromFields, verifyNative } from "./prover.mjs";
import { decodePublicInputs } from "./witness.mjs";

/** In-process UltraHonk verification via bb.js (optional dependency, same bb version). */
async function verifyBbJs(pj, vkPath, runs = 1) {
  let bbjs;
  try {
    bbjs = await import("@aztec/bb.js");
  } catch {
    return null;
  }
  const api = await bbjs.Barretenberg.new({ threads: 1 });
  try {
    const v = new bbjs.UltraHonkVerifierBackend(api);
    const pd = { proof: Buffer.from(pj.proof.slice(2), "hex"), publicInputs: pj.publicInputs, verificationKey: readFileSync(vkPath) };
    let ok = await v.verifyProof(pd, { verifierTarget: "evm" }); // warm-up (CRS + wasm/native init)
    const times = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      ok = (await v.verifyProof(pd, { verifierTarget: "evm" })) && ok;
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    return { ok, ms: times[Math.floor(times.length / 2)], minMs: times[0], engine: "bb.js (in-process)" };
  } catch {
    return { ok: false, ms: 0, minMs: 0, engine: "bb.js (in-process)" };
  } finally {
    await api.destroy();
  }
}

function verifyCli(pj, vkPath) {
  const dir = mkdtempSync(join(tmpdir(), "zkexpense-verify-"));
  try {
    const proofPath = join(dir, "proof");
    const piPath = join(dir, "public_inputs");
    writeFileSync(proofPath, Buffer.from(pj.proof.slice(2), "hex"));
    writeFileSync(piPath, fromFields(pj.publicInputs));
    const r = verifyNative(vkPath, proofPath, piPath, "evm");
    return { ...r, minMs: r.ms, engine: "bb CLI (incl. process start)" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Verifies a proof.json against the circuit's EVM verification key.
 * engine: "auto" (bb.js if installed, else bb CLI) | "cli" | "js"
 */
export async function verifyProofJson(pj, { engine = "auto", runs = 1 } = {}) {
  const { vk } = ensureVk(pj.circuit, "evm");
  let res = engine === "cli" ? null : await verifyBbJs(pj, vk, runs);
  if (!res) {
    if (engine === "js") throw new Error("@aztec/bb.js is not installed");
    res = verifyCli(pj, vk);
  }
  const report = decodePublicInputs(pj.publicInputs);
  // The human-readable report must be exactly what the public inputs say.
  const consistent = JSON.stringify(jsonable(report)) === JSON.stringify(pj.report);
  return { ...res, report, consistent };
}

function jsonable(o) {
  return JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
}

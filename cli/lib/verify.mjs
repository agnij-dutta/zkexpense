import { writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ensureVk, fromFields, verifyNative } from "./prover.mjs";
import { decodePublicInputs } from "./witness.mjs";

/** Verifies a proof.json with bb against the circuit's EVM verification key. */
export function verifyProofJson(pj) {
  const dir = mkdtempSync(join(tmpdir(), "zkexpense-verify-"));
  try {
    const proofPath = join(dir, "proof");
    const piPath = join(dir, "public_inputs");
    writeFileSync(proofPath, Buffer.from(pj.proof.slice(2), "hex"));
    writeFileSync(piPath, fromFields(pj.publicInputs));
    const { vk } = ensureVk(pj.circuit, "evm");
    const res = verifyNative(vk, proofPath, piPath, "evm");
    const report = decodePublicInputs(pj.publicInputs);
    // The human-readable report must be exactly what the public inputs say.
    const consistent = JSON.stringify(jsonable(report)) === JSON.stringify(pj.report);
    return { ...res, report, consistent };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function jsonable(o) {
  return JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
}

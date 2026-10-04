import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { toJson } from "./report.js";
import { ensureVk, fromFields, verifyNative } from "./toolchain.js";
import type { DecodedReport, ProofJson } from "./types.js";
import { decodePublicInputs } from "./witness.js";

export type VerifyEngine = "auto" | "js" | "cli";

export interface VerifyResult {
  ok: boolean;
  /** Median verification time over `runs` (ms). */
  ms: number;
  minMs: number;
  engine: string;
  report: DecodedReport;
  /** proof.json's human-readable `report` matches what the public inputs actually say. */
  consistent: boolean;
}

interface BbJsModule {
  Barretenberg: { new: (opts: { threads: number }) => Promise<{ destroy(): Promise<void> }> };
  UltraHonkVerifierBackend: new (api: unknown) => {
    verifyProof(
      data: { proof: Uint8Array; publicInputs: string[]; verificationKey: Uint8Array },
      opts: { verifierTarget: "evm" },
    ): Promise<boolean>;
  };
}

/** In-process verification with @aztec/bb.js (optional dependency, same bb version). Null if not installed. */
async function verifyBbJs(pj: ProofJson, vkPath: string, runs: number) {
  let bbjs: BbJsModule;
  try {
    bbjs = (await import("@aztec/bb.js")) as unknown as BbJsModule;
  } catch {
    return null;
  }
  const api = await bbjs.Barretenberg.new({ threads: 1 });
  try {
    const verifier = new bbjs.UltraHonkVerifierBackend(api);
    const data = {
      proof: Buffer.from(pj.proof.slice(2), "hex"),
      publicInputs: pj.publicInputs,
      verificationKey: readFileSync(vkPath),
    };
    const once = async () => {
      // bb.js throws on malformed proofs; for a verifier that is a rejection, not an error.
      try {
        return await verifier.verifyProof(data, { verifierTarget: "evm" });
      } catch {
        return false;
      }
    };
    let ok = await once(); // warm-up: native module and CRS initialisation
    const times: number[] = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      ok = (await once()) && ok;
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    return { ok, ms: times[Math.floor(times.length / 2)], minMs: times[0], engine: "bb.js (in-process)" };
  } finally {
    await api.destroy();
  }
}

function verifyCli(pj: ProofJson, vkPath: string) {
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

/** Verify a proof.json against its circuit's EVM verification key. */
export async function verifyProofJson(
  pj: ProofJson,
  { engine = "auto", runs = 1 }: { engine?: VerifyEngine; runs?: number } = {},
): Promise<VerifyResult> {
  if (!/^0x[0-9a-fA-F]*$/.test(pj.proof) || !Array.isArray(pj.publicInputs)) {
    throw new Error("not a zkexpense proof.json (missing proof or publicInputs)");
  }
  const { vk } = ensureVk(pj.circuit, "evm");
  let res = engine === "cli" ? null : await verifyBbJs(pj, vk, runs);
  if (!res) {
    if (engine === "js") throw new Error("@aztec/bb.js is not installed (npm install), or use --engine cli");
    res = verifyCli(pj, vk);
  }
  const report = decodePublicInputs(pj.publicInputs);
  const consistent = JSON.stringify(toJson(report)) === JSON.stringify(pj.report);
  return { ...res, report, consistent };
}

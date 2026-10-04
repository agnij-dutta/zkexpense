// Thin wrapper over the installed toolchain: nargo (witness generation) and bb (UltraHonk).
// Shelling out to the CLIs keeps zkExpense pinned to exactly the versions that generated the
// verification keys and Solidity verifiers, instead of a JS port that may drift.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Repository root (this file lives in dist/lib/ after the build). */
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const CIRCUITS_DIR = join(ROOT, "circuits");

/** bb verifier targets used here: final on-chain proofs, and inner proofs for aggregation. */
export type VerifierTarget = "evm" | "noir-recursive-no-zk";

interface ExecError {
  code?: string;
  stdout?: Buffer | string;
  stderr?: Buffer | string;
}

function run(cmd: string, args: string[], cwd?: string): string {
  try {
    return execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28 }).toString();
  } catch (e) {
    const err = e as ExecError;
    if (err.code === "ENOENT") throw new Error(`${cmd} not found on PATH; see README prerequisites`, { cause: e });
    const out = String(err.stdout ?? "") + String(err.stderr ?? "");
    throw new Error(`${cmd} ${args.join(" ")} failed:\n${out.split("\n").slice(-25).join("\n")}`, { cause: e });
  }
}

const now = (): number => performance.now();
const pkgDir = (pkg: string): string => join(CIRCUITS_DIR, pkg);

/** Path to the compiled ACIR artifact, compiling the circuit on first use. */
export function ensureCompiled(pkg: string): string {
  const artifact = join(pkgDir(pkg), "target", `${pkg}.json`);
  if (!existsSync(artifact)) run("nargo", ["compile", "--silence-warnings"], pkgDir(pkg));
  return artifact;
}

/** Paths to the verification key and its hash for a target, generating them on first use. */
export function ensureVk(pkg: string, target: VerifierTarget): { vk: string; vkHash: string } {
  const bytecode = ensureCompiled(pkg);
  const dir = join(pkgDir(pkg), "target", `vk_${target}`);
  if (!existsSync(join(dir, "vk"))) run("bb", ["write_vk", "-b", bytecode, "-o", dir, "-t", target]);
  return { vk: join(dir, "vk"), vkHash: join(dir, "vk_hash") };
}

/** Write `<name>.toml` into the circuit package and solve the witness with nargo. */
export function execute(pkg: string, toml: string, name: string): { witness: string; ms: number } {
  ensureCompiled(pkg);
  writeFileSync(join(pkgDir(pkg), `${name}.toml`), toml);
  const t0 = now();
  run("nargo", ["execute", "--silence-warnings", "-p", name, name], pkgDir(pkg));
  return { witness: join(pkgDir(pkg), "target", `${name}.gz`), ms: now() - t0 };
}

export interface ProveResult {
  ms: number;
  /** Peak RSS of bb in MB (macOS only, via /usr/bin/time -l), else null. */
  peakRssMb: number | null;
  proof: Buffer;
  publicInputs: Buffer;
}

/** Run `bb prove` for a solved witness. */
export function prove(pkg: string, witness: string, target: VerifierTarget, outDir: string): ProveResult {
  const { vk } = ensureVk(pkg, target);
  mkdirSync(outDir, { recursive: true });
  const args = ["prove", "-b", ensureCompiled(pkg), "-w", witness, "-k", vk, "-o", outDir, "-t", target];
  const timed = process.platform === "darwin" && existsSync("/usr/bin/time");
  const t0 = now();
  const r = timed
    ? spawnSync("/usr/bin/time", ["-l", "bb", ...args], { encoding: "utf8", maxBuffer: 1 << 28 })
    : spawnSync("bb", args, { encoding: "utf8", maxBuffer: 1 << 28 });
  const ms = now() - t0;
  if (r.error) throw new Error(`could not run bb: ${r.error.message}`, { cause: r.error });
  if (r.status !== 0) {
    const out = r.stdout + r.stderr;
    throw new Error(`bb prove failed:\n${out.split("\n").slice(-25).join("\n")}`);
  }
  const rssBytes = timed ? Number(/(\d+)\s+maximum resident set size/.exec(r.stderr)?.[1] ?? 0) : 0;
  return {
    ms,
    peakRssMb: rssBytes ? Math.round(rssBytes / (1 << 20)) : null,
    proof: readFileSync(join(outDir, "proof")),
    publicInputs: readFileSync(join(outDir, "public_inputs")),
  };
}

/**
 * `bb verify`. Returns ok=false only when bb ran and rejected the proof; a missing bb binary
 * throws, so a broken install is never reported as an invalid (or valid) proof.
 */
export function verifyNative(vkPath: string, proofPath: string, piPath: string, target: VerifierTarget = "evm") {
  const t0 = now();
  const r = spawnSync("bb", ["verify", "-k", vkPath, "-p", proofPath, "-i", piPath, "-t", target], { encoding: "utf8" });
  if (r.error) throw new Error(`could not run bb: ${r.error.message}`, { cause: r.error });
  return { ok: r.status === 0, ms: now() - t0 };
}

/** Split bb's binary output (concatenated 32-byte words) into 0x hex field strings. */
export function toFields(buf: Buffer): string[] {
  const out: string[] = [];
  for (let i = 0; i < buf.length; i += 32) out.push("0x" + buf.subarray(i, i + 32).toString("hex"));
  return out;
}

/** Inverse of toFields. */
export function fromFields(fields: readonly string[]): Buffer {
  return Buffer.concat(fields.map((f) => Buffer.from(BigInt(f).toString(16).padStart(64, "0"), "hex")));
}

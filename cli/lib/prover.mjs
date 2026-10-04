// Thin orchestration over the installed toolchain: nargo (witness) + bb (UltraHonk proofs).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const CIRCUITS = join(ROOT, "circuits");

function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28, ...opts }).toString();
  } catch (e) {
    const out = (e.stdout?.toString() ?? "") + (e.stderr?.toString() ?? "");
    throw new Error(`${cmd} ${args.join(" ")} failed:\n${out.split("\n").slice(-25).join("\n")}`);
  }
}

const now = () => performance.now();

export function pkgDir(pkg) {
  return join(CIRCUITS, pkg);
}

export function ensureCompiled(pkg) {
  const art = join(pkgDir(pkg), "target", `${pkg}.json`);
  if (!existsSync(art)) run("nargo", ["compile", "--silence-warnings"], { cwd: pkgDir(pkg) });
  return art;
}

/** target: "evm" (final, on-chain) or "noir-recursive-no-zk" (inner proofs for aggregation) */
export function ensureVk(pkg, target) {
  const bytecode = ensureCompiled(pkg);
  const dir = join(pkgDir(pkg), "target", `vk_${target}`);
  if (!existsSync(join(dir, "vk"))) run("bb", ["write_vk", "-b", bytecode, "-o", dir, "-t", target]);
  return { vk: join(dir, "vk"), vkHash: join(dir, "vk_hash") };
}

/** Writes inputs, runs nargo execute, returns witness path and timing. */
export function execute(pkg, toml, name) {
  ensureCompiled(pkg);
  writeFileSync(join(pkgDir(pkg), `${name}.toml`), toml);
  const t0 = now();
  run("nargo", ["execute", "--silence-warnings", "-p", name, name], { cwd: pkgDir(pkg) });
  return { witness: join(pkgDir(pkg), "target", `${name}.gz`), ms: now() - t0 };
}

export function prove(pkg, witness, target, outDir) {
  const { vk } = ensureVk(pkg, target);
  mkdirSync(outDir, { recursive: true });
  const t0 = now();
  run("bb", ["prove", "-b", ensureCompiled(pkg), "-w", witness, "-k", vk, "-o", outDir, "-t", target]);
  const ms = now() - t0;
  return {
    ms,
    proof: readFileSync(join(outDir, "proof")),
    publicInputs: readFileSync(join(outDir, "public_inputs")),
  };
}

/** Native verification with bb. Returns { ok, ms }. */
export function verifyNative(vkPath, proofPath, piPath, target = "evm") {
  const t0 = now();
  try {
    execFileSync("bb", ["verify", "-k", vkPath, "-p", proofPath, "-i", piPath, "-t", target], { stdio: "pipe" });
    return { ok: true, ms: now() - t0 };
  } catch {
    return { ok: false, ms: now() - t0 };
  }
}

export function toFields(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i += 32) out.push("0x" + buf.subarray(i, i + 32).toString("hex"));
  return out;
}

export function fromFields(fields) {
  return Buffer.concat(fields.map((f) => Buffer.from(BigInt(f).toString(16).padStart(64, "0"), "hex")));
}

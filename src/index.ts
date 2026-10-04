// Public library API. The CLI (src/cli.ts) is a thin layer over these functions.
export * from "./lib/types.js";
export { hash, hash2, merklePath, merkleRoot, toHex, P } from "./lib/hash.js";
export {
  V,
  chainIdOf,
  flattenX402,
  ingestLog,
  ingestVendors,
  leafHash,
  parseAmount,
  parseUsd,
  paymentSalt,
  splitTx,
  totalBlind,
  vendorRoot,
} from "./lib/model.js";
export {
  PUBLIC_INPUT_NAMES,
  buildAggregate,
  buildBatch,
  decodePublicInputs,
  expectedPublicInputs,
  type BatchOptions,
  type BatchWitness,
  type InnerBatch,
} from "./lib/witness.js";
export { AGG_CIRCUITS, CIRCUITS, SINGLE_CIRCUITS, circuitSpec, pickCircuit } from "./lib/circuits.js";
export { PolicyViolation, proveReport, toJson, type ProveOptions } from "./lib/report.js";
export { verifyProofJson, type VerifyEngine, type VerifyResult } from "./lib/verify.js";
export { checkDisclosure, disclose } from "./lib/disclose.js";
export { generateSample, USDC_BASE, type SampleData, type SampleOptions } from "./lib/sample.js";
export { ROOT, ensureCompiled, ensureVk, type VerifierTarget } from "./lib/toolchain.js";

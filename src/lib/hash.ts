// Poseidon2 sponge + Merkle helpers. Bit-for-bit mirror of circuits/lib/src/hash.nr.
import { permute } from "@zkpassport/poseidon2";

/** BN254 scalar field modulus. */
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TWO_64 = 18446744073709551616n;

/**
 * Poseidon2 sponge (t = 4, rate 3, capacity 1) with IV = len * 2^64 in the capacity lane.
 * This is the classic Noir `Poseidon2::hash` layout, so hash2(1, 2) matches it exactly.
 */
export function hash(inputs: readonly bigint[]): bigint {
  const len = inputs.length;
  let state = [0n, 0n, 0n, BigInt(len) * TWO_64];
  const chunks = Math.floor((len + 2) / 3);
  for (let c = 0; c < chunks; c++) {
    for (let j = 0; j < 3; j++) {
      const k = c * 3 + j;
      if (k < len) state[j] = (state[j] + inputs[k]) % P;
    }
    state = permute(state);
  }
  if (len === 0) state = permute(state);
  return state[0];
}

/** Two-to-one compression used for Merkle nodes and the payment hash chain. */
export const hash2 = (a: bigint, b: bigint): bigint => hash([a, b]);

/** Merkle root of a power-of-two sized array. */
export function merkleRoot(leaves: readonly bigint[]): bigint {
  if (leaves.length === 0 || leaves.length & (leaves.length - 1)) {
    throw new Error(`merkle width must be a power of two, got ${leaves.length}`);
  }
  let layer = [...leaves];
  while (layer.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) next.push(hash2(layer[i], layer[i + 1]));
    layer = next;
  }
  return layer[0];
}

/** Sibling path (bottom-up) for leaf `index`, for single-payment disclosure. */
export function merklePath(leaves: readonly bigint[], index: number): bigint[] {
  let layer = [...leaves];
  const path: bigint[] = [];
  let idx = index;
  while (layer.length > 1) {
    path.push(layer[idx ^ 1]);
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) next.push(hash2(layer[i], layer[i + 1]));
    layer = next;
    idx >>= 1;
  }
  return path;
}

/** 0x-prefixed, zero-padded 32-byte hex. */
export const toHex = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");

// Poseidon2 sponge + Merkle helpers. Bit-for-bit mirror of circuits/lib/src/lib.nr.
import { permute } from "@zkpassport/poseidon2";

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TWO_64 = 18446744073709551616n;

export function hash(inputs) {
  const L = inputs.length;
  let state = [0n, 0n, 0n, BigInt(L) * TWO_64];
  const chunks = Math.floor((L + 2) / 3);
  for (let c = 0; c < chunks; c++) {
    for (let j = 0; j < 3; j++) {
      const k = c * 3 + j;
      if (k < L) state[j] = (state[j] + BigInt(inputs[k])) % P;
    }
    state = permute(state);
  }
  if (L === 0) state = permute(state);
  return state[0];
}

export const hash2 = (a, b) => hash([a, b]);

export function merkleRoot(leaves) {
  let layer = leaves.map(BigInt);
  if (layer.length & (layer.length - 1)) throw new Error("merkle width must be a power of two");
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(hash2(layer[i], layer[i + 1]));
    layer = next;
  }
  return layer[0];
}

/** Sibling path for leaf `index` (bottom-up), for selective disclosure of one payment. */
export function merklePath(leaves, index) {
  let layer = leaves.map(BigInt);
  const path = [];
  let idx = index;
  while (layer.length > 1) {
    path.push(layer[idx ^ 1]);
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(hash2(layer[i], layer[i + 1]));
    layer = next;
    idx >>= 1;
  }
  return path;
}

export const toHex = (x) => "0x" + BigInt(x).toString(16).padStart(64, "0");

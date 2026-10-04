import test from "node:test";
import assert from "node:assert/strict";
import { hash, hash2, merklePath, merkleRoot, toHex } from "../cli/lib/hash.mjs";

test("sponge matches the Noir test vectors (circuits/lib test_hash_vectors_match_js)", () => {
  assert.equal(toHex(hash2(1n, 2n)), "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383");
  assert.equal(toHex(hash([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n])), "0x174b592c95a1811beff20ff96e1276cad3d155670a909f90c3658841f0f70fea");
});

test("merkle roots compose (aggregator invariant)", () => {
  const leaves = Array.from({ length: 16 }, (_, i) => BigInt(i * 7 + 1));
  const left = merkleRoot(leaves.slice(0, 8));
  const right = merkleRoot(leaves.slice(8));
  assert.equal(hash2(left, right), merkleRoot(leaves));
});

test("merkle path reconstructs the root (single-payment disclosure)", () => {
  const leaves = Array.from({ length: 8 }, (_, i) => BigInt(i + 100));
  const idx = 5;
  let node = leaves[idx];
  let i = idx;
  for (const sib of merklePath(leaves, idx)) {
    node = i & 1 ? hash2(sib, node) : hash2(node, sib);
    i >>= 1;
  }
  assert.equal(node, merkleRoot(leaves));
});

test("merkle rejects non power of two", () => {
  assert.throws(() => merkleRoot([1n, 2n, 3n]));
});

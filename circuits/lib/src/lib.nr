//! zkExpense core: one proof for a whole batch of agent payments.
//!
//! Statement proven for a batch of up to N payments (the first `count` slots are real,
//! the rest is zero padding):
//!   * every real payment was made by `payer`, in `asset`, on `chain_id`
//!   * every real payee is a member of the (salted) approved vendor set `vendor_root`
//!   * every real timestamp lies in [period_start, period_end], in non-decreasing order
//!   * total = sum(amounts); under_budget = total <= budget
//!   * log_root is the Poseidon2 Merkle root over the payment leaves (padding leaf = 0)
//!   * chain_out = H(...H(H(chain_in, leaf_0), leaf_1)..., leaf_{count-1}); this hash chain
//!     is what an on-chain settlement registry would track to stop the agent omitting payments
//! Amounts and payees stay private. The total is either disclosed or only committed to.

/// Size of the approved vendor table (padded with zero addresses).
pub global V: u32 = 256;
pub global V_DEPTH: u32 = 8;

/// Poseidon2 sponge (t = 4, rate 3, capacity 1) built on the stdlib permutation.
/// IV = len * 2^64 in the capacity lane, matching the classic Noir Poseidon2::hash layout.
/// Mirrored bit-for-bit in cli/lib/hash.mjs.
pub fn hash<let L: u32>(input: [Field; L]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, (L as Field) * 18446744073709551616];
    for chunk in 0..((L + 2) / 3) {
        for j in 0..3 {
            let k = chunk * 3 + j;
            if k < L {
                state[j] += input[k];
            }
        }
        state = std::hash::poseidon2_permutation(state, 4);
    }
    if L == 0 {
        state = std::hash::poseidon2_permutation(state, 4);
    }
    state[0]
}

pub fn hash2(a: Field, b: Field) -> Field {
    hash([a, b])
}

pub struct Payment {
    pub payee: Field,     // payTo address as a field
    pub amount: u64,      // atomic units (USDC: 6 decimals)
    pub timestamp: u64,   // settlement block timestamp (unix seconds)
    pub tx_hi: Field,     // settlement tx hash, high 128 bits
    pub tx_lo: Field,     // settlement tx hash, low 128 bits
    pub salt: Field,      // per-payment blinding, enables single-leaf disclosure later
    pub vendor_idx: u32,  // index of payee in the vendor table (witness hint)
}

pub struct Policy {
    pub payer: Field,
    pub asset: Field,
    pub chain_id: Field,
    pub period_start: u64,
    pub period_end: u64,
    pub budget: u128,
    pub disclose_total: bool,
    pub chain_in: Field,
}

pub struct Report {
    pub log_root: Field,
    pub vendor_root: Field,
    pub count: u32,
    pub under_budget: bool,
    pub disclosed_total: u128,
    pub total_commit: Field,
    pub chain_out: Field,
}

pub fn leaf_hash(policy: Policy, p: Payment) -> Field {
    hash(
        [
            policy.payer, p.payee, p.amount as Field, policy.asset, policy.chain_id,
            p.timestamp as Field, p.tx_hi, p.tx_lo, p.salt,
        ],
    )
}

/// Merkle root of a power-of-two sized array.
pub fn merkle_root<let N: u32>(leaves: [Field; N]) -> Field {
    let mut layer = leaves;
    let mut width = N;
    // log2(N) rounds, each halving the live width in place.
    for _ in 0..32 {
        if width > 1 {
            for i in 0..N / 2 {
                if i < width / 2 {
                    layer[i] = hash2(layer[2 * i], layer[2 * i + 1]);
                }
            }
            width = width / 2;
        }
    }
    layer[0]
}

pub fn vendor_root(vendors: [Field; V], vendor_salt: Field) -> Field {
    let mut leaves = [0; V];
    for i in 0..V {
        leaves[i] = if vendors[i] == 0 { 0 } else { hash2(vendors[i], vendor_salt) };
    }
    merkle_root(leaves)
}

pub fn prove_batch<let N: u32>(
    policy: Policy,
    payments: [Payment; N],
    count: u32,
    vendors: [Field; V],
    vendor_salt: Field,
    total_blind: Field,
) -> Report {
    assert(count <= N, "count exceeds batch size");
    assert(policy.period_start <= policy.period_end, "bad period");

    let mut leaves = [0; N];
    let mut total: u128 = 0;
    let mut chain = policy.chain_in;
    let mut last_ts: u64 = policy.period_start;

    for i in 0..N {
        let p = payments[i];
        if i < count {
            // Vendor membership: ROM lookup into the committed vendor table.
            assert(p.payee != 0, "zero payee");
            assert(vendors[p.vendor_idx] == p.payee, "payee not in approved vendor set");
            // Period + ordering.
            assert(p.timestamp >= last_ts, "timestamp out of order or before period");
            assert(p.timestamp <= policy.period_end, "timestamp after period");
            last_ts = p.timestamp;

            let leaf = leaf_hash(policy, p);
            leaves[i] = leaf;
            total += p.amount as u128;
            chain = hash2(chain, leaf);
        }
    }

    let under_budget = total <= policy.budget;
    Report {
        log_root: merkle_root(leaves),
        vendor_root: vendor_root(vendors, vendor_salt),
        count,
        under_budget,
        disclosed_total: if policy.disclose_total { total } else { 0 },
        total_commit: hash2(total as Field, total_blind),
        chain_out: chain,
    }
}

#[test]
fn test_merkle_small() {
    let r = merkle_root([1, 2, 3, 4]);
    assert(r == hash2(hash2(1, 2), hash2(3, 4)));
}

// ---------------------------------------------------------------------------------------------
// Recursive aggregation: K batch proofs -> one report over K * BATCH payments.
// ---------------------------------------------------------------------------------------------

/// Inner batch proofs are UltraHonk, non-ZK, Poseidon2 transcript (bb -t noir-recursive-no-zk).
/// They never leave the prover, so they do not need to hide anything; the outer proof is ZK.
pub global PROOF_TYPE_HONK: u32 = 0;
pub global INNER_VK_LEN: u32 = 115;
pub global INNER_PROOF_LEN: u32 = 457;
pub global PUBLIC_LEN: u32 = 15;

pub struct Inner {
    pub proof: [Field; INNER_PROOF_LEN],
    pub report: Report,
    pub total: u128,
    pub blind: Field,
}

pub fn public_inputs(policy: Policy, r: Report) -> [Field; PUBLIC_LEN] {
    [
        policy.payer, policy.asset, policy.chain_id, policy.period_start as Field,
        policy.period_end as Field, policy.budget as Field, policy.disclose_total as Field,
        policy.chain_in, r.log_root, r.vendor_root, r.count as Field, r.under_budget as Field,
        r.disclosed_total as Field, r.total_commit, r.chain_out,
    ]
}

pub fn aggregate<let K: u32>(
    policy: Policy,
    batch_size: u32,
    inner_vk: [Field; INNER_VK_LEN],
    inner_vk_hash: Field,
    pinned_vk_hash: Field,
    inners: [Inner; K],
    total_blind: Field,
) -> Report {
    // The inner circuit is pinned: a prover cannot swap in a friendlier circuit.
    assert(inner_vk_hash == pinned_vk_hash, "inner verification key is not the zkExpense batch circuit");

    let mut chain = policy.chain_in;
    let mut total: u128 = 0;
    let mut count: u32 = 0;
    let mut roots = [0; K];
    let vendor_root = inners[0].report.vendor_root;
    let mut prev_full = true;

    for i in 0..K {
        let inn = inners[i];
        // Each batch is proven under the same policy, chained through chain_in, and never discloses.
        let inner_policy = Policy {
            payer: policy.payer,
            asset: policy.asset,
            chain_id: policy.chain_id,
            period_start: policy.period_start,
            period_end: policy.period_end,
            budget: policy.budget,
            disclose_total: false,
            chain_in: chain,
        };
        std::verify_proof_with_type(
            inner_vk,
            inn.proof,
            public_inputs(inner_policy, inn.report),
            inner_vk_hash,
            PROOF_TYPE_HONK,
        );
        assert(inn.report.vendor_root == vendor_root, "batches use different vendor sets");
        assert(inn.report.disclosed_total == 0);
        assert(hash2(inn.total as Field, inn.blind) == inn.report.total_commit, "bad batch total opening");
        // Payments are packed: a batch may only be non-empty if every earlier batch is full.
        if !prev_full {
            assert(inn.report.count == 0, "batches are not packed");
        }
        prev_full = inn.report.count == batch_size;

        total += inn.total;
        count += inn.report.count;
        chain = inn.report.chain_out;
        roots[i] = inn.report.log_root;
    }

    Report {
        // Equals the flat Merkle root over all K * batch_size padded leaves.
        log_root: merkle_root(roots),
        vendor_root,
        count,
        under_budget: total <= policy.budget,
        disclosed_total: if policy.disclose_total { total } else { 0 },
        total_commit: hash2(total as Field, total_blind),
        chain_out: chain,
    }
}

// ---------------------------------------------------------------------------------------------
// Tests (nargo test). Small N keeps them fast; the logic is identical for every batch size.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_hash_vectors_match_js() {
    // Same vectors are asserted in test/hash.test.mjs. hash2(1,2) also equals the canonical
    // Noir Poseidon2::hash([1,2], 2), so the sponge is the standard one.
    assert(hash2(1, 2) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383);
    assert(
        hash([1, 2, 3, 4, 5, 6, 7, 8, 9])
            == 0x174b592c95a1811beff20ff96e1276cad3d155670a909f90c3658841f0f70fea,
    );
}

#[test]
fn test_merkle_composes() {
    // The aggregator relies on: root(root(a), root(b)) == root(a ++ b).
    let a = [1, 2, 3, 4];
    let b = [5, 6, 7, 8];
    let flat = merkle_root([1, 2, 3, 4, 5, 6, 7, 8]);
    assert(hash2(merkle_root(a), merkle_root(b)) == flat);
}

global VENDOR_A: Field = 0xaaaa;
global VENDOR_B: Field = 0xbbbb;
global ROGUE: Field = 0xdead;

fn t_policy(budget: u128, disclose: bool) -> Policy {
    Policy {
        payer: 0x1111,
        asset: 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913,
        chain_id: 8453,
        period_start: 1000,
        period_end: 2000,
        budget,
        disclose_total: disclose,
        chain_in: 0,
    }
}

fn t_vendors() -> [Field; V] {
    let mut v = [0; V];
    v[0] = VENDOR_A;
    v[1] = VENDOR_B;
    v
}

fn pay(payee: Field, amount: u64, ts: u64, idx: u32) -> Payment {
    Payment { payee, amount, timestamp: ts, tx_hi: ts as Field, tx_lo: amount as Field, salt: 7, vendor_idx: idx }
}

fn empty() -> Payment {
    Payment { payee: 0, amount: 0, timestamp: 0, tx_hi: 0, tx_lo: 0, salt: 0, vendor_idx: 0 }
}

#[test]
fn test_batch_happy_path() {
    let payments = [pay(VENDOR_A, 300, 1100, 0), pay(VENDOR_B, 500, 1200, 1), pay(VENDOR_A, 100, 1900, 0), empty()];
    let r = prove_batch(t_policy(1000, true), payments, 3, t_vendors(), 42, 9);
    assert(r.count == 3);
    assert(r.under_budget);
    assert(r.disclosed_total == 900);
    assert(r.total_commit == hash2(900, 9));
    let p = t_policy(1000, true);
    let leaves = [leaf_hash(p, payments[0]), leaf_hash(p, payments[1]), leaf_hash(p, payments[2]), 0];
    assert(r.log_root == merkle_root(leaves));
    assert(r.chain_out == hash2(hash2(hash2(0, leaves[0]), leaves[1]), leaves[2]));
}

#[test]
fn test_batch_hides_total_and_flags_over_budget() {
    let payments = [pay(VENDOR_A, 300, 1100, 0), pay(VENDOR_B, 800, 1200, 1), empty(), empty()];
    let r = prove_batch(t_policy(1000, false), payments, 2, t_vendors(), 42, 9);
    assert(!r.under_budget);
    assert(r.disclosed_total == 0);
}

#[test]
fn test_padding_is_ignored() {
    // Garbage in padding slots must not change anything.
    let a = [pay(VENDOR_A, 300, 1100, 0), empty(), empty(), empty()];
    let b = [pay(VENDOR_A, 300, 1100, 0), pay(ROGUE, 999999, 5, 9), pay(ROGUE, 1, 1, 3), empty()];
    let ra = prove_batch(t_policy(1000, true), a, 1, t_vendors(), 42, 9);
    let rb = prove_batch(t_policy(1000, true), b, 1, t_vendors(), 42, 9);
    assert(ra.log_root == rb.log_root);
    assert(ra.disclosed_total == rb.disclosed_total);
}

#[test(should_fail_with = "payee not in approved vendor set")]
fn test_rejects_unapproved_vendor() {
    let payments = [pay(VENDOR_A, 300, 1100, 0), pay(ROGUE, 5, 1200, 1), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 2, t_vendors(), 42, 9);
}

#[test(should_fail_with = "payee not in approved vendor set")]
fn test_rejects_lying_vendor_index() {
    let payments = [pay(VENDOR_A, 300, 1100, 1), empty(), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 1, t_vendors(), 42, 9);
}

#[test(should_fail_with = "zero payee")]
fn test_rejects_zero_payee_matching_padding_vendor() {
    let payments = [pay(0, 300, 1100, 5), empty(), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 1, t_vendors(), 42, 9);
}

#[test(should_fail_with = "timestamp after period")]
fn test_rejects_payment_after_period() {
    let payments = [pay(VENDOR_A, 300, 2001, 0), empty(), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 1, t_vendors(), 42, 9);
}

#[test(should_fail_with = "timestamp out of order or before period")]
fn test_rejects_payment_before_period() {
    let payments = [pay(VENDOR_A, 300, 999, 0), empty(), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 1, t_vendors(), 42, 9);
}

#[test(should_fail_with = "timestamp out of order or before period")]
fn test_rejects_unsorted_log() {
    let payments = [pay(VENDOR_A, 300, 1500, 0), pay(VENDOR_B, 1, 1400, 1), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 2, t_vendors(), 42, 9);
}

#[test(should_fail_with = "count exceeds batch size")]
fn test_rejects_count_overflow() {
    let payments = [empty(), empty(), empty(), empty()];
    let _ = prove_batch(t_policy(1000, false), payments, 5, t_vendors(), 42, 9);
}

#[test]
fn test_vendor_root_is_salted() {
    assert(vendor_root(t_vendors(), 1) != vendor_root(t_vendors(), 2));
}

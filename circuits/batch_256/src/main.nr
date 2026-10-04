use zkexpense_lib::{Payment, Policy, prove_batch, Report, V};

global N: u32 = 256;

fn main(
    policy: pub Policy,
    payments: [Payment; N],
    count: u32,
    vendors: [Field; V],
    vendor_salt: Field,
    total_blind: Field,
) -> pub Report {
    prove_batch(policy, payments, count, vendors, vendor_salt, total_blind)
}

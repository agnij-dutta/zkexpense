import type { CircuitName, CircuitSpec } from "./types.js";

/** Single-batch circuits, smallest first. Capacity = number of payment slots. */
export const SINGLE_CIRCUITS: CircuitSpec[] = ([64, 256, 512, 1024] as const).map((n) => ({
  name: `batch_${n}` as CircuitName,
  kind: "single",
  capacity: n,
  batch: n,
}));

/** Recursive aggregators: K inner batch proofs verified in-circuit. */
export const AGG_CIRCUITS: CircuitSpec[] = [
  { name: "agg_64x2", kind: "agg", inner: "batch_64", batch: 64, k: 2, capacity: 128 },
  { name: "agg_1024x4", kind: "agg", inner: "batch_1024", batch: 1024, k: 4, capacity: 4096 },
];

export const CIRCUITS: CircuitSpec[] = [...SINGLE_CIRCUITS, ...AGG_CIRCUITS];

export function circuitSpec(name: string): CircuitSpec {
  const spec = CIRCUITS.find((c) => c.name === name);
  if (!spec) throw new Error(`unknown circuit "${name}"; one of ${CIRCUITS.map((c) => c.name).join(", ")}`);
  return spec;
}

/**
 * Smallest single batch that fits, else the 4096-slot aggregator. A single batch is always
 * preferred: one in-circuit verification costs more gates than a whole 1024-payment batch.
 */
export function pickCircuit(payments: number, forced?: string): CircuitSpec {
  if (forced) {
    const spec = circuitSpec(forced);
    if (payments > spec.capacity) throw new Error(`${payments} payments exceed ${spec.name} capacity ${spec.capacity}`);
    return spec;
  }
  const spec =
    SINGLE_CIRCUITS.find((c) => c.capacity >= payments) ??
    AGG_CIRCUITS.find((c) => c.capacity >= payments && c.k === 4);
  if (!spec) throw new Error(`${payments} payments exceed the largest supported report (4096); split the period`);
  return spec;
}

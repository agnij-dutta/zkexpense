/** One settled x402 payment, normalized. Addresses and tx hashes are lowercase hex. */
export interface Payment {
  /** Settlement transaction hash (32 bytes). */
  transaction: string;
  payer: string;
  payTo: string;
  /** Atomic units of the asset (USDC: 6 decimals). Must fit in u64. */
  amount: bigint;
  asset: string;
  /** EVM chain id of the settlement network. */
  chainId: number;
  /** Settlement block timestamp, unix seconds. */
  timestamp: number;
}

/** A validated log for one payer wallet, one asset and one chain, sorted by settlement time. */
export interface PaymentLog {
  agentId: string | null;
  payer: string;
  asset: string;
  chainId: number;
  payments: Payment[];
}

/** Approved vendor set: deduplicated lowercase addresses plus the salt that hides the root. */
export interface VendorSet {
  addrs: string[];
  salt: bigint;
}

/** The public statement parameters of a report (first 8 public inputs). */
export interface Policy {
  payer: string;
  asset: string;
  chainId: number;
  periodStart: number;
  periodEnd: number;
  budget: bigint;
  discloseTotal: boolean;
  /** Hash-chain head before this report: 0 for an agent's first report, else the previous chainOut. */
  chainIn: bigint;
}

/** What the circuit outputs (last 7 public inputs). */
export interface Report {
  logRoot: bigint;
  vendorRoot: bigint;
  count: number;
  underBudget: boolean;
  disclosedTotal: bigint;
  totalCommit: bigint;
  chainOut: bigint;
}

/** All 15 public inputs, decoded for humans. Roots stay as 0x-prefixed 32-byte hex. */
export interface DecodedReport {
  payer: string;
  asset: string;
  chainId: number;
  periodStart: number;
  periodEnd: number;
  budget: bigint;
  discloseTotal: boolean;
  chainIn: string;
  logRoot: string;
  vendorRoot: string;
  count: number;
  underBudget: boolean;
  disclosedTotal: bigint;
  totalCommit: string;
  chainOut: string;
}

/** DecodedReport as stored in proof.json (bigints become decimal strings). */
export type DecodedReportJson = Omit<DecodedReport, "budget" | "disclosedTotal"> & {
  budget: string;
  disclosedTotal: string;
};

export type CircuitName = "batch_64" | "batch_256" | "batch_512" | "batch_1024" | "agg_64x2" | "agg_1024x4";

export interface CircuitSpec {
  name: CircuitName;
  kind: "single" | "agg";
  /** Maximum number of payments the circuit accepts. */
  capacity: number;
  /** Payments per (inner) batch. */
  batch: number;
  /** Aggregators only: inner batch circuit and number of inner proofs. */
  inner?: CircuitName;
  k?: number;
}

export interface ProofTimings {
  witnessMs: number;
  proveMs: number;
  peakRssMb: number | null;
  innerProveMs?: number[];
  aggregateProveMs?: number;
  totalMs?: number;
}

/** The file written by `zkexpense prove`. */
export interface ProofJson {
  version: 1;
  scheme: string;
  circuit: CircuitName;
  agentId: string | null;
  report: DecodedReportJson;
  /** 15 public inputs, 0x-prefixed 32-byte hex, in circuit order. */
  publicInputs: string[];
  /** UltraHonk proof bytes, 0x-prefixed hex. */
  proof: string;
  meta: {
    payments: number;
    proofBytes: number;
    timings: ProofTimings;
    createdAt: string;
  };
}

/** One payment opened against a report's log root. */
export interface Disclosure {
  logRoot: string;
  circuit: CircuitName;
  index: number;
  payment: {
    transaction: string;
    payer: string;
    payTo: string;
    amount: string;
    asset: string;
    chainId: number;
    timestamp: number;
  };
  salt: string;
  path: string[];
}

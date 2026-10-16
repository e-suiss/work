// T-5 T-34
import init, {
  apiVersion,
  compareApiVersions as wasmCompareApiVersions,
  deriveRecords as wasmDeriveRecords,
  evaluatePolicyChange as wasmEvaluatePolicyChange,
  evaluateSecuritySwitch as wasmEvaluateSecuritySwitch,
  validateRecord as wasmValidateRecord,
} from "../wasm/work_kernel_wasm.js";
import type {
  ChangeOutcome,
  PolicyDirection,
  SwitchBasis,
  SwitchOutcome,
  VersionOrder,
} from "../wasm/work_kernel_wasm.js";

export type { ChangeOutcome, PolicyDirection, SwitchBasis, SwitchOutcome, VersionOrder };

export type KernelSource = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface ApiVersion {
  readonly major: number;
  readonly minor: number;
}

export interface PolicyDefault {
  readonly direction: PolicyDirection;
  readonly min: bigint;
  readonly max: bigint;
}

export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/** A record as the `decoded` JSON projection of its CBOR: byte strings as lowercase hex, integers beyond 2^53 as decimal strings. */
export type DecodedRecord = Readonly<Record<string, JsonValue>>;

/** A digest as `[-16, hex]` (P-5). */
export type DigestJson = readonly [-16, string];

export type ActorType = "human" | "agent" | "system" | "machine" | "organization";
export type ActorTypeSource = "access_binding" | "declared_unverified";
export type ActorTypeEntry = readonly [ActorType, ActorTypeSource];

/** Verifier inputs that are not record bytes, in the record vector `context` shape (P-12, P-19, T-66). */
export interface RecordContext {
  readonly origin: "direct" | "automation";
  readonly actor_type: {
    readonly author: ActorTypeEntry;
    readonly on_behalf_of?: readonly ActorTypeEntry[];
  };
  readonly understood_extensions: readonly string[];
  readonly recorded_at?: number | string;
}

/** The kernel's decision about one record (P-11, P-19). */
export type Validation =
  | { readonly outcome: "accept" }
  | { readonly outcome: "reject" | "quarantine"; readonly reason: string };

/** One ledger record with the envelope facts derivation needs. */
export interface DerivationEntry {
  readonly id: DigestJson;
  readonly record: DecodedRecord;
  readonly position: number | string;
  readonly recorded_at: number | string;
  readonly ingest: "admitted" | readonly ["quarantined", string];
  readonly restriction: "no_objection" | "deny" | "require";
  readonly issuer: "local" | readonly ["federated", string];
}

/** Every input besides the records that the normative result depends on (P-31, T-6). */
export interface DerivationInputs {
  readonly protocol: readonly [number, number];
  readonly profile: number;
  readonly practices: Readonly<Record<string, DigestJson>>;
  readonly trusted_publishers: readonly string[];
  readonly ledger_time: number | string;
  readonly calendar: "continuous";
}

export type Admission = "admitted" | readonly ["quarantined" | "rejected", string];

export type Effect = "normative" | "conflicted" | readonly ["none", string];

export interface DerivedRecord {
  readonly id: DigestJson;
  readonly admission: Admission;
  readonly effect: Effect;
  readonly superseded_by: readonly DigestJson[];
}

export interface Chain {
  readonly root: DigestJson;
  readonly version: number;
  readonly heads: readonly DigestJson[];
  readonly status: "open" | "terminal" | "conflicted";
}

/** The derived view, in input order (P-31). */
export interface Derivation {
  readonly records: readonly DerivedRecord[];
  readonly chains: readonly Chain[];
}

/** Input the kernel bindings could not map, or a ledger order the kernel refuses; never a decision about a record. */
export class KernelInputError extends Error {
  readonly code: string;
  readonly detail: Readonly<Record<string, JsonValue>>;

  constructor(detail: Readonly<Record<string, JsonValue>>) {
    const code = typeof detail["code"] === "string" ? detail["code"] : "unknown";
    super(`kernel input error: ${code}`);
    this.name = "KernelInputError";
    this.code = code;
    this.detail = detail;
  }
}

export interface Kernel {
  readonly apiVersion: () => string;
  readonly compareApiVersions: (a: ApiVersion, b: ApiVersion) => VersionOrder;
  readonly evaluatePolicyChange: (
    policy: PolicyDefault,
    current: bigint,
    proposed: bigint,
  ) => ChangeOutcome;
  readonly evaluateSecuritySwitch: (
    current: boolean,
    proposed: boolean,
    basis: SwitchBasis,
  ) => SwitchOutcome;
  readonly validateRecord: (decoded: DecodedRecord, context: RecordContext) => Validation;
  readonly deriveRecords: (
    entries: readonly DerivationEntry[],
    inputs: DerivationInputs,
  ) => Derivation;
}

const U16_MAX = 0xffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function u16(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U16_MAX) {
    throw new RangeError(`${name} must be an integer in 0..=${String(U16_MAX)}`);
  }
  return value;
}

function u64(value: bigint, name: string): bigint {
  if (value < 0n || value > U64_MAX) {
    throw new RangeError(`${name} must be in 0..=${String(U64_MAX)}`);
  }
  return value;
}

function compareApiVersions(a: ApiVersion, b: ApiVersion): VersionOrder {
  return wasmCompareApiVersions(
    u16(a.major, "a.major"),
    u16(a.minor, "a.minor"),
    u16(b.major, "b.major"),
    u16(b.minor, "b.minor"),
  );
}

function evaluatePolicyChange(
  policy: PolicyDefault,
  current: bigint,
  proposed: bigint,
): ChangeOutcome {
  const outcome = wasmEvaluatePolicyChange(
    policy.direction,
    u64(policy.min, "min"),
    u64(policy.max, "max"),
    u64(current, "current"),
    u64(proposed, "proposed"),
  );
  if (outcome === undefined) {
    throw new TypeError(`unknown policy direction "${policy.direction}"`);
  }
  return outcome;
}

function evaluateSecuritySwitch(
  current: boolean,
  proposed: boolean,
  basis: SwitchBasis,
): SwitchOutcome {
  const outcome = wasmEvaluateSecuritySwitch(current, proposed, basis);
  if (outcome === undefined) {
    throw new TypeError(`unknown switch basis "${basis}"`);
  }
  return outcome;
}

interface Answer {
  readonly error?: Readonly<Record<string, JsonValue>>;
  readonly derivation?: Derivation;
}

function answer(text: string): Answer {
  const parsed = JSON.parse(text) as Answer;
  if (parsed.error !== undefined) {
    throw new KernelInputError(parsed.error);
  }
  return parsed;
}

function validateRecord(decoded: DecodedRecord, context: RecordContext): Validation {
  return answer(wasmValidateRecord(JSON.stringify(decoded), JSON.stringify(context))) as Validation;
}

function deriveRecords(entries: readonly DerivationEntry[], inputs: DerivationInputs): Derivation {
  const { derivation } = answer(wasmDeriveRecords(JSON.stringify(entries), JSON.stringify(inputs)));
  if (derivation === undefined) {
    throw new KernelInputError({ code: "no_derivation" });
  }
  return derivation;
}

let loading: Promise<Kernel> | undefined;

export function loadKernel(source?: KernelSource): Promise<Kernel> {
  loading ??= (source === undefined ? init() : init({ module_or_path: source })).then(
    (): Kernel => ({
      apiVersion,
      compareApiVersions,
      evaluatePolicyChange,
      evaluateSecuritySwitch,
      validateRecord,
      deriveRecords,
    }),
    (error: unknown) => {
      loading = undefined;
      throw error;
    },
  );
  return loading;
}

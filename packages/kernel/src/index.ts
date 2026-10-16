// T-5 T-34
import init, {
  apiVersion,
  compareApiVersions as wasmCompareApiVersions,
  evaluatePolicyChange as wasmEvaluatePolicyChange,
  evaluateSecuritySwitch as wasmEvaluateSecuritySwitch,
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

let loading: Promise<Kernel> | undefined;

export function loadKernel(source?: KernelSource): Promise<Kernel> {
  loading ??= (source === undefined ? init() : init({ module_or_path: source })).then(
    (): Kernel => ({
      apiVersion,
      compareApiVersions,
      evaluatePolicyChange,
      evaluateSecuritySwitch,
    }),
    (error: unknown) => {
      loading = undefined;
      throw error;
    },
  );
  return loading;
}

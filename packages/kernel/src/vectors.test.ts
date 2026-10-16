import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import type {
  ChangeOutcome,
  PolicyDirection,
  SwitchBasis,
  SwitchOutcome,
  VersionOrder,
} from "./index.js";
import { loadKernel } from "./index.js";

interface ApiVectors {
  readonly api_version: string;
  readonly compare: readonly {
    readonly id: string;
    readonly a: { readonly major: number; readonly minor: number };
    readonly b: { readonly major: number; readonly minor: number };
    readonly expected: VersionOrder;
  }[];
}

interface PolicyVectors {
  readonly change: readonly {
    readonly id: string;
    readonly direction: PolicyDirection;
    readonly min: string;
    readonly max: string;
    readonly current: string;
    readonly proposed: string;
    readonly expected: ChangeOutcome;
  }[];
  readonly switch: readonly {
    readonly id: string;
    readonly current: boolean;
    readonly proposed: boolean;
    readonly basis: SwitchBasis;
    readonly expected: SwitchOutcome;
  }[];
}

const vectors = new URL("../../../conformance/vectors/kernel/", import.meta.url);

async function load<T>(name: string): Promise<T> {
  return JSON.parse(await readFile(new URL(name, vectors), "utf8")) as T;
}

const kernel = loadKernel(
  await readFile(new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url)),
);
const api = await load<ApiVectors>("api-version.json");
const policy = await load<PolicyVectors>("policy-default.json");

// T-5 T-37
describe("t_5_t_37 WebAssembly kernel matches the shared vectors", () => {
  it("api version", async () => {
    expect((await kernel).apiVersion()).toBe(api.api_version);
  });

  it.each(api.compare)("compare $id", async ({ a, b, expected }) => {
    expect((await kernel).compareApiVersions(a, b)).toBe(expected);
  });

  it.each(policy.change)("policy change $id", async (c) => {
    const outcome = (await kernel).evaluatePolicyChange(
      { direction: c.direction, min: BigInt(c.min), max: BigInt(c.max) },
      BigInt(c.current),
      BigInt(c.proposed),
    );
    expect(outcome).toBe(c.expected);
  });

  it.each(policy.switch)("security switch $id", async (c) => {
    expect((await kernel).evaluateSecuritySwitch(c.current, c.proposed, c.basis)).toBe(c.expected);
  });
});

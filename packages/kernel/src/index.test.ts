import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { loadKernel } from "./index.js";

const wasm = new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url);

describe("loadKernel", () => {
  // T-5
  it("t_5 loads the module only once", async () => {
    const kernel = await loadKernel(await readFile(wasm));
    expect(await loadKernel()).toBe(kernel);
  });

  // T-34
  it("t_34 rejects values outside the kernel integer ranges", async () => {
    const kernel = await loadKernel(await readFile(wasm));
    const policy = { direction: "bounded", min: 0n, max: 10n } as const;
    expect(() => kernel.evaluatePolicyChange(policy, -1n, 1n)).toThrow(RangeError);
    expect(() => kernel.evaluatePolicyChange(policy, 1n, 1n << 64n)).toThrow(RangeError);
    expect(() =>
      kernel.compareApiVersions({ major: 0, minor: 1.5 }, { major: 0, minor: 0 }),
    ).toThrow(RangeError);
  });

  // T-34
  it("t_34 rejects names the kernel does not declare", async () => {
    const kernel = await loadKernel(await readFile(wasm));
    const direction = "loosest" as unknown as "bounded";
    expect(() => kernel.evaluatePolicyChange({ direction, min: 0n, max: 10n }, 1n, 2n)).toThrow(
      TypeError,
    );
    const basis = "implicit" as unknown as "unrecorded";
    expect(() => kernel.evaluateSecuritySwitch(true, false, basis)).toThrow(TypeError);
  });
});

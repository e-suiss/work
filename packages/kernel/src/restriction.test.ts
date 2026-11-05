import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { restrictionChecks } from "../e2e/restriction.js";
import { restriction } from "../e2e/vectors.js";
import * as raw from "../wasm/work_kernel_wasm.js";
import { KernelInputError, loadKernel } from "./index.js";

const kernel = await loadKernel(
  await readFile(new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url)),
);
const checks = restrictionChecks(kernel, raw, restriction);

// T-23 PR-17 PR-23 T-5 T-37
describe("t_23_pr_17 WebAssembly restriction engine matches the shared vectors", () => {
  it("runs every case through the raw export and the typed kernel", () => {
    expect(checks).toHaveLength(2 * restriction.cases.length);
  });

  it.each(checks)("$file $id", (c) => {
    expect(c.got).toBe(c.want);
  });
});

// T-23 PR-23 T-5
describe("t_23_pr_23 a rule set that does not compile is an input error, not a verdict", () => {
  it("throws restriction_compile_refused with the crate code", () => {
    const ruleSet = restriction.rule_sets["permit"];
    const request = restriction.cases[0]?.request;
    if (ruleSet === undefined || request === undefined) {
      throw new Error("no restriction vectors");
    }
    let caught: unknown;
    try {
      kernel.evaluateRestriction(ruleSet, request);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(KernelInputError);
    expect((caught as KernelInputError).code).toBe("restriction_compile_refused");
    expect((caught as KernelInputError).detail["code_detail"]).toBe("policy-permit");
  });
});

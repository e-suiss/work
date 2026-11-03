import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { byteChecks } from "../e2e/suite.js";
import { byteVectors } from "../e2e/vectors.js";
import * as raw from "../wasm/work_kernel_wasm.js";
import { KernelInputError, loadKernel } from "./index.js";

const kernel = await loadKernel(
  await readFile(new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url)),
);
const checks = byteChecks(kernel, raw, byteVectors);

// T-5 T-37 T-69 INV-7 INV-8 X-24 T-95
describe("t_5_t_37_inv_7 WebAssembly byte entry points match their vectors", () => {
  it("runs every record format vector file and the touched item vectors", () => {
    expect(new Set(checks.map((c) => c.file)).size).toBe(9);
  });

  it.each(checks)("$file $id", (c) => {
    expect(c.got).toBe(c.want);
  });
});

// T-5 T-34 T-69 T-95
describe("t_5_t_34 byte entry points raise kernel input errors instead of deciding", () => {
  it("rejects keys, proofs and integers the binding cannot map", () => {
    const keys = { party: "party:acme:alice", allowed: [-19], keys: [] };
    expect(() => kernel.verifyRecordSignature(new Uint8Array(), { ...keys, party: "" })).toThrow(
      KernelInputError,
    );
    const proof = { position: 0, size: 1, leaf: [-16, "00"], path: [], root: [-16, "00"] } as const;
    expect(() => kernel.verifyInclusion(proof)).toThrow(KernelInputError);
    expect(() => kernel.evidenceStatement(new Uint8Array(), -1)).toThrow(RangeError);
    expect(() => kernel.checkPublicKey(2 ** 31, new Uint8Array())).toThrow(RangeError);
    expect(() => kernel.checkPublicKey(-1, new Uint8Array(32))).toThrow(KernelInputError);
  });
});

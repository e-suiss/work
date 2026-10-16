import type {
  DecodedRecord,
  DerivationEntry,
  DerivationInputs,
  RecordContext,
} from "../src/index.js";

import { expect, test } from "./fixtures.js";
import {
  api,
  entries,
  expectedDerivation,
  inputs,
  kernelFiles,
  nativeOnlyRecordFiles,
  policy,
  recordCases,
  recordFiles,
  vectorFiles,
} from "./vectors.js";

// T-5 T-37
test.describe("t_5_t_37 browser WebAssembly kernel matches the shared kernel vectors", () => {
  test("every vector file is run in the browser or named as native only", async () => {
    const files = await vectorFiles();
    expect(files.kernel).toEqual([...kernelFiles].sort());
    expect(files.records).toEqual([...recordFiles, ...nativeOnlyRecordFiles].sort());
  });

  test("api-version.json", async ({ page }) => {
    const got = await page.evaluate(async (compare) => {
      const kernel = await window.workKernel.load();
      return {
        version: kernel.apiVersion(),
        compare: compare.map(({ a, b }) => kernel.compareApiVersions(a, b)),
      };
    }, api.compare);
    expect(got.version).toBe(api.api_version);
    api.compare.forEach((c, i) => {
      expect.soft(got.compare[i], c.id).toBe(c.expected);
    });
  });

  test("policy-default.json", async ({ page }) => {
    const got = await page.evaluate(
      async ({ change, flip }) => {
        const kernel = await window.workKernel.load();
        return {
          change: change.map((c) =>
            kernel.evaluatePolicyChange(
              { direction: c.direction, min: BigInt(c.min), max: BigInt(c.max) },
              BigInt(c.current),
              BigInt(c.proposed),
            ),
          ),
          flip: flip.map((c) => kernel.evaluateSecuritySwitch(c.current, c.proposed, c.basis)),
        };
      },
      { change: policy.change, flip: policy.switch },
    );
    policy.change.forEach((c, i) => {
      expect.soft(got.change[i], c.id).toBe(c.expected);
    });
    policy.switch.forEach((c, i) => {
      expect.soft(got.flip[i], c.id).toBe(c.expected);
    });
  });
});

// T-5 T-37 INV-7 INV-8 X-24
test.describe("t_5_t_37_inv_7 browser WebAssembly kernel matches every record vector", () => {
  test("covers accept, quarantine and reject", () => {
    const cases = Object.values(recordCases).flat();
    for (const outcome of ["accept", "quarantine", "reject"]) {
      expect(cases.some((c) => c.expect.outcome === outcome)).toBe(true);
    }
  });

  for (const file of recordFiles) {
    test(file, async ({ page }) => {
      const cases = recordCases[file];
      const texts = cases.map((c) => [JSON.stringify(c.decoded), JSON.stringify(c.context)]);
      const got = await page.evaluate(async (ts) => {
        const kernel = await window.workKernel.load();
        const { validateRecord } = window.workKernel.raw;
        return ts.map(([decoded = "", context = ""]) => ({
          raw: validateRecord(decoded, context),
          wrapped: kernel.validateRecord(
            JSON.parse(decoded) as DecodedRecord,
            JSON.parse(context) as RecordContext,
          ),
        }));
      }, texts);
      expect(got).toHaveLength(cases.length);
      cases.forEach((c, i) => {
        expect.soft(got[i]?.raw, c.id).toBe(JSON.stringify(c.expect));
        expect.soft(got[i]?.wrapped, c.id).toStrictEqual(c.expect);
      });
    });
  }
});

// T-5 T-37 INV-7 P-31
test.describe("t_5_t_37_inv_7 browser WebAssembly derivation matches the native bytes", () => {
  test("derives the accepted record chain byte for byte", async ({ page }) => {
    const got = await page.evaluate(
      async ([entries, inputs]) => {
        const kernel = await window.workKernel.load();
        return {
          raw: window.workKernel.raw.deriveRecords(entries, inputs),
          wrapped: JSON.stringify(
            kernel.deriveRecords(
              JSON.parse(entries) as DerivationEntry[],
              JSON.parse(inputs) as DerivationInputs,
            ),
          ),
        };
      },
      [JSON.stringify(entries), JSON.stringify(inputs)] as const,
    );
    expect(got.raw).toBe(expectedDerivation);
    expect({ derivation: JSON.parse(got.wrapped) as unknown }).toStrictEqual(
      JSON.parse(expectedDerivation),
    );
  });

  test("raises kernel input errors instead of deciding", async ({ page }) => {
    const first = recordCases["records.json"][0];
    if (first === undefined) {
      throw new Error("no record vectors");
    }
    const gap = entries.map((e, i) => (i === 1 ? { ...e, position: 99 } : e));
    const got = await page.evaluate(
      async (texts) => {
        const kernel = await window.workKernel.load();
        const gap = JSON.parse(texts.gap) as DerivationEntry[];
        const inputs = JSON.parse(texts.inputs) as DerivationInputs;
        const decoded = JSON.parse(texts.decoded) as DecodedRecord;
        const context = JSON.parse(texts.context) as RecordContext;
        const caught = (run: () => unknown): string => {
          try {
            run();
            return "no error";
          } catch (error) {
            return error instanceof Error ? error.name : "not an Error";
          }
        };
        const origin = "elsewhere" as unknown as "direct";
        return [
          caught(() => kernel.deriveRecords(gap, inputs)),
          caught(() => kernel.validateRecord(decoded, { ...context, origin })),
        ];
      },
      {
        gap: JSON.stringify(gap),
        inputs: JSON.stringify(inputs),
        decoded: JSON.stringify(first.decoded),
        context: JSON.stringify(first.context),
      },
    );
    expect(got).toEqual(["KernelInputError", "KernelInputError"]);
  });
});

const startupRuns = 5;

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

// T-44
test.describe("t_44 browser WebAssembly start-up time", () => {
  test("instantiate and first call in a fresh browser context", async ({
    browser,
    browserName,
  }) => {
    const first = recordCases["records.json"][0];
    if (first === undefined) {
      throw new Error("no record vectors");
    }
    const instantiate: number[] = [];
    const firstCall: number[] = [];
    for (let run = 0; run < startupRuns; run += 1) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto("/");
      await page.waitForFunction(() => "workKernel" in window);
      const got = await page.evaluate(
        async ([decoded, context]) => {
          const startup = await window.workKernel.startup(
            JSON.parse(decoded) as DecodedRecord,
            JSON.parse(context) as RecordContext,
          );
          return { ...startup, validation: JSON.stringify(startup.validation) };
        },
        [JSON.stringify(first.decoded), JSON.stringify(first.context)] as const,
      );
      await context.close();
      expect(got.validation).toBe(JSON.stringify(first.expect));
      instantiate.push(got.instantiateMs);
      firstCall.push(got.firstCallMs);
    }
    const line = `wasm start-up ${browserName}: instantiate median ${median(instantiate).toFixed(2)} ms (runs ${instantiate.map((t) => t.toFixed(2)).join(", ")}), first validateRecord median ${median(firstCall).toFixed(2)} ms`;
    test.info().annotations.push({ type: "T-44", description: line });
    console.log(line);
  });
});

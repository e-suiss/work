import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import type {
  DecodedRecord,
  DerivationEntry,
  DerivationInputs,
  DigestJson,
  RecordContext,
  Validation,
} from "./index.js";
import { KernelInputError, loadKernel } from "./index.js";
import { deriveRecords, validateRecord } from "../wasm/work_kernel_wasm.js";

interface RecordCase {
  readonly id: string;
  readonly decoded: DecodedRecord;
  readonly context: RecordContext;
  readonly expect: Validation;
}

interface Envelope {
  readonly decoded: {
    readonly pos: number;
    readonly record: DigestJson;
    readonly recorded_at: number;
    readonly ingest: DerivationEntry["ingest"];
  };
}

const vectors = new URL("../../../conformance/vectors/records/", import.meta.url);
const fixtures = new URL("../../../sdks/bindings/core/tests/fixtures/", import.meta.url);

async function text(base: URL, name: string): Promise<string> {
  return readFile(new URL(name, base), "utf8");
}

async function load<T>(name: string): Promise<T> {
  return JSON.parse(await text(vectors, name)) as T;
}

const kernel = await loadKernel(
  await readFile(new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url)),
);
const records = await load<{ records: RecordCase[]; envelopes: Envelope[] }>("records.json");
const rejects = await load<{ cases: RecordCase[] }>("records-reject.json");
const quarantine = await load<{ cases: RecordCase[] }>("records-quarantine.json");
const cases = [...records.records, ...rejects.cases, ...quarantine.cases];
const inputs = JSON.parse(await text(fixtures, "derive-inputs.json")) as DerivationInputs;
const expectedDerivation = (await text(fixtures, "derive-expected.json")).trimEnd();

const entries: DerivationEntry[] = records.records.map((r, i) => {
  const envelope = records.envelopes[i];
  if (envelope === undefined) {
    throw new Error(`no envelope for ${r.id}`);
  }
  const e = envelope.decoded;
  return {
    id: e.record,
    record: r.decoded,
    position: e.pos,
    recorded_at: e.recorded_at,
    ingest: e.ingest,
    restriction: "no_objection",
    issuer: "local",
  };
});

// T-5 T-37 INV-7 INV-8 X-24
describe("t_5_t_37_inv_7 WebAssembly kernel matches every record vector", () => {
  it("covers accept, quarantine and reject", () => {
    for (const outcome of ["accept", "quarantine", "reject"]) {
      expect(cases.some((c) => c.expect.outcome === outcome)).toBe(true);
    }
  });

  it.each(cases)("$id", (c) => {
    const decoded = JSON.stringify(c.decoded);
    const ctx = JSON.stringify(c.context);
    expect(JSON.parse(validateRecord(decoded, ctx))).toStrictEqual(c.expect);
    expect(kernel.validateRecord(c.decoded, c.context)).toStrictEqual(c.expect);
  });
});

// T-5 T-37 INV-7 P-31
describe("t_5_t_37_inv_7 WebAssembly derivation matches the native bytes", () => {
  it("derives the accepted record chain byte for byte", () => {
    expect(deriveRecords(JSON.stringify(entries), JSON.stringify(inputs))).toBe(expectedDerivation);
    expect({ derivation: kernel.deriveRecords(entries, inputs) }).toStrictEqual(
      JSON.parse(expectedDerivation),
    );
  });

  it("raises kernel input errors instead of deciding", () => {
    const gap = entries.map((e, i) => (i === 1 ? { ...e, position: 99 } : e));
    expect(() => kernel.deriveRecords(gap, inputs)).toThrow(KernelInputError);
    const origin = "elsewhere" as unknown as "direct";
    const first = cases[0];
    if (first === undefined) {
      throw new Error("no record vectors");
    }
    expect(() => kernel.validateRecord(first.decoded, { ...first.context, origin })).toThrow(
      KernelInputError,
    );
  });
});

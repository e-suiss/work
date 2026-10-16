// T-44
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

type Glue = typeof import("../wasm/work_kernel_wasm.js");

interface RecordCase {
  readonly id: string;
  readonly decoded: unknown;
  readonly context: unknown;
}

const runs = 10;
const wasmUrl = new URL("../wasm/work_kernel_wasm_bg.wasm", import.meta.url);
const vectors = JSON.parse(
  await readFile(
    new URL("../../../conformance/vectors/records/records.json", import.meta.url),
    "utf8",
  ),
) as { records: RecordCase[] };
const first = vectors.records[0];
if (first === undefined) {
  throw new Error("no record vectors");
}
const decoded = JSON.stringify(first.decoded);
const context = JSON.stringify(first.context);
const bytes = await readFile(wasmUrl);

const instantiate: number[] = [];
const firstCall: number[] = [];
for (let run = 0; run < runs; run += 1) {
  const glue = (await import(
    new URL(`../wasm/work_kernel_wasm.js?run=${String(run)}`, import.meta.url).href
  )) as Glue;
  const t0 = performance.now();
  await glue.default({ module_or_path: bytes });
  const t1 = performance.now();
  glue.validateRecord(decoded, context);
  const t2 = performance.now();
  instantiate.push(t1 - t0);
  firstCall.push(t2 - t1);
}

const steady = (await import(
  new URL("../wasm/work_kernel_wasm.js?run=steady", import.meta.url).href
)) as Glue;
await steady.default({ module_or_path: bytes });
const iterations = 2000;
const perCall: string[] = [];
for (const record of vectors.records) {
  const d = JSON.stringify(record.decoded);
  const c = JSON.stringify(record.context);
  const samples: number[] = [];
  for (let i = 0; i < iterations; i += 1) {
    const t0 = performance.now();
    steady.validateRecord(d, c);
    samples.push(performance.now() - t0);
  }
  perCall.push(`${record.id} ${(median(samples) * 1000).toFixed(1)} µs`);
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

const ms = (t: number): string => `${t.toFixed(2)} ms`;
console.log(
  `wasm start-up node ${process.version}: ${String(bytes.byteLength)} bytes; instantiate cold ${ms(instantiate[0] ?? Number.NaN)}, warm median ${ms(median(instantiate.slice(1)))}; first validateRecord (${first.id}) cold ${ms(firstCall[0] ?? Number.NaN)}, warm median ${ms(median(firstCall.slice(1)))}; ${String(runs - 1)} warm runs reuse the same Node process`,
);
console.log(
  `wasm validateRecord median per call over ${String(iterations)} calls: ${perCall.join("; ")}`,
);

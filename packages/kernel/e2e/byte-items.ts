// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import { Checks, accept, bytes, need, unknownProtocol } from "./checks.js";

export function touchedChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("items-touched.json");
  const records = [...vectors.records.records, ...vectors.quarantine.cases];
  for (const v of vectors.items.cases) {
    const vector = need(records.find((r) => r.id === v.id), v.id);
    const record = bytes(vector.hex);
    const want = accept({ touches: v.touches });
    c.same(v.id, raw.touched(record), kernel.touched(record), want);
  }
  for (const v of vectors.quarantine.cases) {
    if (unknownProtocol(v.expect)) {
      const record = bytes(v.hex);
      c.same(v.id, raw.touched(record), kernel.touched(record), v.expect);
    }
  }
  return c.all;
}

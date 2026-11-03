// P-48 P-49 P-51 P-52 T-5 T-37
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import { Checks, bytes } from "./checks.js";

export function mappingChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("mapping.json");
  for (const v of vectors.mapping.cases) {
    const record = bytes(v.hex);
    const context = JSON.stringify(v.context);
    c.same(v.id, raw.mapRecord(record, context), kernel.mapRecord(record, v.context), v.expect);
  }
  for (const v of vectors.mapping.reimport) {
    const record = bytes(v.hex);
    c.same(v.id, raw.decodeRecord(record), kernel.decodeRecord(record), v.expect);
  }
  return c.all;
}

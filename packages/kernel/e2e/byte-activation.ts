// T-5 T-37 INV-7 P-110
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import { ALLOWED, Checks, bytes, found } from "./checks.js";

export function activationChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("activation.json");
  for (const v of vectors.activation.cases) {
    const input = bytes(v.hex);
    c.same(v.id, raw.decodeEnvelope(input), kernel.decodeEnvelope(input), v.expect);
    if (v.entry_id !== undefined && v.leaf_hash !== undefined) {
      c.same(v.id, raw.recordId(input), kernel.recordId(input), found(v.entry_id));
      c.same(v.id, raw.leafHash(input), kernel.leafHash(input), found(v.leaf_hash));
    }
  }
  for (const v of vectors.activation.sequences) {
    const entries = v.entries.map(bytes);
    const got = raw.checkActivations(JSON.stringify(v.entries));
    c.same(v.id, got, kernel.checkActivations(entries), v.expect);
  }
  const keys = { party: "party:acme:operator", allowed: ALLOWED, keys: [] };
  for (const v of vectors.activation.verify) {
    const envelope = bytes(v.envelope);
    const record = bytes(v.record);
    const got = raw.verifyEntry(
      JSON.stringify(v.at),
      envelope,
      record,
      undefined,
      JSON.stringify(keys),
    );
    c.same(v.id, got, kernel.verifyEntry(v.at, envelope, record, undefined, keys), v.expect);
  }
  return c.all;
}

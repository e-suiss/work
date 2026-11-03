// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import { cborChecks, decodeChecks, digestChecks, signatureChecks } from "./byte-records.js";
import { entryChecks } from "./byte-entries.js";
import { touchedChecks } from "./byte-items.js";
import { proofChecks } from "./byte-proofs.js";

/** Every byte entry point of the kernel bindings against the vectors, through the raw WebAssembly exports and the package's typed kernel (T-5, T-37, T-69, INV-7, INV-8, X-24). */
export function byteChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  return [
    ...cborChecks(kernel, raw, vectors),
    ...digestChecks(kernel, raw, vectors),
    ...decodeChecks(kernel, raw, vectors),
    ...signatureChecks(kernel, raw, vectors),
    ...entryChecks(kernel, raw, vectors),
    ...proofChecks(kernel, raw, vectors),
    ...touchedChecks(kernel, raw, vectors),
  ];
}

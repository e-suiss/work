// T-5 T-37 T-44
import type { DecodedRecord, Kernel, RecordContext, Validation } from "../../src/index.js";
import { loadKernel } from "../../src/index.js";
import { deriveRecords, validateRecord } from "../../wasm/work_kernel_wasm.js";

/** Milliseconds from page code to a usable kernel, and to the first answer after it (T-44). */
export interface Startup {
  readonly instantiateMs: number;
  readonly firstCallMs: number;
  readonly validation: Validation;
}

/** What the page hands to the browser tests: the package's kernel and the raw WebAssembly exports. */
export interface KernelPage {
  readonly load: () => Promise<Kernel>;
  readonly startup: (decoded: DecodedRecord, context: RecordContext) => Promise<Startup>;
  readonly raw: {
    readonly validateRecord: typeof validateRecord;
    readonly deriveRecords: typeof deriveRecords;
  };
}

declare global {
  interface Window {
    workKernel: KernelPage;
  }
}

async function startup(decoded: DecodedRecord, context: RecordContext): Promise<Startup> {
  const t0 = performance.now();
  const kernel = await loadKernel();
  const t1 = performance.now();
  const validation = kernel.validateRecord(decoded, context);
  const t2 = performance.now();
  return { instantiateMs: t1 - t0, firstCallMs: t2 - t1, validation };
}

window.workKernel = {
  load: () => loadKernel(),
  startup,
  raw: { validateRecord, deriveRecords },
};

// T-23 PR-17 PR-23 T-5 T-37
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type {
  Kernel,
  RestrictionRequest,
  RestrictionRuleSet,
  RestrictionVerdict,
} from "../src/index.js";
import { KernelInputError } from "../src/index.js";
import type { Check } from "./byte-vectors.js";
import { Checks } from "./checks.js";

export interface RestrictionCase {
  readonly id: string;
  readonly rule_set: string;
  readonly request: RestrictionRequest;
  readonly expect: RestrictionVerdict | { readonly error: object };
}

/** The parsed `restriction.json` vector file. */
export interface RestrictionVectors {
  readonly rule_sets: Readonly<Record<string, RestrictionRuleSet>>;
  readonly cases: readonly RestrictionCase[];
}

function wrapped(run: () => RestrictionVerdict): unknown {
  try {
    return run();
  } catch (error) {
    if (error instanceof KernelInputError) {
      return { error: error.detail };
    }
    throw error;
  }
}

/** Every restriction vector through the raw WebAssembly export and the package's typed kernel. */
export function restrictionChecks(
  kernel: Kernel,
  raw: typeof Raw,
  vectors: RestrictionVectors,
): Check[] {
  const c = new Checks("restriction.json");
  for (const v of vectors.cases) {
    const ruleSet = vectors.rule_sets[v.rule_set];
    if (ruleSet === undefined) {
      throw new Error(`vector ${v.id} names an unknown rule set`);
    }
    c.same(
      v.id,
      raw.evaluateRestriction(JSON.stringify(ruleSet), JSON.stringify(v.request)),
      wrapped(() => kernel.evaluateRestriction(ruleSet, v.request)),
      v.expect,
    );
  }
  return c.all;
}

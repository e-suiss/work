// T-5 T-37 INV-7
import { readdir, readFile } from "node:fs/promises";

import type {
  ChangeOutcome,
  DecodedRecord,
  DerivationEntry,
  DerivationInputs,
  DigestJson,
  PolicyDirection,
  RecordContext,
  SwitchBasis,
  SwitchOutcome,
  Validation,
  VersionOrder,
} from "../src/index.js";
import type { ByteVectors } from "./byte-vectors.js";

export interface ApiVectors {
  readonly api_version: string;
  readonly compare: readonly {
    readonly id: string;
    readonly a: { readonly major: number; readonly minor: number };
    readonly b: { readonly major: number; readonly minor: number };
    readonly expected: VersionOrder;
  }[];
}

export interface PolicyVectors {
  readonly change: readonly {
    readonly id: string;
    readonly direction: PolicyDirection;
    readonly min: string;
    readonly max: string;
    readonly current: string;
    readonly proposed: string;
    readonly expected: ChangeOutcome;
  }[];
  readonly switch: readonly {
    readonly id: string;
    readonly current: boolean;
    readonly proposed: boolean;
    readonly basis: SwitchBasis;
    readonly expected: SwitchOutcome;
  }[];
}

export interface RecordCase {
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

const kernelDir = new URL("../../../conformance/vectors/kernel/", import.meta.url);
const recordsDir = new URL("../../../conformance/vectors/records/", import.meta.url);

/** Record vector files the browser runs through `validateRecord` and `deriveRecords` on their `decoded` projection. */
export const recordFiles = [
  "records.json",
  "records-reject.json",
  "records-quarantine.json",
] as const;

/** Record vector files the browser runs only through the byte entry points. */
export const byteRecordFiles = [
  "cbor-canonical.json",
  "cose-sign1.json",
  "digest.json",
  "evidence.json",
  "genesis.json",
  "merkle.json",
] as const;

/** Kernel vector files the browser runs. */
export const kernelFiles = [
  "api-version.json",
  "derive-expected.json",
  "derive-inputs.json",
  "items-touched.json",
  "policy-default.json",
] as const;

async function json<T>(base: URL, name: string): Promise<T> {
  return JSON.parse(await readFile(new URL(name, base), "utf8")) as T;
}

async function jsonFiles(dir: URL): Promise<string[]> {
  return (await readdir(dir)).filter((name) => name.endsWith(".json")).sort();
}

/** Every `*.json` file in the kernel and record vector directories. */
export async function vectorFiles(): Promise<{ kernel: string[]; records: string[] }> {
  return { kernel: await jsonFiles(kernelDir), records: await jsonFiles(recordsDir) };
}

export const api = await json<ApiVectors>(kernelDir, "api-version.json");
export const policy = await json<PolicyVectors>(kernelDir, "policy-default.json");

const records = await json<{ records: RecordCase[]; envelopes: Envelope[] }>(
  recordsDir,
  "records.json",
);
const rejects = await json<{ cases: RecordCase[] }>(recordsDir, "records-reject.json");
const quarantine = await json<{ cases: RecordCase[] }>(recordsDir, "records-quarantine.json");

/** Record cases per vector file, in file order. */
export const recordCases: Readonly<Record<(typeof recordFiles)[number], readonly RecordCase[]>> = {
  "records.json": records.records,
  "records-reject.json": rejects.cases,
  "records-quarantine.json": quarantine.cases,
};

/** The accepted records of `records.json` with their envelope facts, as the derivation golden feeds them. */
export const entries: readonly DerivationEntry[] = records.records.map((r, i) => {
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

export const inputs = await json<DerivationInputs>(kernelDir, "derive-inputs.json");

/** The native derivation bytes, without the trailing newline. */
export const expectedDerivation = (
  await readFile(new URL("derive-expected.json", kernelDir), "utf8")
).trimEnd();

/** Every record format vector file and the touched item vectors, for the byte entry points (T-5, T-37). */
export const byteVectors: ByteVectors = {
  cbor: await json<ByteVectors["cbor"]>(recordsDir, "cbor-canonical.json"),
  cose: await json<ByteVectors["cose"]>(recordsDir, "cose-sign1.json"),
  digest: await json<ByteVectors["digest"]>(recordsDir, "digest.json"),
  evidence: await json<ByteVectors["evidence"]>(recordsDir, "evidence.json"),
  genesis: await json<ByteVectors["genesis"]>(recordsDir, "genesis.json"),
  merkle: await json<ByteVectors["merkle"]>(recordsDir, "merkle.json"),
  records: await json<ByteVectors["records"]>(recordsDir, "records.json"),
  quarantine: await json<ByteVectors["quarantine"]>(recordsDir, "records-quarantine.json"),
  rejects: await json<ByteVectors["rejects"]>(recordsDir, "records-reject.json"),
  items: await json<ByteVectors["items"]>(kernelDir, "items-touched.json"),
};

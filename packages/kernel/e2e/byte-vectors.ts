// T-5 T-37 INV-7
import type {
  DecodedRecord,
  DigestJson,
  JsonObject,
  JsonValue,
  MappingContext,
  RecordContext,
  Touch,
  Validation,
} from "../src/index.js";

export interface Expect {
  readonly outcome: string;
  readonly reason?: string;
}

export interface Filler {
  readonly fill_hex: string;
  readonly fill_count: number;
}

export interface CborGenerator extends Filler {
  readonly head_hex: string;
}

export interface CborCase {
  readonly id: string;
  readonly hex?: string;
  readonly generator?: CborGenerator;
  readonly context: { readonly tag_allowlist: readonly number[] };
  readonly expect: Expect;
}

export interface DigestCase {
  readonly id: string;
  readonly encoded_digest_hex?: string;
  readonly digest_hex?: string;
  readonly expect?: Expect;
  readonly salt_hex?: string;
  readonly part?: {
    readonly name: string;
    readonly media_type: string;
    readonly content_hex?: string;
    readonly content?: Filler;
  };
  readonly cose_hex?: string;
  readonly kid_hex?: string;
  readonly public_key_hex?: string;
  readonly record_id_hex?: string;
}

export interface GenesisCase {
  readonly id: string;
  readonly hex: string;
  readonly decoded: JsonObject;
  readonly expect: Expect;
  readonly ledger_id?: { readonly digest_hex: string };
  readonly leaf_hash?: string;
}

export interface EnvelopeDecoded {
  readonly pos: number;
  readonly record: DigestJson;
  readonly ledger: DigestJson;
  readonly recorded_at: number;
  readonly ingest: JsonValue;
}

export interface EnvelopeVector {
  readonly id?: string;
  readonly hex: string;
  readonly leaf_hash: string;
  readonly decoded: EnvelopeDecoded;
}

export interface RecordVector {
  readonly id: string;
  readonly hex: string;
  readonly decoded: DecodedRecord;
  readonly context: RecordContext;
  readonly record_digest: string;
  readonly expect: Validation;
}

export interface LedgerVector extends RecordVector {
  readonly envelope: EnvelopeVector;
}

export interface MappingCase {
  readonly id: string;
  readonly hex: string;
  readonly context: MappingContext;
  readonly expect: JsonObject;
}

export interface ReimportCase {
  readonly id: string;
  readonly hex: string;
  readonly expect: Expect;
}

export interface ItemsCase {
  readonly id: string;
  readonly touches: readonly Touch[];
}

export interface CoseKey {
  readonly id: string;
  readonly party: string;
  readonly alg: number;
  readonly kid_hex: string;
  readonly public_key_hex: string;
}

export interface CoseCase {
  readonly id: string;
  readonly author: string;
  readonly cose_hex: string;
  readonly envelope?: string;
  readonly record_id_hex?: string;
  readonly proof_commit_hex?: string;
  readonly expect: Expect;
}

export interface KeyCase {
  readonly id: string;
  readonly alg: number;
  readonly public_key_hex: string;
  readonly expect: Expect;
}

export interface EvidenceCase {
  readonly id: string;
  readonly hex: string;
  readonly decoded: DecodedRecord;
  readonly evidence_index?: number;
  readonly statement_hex?: string;
  readonly presenter?: string;
  readonly cose_hex?: string;
  readonly expect: Expect;
}

export interface NoteKeyVector {
  readonly name: string;
  readonly public_key_hex: string;
}

export interface CheckpointExpect extends Expect {
  readonly size?: number;
  readonly root_hex?: string;
  readonly profile?: readonly string[];
  readonly cosignatures?: readonly JsonObject[];
}

export interface CheckpointCase {
  readonly id: string;
  readonly origin: string;
  readonly note: string;
  readonly expect: CheckpointExpect;
}

export interface InclusionCase {
  readonly id: string;
  readonly index: number;
  readonly size: number;
  readonly leaf_hash_hex: string;
  readonly path_hex: readonly string[];
  readonly root_hex: string;
  readonly expect: Expect;
}

export interface ConsistencyCase {
  readonly id: string;
  readonly first: number;
  readonly second: number;
  readonly first_root_hex: string;
  readonly second_root_hex: string;
  readonly path_hex: readonly string[];
  readonly expect: Expect;
}

/** The parsed record format, touched item and mapping vector files the byte entry points run against. */
export interface ByteVectors {
  readonly cbor: { readonly cases: readonly CborCase[] };
  readonly cose: {
    readonly keys: readonly CoseKey[];
    readonly cases: readonly CoseCase[];
    readonly key_cases: readonly KeyCase[];
  };
  readonly digest: { readonly cases: readonly DigestCase[] };
  readonly evidence: { readonly cases: readonly EvidenceCase[] };
  readonly genesis: { readonly cases: readonly GenesisCase[] };
  readonly merkle: {
    readonly nodes: readonly {
      readonly id: string;
      readonly left_hex: string;
      readonly right_hex: string;
      readonly digest_hex: string;
    }[];
    readonly roots: readonly { readonly size: number; readonly root_hex: string }[];
    readonly inclusion: readonly InclusionCase[];
    readonly consistency: readonly ConsistencyCase[];
    readonly keys: { readonly log: NoteKeyVector; readonly witnesses: readonly NoteKeyVector[] };
    readonly checkpoints: readonly CheckpointCase[];
  };
  readonly records: {
    readonly records: readonly RecordVector[];
    readonly envelopes: readonly EnvelopeVector[];
  };
  readonly quarantine: {
    readonly cases: readonly LedgerVector[];
  };
  readonly rejects: { readonly cases: readonly RecordVector[] };
  readonly items: { readonly cases: readonly ItemsCase[] };
  readonly mapping: {
    readonly cases: readonly MappingCase[];
    readonly reimport: readonly ReimportCase[];
  };
}

/** One answer of a binding entry point next to the answer its vector states, both as compact JSON with sorted keys. */
export interface Check {
  readonly file: string;
  readonly id: string;
  readonly got: string;
  readonly want: string;
}

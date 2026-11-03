// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type {
  DecodedRecord,
  DigestJson,
  JsonObject,
  JsonValue,
  Kernel,
  PartyKey,
  PartyKeys,
  RecordContext,
  Touch,
  Validation,
} from "../src/index.js";

interface Expect {
  readonly outcome: string;
  readonly reason?: string;
}

interface Filler {
  readonly fill_hex: string;
  readonly fill_count: number;
}

interface CborCase {
  readonly id: string;
  readonly hex?: string;
  readonly generator?: Filler & { readonly head_hex: string };
  readonly context: { readonly tag_allowlist: readonly number[] };
  readonly expect: Expect;
}

interface DigestCase {
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

interface GenesisCase {
  readonly id: string;
  readonly hex: string;
  readonly decoded: JsonObject;
  readonly expect: Expect;
  readonly ledger_id?: { readonly digest_hex: string };
  readonly leaf_hash?: string;
}

interface EnvelopeVector {
  readonly id?: string;
  readonly hex: string;
  readonly leaf_hash: string;
  readonly decoded: JsonObject & {
    readonly pos: number;
    readonly record: DigestJson;
    readonly ledger: DigestJson;
    readonly recorded_at: number;
    readonly ingest: JsonValue;
  };
}

interface RecordVector {
  readonly id: string;
  readonly hex: string;
  readonly decoded: DecodedRecord;
  readonly context: RecordContext;
  readonly record_digest: string;
  readonly expect: Validation;
}

interface CoseKey {
  readonly id: string;
  readonly party: string;
  readonly alg: number;
  readonly kid_hex: string;
  readonly public_key_hex: string;
}

interface CoseCase {
  readonly id: string;
  readonly author: string;
  readonly cose_hex: string;
  readonly envelope?: string;
  readonly record_id_hex?: string;
  readonly proof_commit_hex?: string;
  readonly expect: Expect;
}

interface KeyCase {
  readonly id: string;
  readonly alg: number;
  readonly public_key_hex: string;
  readonly expect: Expect;
}

interface EvidenceCase {
  readonly id: string;
  readonly hex: string;
  readonly decoded: DecodedRecord;
  readonly evidence_index?: number;
  readonly statement_hex?: string;
  readonly presenter?: string;
  readonly cose_hex?: string;
  readonly expect: Expect;
}

interface NoteKeyVector {
  readonly name: string;
  readonly public_key_hex: string;
}

interface CheckpointCase {
  readonly id: string;
  readonly origin: string;
  readonly note: string;
  readonly expect: Expect & {
    readonly size?: number;
    readonly root_hex?: string;
    readonly profile?: readonly string[];
    readonly cosignatures?: readonly JsonObject[];
  };
}

interface InclusionCase {
  readonly id: string;
  readonly index: number;
  readonly size: number;
  readonly leaf_hash_hex: string;
  readonly path_hex: readonly string[];
  readonly root_hex: string;
  readonly expect: Expect;
}

interface ConsistencyCase {
  readonly id: string;
  readonly first: number;
  readonly second: number;
  readonly first_root_hex: string;
  readonly second_root_hex: string;
  readonly path_hex: readonly string[];
  readonly expect: Expect;
}

/** The parsed record format and touched item vector files the byte entry points run against. */
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
    readonly cases: readonly (RecordVector & { readonly envelope: EnvelopeVector })[];
  };
  readonly rejects: { readonly cases: readonly RecordVector[] };
  readonly items: { readonly cases: readonly { readonly id: string; readonly touches: Touch[] }[] };
}

/** One answer of a binding entry point next to the answer its vector states, both as compact JSON with sorted keys. */
export interface Check {
  readonly file: string;
  readonly id: string;
  readonly got: string;
  readonly want: string;
}

const ALLOWED = [-19, -9, -7] as const;
const COSE_SIGN1_TAG = 18;
const DIGEST_PREFIX = "822f5820";
const SHA256_OF_NOTHING = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** Compact JSON with object keys sorted, as the kernel bindings write it. */
export function sortedJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

function bytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function filled(head: string, filler: Filler): Uint8Array {
  return bytes(head + filler.fill_hex.repeat(filler.fill_count));
}

function digest(hex: string): DigestJson {
  return [-16, hex];
}

function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`vector without ${what}`);
  }
  return value;
}

function accept(fields: object = {}): object {
  return { ...fields, outcome: "accept" };
}

function unknownProtocol(expect: Expect): boolean {
  return expect.outcome === "quarantine" && expect.reason === "protocol_version_unknown";
}

function found(hex: string): { readonly digest: DigestJson } {
  return { digest: digest(hex) };
}

class Checks {
  readonly all: Check[] = [];

  constructor(private readonly file: string) {}

  same(id: string, raw: string, wrapped: unknown, want: unknown): void {
    const expected = sortedJson(want);
    this.all.push({ file: this.file, id, got: raw, want: expected });
    const typed = sortedJson(wrapped);
    this.all.push({ file: this.file, id: `${id} (wrapped)`, got: typed, want: expected });
  }
}

function keySets(vectors: ByteVectors): Map<string, PartyKey[]> {
  const sets = new Map<string, PartyKey[]>();
  for (const k of vectors.cose.keys) {
    const list = sets.get(k.party) ?? [];
    list.push({ kid: k.kid_hex, alg: k.alg, public_key: k.public_key_hex });
    sets.set(k.party, list);
  }
  return sets;
}

function keysOf(sets: Map<string, PartyKey[]>, party: string): PartyKeys {
  return { party, allowed: ALLOWED, keys: sets.get(party) ?? [] };
}

function ledger(vectors: ByteVectors): (RecordVector & { readonly envelope: EnvelopeVector })[] {
  const out = vectors.records.records.map((r, i) => ({
    ...r,
    envelope: need(vectors.records.envelopes[i], `envelope ${r.id}`),
  }));
  return [...out, ...vectors.quarantine.cases];
}

function cborChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("cbor-canonical.json");
  for (const v of vectors.cbor.cases) {
    const g = v.generator;
    const input = g === undefined ? bytes(need(v.hex, "hex")) : filled(g.head_hex, g);
    const tags = v.context.tag_allowlist;
    if (tags.includes(COSE_SIGN1_TAG) && input[0] === 0xd2) {
      c.same(v.id, raw.parseCoseContainer(input), kernel.parseCoseContainer(input), v.expect);
    } else {
      c.same(
        v.id,
        raw.checkCbor(input, JSON.stringify(tags)),
        kernel.checkCbor(input, tags),
        v.expect,
      );
    }
  }
  return c.all;
}

function digestChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("digest.json");
  const first = need(vectors.records.records[0], "records");
  const envelope = need(vectors.records.envelopes[0], "envelopes");
  for (const v of vectors.digest.cases) {
    if (v.encoded_digest_hex !== undefined) {
      const input = bytes(v.encoded_digest_hex);
      const want = v.digest_hex === undefined ? v.expect : accept(found(v.digest_hex));
      c.same(v.id, raw.decodeDigest(input), kernel.decodeDigest(input), want);
    } else if (v.part !== undefined) {
      const salt = bytes(need(v.salt_hex, "salt"));
      const hex = v.part.content_hex;
      const content = hex === undefined ? filled("", need(v.part.content, "content")) : bytes(hex);
      const { name, media_type: media } = v.part;
      c.same(
        v.id,
        raw.bodyCommitment(salt, name, media, content),
        kernel.bodyCommitment(salt, name, media, content),
        accept(found(need(v.digest_hex, "digest"))),
      );
    } else if (v.id === "digest/record-id") {
      const input = bytes(first.hex);
      c.same(v.id, raw.recordId(input), kernel.recordId(input), found(need(v.digest_hex, "d")));
    } else if (v.id === "digest/leaf-0x00") {
      const input = bytes(envelope.hex);
      c.same(v.id, raw.leafHash(input), kernel.leafHash(input), found(need(v.digest_hex, "d")));
    } else if (v.id === "digest/proof-commit") {
      const cose = bytes(need(v.cose_hex, "cose"));
      c.same(v.id, raw.proofCommit(cose), kernel.proofCommit(cose), found(need(v.digest_hex, "d")));
      const keys: PartyKeys = {
        party: first.decoded.author,
        allowed: [-19],
        keys: [{ kid: need(v.kid_hex, "kid"), alg: -19, public_key: need(v.public_key_hex, "pk") }],
      };
      c.same(
        v.id,
        raw.verifyRecordSignature(cose, JSON.stringify(keys)),
        kernel.verifyRecordSignature(cose, keys),
        accept({ author: first.decoded.author, record: digest(need(v.record_id_hex, "id")) }),
      );
    } else {
      throw new Error(`${v.id}: no binding check`);
    }
  }
  return c.all;
}

function decodeChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("genesis.json");
  for (const v of vectors.genesis.cases) {
    const input = bytes(v.hex);
    const want = v.expect.outcome === "accept" ? accept({ decoded: v.decoded }) : v.expect;
    c.same(v.id, raw.decodeEnvelope(input), kernel.decodeEnvelope(input), want);
  }
  const genesis = need(vectors.genesis.cases[0], "genesis");
  const input = bytes(genesis.hex);
  const ledgerDigest = digest(need(genesis.ledger_id, "ledger id").digest_hex);
  const prev = digest(need(genesis.leaf_hash, "leaf hash"));
  c.same("ledger_id", raw.ledgerId(input), kernel.ledgerId(input), { digest: ledgerDigest });
  c.same("leaf_hash", raw.leafHash(input), kernel.leafHash(input), { digest: prev });
  c.same(
    "genesis",
    raw.genesisChainPoint(input),
    kernel.genesisChainPoint(input),
    accept({ ledger: ledgerDigest, prev }),
  );
  const r = new Checks("records.json");
  for (const v of ledger(vectors)) {
    const record = bytes(v.hex);
    const want = unknownProtocol(v.expect) ? v.expect : accept({ decoded: v.decoded });
    r.same(v.id, raw.decodeRecord(record), kernel.decodeRecord(record), want);
    const id = found(v.record_digest.slice(DIGEST_PREFIX.length));
    r.same(v.id, raw.recordId(record), kernel.recordId(record), id);
    const envelope = bytes(v.envelope.hex);
    const decoded = accept({ decoded: v.envelope.decoded });
    r.same(v.id, raw.decodeEnvelope(envelope), kernel.decodeEnvelope(envelope), decoded);
    const leaf = found(v.envelope.leaf_hash);
    r.same(v.id, raw.leafHash(envelope), kernel.leafHash(envelope), leaf);
  }
  const all = [...vectors.records.records, ...vectors.rejects.cases, ...vectors.quarantine.cases];
  for (const v of all) {
    const record = bytes(v.hex);
    const context = JSON.stringify(v.context);
    r.same(
      v.id,
      raw.validateRecordCbor(record, context),
      kernel.validateRecordCbor(record, v.context),
      v.expect,
    );
  }
  return [...c.all, ...r.all];
}

function signatureChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const sets = keySets(vectors);
  const c = new Checks("cose-sign1.json");
  for (const v of vectors.cose.cases) {
    const cose = bytes(v.cose_hex);
    const keys = keysOf(sets, v.author);
    const got = raw.verifyRecordSignature(cose, JSON.stringify(keys));
    const wrapped = kernel.verifyRecordSignature(cose, keys);
    if (v.expect.outcome === "accept") {
      const record = digest(need(v.record_id_hex, "record id"));
      c.same(v.id, got, wrapped, accept({ author: v.author, record }));
      const commit = found(need(v.proof_commit_hex, "proof commit"));
      c.same(v.id, raw.proofCommit(cose), kernel.proofCommit(cose), commit);
    } else {
      c.same(v.id, got, wrapped, v.expect);
    }
  }
  for (const k of vectors.cose.keys) {
    const key = bytes(k.public_key_hex);
    c.same(k.id, raw.checkPublicKey(k.alg, key), kernel.checkPublicKey(k.alg, key), accept());
  }
  for (const k of vectors.cose.key_cases) {
    const key = bytes(k.public_key_hex);
    c.same(k.id, raw.checkPublicKey(k.alg, key), kernel.checkPublicKey(k.alg, key), k.expect);
  }
  const e = new Checks("evidence.json");
  for (const v of vectors.evidence.cases) {
    const record = bytes(v.hex);
    if (v.cose_hex === undefined) {
      e.same(v.id, raw.decodeRecord(record), kernel.decodeRecord(record), v.expect);
      continue;
    }
    const cose = bytes(v.cose_hex);
    const index = need(v.evidence_index, "evidence index");
    const keys = keysOf(sets, need(v.presenter, "presenter"));
    e.same(
      v.id,
      raw.verifyEvidenceSignature(record, index, cose, JSON.stringify(keys)),
      kernel.verifyEvidenceSignature(record, index, cose, keys),
      v.expect,
    );
    if (v.id !== "evidence/statement-changed") {
      const reference = need(v.decoded.evidence?.[index], "evidence reference");
      const want = accept({
        statement: v.statement_hex,
        presenter: reference.presenter,
        signature: reference.signature,
      });
      e.same(
        v.id,
        raw.evidenceStatement(record, index),
        kernel.evidenceStatement(record, index),
        want,
      );
    }
  }
  return [...c.all, ...e.all];
}

function quarantined(id: string): string {
  return `records-quarantine.json ${id} envelope`;
}

function signaturesByEnvelope(vectors: ByteVectors): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const v of vectors.cose.cases) {
    if (v.envelope !== undefined) {
      out.set(v.envelope, bytes(v.cose_hex));
    }
  }
  return out;
}

function entryChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("records.json envelopes");
  const sets = keySets(vectors);
  const signed = signaturesByEnvelope(vectors);
  const genesis = need(vectors.genesis.cases[0], "genesis");
  let at = {
    ledger: digest(need(genesis.ledger_id, "ledger id").digest_hex),
    prev: digest(need(genesis.leaf_hash, "leaf hash")),
  };
  for (const v of ledger(vectors)) {
    const id = v.envelope.id;
    const name = id === undefined ? quarantined(v.id) : `records.json ${id}`;
    const cose = signed.get(name);
    const keys = keysOf(sets, v.decoded.author);
    const envelope = bytes(v.envelope.hex);
    const record = bytes(v.hex);
    const e = v.envelope.decoded;
    const leaf = digest(v.envelope.leaf_hash);
    const next = { ledger: e.ledger, prev: leaf };
    let want: object = { outcome: "reject", reason: "protocol_version_unknown" };
    if (cose !== undefined || !unknownProtocol(v.expect)) {
      want = accept({
        record: e.record,
        author: v.decoded.author,
        binding: cose === undefined ? "auth_context" : "signature_valid",
        ledger: e.ledger,
        position: e.pos,
        recorded_at: e.recorded_at,
        ingest: e.ingest,
        leaf,
        next,
      });
    }
    c.same(
      v.id,
      raw.verifyEntry(JSON.stringify(at), envelope, record, cose, JSON.stringify(keys)),
      kernel.verifyEntry(at, envelope, record, cose, keys),
      want,
    );
    at = next;
  }
  return c.all;
}

function noteKey(k: NoteKeyVector): { readonly name: string; readonly public_key: string } {
  return { name: k.name, public_key: k.public_key_hex };
}

function proofChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("merkle.json");
  const m = vectors.merkle;
  for (const v of m.nodes) {
    const [left, right] = [digest(v.left_hex), digest(v.right_hex)];
    c.same(
      v.id,
      raw.merkleNodeHash(JSON.stringify(left), JSON.stringify(right)),
      kernel.merkleNodeHash(left, right),
      found(v.digest_hex),
    );
  }
  const genesis = need(vectors.genesis.cases[0], "genesis");
  const leaves = [genesis.hex, ...ledger(vectors).map((v) => v.envelope.hex)];
  for (const v of m.roots) {
    const prefix = leaves.slice(0, v.size);
    c.same(
      `root ${String(v.size)}`,
      raw.merkleRoot(JSON.stringify(prefix)),
      kernel.merkleRoot(prefix.map(bytes)),
      found(v.root_hex),
    );
  }
  c.same("root empty", raw.merkleRoot("[]"), kernel.merkleRoot([]), found(SHA256_OF_NOTHING));
  for (const v of m.inclusion) {
    const proof = {
      position: v.index,
      size: v.size,
      leaf: digest(v.leaf_hash_hex),
      path: v.path_hex.map(digest),
      root: digest(v.root_hex),
    };
    c.same(
      v.id,
      raw.verifyInclusion(JSON.stringify(proof)),
      kernel.verifyInclusion(proof),
      v.expect,
    );
  }
  for (const v of m.consistency) {
    const proof = {
      first: v.first,
      second: v.second,
      first_root: digest(v.first_root_hex),
      second_root: digest(v.second_root_hex),
      path: v.path_hex.map(digest),
    };
    c.same(
      v.id,
      raw.verifyConsistency(JSON.stringify(proof)),
      kernel.verifyConsistency(proof),
      v.expect,
    );
  }
  const note = (v: CheckpointCase, witnessed: boolean) => ({
    note: v.note,
    origin: v.origin,
    log: noteKey(m.keys.log),
    witnesses: witnessed ? m.keys.witnesses.map(noteKey) : [],
  });
  for (const v of m.checkpoints) {
    const x = v.expect;
    let want: object = x;
    if (x.outcome === "accept") {
      const root = digest(need(x.root_hex, "root"));
      want = accept({ size: x.size, root, profile: x.profile, cosignatures: x.cosignatures });
    }
    const n = note(v, true);
    c.same(v.id, raw.verifyCheckpoint(JSON.stringify(n)), kernel.verifyCheckpoint(n), want);
  }
  const first = need(m.checkpoints[0], "checkpoint");
  const signed = note(first, true);
  for (const v of m.inclusion) {
    if (v.size !== first.expect.size || v.expect.outcome !== "accept") {
      continue;
    }
    const leaf = digest(v.leaf_hash_hex);
    const proof = { position: v.index, leaf, path: v.path_hex.map(digest) };
    c.same(
      `${v.id} in ${first.id}`,
      raw.checkpointIncludes(JSON.stringify(signed), JSON.stringify(proof)),
      kernel.checkpointIncludes(signed, proof),
      accept(),
    );
  }
  const older = note(first, false);
  c.same(
    "extends",
    raw.checkpointExtendsTo(JSON.stringify(older), JSON.stringify(signed), "[]"),
    kernel.checkpointExtendsTo(older, signed, []),
    accept(),
  );
  return c.all;
}

function touchedChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("items-touched.json");
  const records = [...vectors.records.records, ...vectors.quarantine.cases];
  for (const v of vectors.items.cases) {
    const record = bytes(need(records.find((r) => r.id === v.id), v.id).hex);
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

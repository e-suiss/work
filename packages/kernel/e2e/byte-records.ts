// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel, PartyKeys } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import {
  COSE_SIGN1_TAG,
  Checks,
  DIGEST_PREFIX,
  accept,
  bytes,
  digest,
  filled,
  found,
  keySets,
  keysOf,
  ledger,
  need,
  unknownProtocol,
} from "./checks.js";

export function cborChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
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

export function digestChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
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
      const fill = v.part.content;
      const content = hex === undefined ? filled("", need(fill, "content")) : bytes(hex);
      const { name, media_type: media } = v.part;
      c.same(
        v.id,
        raw.bodyCommitment(salt, name, media, content),
        kernel.bodyCommitment(salt, name, media, content),
        accept(found(need(v.digest_hex, "digest"))),
      );
    } else if (v.id === "digest/record-id") {
      const input = bytes(first.hex);
      const id = found(need(v.digest_hex, "digest"));
      c.same(v.id, raw.recordId(input), kernel.recordId(input), id);
    } else if (v.id === "digest/leaf-0x00") {
      const input = bytes(envelope.hex);
      const leaf = found(need(v.digest_hex, "digest"));
      c.same(v.id, raw.leafHash(input), kernel.leafHash(input), leaf);
    } else if (v.id === "digest/proof-commit") {
      const cose = bytes(need(v.cose_hex, "cose"));
      const commit = found(need(v.digest_hex, "digest"));
      c.same(v.id, raw.proofCommit(cose), kernel.proofCommit(cose), commit);
      const kid = need(v.kid_hex, "kid");
      const key = need(v.public_key_hex, "public key");
      const keys: PartyKeys = {
        party: first.decoded.author,
        allowed: [-19],
        keys: [{ kid, alg: -19, public_key: key }],
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

export function decodeChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
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
  const all = [...ledger(vectors), ...vectors.rejects.cases];
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

export function signatureChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
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

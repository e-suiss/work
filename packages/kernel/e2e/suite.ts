// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check, CheckpointCase, NoteKeyVector } from "./byte-vectors.js";
import {
  Checks,
  SHA256_OF_NOTHING,
  accept,
  bytes,
  digest,
  found,
  keySets,
  keysOf,
  ledger,
  need,
  unknownProtocol,
} from "./checks.js";
import { cborChecks, decodeChecks, digestChecks, signatureChecks } from "./byte-records.js";

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

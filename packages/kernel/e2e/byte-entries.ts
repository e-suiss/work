// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check } from "./byte-vectors.js";
import {
  Checks,
  accept,
  bytes,
  digest,
  keySets,
  keysOf,
  ledger,
  need,
  unknownProtocol,
} from "./checks.js";

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

export function entryChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
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
    const got = raw.verifyEntry(JSON.stringify(at), envelope, record, cose, JSON.stringify(keys));
    c.same(v.id, got, kernel.verifyEntry(at, envelope, record, cose, keys), want);
    at = next;
  }
  return c.all;
}

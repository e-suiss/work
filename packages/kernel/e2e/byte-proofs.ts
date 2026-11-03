// T-5 T-37 INV-7
import type * as Raw from "../wasm/work_kernel_wasm.js";
import type { Kernel } from "../src/index.js";
import type { ByteVectors, Check, CheckpointCase, NoteKeyVector } from "./byte-vectors.js";
import { Checks, SHA256_OF_NOTHING, accept, bytes, digest, found, ledger, need } from "./checks.js";

function noteKey(k: NoteKeyVector): { readonly name: string; readonly public_key: string } {
  return { name: k.name, public_key: k.public_key_hex };
}

export function proofChecks(kernel: Kernel, raw: typeof Raw, vectors: ByteVectors): Check[] {
  const c = new Checks("merkle.json");
  const m = vectors.merkle;
  for (const v of m.nodes) {
    const [left, right] = [digest(v.left_hex), digest(v.right_hex)];
    const got = raw.merkleNodeHash(JSON.stringify(left), JSON.stringify(right));
    c.same(v.id, got, kernel.merkleNodeHash(left, right), found(v.digest_hex));
  }
  const genesis = need(vectors.genesis.cases[0], "genesis");
  const leaves = [genesis.hex, ...ledger(vectors).map((v) => v.envelope.hex)];
  for (const v of m.roots) {
    const prefix = leaves.slice(0, v.size);
    const got = raw.merkleRoot(JSON.stringify(prefix));
    const typed = kernel.merkleRoot(prefix.map(bytes));
    c.same(`root ${String(v.size)}`, got, typed, found(v.root_hex));
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
    const got = raw.verifyInclusion(JSON.stringify(proof));
    c.same(v.id, got, kernel.verifyInclusion(proof), v.expect);
  }
  for (const v of m.consistency) {
    const proof = {
      first: v.first,
      second: v.second,
      first_root: digest(v.first_root_hex),
      second_root: digest(v.second_root_hex),
      path: v.path_hex.map(digest),
    };
    const got = raw.verifyConsistency(JSON.stringify(proof));
    c.same(v.id, got, kernel.verifyConsistency(proof), v.expect);
  }
  const log = noteKey(m.keys.log);
  const witnesses = m.keys.witnesses.map(noteKey);
  const note = (v: CheckpointCase, witnessed: boolean) => {
    return { note: v.note, origin: v.origin, log, witnesses: witnessed ? witnesses : [] };
  };
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
    const got = raw.checkpointIncludes(JSON.stringify(signed), JSON.stringify(proof));
    c.same(`${v.id} in ${first.id}`, got, kernel.checkpointIncludes(signed, proof), accept());
  }
  const older = note(first, false);
  const got = raw.checkpointExtendsTo(JSON.stringify(older), JSON.stringify(signed), "[]");
  c.same("extends", got, kernel.checkpointExtendsTo(older, signed, []), accept());
  return c.all;
}

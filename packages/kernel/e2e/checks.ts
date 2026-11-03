// T-5 T-37 INV-7
import type { DigestJson, PartyKey, PartyKeys } from "../src/index.js";
import type { ByteVectors, Check, Expect, Filler, LedgerVector } from "./byte-vectors.js";

export const ALLOWED = [-19, -9, -7] as const;
export const COSE_SIGN1_TAG = 18;
export const DIGEST_PREFIX = "822f5820";
export const SHA256_OF_NOTHING = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** Compact JSON with object keys sorted, as the kernel bindings write it. */
export function sortedJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

export function bytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

export function filled(head: string, filler: Filler): Uint8Array {
  return bytes(head + filler.fill_hex.repeat(filler.fill_count));
}

export function digest(hex: string): DigestJson {
  return [-16, hex];
}

export function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`vector without ${what}`);
  }
  return value;
}

export function accept(fields: object = {}): object {
  return { ...fields, outcome: "accept" };
}

export function unknownProtocol(expect: Expect): boolean {
  return expect.outcome === "quarantine" && expect.reason === "protocol_version_unknown";
}

export function found(hex: string): { readonly digest: DigestJson } {
  return { digest: digest(hex) };
}

export class Checks {
  readonly all: Check[] = [];

  constructor(private readonly file: string) {}

  same(id: string, raw: string, wrapped: unknown, want: unknown): void {
    const expected = sortedJson(want);
    this.all.push({ file: this.file, id, got: raw, want: expected });
    const typed = sortedJson(wrapped);
    this.all.push({ file: this.file, id: `${id} (wrapped)`, got: typed, want: expected });
  }
}

export function keySets(vectors: ByteVectors): Map<string, PartyKey[]> {
  const sets = new Map<string, PartyKey[]>();
  for (const k of vectors.cose.keys) {
    const list = sets.get(k.party) ?? [];
    list.push({ kid: k.kid_hex, alg: k.alg, public_key: k.public_key_hex });
    sets.set(k.party, list);
  }
  return sets;
}

export function keysOf(sets: Map<string, PartyKey[]>, party: string): PartyKeys {
  return { party, allowed: ALLOWED, keys: sets.get(party) ?? [] };
}

export function ledger(vectors: ByteVectors): LedgerVector[] {
  const out = vectors.records.records.map((r, i) => ({
    ...r,
    envelope: need(vectors.records.envelopes[i], `envelope ${r.id}`),
  }));
  return [...out, ...vectors.quarantine.cases];
}

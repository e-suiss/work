// T-5 T-34
import init, {
  apiVersion,
  compareApiVersions as wasmCompareApiVersions,
  deriveRecords as wasmDeriveRecords,
  evaluatePolicyChange as wasmEvaluatePolicyChange,
  evaluateSecuritySwitch as wasmEvaluateSecuritySwitch,
  validateRecord as wasmValidateRecord,
} from "../wasm/work_kernel_wasm.js";
import * as wasm from "../wasm/work_kernel_wasm.js";
import type {
  ChangeOutcome,
  PolicyDirection,
  SwitchBasis,
  SwitchOutcome,
  VersionOrder,
} from "../wasm/work_kernel_wasm.js";

import type { QuarantineCode, ReasonCode, WithSubCode } from "./reasons.js";

export type { ChangeOutcome, PolicyDirection, SwitchBasis, SwitchOutcome, VersionOrder };
export type { QuarantineCode, ReasonCode, WithSubCode };
export { QUARANTINE_CODES, REASON_CODES } from "./reasons.js";

export type KernelSource = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface ApiVersion {
  readonly major: number;
  readonly minor: number;
}

export interface PolicyDefault {
  readonly direction: PolicyDirection;
  readonly min: bigint;
  readonly max: bigint;
}

export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/** A digest as `[-16, hex]` (P-5). */
export type DigestJson = readonly [-16, string];

/** An unsigned integer: a JSON number, or a decimal string beyond 2^53. */
export type UintJson = number | string;

/** Who may see a record (P-77, EV-21). */
export interface VisibilityJson {
  readonly see: "work" | "author" | readonly ["parties", readonly string[]];
  readonly search?: false;
  readonly agent_context?: false;
}

/** A typed relation endpoint (P-73). */
export type EndpointJson =
  readonly ["record" | "evidence", DigestJson] | readonly ["work" | "party" | "external", string];

/** One of the eight canonical relations (C-25, P-73). */
export interface RelationJson {
  readonly rel:
    | "engaged_in"
    | "concerns"
    | "part_of"
    | "serves"
    | "supersedes"
    | "derived_from"
    | "on_behalf_of"
    | "references";
  readonly source?: EndpointJson;
  readonly target: EndpointJson;
  readonly qualifier?: string;
}

/** A typed evidence reference (EV-3). */
export interface EvidenceJson {
  readonly subject: DigestJson | string;
  readonly type: string;
  readonly presenter: string;
  readonly claimed_at?: UintJson;
  readonly source?: string;
  readonly observation?: DigestJson;
  readonly visibility?: VisibilityJson;
  readonly signature: DigestJson;
}

/** A normative parameter scalar (P-80). */
export type ParamScalarJson = UintJson | boolean | DigestJson;

/**
 * A protocol 1.0 record as the `decoded` JSON projection of its CBOR: byte strings as lowercase hex, integers beyond 2^53 as decimal strings (P-10, P-87).
 * A record of another protocol version is passed as its projection cast to this type; the kernel quarantines it before reading any other field.
 */
export interface DecodedRecord {
  readonly kind: "act" | "declaration" | "claim";
  readonly type: string;
  readonly occurred_at?: UintJson;
  readonly author: string;
  readonly on_behalf_of?: readonly string[];
  readonly capacity?: "own" | readonly ["for", string];
  readonly basis?: readonly DigestJson[];
  readonly visibility: VisibilityJson;
  readonly ledger: DigestJson;
  readonly concerns: readonly string[];
  readonly relations?: readonly RelationJson[];
  readonly authority?: {
    readonly proof:
      | "decision_receipt"
      | "portable_authority_proof"
      | "approval_act_statement"
      | "eligibility_check";
    readonly digest: DigestJson;
  };
  readonly producer?: {
    readonly version: string;
    readonly config: DigestJson;
    readonly model?: string;
    readonly toolset?: DigestJson;
    readonly instructions?: DigestJson;
    readonly attestation?: DigestJson;
  };
  readonly correlation?: readonly (readonly [string, string])[];
  readonly evidence?: readonly EvidenceJson[];
  readonly body?: readonly { readonly part: string; readonly commit: DigestJson }[];
  readonly params?: Readonly<Record<string, ParamScalarJson | readonly ParamScalarJson[]>>;
  readonly versions: {
    readonly protocol: readonly [UintJson, UintJson];
    readonly schema: DigestJson;
    readonly practices?: Readonly<Record<string, DigestJson>>;
  };
  readonly ext?: Readonly<Record<string, JsonValue>>;
  readonly critical?: readonly string[];
}

export type ActorType = "human" | "agent" | "system" | "machine" | "organization";
export type ActorTypeSource = "access_binding" | "declared_unverified";
export type ActorTypeEntry = readonly [ActorType, ActorTypeSource];

/** Verifier inputs that are not record bytes, in the record vector `context` shape (P-12, P-19, T-66, EV-35). */
export interface RecordContext {
  readonly origin: "direct" | "automation";
  readonly actor_type: {
    readonly author: ActorTypeEntry;
    readonly on_behalf_of?: readonly ActorTypeEntry[];
    readonly evidence?: readonly ActorTypeEntry[];
  };
  readonly understood_extensions: readonly string[];
  readonly recorded_at?: UintJson;
}

/** The kernel's decision about one record (P-11, P-19). */
export type Validation =
  | { readonly outcome: "accept" }
  | { readonly outcome: "reject"; readonly reason: ReasonCode }
  | { readonly outcome: "quarantine"; readonly reason: QuarantineCode };

/** One ledger record with the envelope facts derivation needs. */
export interface DerivationEntry {
  readonly id: DigestJson;
  readonly record: DecodedRecord;
  readonly position: UintJson;
  readonly recorded_at: UintJson;
  readonly ingest: "admitted" | readonly ["quarantined", WithSubCode<QuarantineCode>];
  readonly restriction: "no_objection" | "deny" | "require";
  readonly issuer: "local" | readonly ["federated", string];
}

/** Every input besides the records that the normative result depends on (P-31, T-6). */
export interface DerivationInputs {
  readonly protocol: readonly [number, number];
  readonly profile: number;
  readonly practices: Readonly<Record<string, DigestJson>>;
  readonly trusted_publishers: readonly string[];
  readonly ledger_time: UintJson;
  readonly calendar: "continuous";
}

export type Admission =
  "admitted" | readonly ["quarantined", QuarantineCode] | readonly ["rejected", ReasonCode];

export type Effect = "normative" | "conflicted" | readonly ["none", string];

export interface DerivedRecord {
  readonly id: DigestJson;
  readonly admission: Admission;
  readonly effect: Effect;
  readonly superseded_by: readonly DigestJson[];
}

export interface Chain {
  readonly root: DigestJson;
  readonly version: number;
  readonly heads: readonly DigestJson[];
  readonly status: "open" | "terminal" | "conflicted";
}

/** The derived view, in input order (P-31). */
export interface Derivation {
  readonly records: readonly DerivedRecord[];
  readonly chains: readonly Chain[];
}

/** A JSON object of the `decoded` projection (P-10). */
export type JsonObject = Readonly<Record<string, JsonValue>>;

/** The outcome of a kernel decision that accepts. */
export interface AcceptOutcome {
  readonly outcome: "accept";
}

/** A kernel decision that accepts, with the decision's own fields. */
export type Accepted<Fields extends object = object> = Readonly<Fields> & AcceptOutcome;

/** A kernel decision that rejects: a Work reason code, or for a proof or checkpoint the shared crate's code (T-88). */
export interface Rejected<Code extends string = ReasonCode> {
  readonly outcome: "reject";
  readonly reason: Code;
}

/** A record of a protocol version without a rule set (P-87, P-94). */
export interface UnknownProtocol {
  readonly outcome: "quarantine";
  readonly reason: "protocol_version_unknown";
}

/** A digest the kernel computed from bytes as received (P-67, P-79, P-101). */
export interface DigestAnswer {
  readonly digest: DigestJson;
}

/** A shared crate code of a Merkle proof (T-88). */
export type ProofCode = "proof-range" | "proof-length" | "proof-mismatch";

/** One key Access binds to a Party: key ID and public key in hex, COSE algorithm (P-6, Access CR-55). */
export interface PartyKey {
  readonly kid: string;
  readonly alg: number;
  readonly public_key: string;
}

/** The keys Access binds to one Party, with the COSE algorithms the caller's policy allows (P-6, P-105). */
export interface PartyKeys {
  readonly party: string;
  readonly allowed: readonly number[];
  readonly keys: readonly PartyKey[];
}

/** Where the next ledger entry continues the chain (P-100). */
export interface ChainPoint {
  readonly ledger: DigestJson;
  readonly prev: DigestJson;
}

/** What verifying a stored ledger entry establishes; never truth or authorisation (SEC-5, P-22, T-10). */
export interface EntryVerification {
  readonly record: DigestJson;
  readonly author: string;
  readonly binding: "signature_valid" | "auth_context";
  readonly ledger: DigestJson;
  readonly position: UintJson;
  readonly recorded_at: UintJson;
  readonly ingest:
    | "admitted"
    | readonly ["quarantined", QuarantineCode]
    | readonly ["rejected", ReasonCode];
  readonly leaf: DigestJson;
  readonly next: ChainPoint;
}

/** An RFC 9162 inclusion proof (P-101). */
export interface InclusionProof {
  readonly position: UintJson;
  readonly size: UintJson;
  readonly leaf: DigestJson;
  readonly path: readonly DigestJson[];
  readonly root: DigestJson;
}

/** An RFC 9162 consistency proof (P-101). */
export interface ConsistencyProof {
  readonly first: UintJson;
  readonly second: UintJson;
  readonly first_root: DigestJson;
  readonly second_root: DigestJson;
  readonly path: readonly DigestJson[];
}

/** An Ed25519 note key: the log's or a witness's, public key in hex (T-88, OP-33). */
export interface NoteKey {
  readonly name: string;
  readonly public_key: string;
}

/** A C2SP signed note with the keys to verify it as a checkpoint of `origin` (T-88, OP-46). */
export interface CheckpointNote {
  readonly note: string;
  readonly origin: string;
  readonly log: NoteKey;
  readonly witnesses: readonly NoteKey[];
}

/** A checkpoint whose log signature verified, with its profile lines and verified witness cosignatures (P-20, OP-46). */
export interface VerifiedCheckpoint {
  readonly size: UintJson;
  readonly root: DigestJson;
  readonly profile: readonly string[];
  readonly cosignatures: readonly { readonly name: string; readonly timestamp: number }[];
}

/** One work item a record touches (T-89). */
export interface Touch {
  readonly item: readonly ["work" | "commitment" | "condition", string];
  readonly expect: "next" | { readonly version: UintJson };
  readonly heads: readonly string[] | null;
}

/** The items a record touches, in the kernel's order (T-89). */
export interface Touches {
  readonly touches: readonly Touch[];
}

/** A verified record signature: the digest of the payload and the signing Party (P-6, P-79). */
export interface SignedRecord {
  readonly record: DigestJson;
  readonly author: string;
}

/** What an evidence presenter signs, in hex, and the digest its reference names (EV-3, EV-8). */
export interface EvidenceStatement {
  readonly statement: string;
  readonly presenter: string;
  readonly signature: DigestJson;
}

/** An inclusion proof against a verified checkpoint's tree (P-108). */
export type CheckpointInclusion = Pick<InclusionProof, "position" | "leaf" | "path">;

/** The decoding of `SignedRecord` bytes (P-5, P-87). */
export type DecodedRecordAnswer = Accepted<{ decoded: DecodedRecord }> | Rejected | UnknownProtocol;

/** The verification of a checkpoint note (T-88, OP-46). */
export type CheckpointAnswer = Accepted<VerifiedCheckpoint> | Rejected<string>;

/** The items a record's bytes touch (T-89). */
export type TouchedAnswer = Accepted<Touches> | Rejected | UnknownProtocol;

/** Input the kernel bindings could not map, or a ledger order the kernel refuses; never a decision about a record. */
export class KernelInputError extends Error {
  readonly code: string;
  readonly detail: Readonly<Record<string, JsonValue>>;

  constructor(detail: Readonly<Record<string, JsonValue>>) {
    const code = typeof detail["code"] === "string" ? detail["code"] : "unknown";
    super(`kernel input error: ${code}`);
    this.name = "KernelInputError";
    this.code = code;
    this.detail = detail;
  }
}

/** The kernel's record decoding, digest, signature, ledger entry, proof, checkpoint and touched item functions over bytes as received (T-5, T-10, T-88, T-89, X-24). */
export interface Verifier {
  readonly validateRecordCbor: (record: Uint8Array, context: RecordContext) => Validation;
  readonly decodeRecord: (record: Uint8Array) => DecodedRecordAnswer;
  readonly decodeEnvelope: (envelope: Uint8Array) => Accepted<{ decoded: JsonObject }> | Rejected;
  readonly checkCbor: (bytes: Uint8Array, tags: readonly number[]) => Accepted | Rejected;
  readonly parseCoseContainer: (bytes: Uint8Array) => Accepted | Rejected;
  readonly decodeDigest: (bytes: Uint8Array) => Accepted<DigestAnswer> | Rejected;
  readonly recordId: (record: Uint8Array) => DigestAnswer;
  readonly ledgerId: (genesis: Uint8Array) => DigestAnswer;
  readonly leafHash: (envelope: Uint8Array) => DigestAnswer;
  readonly proofCommit: (coseSign1: Uint8Array) => DigestAnswer;
  readonly bodyCommitment: (
    salt: Uint8Array,
    name: string,
    mediaType: string,
    content: Uint8Array,
  ) => Accepted<DigestAnswer> | Rejected;
  readonly checkPublicKey: (alg: number, publicKey: Uint8Array) => Accepted | Rejected;
  readonly verifyRecordSignature: (
    coseSign1: Uint8Array,
    authorKeys: PartyKeys,
  ) => Accepted<SignedRecord> | Rejected;
  readonly evidenceStatement: (
    record: Uint8Array,
    index: number,
  ) => Accepted<EvidenceStatement> | Rejected;
  readonly verifyEvidenceSignature: (
    record: Uint8Array,
    index: number,
    coseSign1: Uint8Array,
    presenterKeys: PartyKeys,
  ) => Accepted | Rejected;
  readonly genesisChainPoint: (genesis: Uint8Array) => Accepted<ChainPoint> | Rejected;
  readonly verifyEntry: (
    at: ChainPoint,
    envelope: Uint8Array,
    record: Uint8Array,
    coseSign1: Uint8Array | undefined,
    authorKeys: PartyKeys,
  ) => Accepted<EntryVerification> | Rejected;
  readonly merkleNodeHash: (left: DigestJson, right: DigestJson) => DigestAnswer;
  readonly merkleRoot: (envelopes: readonly Uint8Array[]) => DigestAnswer;
  readonly verifyInclusion: (proof: InclusionProof) => Accepted | Rejected<ProofCode>;
  readonly verifyConsistency: (proof: ConsistencyProof) => Accepted | Rejected<ProofCode>;
  readonly verifyCheckpoint: (checkpoint: CheckpointNote) => CheckpointAnswer;
  readonly checkpointIncludes: (
    checkpoint: CheckpointNote,
    inclusion: CheckpointInclusion,
  ) => Accepted | Rejected<string>;
  readonly checkpointExtendsTo: (
    older: CheckpointNote,
    newer: CheckpointNote,
    path: readonly DigestJson[],
  ) => Accepted | Rejected<string>;
  readonly touched: (record: Uint8Array) => TouchedAnswer;
}

export interface Kernel extends Verifier {
  readonly apiVersion: () => string;
  readonly compareApiVersions: (a: ApiVersion, b: ApiVersion) => VersionOrder;
  readonly evaluatePolicyChange: (
    policy: PolicyDefault,
    current: bigint,
    proposed: bigint,
  ) => ChangeOutcome;
  readonly evaluateSecuritySwitch: (
    current: boolean,
    proposed: boolean,
    basis: SwitchBasis,
  ) => SwitchOutcome;
  readonly validateRecord: (decoded: DecodedRecord, context: RecordContext) => Validation;
  readonly deriveRecords: (
    entries: readonly DerivationEntry[],
    inputs: DerivationInputs,
  ) => Derivation;
}

const U16_MAX = 0xffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function u16(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U16_MAX) {
    throw new RangeError(`${name} must be an integer in 0..=${String(U16_MAX)}`);
  }
  return value;
}

function u64(value: bigint, name: string): bigint {
  if (value < 0n || value > U64_MAX) {
    throw new RangeError(`${name} must be in 0..=${String(U64_MAX)}`);
  }
  return value;
}

function compareApiVersions(a: ApiVersion, b: ApiVersion): VersionOrder {
  return wasmCompareApiVersions(
    u16(a.major, "a.major"),
    u16(a.minor, "a.minor"),
    u16(b.major, "b.major"),
    u16(b.minor, "b.minor"),
  );
}

function evaluatePolicyChange(
  policy: PolicyDefault,
  current: bigint,
  proposed: bigint,
): ChangeOutcome {
  const outcome = wasmEvaluatePolicyChange(
    policy.direction,
    u64(policy.min, "min"),
    u64(policy.max, "max"),
    u64(current, "current"),
    u64(proposed, "proposed"),
  );
  if (outcome === undefined) {
    throw new TypeError(`unknown policy direction "${policy.direction}"`);
  }
  return outcome;
}

function evaluateSecuritySwitch(
  current: boolean,
  proposed: boolean,
  basis: SwitchBasis,
): SwitchOutcome {
  const outcome = wasmEvaluateSecuritySwitch(current, proposed, basis);
  if (outcome === undefined) {
    throw new TypeError(`unknown switch basis "${basis}"`);
  }
  return outcome;
}

interface InputError {
  readonly error: Readonly<Record<string, JsonValue>>;
}

function unwrap<T extends object>(parsed: T | InputError): T {
  if ("error" in parsed) {
    throw new KernelInputError(parsed.error);
  }
  return parsed;
}

function validateRecord(decoded: DecodedRecord, context: RecordContext): Validation {
  const text = wasmValidateRecord(JSON.stringify(decoded), JSON.stringify(context));
  return unwrap(JSON.parse(text) as Validation | InputError);
}

function deriveRecords(entries: readonly DerivationEntry[], inputs: DerivationInputs): Derivation {
  const text = wasmDeriveRecords(JSON.stringify(entries), JSON.stringify(inputs));
  return unwrap(JSON.parse(text) as { readonly derivation: Derivation } | InputError).derivation;
}

const U32_MAX = 0xffff_ffff;
const I32_MIN = -0x8000_0000;
const I32_MAX = 0x7fff_ffff;

function u32(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new RangeError(`${name} must be an integer in 0..=${String(U32_MAX)}`);
  }
  return value;
}

function i32(value: number, name: string): number {
  if (!Number.isInteger(value) || value < I32_MIN || value > I32_MAX) {
    throw new RangeError(`${name} must be a 32-bit signed integer`);
  }
  return value;
}

function answer<T extends object>(text: string): T {
  return unwrap(JSON.parse(text) as T | InputError);
}

function j(value: unknown): string {
  return JSON.stringify(value);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const verifier: Verifier = {
  validateRecordCbor: (record, context) => answer(wasm.validateRecordCbor(record, j(context))),
  decodeRecord: (record) => answer(wasm.decodeRecord(record)),
  decodeEnvelope: (envelope) => answer(wasm.decodeEnvelope(envelope)),
  checkCbor: (bytes, tags) => answer(wasm.checkCbor(bytes, j(tags))),
  parseCoseContainer: (bytes) => answer(wasm.parseCoseContainer(bytes)),
  decodeDigest: (bytes) => answer(wasm.decodeDigest(bytes)),
  recordId: (record) => answer(wasm.recordId(record)),
  ledgerId: (genesis) => answer(wasm.ledgerId(genesis)),
  leafHash: (envelope) => answer(wasm.leafHash(envelope)),
  proofCommit: (coseSign1) => answer(wasm.proofCommit(coseSign1)),
  bodyCommitment: (salt, name, mediaType, content) =>
    answer(wasm.bodyCommitment(salt, name, mediaType, content)),
  checkPublicKey: (alg, publicKey) => answer(wasm.checkPublicKey(i32(alg, "alg"), publicKey)),
  verifyRecordSignature: (coseSign1, authorKeys) =>
    answer(wasm.verifyRecordSignature(coseSign1, j(authorKeys))),
  evidenceStatement: (record, index) => answer(wasm.evidenceStatement(record, u32(index, "index"))),
  verifyEvidenceSignature: (record, index, coseSign1, keys) =>
    answer(wasm.verifyEvidenceSignature(record, u32(index, "index"), coseSign1, j(keys))),
  genesisChainPoint: (genesis) => answer(wasm.genesisChainPoint(genesis)),
  verifyEntry: (at, envelope, record, coseSign1, keys) =>
    answer(wasm.verifyEntry(j(at), envelope, record, coseSign1, j(keys))),
  merkleNodeHash: (left, right) => answer(wasm.merkleNodeHash(j(left), j(right))),
  merkleRoot: (envelopes) => answer(wasm.merkleRoot(j(envelopes.map(hex)))),
  verifyInclusion: (proof) => answer(wasm.verifyInclusion(j(proof))),
  verifyConsistency: (proof) => answer(wasm.verifyConsistency(j(proof))),
  verifyCheckpoint: (checkpoint) => answer(wasm.verifyCheckpoint(j(checkpoint))),
  checkpointIncludes: (checkpoint, inclusion) =>
    answer(wasm.checkpointIncludes(j(checkpoint), j(inclusion))),
  checkpointExtendsTo: (older, newer, path) =>
    answer(wasm.checkpointExtendsTo(j(older), j(newer), j(path))),
  touched: (record) => answer(wasm.touched(record)),
};

let loading: Promise<Kernel> | undefined;

export function loadKernel(source?: KernelSource): Promise<Kernel> {
  loading ??= (source === undefined ? init() : init({ module_or_path: source })).then(
    (): Kernel => ({
      apiVersion,
      compareApiVersions,
      evaluatePolicyChange,
      evaluateSecuritySwitch,
      validateRecord,
      deriveRecords,
      ...verifier,
    }),
    (error: unknown) => {
      loading = undefined;
      throw error;
    },
  );
  return loading;
}

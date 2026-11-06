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

/** One stored ledger entry as derivation takes it: its bytes in lowercase hex and the keys Access binds to its author; the record ID, position, time and ingest come from the verified bytes (T-10). */
export interface DerivationEntry {
  readonly envelope: string;
  readonly record: string;
  readonly cose_sign1?: string;
  readonly author_keys: PartyKeys;
  readonly restriction: "no_objection" | "deny" | "require";
  readonly issuer: "local" | readonly ["federated", string];
}

/** Stored ledger entries in ledger order after the chain point `at` (T-10, P-100). */
export interface DerivationEntries {
  readonly at: ChainPoint;
  readonly entries: readonly DerivationEntry[];
}

/** Every input besides the records that the normative result depends on, the ledger's activations as `[position, [major, minor]]` with the genesis first among them (P-31, P-110, T-6). */
export interface DerivationInputs {
  readonly activations: readonly (readonly [UintJson, readonly [number, number]])[];
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
  readonly ingest: Admission;
  readonly leaf: DigestJson;
  readonly next: ChainPoint;
}

/** A protocol version and the digest of its normative CDDL bytes (P-110). */
export interface ActivatedVersion {
  readonly protocol: readonly [UintJson, UintJson];
  readonly schema: DigestJson;
}

/** What verifying a stored version activation establishes: its place in the chain and the operator's Access context as its binding (P-110). */
export interface ActivationVerification {
  readonly record: DigestJson;
  readonly binding: "auth_context";
  readonly ledger: DigestJson;
  readonly position: UintJson;
  readonly recorded_at: UintJson;
  readonly activation: ActivatedVersion;
  readonly leaf: DigestJson;
  readonly next: ChainPoint;
}

/** One activation of a ledger, the genesis at position 0 (P-110). */
export interface Activation extends ActivatedVersion {
  readonly position: UintJson;
}

/** The activations of a ledger that pass the sequence rule (P-110). */
export interface ActivationList {
  readonly activations: readonly Activation[];
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

/** The envelope actor types of a record's author and principals, and the records its viewer may not see (P-12, EV-12). */
export interface MappingContext {
  readonly actor_type: {
    readonly author: ActorTypeEntry;
    readonly on_behalf_of?: readonly ActorTypeEntry[];
  };
  readonly withheld?: readonly DigestJson[];
}

/** An Activity Streams 2.0 activity (P-51). */
export interface As2Activity {
  readonly type: string;
  readonly vocabulary: string;
}

/** A record's PROV-JSON document and Activity Streams 2.0 activity, `null` when it maps to none (P-49, P-51). */
export interface RecordMapping {
  readonly prov: JsonObject;
  readonly as2: As2Activity | null;
}

/** The external standard mappings of a record's bytes (P-48). */
export type MappingAnswer = Accepted<RecordMapping> | Rejected | UnknownProtocol;

/** One restriction rule set: the Cedar schema and the Access Restriction Profile policy source (T-23, PR-17). */
export interface RestrictionRuleSet {
  readonly schema: string;
  readonly policies: string;
  /** The rule set's 16-byte reference, unpadded base64url; its `DENY` explanation names it. */
  readonly ref?: string;
  /** The requirement terms each `@require` reference names (PR-11, PR-17). */
  readonly requirements?: Readonly<Record<string, readonly RequirementTerm[]>>;
}

/** One requirement term in Access's JSON form (`urn:suiss:access:schema:explanation:1`). */
export interface RequirementTerm {
  readonly proof_kind: "claim" | "contribution" | "authentication" | "foreign_authority";
  readonly class: string;
  readonly count?: number;
  readonly binding?: "actor_instance" | "intent_digest" | "resource";
  readonly freshness_ms?: number;
  readonly independence?: { readonly distinct: "party" | "instance" | "issuer" };
  readonly consumption?: "single_use";
  readonly source?: JsonValue;
  readonly assurance?: Readonly<Record<string, number>>;
}

/** Where a blocker or an unmet term sits. */
export type ExplanationPosition =
  "instance" | "anchor" | "domain-policy" | "foreign" | "actor-side" | { readonly hop: number };

/** The decision explanation shared with Access (`urn:suiss:access:schema:explanation:1`; PR-11, PR-17). */
export interface Explanation {
  readonly outcome: "allow" | "deny" | "require_action";
  readonly blockers?: readonly {
    readonly class: string;
    readonly subcode?: string;
    readonly position?: ExplanationPosition;
    readonly resolver: string | { readonly grantor_of_hop: number };
    readonly remediation: string | { readonly wait_until: number };
  }[];
  readonly unmet?: readonly {
    readonly term: RequirementTerm;
    readonly missing: number;
    readonly position: ExplanationPosition;
    readonly satisfiable_by_actor: boolean;
  }[];
  readonly relied_on?: readonly string[];
}

/** One request to a restriction rule set: Cedar entity UIDs, and the context object and entity array as JSON text the engine reads unchanged (T-23). */
export interface RestrictionRequest {
  readonly principal: string;
  readonly action: string;
  readonly resource: string;
  readonly context: string;
  readonly entities: string;
}

/** What one rule set says about a request; `no_objection` is not a permission, `attention` marks a denial from an input over a limit or an evaluation error, and `explanation` says why in the format shared with Access (PR-11, PR-17, PR-23). */
export type RestrictionVerdict =
  | { readonly outcome: "no_objection" }
  | {
      readonly outcome: "require";
      readonly requirements: readonly string[];
      readonly explanation: Explanation;
    }
  | {
      readonly outcome: "deny";
      readonly policies: readonly string[];
      readonly attention: boolean;
      readonly explanation: Explanation;
    };

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

/** The kernel's record decoding, digest, signature, ledger entry, proof, checkpoint and touched item functions and the proto's external standard mappings over bytes as received, and the shared restriction engine (T-5, T-10, T-88, T-89, P-48, X-24, T-23). */
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
  ) => Accepted<EntryVerification> | Accepted<ActivationVerification> | Rejected;
  readonly checkActivations: (
    entries: readonly Uint8Array[],
  ) => Accepted<ActivationList> | Rejected;
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
  readonly mapRecord: (record: Uint8Array, context: MappingContext) => MappingAnswer;
  readonly evaluateRestriction: (
    ruleSet: RestrictionRuleSet,
    request: RestrictionRequest,
  ) => RestrictionVerdict;
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
  readonly deriveRecords: (entries: DerivationEntries, inputs: DerivationInputs) => Derivation;
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

function deriveRecords(entries: DerivationEntries, inputs: DerivationInputs): Derivation {
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

type Answer<Name extends keyof Verifier> = ReturnType<Verifier[Name]>;

function answer<Name extends keyof Verifier>(_name: Name, text: string): Answer<Name> {
  const parsed = JSON.parse(text) as object;
  if ("error" in parsed) {
    throw new KernelInputError((parsed as InputError).error);
  }
  return parsed as unknown as Answer<Name>;
}

function j(value: unknown): string {
  return JSON.stringify(value);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const verifier: Verifier = {
  validateRecordCbor: (record, context) =>
    answer("validateRecordCbor", wasm.validateRecordCbor(record, j(context))),
  decodeRecord: (record) => answer("decodeRecord", wasm.decodeRecord(record)),
  decodeEnvelope: (envelope) => answer("decodeEnvelope", wasm.decodeEnvelope(envelope)),
  checkCbor: (bytes, tags) => answer("checkCbor", wasm.checkCbor(bytes, j(tags))),
  parseCoseContainer: (bytes) => answer("parseCoseContainer", wasm.parseCoseContainer(bytes)),
  decodeDigest: (bytes) => answer("decodeDigest", wasm.decodeDigest(bytes)),
  recordId: (record) => answer("recordId", wasm.recordId(record)),
  ledgerId: (genesis) => answer("ledgerId", wasm.ledgerId(genesis)),
  leafHash: (envelope) => answer("leafHash", wasm.leafHash(envelope)),
  proofCommit: (coseSign1) => answer("proofCommit", wasm.proofCommit(coseSign1)),
  bodyCommitment: (salt, name, mediaType, content) =>
    answer("bodyCommitment", wasm.bodyCommitment(salt, name, mediaType, content)),
  checkPublicKey: (alg, publicKey) =>
    answer("checkPublicKey", wasm.checkPublicKey(i32(alg, "alg"), publicKey)),
  verifyRecordSignature: (coseSign1, authorKeys) =>
    answer("verifyRecordSignature", wasm.verifyRecordSignature(coseSign1, j(authorKeys))),
  evidenceStatement: (record, index) =>
    answer("evidenceStatement", wasm.evidenceStatement(record, u32(index, "index"))),
  verifyEvidenceSignature: (record, index, coseSign1, keys) =>
    answer(
      "verifyEvidenceSignature",
      wasm.verifyEvidenceSignature(record, u32(index, "index"), coseSign1, j(keys)),
    ),
  genesisChainPoint: (genesis) => answer("genesisChainPoint", wasm.genesisChainPoint(genesis)),
  verifyEntry: (at, envelope, record, coseSign1, keys) =>
    answer("verifyEntry", wasm.verifyEntry(j(at), envelope, record, coseSign1, j(keys))),
  checkActivations: (entries) =>
    answer("checkActivations", wasm.checkActivations(j(entries.map(hex)))),
  merkleNodeHash: (left, right) => answer("merkleNodeHash", wasm.merkleNodeHash(j(left), j(right))),
  merkleRoot: (envelopes) => answer("merkleRoot", wasm.merkleRoot(j(envelopes.map(hex)))),
  verifyInclusion: (proof) => answer("verifyInclusion", wasm.verifyInclusion(j(proof))),
  verifyConsistency: (proof) => answer("verifyConsistency", wasm.verifyConsistency(j(proof))),
  verifyCheckpoint: (checkpoint) =>
    answer("verifyCheckpoint", wasm.verifyCheckpoint(j(checkpoint))),
  checkpointIncludes: (checkpoint, inclusion) =>
    answer("checkpointIncludes", wasm.checkpointIncludes(j(checkpoint), j(inclusion))),
  checkpointExtendsTo: (older, newer, path) =>
    answer("checkpointExtendsTo", wasm.checkpointExtendsTo(j(older), j(newer), j(path))),
  touched: (record) => answer("touched", wasm.touched(record)),
  mapRecord: (record, context) => answer("mapRecord", wasm.mapRecord(record, j(context))),
  evaluateRestriction: (ruleSet, request) =>
    answer("evaluateRestriction", wasm.evaluateRestriction(j(ruleSet), j(request))),
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

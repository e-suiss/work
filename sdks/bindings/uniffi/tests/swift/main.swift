// T-5 T-37
import Foundation

struct Version: Decodable {
    let major: UInt16
    let minor: UInt16
}

struct CompareCase: Decodable {
    let id: String
    let a: Version
    let b: Version
    let expected: String
}

struct ApiVectors: Decodable {
    let api_version: String
    let compare: [CompareCase]
}

struct ChangeCase: Decodable {
    let id: String
    let direction: String
    let min: String
    let max: String
    let current: String
    let proposed: String
    let expected: String
}

struct SwitchCase: Decodable {
    let id: String
    let current: Bool
    let proposed: Bool
    let basis: String
    let expected: String
}

struct PolicyVectors: Decodable {
    let change: [ChangeCase]
    let `switch`: [SwitchCase]
}

enum HarnessError: Error {
    case usage
    case malformed(String)
}

struct Tally {
    var cases = 0
    var failures = 0
}

func check(
    _ tally: inout Tally, _ name: String, _ id: String, _ actual: String, _ expected: String
) {
    tally.cases += 1
    if actual != expected {
        tally.failures += 1
        print("FAIL \(name) \(id): got \(actual), expected \(expected)")
    }
}

func load<T: Decodable>(_ type: T.Type, _ dir: URL, _ file: String) throws -> T {
    try JSONDecoder().decode(type, from: Data(contentsOf: dir.appendingPathComponent(file)))
}

func number(_ text: String, _ id: String) throws -> UInt64 {
    guard let value = UInt64(text) else { throw HarnessError.malformed(id) }
    return value
}

func direction(_ name: String, _ id: String) throws -> Direction {
    switch name {
    case "tighten_only_higher": return .tightenOnly(.higher)
    case "tighten_only_lower": return .tightenOnly(.lower)
    case "extend_only": return .extendOnly
    case "bounded": return .bounded
    default: throw HarnessError.malformed(id)
    }
}

func orderName(_ order: VersionOrder) -> String {
    switch order {
    case .less: return "less"
    case .equal: return "equal"
    case .greater: return "greater"
    }
}

func changeName(_ outcome: ChangeOutcome) -> String {
    switch outcome {
    case .allowed: return "allowed"
    case .outOfBounds: return "out_of_bounds"
    case .loosens: return "loosens"
    case .shortens: return "shortens"
    }
}

func switchName(_ outcome: SwitchOutcome) -> String {
    switch outcome {
    case .allowed: return "allowed"
    case .requiresRecordedDeclaration: return "requires_recorded_declaration"
    }
}

// T-5 T-37
func t_5_t_37_swift_api_version_matches_shared_vectors(_ dir: URL, _ tally: inout Tally) throws {
    let name = #function
    let vectors = try load(ApiVectors.self, dir, "api-version.json")
    let version = apiVersion()
    check(&tally, name, "api_version", "\(version.major).\(version.minor)", vectors.api_version)
    for c in vectors.compare {
        let a = ApiVersion(major: c.a.major, minor: c.a.minor)
        let b = ApiVersion(major: c.b.major, minor: c.b.minor)
        check(&tally, name, c.id, orderName(compareApiVersions(a: a, b: b)), c.expected)
    }
}

// T-5 T-37 F-26
func t_5_t_37_swift_policy_defaults_match_shared_vectors(_ dir: URL, _ tally: inout Tally) throws {
    let name = #function
    let vectors = try load(PolicyVectors.self, dir, "policy-default.json")
    guard !vectors.change.isEmpty, !vectors.switch.isEmpty else {
        throw HarnessError.malformed("policy-default.json")
    }
    for c in vectors.change {
        let policy = PolicyDefault(
            direction: try direction(c.direction, c.id),
            min: try number(c.min, c.id),
            max: try number(c.max, c.id)
        )
        let outcome = evaluatePolicyChange(
            policy: policy,
            current: try number(c.current, c.id),
            proposed: try number(c.proposed, c.id)
        )
        check(&tally, name, c.id, changeName(outcome), c.expected)
    }
    for c in vectors.switch {
        let basis: SwitchBasis
        switch c.basis {
        case "recorded_declaration": basis = .recordedDeclaration
        case "unrecorded": basis = .unrecorded
        default: throw HarnessError.malformed(c.id)
        }
        let outcome = evaluateSecuritySwitch(current: c.current, proposed: c.proposed, basis: basis)
        check(&tally, name, c.id, switchName(outcome), c.expected)
    }
}

func object(_ data: Data, _ id: String) throws -> [String: Any] {
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw HarnessError.malformed(id)
    }
    return value
}

func json(_ value: Any, _ id: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value)
    guard let text = String(data: data, encoding: .utf8) else { throw HarnessError.malformed(id) }
    return text
}

func cases(_ file: [String: Any], _ key: String, _ name: String) throws -> [[String: Any]] {
    guard let list = file[key] as? [[String: Any]], !list.isEmpty else {
        throw HarnessError.malformed(name)
    }
    return list
}

func sortedJson(_ value: Any, _ id: String) throws -> String {
    let data = try JSONSerialization.data(
        withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    guard let text = String(data: data, encoding: .utf8) else { throw HarnessError.malformed(id) }
    return text
}

// T-5 T-37 INV-7 INV-8 X-24
func t_5_t_37_inv_7_swift_record_vectors_match(_ dir: URL, _ tally: inout Tally) throws {
    let name = #function
    var all: [[String: Any]] = []
    for (file, key) in [
        ("records.json", "records"), ("records-reject.json", "cases"),
        ("records-quarantine.json", "cases"),
    ] {
        let data = try Data(contentsOf: dir.appendingPathComponent(file))
        all += try cases(try object(data, file), key, file)
    }
    var seen = Set<String>()
    for c in all {
        guard let id = c["id"] as? String, let decoded = c["decoded"], let context = c["context"] else {
            throw HarnessError.malformed("record case")
        }
        guard let expect = c["expect"] as? [String: String], let outcome = expect["outcome"] else {
            throw HarnessError.malformed(id)
        }
        let actual = validateRecord(decoded: try json(decoded, id), context: try json(context, id))
        check(&tally, name, id, actual, try sortedJson(expect, id))
        seen.insert(outcome)
    }
    guard seen == ["accept", "quarantine", "reject"] else { throw HarnessError.malformed(name) }
}

// T-5 T-37 INV-7 P-31
func t_5_t_37_inv_7_swift_derivation_matches_native_bytes(
    _ dir: URL, _ fixtures: URL, _ tally: inout Tally
) throws {
    let name = #function
    let file = try object(try Data(contentsOf: dir.appendingPathComponent("records.json")), name)
    let records = try cases(file, "records", name)
    let envelopes = try cases(file, "envelopes", name)
    guard records.count == envelopes.count else { throw HarnessError.malformed(name) }
    var entries: [[String: Any]] = []
    for (r, e) in zip(records, envelopes) {
        guard let env = e["decoded"] as? [String: Any], let record = r["decoded"] else {
            throw HarnessError.malformed(name)
        }
        entries.append([
            "id": env["record"] as Any, "record": record, "position": env["pos"] as Any,
            "recorded_at": env["recorded_at"] as Any, "ingest": env["ingest"] as Any,
            "restriction": "no_objection", "issuer": "local",
        ])
    }
    let inputs = try String(
        contentsOf: fixtures.appendingPathComponent("derive-inputs.json"), encoding: .utf8)
    let expected = try String(
        contentsOf: fixtures.appendingPathComponent("derive-expected.json"), encoding: .utf8)
    let actual = deriveRecords(entries: try json(entries, name), inputs: inputs)
    check(
        &tally, name, "records.json", actual,
        expected.trimmingCharacters(in: .newlines))
}

typealias JSONObject = [String: Any]

func text(_ value: Any?, _ id: String) throws -> String {
    guard let s = value as? String else { throw HarnessError.malformed(id) }
    return s
}

func objectOf(_ value: Any?, _ id: String) throws -> JSONObject {
    guard let m = value as? JSONObject else { throw HarnessError.malformed(id) }
    return m
}

func maps(_ value: Any?, _ id: String) throws -> [JSONObject] {
    guard let list = value as? [JSONObject] else { throw HarnessError.malformed(id) }
    return list
}

func integer(_ value: Any?, _ id: String) throws -> Int {
    guard let n = value as? Int else { throw HarnessError.malformed(id) }
    return n
}

func bytes(_ hex: String, _ id: String) throws -> Data {
    guard hex.utf8.count % 2 == 0 else { throw HarnessError.malformed(id) }
    var out = Data(capacity: hex.utf8.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else { throw HarnessError.malformed(id) }
        out.append(byte)
        index = next
    }
    return out
}

func digest(_ hex: Any?) -> [Any] {
    [-16, hex ?? NSNull()]
}

func found(_ hex: Any?) -> JSONObject {
    ["digest": digest(hex)]
}

func accepted(_ fields: JSONObject = [:]) -> JSONObject {
    var out = fields
    out["outcome"] = "accept"
    return out
}

func same(
    _ tally: inout Tally, _ name: String, _ id: String, _ got: String, _ want: Any
) throws {
    check(&tally, name, id, got, try sortedJson(want, id))
}

func vectorFile(_ dir: URL, _ file: String) throws -> JSONObject {
    try object(try Data(contentsOf: dir.appendingPathComponent(file)), file)
}

func unknownProtocol(_ c: JSONObject) -> Bool {
    let expect = c["expect"] as? JSONObject
    return expect?["outcome"] as? String == "quarantine"
        && expect?["reason"] as? String == "protocol_version_unknown"
}

/// The records and envelopes of the golden ledger after the genesis, in ledger order.
func ledger(_ records: URL) throws -> [(JSONObject, JSONObject)] {
    let file = try vectorFile(records, "records.json")
    let list = try cases(file, "records", "records.json")
    let envelopes = try cases(file, "envelopes", "records.json")
    guard list.count == envelopes.count else { throw HarnessError.malformed("records.json") }
    var out = Array(zip(list, envelopes))
    for c in try cases(try vectorFile(records, "records-quarantine.json"), "cases", "quarantine") {
        out.append((c, try objectOf(c["envelope"], "quarantine envelope")))
    }
    return out
}

/// The keys Access binds to each party of `cose-sign1.json`, in the binding's keys shape.
func keySets(_ records: URL) throws -> [String: [JSONObject]] {
    var sets: [String: [JSONObject]] = [:]
    for k in try cases(try vectorFile(records, "cose-sign1.json"), "keys", "cose keys") {
        let party = try text(k["party"], "cose key")
        let entry: JSONObject = [
            "kid": k["kid_hex"] ?? NSNull(), "alg": k["alg"] ?? NSNull(),
            "public_key": k["public_key_hex"] ?? NSNull(),
        ]
        sets[party, default: []].append(entry)
    }
    return sets
}

func keysOf(_ sets: [String: [JSONObject]], _ party: String) throws -> String {
    let keys: JSONObject = ["party": party, "allowed": [-19, -9, -7], "keys": sets[party] ?? []]
    return try json(keys, party)
}

// P-5 P-7 P-72 P-103 T-37 Access CR-10
func p_5_swift_cbor_canonical_vectors_match(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    for c in try cases(try vectorFile(records, "cbor-canonical.json"), "cases", name) {
        let id = try text(c["id"], name)
        let input: Data
        if let hex = c["hex"] as? String {
            input = try bytes(hex, id)
        } else {
            let g = try objectOf(c["generator"], id)
            let fill = String(repeating: try text(g["fill_hex"], id), count: try integer(g["fill_count"], id))
            input = try bytes(try text(g["head_hex"], id) + fill, id)
        }
        guard let tags = try objectOf(c["context"], id)["tag_allowlist"] as? [Int] else {
            throw HarnessError.malformed(id)
        }
        let got: String
        if tags.contains(18) && input.first == 0xd2 {
            got = parseCoseContainer(bytes: input)
        } else {
            got = checkCbor(bytes: input, tags: try json(tags, id))
        }
        try same(&tally, name, id, got, c["expect"] ?? NSNull())
    }
}

// P-5 P-67 P-68 P-75 P-79 P-101 P-104 T-37 Access CR-1
func p_79_swift_digest_vectors_match(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    let file = try vectorFile(records, "records.json")
    let first = try cases(file, "records", name)[0]
    let envelope = try cases(file, "envelopes", name)[0]
    let author = try objectOf(first["decoded"], name)["author"] ?? NSNull()
    for c in try cases(try vectorFile(records, "digest.json"), "cases", name) {
        let id = try text(c["id"], name)
        if let encoded = c["encoded_digest_hex"] as? String {
            var want: Any = c["expect"] ?? NSNull()
            if let value = c["digest_hex"] {
                want = accepted(found(value))
            }
            try same(&tally, name, id, decodeDigest(bytes: try bytes(encoded, id)), want)
        } else if let part = c["part"] as? JSONObject {
            let content: Data
            if let hex = part["content_hex"] as? String {
                content = try bytes(hex, id)
            } else {
                let spec = try objectOf(part["content"], id)
                let fill = try text(spec["fill_hex"], id)
                content = try bytes(String(repeating: fill, count: try integer(spec["fill_count"], id)), id)
            }
            let got = bodyCommitment(
                salt: try bytes(try text(c["salt_hex"], id), id), name: try text(part["name"], id),
                mediaType: try text(part["media_type"], id), content: content)
            try same(&tally, name, id, got, accepted(found(c["digest_hex"])))
        } else if id == "digest/record-id" {
            let got = recordId(record: try bytes(try text(first["hex"], id), id))
            try same(&tally, name, id, got, found(c["digest_hex"]))
        } else if id == "digest/leaf-0x00" {
            let got = leafHash(envelope: try bytes(try text(envelope["hex"], id), id))
            try same(&tally, name, id, got, found(c["digest_hex"]))
        } else if id == "digest/proof-commit" {
            let cose = try bytes(try text(c["cose_hex"], id), id)
            try same(&tally, name, id, proofCommit(coseSign1: cose), found(c["digest_hex"]))
            let key: JSONObject = [
                "kid": c["kid_hex"] ?? NSNull(), "alg": -19,
                "public_key": c["public_key_hex"] ?? NSNull(),
            ]
            let keys: JSONObject = ["party": author, "allowed": [-19], "keys": [key]]
            let got = verifyRecordSignature(coseSign1: cose, authorKeys: try json(keys, id))
            let want = accepted(["author": author, "record": digest(c["record_id_hex"])])
            try same(&tally, name, id, got, want)
        } else {
            throw HarnessError.malformed(id)
        }
    }
}

// P-100 P-11 P-67 P-87 P-101 T-37 T-69
func p_100_swift_genesis_envelope_and_record_bytes_match(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    let genesis = try cases(try vectorFile(records, "genesis.json"), "cases", name)
    for c in genesis {
        let id = try text(c["id"], name)
        var want: Any = c["expect"] ?? NSNull()
        if (c["expect"] as? JSONObject)?["outcome"] as? String == "accept" {
            want = accepted(["decoded": c["decoded"] ?? NSNull()])
        }
        try same(&tally, name, id, decodeEnvelope(envelope: try bytes(try text(c["hex"], id), id)), want)
    }
    let first = genesis[0]
    let input = try bytes(try text(first["hex"], name), name)
    let ledgerDigest = digest(try objectOf(first["ledger_id"], name)["digest_hex"])
    let prev = digest(first["leaf_hash"])
    try same(&tally, name, "ledger_id", ledgerId(genesis: input), ["digest": ledgerDigest])
    try same(&tally, name, "leaf_hash", leafHash(envelope: input), ["digest": prev])
    let point = accepted(["ledger": ledgerDigest, "prev": prev])
    try same(&tally, name, "genesis", genesisChainPoint(genesis: input), point)
    for (record, envelope) in try ledger(records) {
        let id = try text(record["id"], name)
        let input = try bytes(try text(record["hex"], id), id)
        var want: Any = record["expect"] ?? NSNull()
        if !unknownProtocol(record) {
            want = accepted(["decoded": record["decoded"] ?? NSNull()])
        }
        try same(&tally, name, id, decodeRecord(record: input), want)
        let encoded = try text(record["record_digest"], id)
        guard encoded.hasPrefix("822f5820") else { throw HarnessError.malformed(id) }
        try same(&tally, name, id, recordId(record: input), found(String(encoded.dropFirst(8))))
        let bytesOfEnvelope = try bytes(try text(envelope["hex"], id), id)
        let decoded = accepted(["decoded": envelope["decoded"] ?? NSNull()])
        try same(&tally, name, id, decodeEnvelope(envelope: bytesOfEnvelope), decoded)
        try same(&tally, name, id, leafHash(envelope: bytesOfEnvelope), found(envelope["leaf_hash"]))
    }
    var all: [JSONObject] = []
    for (file, key) in [
        ("records.json", "records"), ("records-reject.json", "cases"),
        ("records-quarantine.json", "cases"),
    ] {
        all += try cases(try vectorFile(records, file), key, file)
    }
    for c in all {
        let id = try text(c["id"], name)
        let got = validateRecordCbor(
            record: try bytes(try text(c["hex"], id), id), context: try json(c["context"] ?? NSNull(), id))
        try same(&tally, name, id, got, c["expect"] ?? NSNull())
    }
}

// P-32 P-6 P-7 P-75 P-102 P-105 P-106 EV-3 EV-8 P-107 T-37 Access CR-9
func p_32_swift_signature_and_evidence_vectors_match(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    let sets = try keySets(records)
    let cose = try vectorFile(records, "cose-sign1.json")
    for c in try cases(cose, "cases", name) {
        let id = try text(c["id"], name)
        let signature = try bytes(try text(c["cose_hex"], id), id)
        let author = try text(c["author"], id)
        let got = verifyRecordSignature(coseSign1: signature, authorKeys: try keysOf(sets, author))
        if (c["expect"] as? JSONObject)?["outcome"] as? String == "accept" {
            try same(&tally, name, id, got, accepted(["author": author, "record": digest(c["record_id_hex"])]))
            try same(&tally, name, id, proofCommit(coseSign1: signature), found(c["proof_commit_hex"]))
        } else {
            try same(&tally, name, id, got, c["expect"] ?? NSNull())
        }
    }
    for k in try cases(cose, "keys", name) {
        let id = try text(k["id"], name)
        let got = checkPublicKey(
            alg: Int64(try integer(k["alg"], id)), publicKey: try bytes(try text(k["public_key_hex"], id), id))
        try same(&tally, name, id, got, accepted())
    }
    for k in try cases(cose, "key_cases", name) {
        let id = try text(k["id"], name)
        let got = checkPublicKey(
            alg: Int64(try integer(k["alg"], id)), publicKey: try bytes(try text(k["public_key_hex"], id), id))
        try same(&tally, name, id, got, k["expect"] ?? NSNull())
    }
    for c in try cases(try vectorFile(records, "evidence.json"), "cases", name) {
        let id = try text(c["id"], name)
        let record = try bytes(try text(c["hex"], id), id)
        guard let coseHex = c["cose_hex"] as? String else {
            try same(&tally, name, id, decodeRecord(record: record), c["expect"] ?? NSNull())
            continue
        }
        let index = try integer(c["evidence_index"], id)
        let keys = try keysOf(sets, try text(c["presenter"], id))
        let got = verifyEvidenceSignature(
            record: record, index: UInt32(index), coseSign1: try bytes(coseHex, id), presenterKeys: keys)
        try same(&tally, name, id, got, c["expect"] ?? NSNull())
        if id != "evidence/statement-changed" {
            let references = try maps(try objectOf(c["decoded"], id)["evidence"], id)
            guard index < references.count else { throw HarnessError.malformed(id) }
            let reference = references[index]
            let want = accepted([
                "statement": c["statement_hex"] ?? NSNull(),
                "presenter": reference["presenter"] ?? NSNull(),
                "signature": reference["signature"] ?? NSNull(),
            ])
            try same(&tally, name, id, evidenceStatement(record: record, index: UInt32(index)), want)
        }
    }
}

// T-10 P-11 P-21 P-75 P-79 P-100 P-108 EV-35 T-37
func t_10_swift_stored_entries_verify_from_their_bytes(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    let sets = try keySets(records)
    var signed: [String: Data] = [:]
    for c in try cases(try vectorFile(records, "cose-sign1.json"), "cases", name) {
        if let envelope = c["envelope"] as? String {
            signed[envelope] = try bytes(try text(c["cose_hex"], envelope), envelope)
        }
    }
    let genesis = try cases(try vectorFile(records, "genesis.json"), "cases", name)[0]
    var at: JSONObject = [
        "ledger": digest(try objectOf(genesis["ledger_id"], name)["digest_hex"]),
        "prev": digest(genesis["leaf_hash"]),
    ]
    var verified = 0
    for (record, envelope) in try ledger(records) {
        let id = try text(record["id"], name)
        let label: String
        if let envelopeId = envelope["id"] as? String {
            label = "records.json \(envelopeId)"
        } else {
            label = "records-quarantine.json \(id) envelope"
        }
        let signature = signed[label]
        let author = try text(try objectOf(record["decoded"], id)["author"], id)
        let e = try objectOf(envelope["decoded"], id)
        let leaf = digest(envelope["leaf_hash"])
        let next: JSONObject = ["ledger": e["ledger"] ?? NSNull(), "prev": leaf]
        var want: JSONObject = ["outcome": "reject", "reason": "protocol_version_unknown"]
        if signature != nil || !unknownProtocol(record) {
            verified += 1
            want = accepted([
                "record": e["record"] ?? NSNull(), "author": author,
                "binding": signature == nil ? "auth_context" : "signature_valid",
                "ledger": e["ledger"] ?? NSNull(), "position": e["pos"] ?? NSNull(),
                "recorded_at": e["recorded_at"] ?? NSNull(), "ingest": e["ingest"] ?? NSNull(),
                "leaf": leaf, "next": next,
            ])
        }
        let got = verifyEntry(
            at: try json(at, id), envelope: try bytes(try text(envelope["hex"], id), id),
            record: try bytes(try text(record["hex"], id), id), coseSign1: signature,
            authorKeys: try keysOf(sets, author))
        try same(&tally, name, id, got, want)
        at = next
    }
    guard verified == 14 else { throw HarnessError.malformed(name) }
}

func digests(_ value: Any?, _ id: String) throws -> [Any] {
    guard let list = value as? [String] else { throw HarnessError.malformed(id) }
    return list.map { digest($0) }
}

func noteKey(_ value: Any?, _ id: String) throws -> JSONObject {
    let k = try objectOf(value, id)
    return ["name": k["name"] ?? NSNull(), "public_key": k["public_key_hex"] ?? NSNull()]
}

// T-4 T-88 P-11 P-20 P-100 P-101 P-108 OP-33 OP-46 T-37
func t_4_swift_merkle_and_checkpoint_vectors_match(_ records: URL, _ tally: inout Tally) throws {
    let name = #function
    let merkle = try vectorFile(records, "merkle.json")
    for n in try cases(merkle, "nodes", name) {
        let id = try text(n["id"], name)
        let got = merkleNodeHash(
            left: try json(digest(n["left_hex"]), id), right: try json(digest(n["right_hex"]), id))
        try same(&tally, name, id, got, found(n["digest_hex"]))
    }
    let genesis = try cases(try vectorFile(records, "genesis.json"), "cases", name)[0]
    var leaves: [Any] = [genesis["hex"] ?? NSNull()]
    for (_, envelope) in try ledger(records) {
        leaves.append(envelope["hex"] ?? NSNull())
    }
    for r in try cases(merkle, "roots", name) {
        let size = try integer(r["size"], name)
        guard size <= leaves.count else { throw HarnessError.malformed(name) }
        let got = merkleRoot(envelopes: try json(Array(leaves.prefix(size)), name))
        try same(&tally, name, "root \(size)", got, found(r["root_hex"]))
    }
    let inclusion = try cases(merkle, "inclusion", name)
    for c in inclusion {
        let id = try text(c["id"], name)
        let proof: JSONObject = [
            "position": c["index"] ?? NSNull(), "size": c["size"] ?? NSNull(),
            "leaf": digest(c["leaf_hash_hex"]), "path": try digests(c["path_hex"], id),
            "root": digest(c["root_hex"]),
        ]
        try same(&tally, name, id, verifyInclusion(inclusion: try json(proof, id)), c["expect"] ?? NSNull())
    }
    for c in try cases(merkle, "consistency", name) {
        let id = try text(c["id"], name)
        let proof: JSONObject = [
            "first": c["first"] ?? NSNull(), "second": c["second"] ?? NSNull(),
            "first_root": digest(c["first_root_hex"]), "second_root": digest(c["second_root_hex"]),
            "path": try digests(c["path_hex"], id),
        ]
        try same(&tally, name, id, verifyConsistency(consistency: try json(proof, id)), c["expect"] ?? NSNull())
    }
    let keys = try objectOf(merkle["keys"], name)
    let log = try noteKey(keys["log"], name)
    var witnesses: [JSONObject] = []
    for w in try maps(keys["witnesses"], name) {
        witnesses.append(try noteKey(w, name))
    }
    let notes = try cases(merkle, "checkpoints", name)
    for c in notes {
        let id = try text(c["id"], name)
        let expect = try objectOf(c["expect"], id)
        var want: Any = expect
        if expect["outcome"] as? String == "accept" {
            want = accepted([
                "size": expect["size"] ?? NSNull(), "root": digest(expect["root_hex"]),
                "profile": expect["profile"] ?? NSNull(), "cosignatures": expect["cosignatures"] ?? NSNull(),
            ])
        }
        let note: JSONObject = [
            "note": c["note"] ?? NSNull(), "origin": c["origin"] ?? NSNull(), "log": log,
            "witnesses": witnesses,
        ]
        try same(&tally, name, id, verifyCheckpoint(checkpoint: try json(note, id)), want)
    }
    let first = notes[0]
    let size = try integer(try objectOf(first["expect"], name)["size"], name)
    var signed: JSONObject = [
        "note": first["note"] ?? NSNull(), "origin": first["origin"] ?? NSNull(), "log": log,
        "witnesses": witnesses,
    ]
    let checkpoint = try json(signed, name)
    var included = 0
    for c in inclusion {
        let accept = (c["expect"] as? JSONObject)?["outcome"] as? String == "accept"
        guard accept, try integer(c["size"], name) == size else { continue }
        let id = try text(c["id"], name)
        let proof: JSONObject = [
            "position": c["index"] ?? NSNull(), "leaf": digest(c["leaf_hash_hex"]),
            "path": try digests(c["path_hex"], id),
        ]
        let got = checkpointIncludes(checkpoint: checkpoint, inclusion: try json(proof, id))
        try same(&tally, name, id, got, accepted())
        included += 1
    }
    guard included == 17 else { throw HarnessError.malformed(name) }
    signed["witnesses"] = [JSONObject]()
    let got = checkpointExtendsTo(older: try json(signed, name), newer: checkpoint, path: "[]")
    try same(&tally, name, "extends", got, accepted())
}

// T-89 P-29 C-34 T-37
func t_89_swift_touched_item_vectors_match(_ records: URL, _ kernel: URL, _ tally: inout Tally) throws {
    let name = #function
    var byId: [String: JSONObject] = [:]
    let quarantine = try cases(try vectorFile(records, "records-quarantine.json"), "cases", name)
    for c in try cases(try vectorFile(records, "records.json"), "records", name) + quarantine {
        let id = try text(c["id"], name)
        byId[id] = c
    }
    for c in try cases(try vectorFile(kernel, "items-touched.json"), "cases", name) {
        let id = try text(c["id"], name)
        guard let record = byId[id] else { throw HarnessError.malformed(id) }
        let got = touched(record: try bytes(try text(record["hex"], id), id))
        try same(&tally, name, id, got, accepted(["touches": c["touches"] ?? NSNull()]))
    }
    for c in quarantine where unknownProtocol(c) {
        let id = try text(c["id"], name)
        try same(&tally, name, id, touched(record: try bytes(try text(c["hex"], id), id)), c["expect"] ?? NSNull())
    }
}

do {
    guard CommandLine.arguments.count == 4 else { throw HarnessError.usage }
    let dir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    let records = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let fixtures = URL(fileURLWithPath: CommandLine.arguments[3], isDirectory: true)
    var tally = Tally()
    try t_5_t_37_swift_api_version_matches_shared_vectors(dir, &tally)
    try t_5_t_37_swift_policy_defaults_match_shared_vectors(dir, &tally)
    try t_5_t_37_inv_7_swift_record_vectors_match(records, &tally)
    try t_5_t_37_inv_7_swift_derivation_matches_native_bytes(records, fixtures, &tally)
    try p_5_swift_cbor_canonical_vectors_match(records, &tally)
    try p_79_swift_digest_vectors_match(records, &tally)
    try p_100_swift_genesis_envelope_and_record_bytes_match(records, &tally)
    try p_32_swift_signature_and_evidence_vectors_match(records, &tally)
    try t_10_swift_stored_entries_verify_from_their_bytes(records, &tally)
    try t_4_swift_merkle_and_checkpoint_vectors_match(records, &tally)
    try t_89_swift_touched_item_vectors_match(records, dir, &tally)
    if tally.failures > 0 {
        print("\(tally.failures) of \(tally.cases) kernel vectors differ through Swift")
        exit(1)
    }
    print("ok \(tally.cases) kernel vectors through Swift")
} catch {
    print("error: \(error)")
    exit(1)
}

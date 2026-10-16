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

/// The vectors carry the author's actor type only; every `on_behalf_of` ring is an Access-bound organization, as in the envelopes.
func context(_ c: [String: Any], _ id: String) throws -> [String: Any] {
    guard var context = c["context"] as? [String: Any],
        var actors = context["actor_type"] as? [String: Any],
        let decoded = c["decoded"] as? [String: Any]
    else { throw HarnessError.malformed(id) }
    if let rings = decoded["on_behalf_of"] as? [Any], !rings.isEmpty, actors["on_behalf_of"] == nil {
        actors["on_behalf_of"] = rings.map { _ in ["organization", "access_binding"] }
        context["actor_type"] = actors
    }
    return context
}

func outcomeText(_ value: Any?, _ id: String) throws -> String {
    guard let fields = value as? [String: String], let outcome = fields["outcome"] else {
        throw HarnessError.malformed(id)
    }
    return fields["reason"].map { "\(outcome) \($0)" } ?? outcome
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
        guard let id = c["id"] as? String, let decoded = c["decoded"] else {
            throw HarnessError.malformed("record case")
        }
        let out = validateRecord(decoded: try json(decoded, id), context: try json(try context(c, id), id))
        let actual = try outcomeText(try JSONSerialization.jsonObject(with: Data(out.utf8)), id)
        let expected = try outcomeText(c["expect"], id)
        check(&tally, name, id, actual, expected)
        seen.insert(String(expected.prefix { $0 != " " }))
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
    if tally.failures > 0 {
        print("\(tally.failures) of \(tally.cases) kernel vectors differ through Swift")
        exit(1)
    }
    print("ok \(tally.cases) kernel vectors through Swift")
} catch {
    print("error: \(error)")
    exit(1)
}

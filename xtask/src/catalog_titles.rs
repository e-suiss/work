//! Curated English catalog text (T-46): rule titles, must-never items (F-9),
//! guarantee matrix items (SEC-31, SEC-32, SEC-33) and the threat model (SEC-21,
//! T-49). Regeneration takes text only from here, so the tracked catalog never
//! carries spec prose.

/// Short English titles by rule ID.
pub(crate) const TITLES: &[(&str, &str)] = &[
    (
        "MD-14",
        "Required infrastructure is PostgreSQL and NATS JetStream, used only as a signal",
    ),
    (
        "MD-15",
        "Fully open source under Apache-2.0 with no open core",
    ),
    ("F-9", "The must-never list is binding"),
    (
        "F-21",
        "Frozen technical, protocol and MKT rows carry acceptance tests and counterexamples",
    ),
    (
        "F-24",
        "Guarantee classes and claim language bind product and documentation text",
    ),
    (
        "F-27",
        "Unset policy defaults are marked and block dependent features from release",
    ),
    (
        "MKT-1",
        "Differentiation claims carry a comparison set, a date and a counterexample",
    ),
    ("INV-34", "Wording never exceeds the guarantee"),
    (
        "E-40",
        "Access and Relay counterpart clauses are tracked one to one",
    ),
    (
        "SEC-33",
        "Things Work does not claim are never stated in guarantee language",
    ),
    (
        "SEC-34",
        "Claim language binds product text, API field names and documentation",
    ),
    (
        "P-1",
        "Protocol, API and normative external surfaces are separate layers",
    ),
    (
        "P-2",
        "Protocol, CDDL, vectors and verifier are Apache-2.0 and verifiable offline",
    ),
    (
        "T-3",
        "All code is Apache-2.0 in a public repository with no open core",
    ),
    (
        "T-4",
        "The kernel is no_std, forbids unsafe, has no I/O and never panics",
    ),
    (
        "T-8",
        "Code is shared but data and keys are not; Access only through its public API",
    ),
    (
        "T-22",
        "Accelerators only with measured need; optional components are never canonical",
    ),
    (
        "T-29",
        "Engineering rules follow Access; Work adaptations are written down with reasons",
    ),
    (
        "T-30",
        "Out of scope: workflow engines owning state, execution and delivery timers",
    ),
    (
        "T-31",
        "One repository, exact shared crate versions and an enforced dependency direction",
    ),
    (
        "T-32",
        "Component layers and ports; clock and randomness only through ports",
    ),
    (
        "T-33",
        "Strict lints, no request-path panics, checked arithmetic and redacting types",
    ),
    (
        "T-34",
        "Strict TypeScript clients on esuiss-ui with a generated API client",
    ),
    (
        "T-35",
        "OpenAPI from code, AsyncAPI events, CDDL first and internal ConnectRPC",
    ),
    (
        "T-36",
        "No ORM, SQL only in store, no physical delete, real PostgreSQL in tests",
    ),
    (
        "T-37",
        "Every normative rule has a test; flaky tests are never retried until green",
    ),
    (
        "T-38",
        "Supply chain gates: deny, vet, audit, cooldown and a build script allowlist",
    ),
    (
        "T-39",
        "OpenTelemetry signals with trace context, no identity labels and no secrets",
    ),
    (
        "T-40",
        "Separate product, SDK, kernel and protocol versions with a compatibility table",
    ),
    (
        "T-41",
        "The local environment always includes local Access and Relay",
    ),
    (
        "T-42",
        "Spec registers are the decision record; the README never links to docs",
    ),
    (
        "T-43",
        "Contribution process as in Access with sensitive paths in CODEOWNERS",
    ),
    (
        "T-44",
        "Benchmarks and an instruction-count gate; nothing optimised without measurement",
    ),
    (
        "T-45",
        "Engineering paths deliberately not used, such as an ORM or a second kernel",
    ),
    (
        "T-46",
        "Tracked rule catalog generated from the spec with coverage and value reports",
    ),
    (
        "T-47",
        "Tests carry rule IDs in their name or a bare ID line",
    ),
    (
        "T-48",
        "A forbidden-claims dictionary is scanned over documents, API files and messages",
    ),
    (
        "T-49",
        "Threat model as code; public comparison text only in COMPARISON.md",
    ),
    (
        "T-50",
        "A local check detects changed Access and Relay counterpart clauses",
    ),
    (
        "T-51",
        "compat.toml pins Access, Relay and shared crates for one local compose file",
    ),
    ("T-52", "Each rule check has exactly one tool"),
    ("T-53", "Code carries no explanatory comments"),
    ("T-54", "Published package names carry the esuiss prefix"),
    (
        "T-55",
        "The maintainer pushes signed commits to main; everyone else uses pull requests",
    ),
    (
        "T-56",
        "Keys and secrets only through PKCS#11, with SoftHSM locally",
    ),
    (
        "T-57",
        "Observability with OpenTelemetry Collector, Jaeger, Prometheus and Grafana locally",
    ),
    (
        "T-58",
        "Every JavaScript or TypeScript package is an independent npm project",
    ),
    ("T-59", "Reproducible builds are a goal, not a release gate"),
    (
        "T-60",
        "Five percent instruction threshold, seven-day cooldown and pinned references",
    ),
    (
        "T-61",
        "Browser endpoints may use a CDN tunnel; mTLS endpoints use passthrough",
    ),
    (
        "T-62",
        "Benchmarks run on a dedicated runner for scheduled and manual main jobs only",
    ),
    (
        "T-63",
        "Stage 0 items that need later code move to that stage",
    ),
    (
        "OP-12",
        "Records are never physically deleted; personal data is crypto-shredded",
    ),
    (
        "OP-18",
        "Telemetry is minimised, pseudonymous and never a decision input",
    ),
    (
        "OP-26",
        "Capacity and latency numbers are set only by measurement",
    ),
];

/// IDs whose title must not be empty regardless of stage.
pub(crate) const REQUIRED_TITLES: &[&str] = &[
    "P-1", "P-2", "MKT-1", "F-21", "F-24", "F-27", "INV-34", "SEC-33", "SEC-34", "E-40", "MD-14",
    "MD-15", "OP-12", "OP-18", "OP-26", "T-29", "T-30", "T-31", "T-32", "T-33", "T-34", "T-35",
    "T-36", "T-37", "T-38", "T-39", "T-40", "T-41", "T-42", "T-43", "T-44", "T-45", "T-46", "T-47",
    "T-48", "T-49", "T-50", "T-51", "T-52", "T-53", "T-54", "T-55", "T-56", "T-57", "T-58", "T-59",
    "T-60", "T-61", "T-62", "T-63",
];

/// The F-9 must-never list, in spec order.
pub(crate) const MUST_NEVER: &[&str] = &[
    "Never creates or widens authority, nor overrides an Access denial",
    "Never gives normative effect to claims, observations, content, chat or notification actions",
    "Never treats silence, no answer or expiry as approval or acceptance",
    "Never shows a doer's done statement as acceptance",
    "Never makes an agent solely accountable or leaves work without an accountable owner",
    "Never rewrites record history and never deletes physically",
    "Never keeps state as a hand-edited field or shows unreported work as running",
    "Never offers controls the executor did not declare, nor shows revoked as stopped",
    "Never shows or ranks by an agent's self-reported confidence",
    "Never leaks visibility across organisations nor silently drops an authorised peer's record",
    "Never stores passwords, tokens, cookies, API secrets or payment data",
    "Never runs a built-in authority mode or a direct notification mode",
    "Never picks or ranks the best agent, nor sells ranking",
    "Never acts in the outside world or moves money",
    "Never locks a feature to SaaS or a licence flag",
    "Never gives first-party Suiss components semantic privileges others lack",
    "Never shows raw chain of thought nor reads personal memory",
    "Never presents an agent as a human",
    "Never opens person-level manager views the person cannot see",
    "Never accepts a generic confirmation or agent-written text as approval content",
];

/// Rules each must-never item traces to (by item number).
pub(crate) const MUST_NEVER_RULES: &[(u32, &[&str])] = &[(15, &["MD-15", "P-2", "T-3"])];

/// Guarantee matrix items: (rule, items in spec order); classes come from the spec.
pub(crate) const GUARANTEES: &[(&str, &[&str])] = &[
    (
        "SEC-31",
        &[
            "Normative state changes only through a Declaration",
            "Claims and Acts alone have no normative effect",
            "Work never creates or widens authority; autonomy stays within authority",
            "Every agent action traces to a recorded normative basis",
            "The accountability chain ends in a Party under a declared regime",
            "Signed record bytes and provenance never change; corrections use supersedes",
            "The same semantic inputs give the same normative result",
            "Normative time is ledger time, not a client clock",
            "No approval exists without an underlying commitment or gate",
            "Experience and metrics never create canonical state",
            "Record verification needs no online Suiss service",
            "A foreign record has no local normative effect before local admission",
            "An authenticated federation record is never silently dropped",
            "A statement without evidence is marked so on every surface",
            "An unanswered decision is never a yes; implicit acceptance needs a prior Declaration",
            "Delivery, acknowledgement and channel replies are never approval or authority",
            "Work is not the sole recovery authority for a Party identity",
        ],
    ),
    (
        "SEC-32",
        &[
            "A recorded entry survives a region loss with multi-region placement",
            "Execution stops after revocation when the executor supports and confirms it",
            "A safe state is reached when policy defines a reachable one",
            "Existence at a time holds with an external witness or timestamp",
            "Ledger equivocation is detected when witnesses or checkpoints are compared",
            "An agent's real-world identity holds with a trusted identity binding in Access",
            "Runtime and model configuration hold under compatible remote attestation",
            "Personal data bodies become unreadable by crypto-shredding without other key copies",
            "Approval surface integrity holds on a conforming trusted surface",
            "Operators cannot read only client-side encrypted parts",
            "Reads never use authority older than the freshness bound Access declares",
            "A consequential external effect happens once when the system supports idempotency",
        ],
    ),
    (
        "SEC-33",
        &[
            "Making a recipient forget disclosed data",
            "Knowing an offline or compromised executor stopped without confirmation",
            "Proving a signed Claim is true",
            "Fully preventing a model from inferring from private data it saw",
            "Turning human approval into proof of good judgement",
            "Guaranteeing a model is immune to prompt injection",
            "Telling a compromised but authorised agent from legitimate behaviour before detection",
            "Detecting undeclared operator configuration changes without remote attestation",
            "Proving that seemingly independent Parties are not colluding",
            "Stopping colluding humans from getting around split authority",
            "Guaranteeing exactly-once external effects without idempotency support",
            "Guaranteeing no ledger equivocation when nobody compares witnesses",
            "Claiming the hosted service cannot read body content",
            "Detecting censorship before recording on its own",
            "Fully preventing cross-work leakage through external model providers",
            "Equating accountability in Work with legal responsibility",
            "Forcing an ambient-session action to look distinct from the user externally",
            "Deleting previously distributed copies by redaction or crypto-shredding",
            "Promising every action has a meaningful safe state",
            "Guaranteeing a federation peer honours a redaction request",
            "Guaranteeing trust-zone labels alone make agent behaviour safe",
        ],
    ),
];

/// One threat-model row (SEC-21, T-49): rule IDs per prevent, limit, detect and recover cell.
pub(crate) struct ThreatRow {
    pub(crate) key: &'static str,
    pub(crate) title: &'static str,
    pub(crate) prevent: &'static [&'static str],
    pub(crate) limit: &'static [&'static str],
    pub(crate) detect: &'static [&'static str],
    pub(crate) recover: &'static [&'static str],
}

/// The seven threats of the threat posture table, in spec order.
pub(crate) const THREATS: &[ThreatRow] = &[
    ThreatRow {
        key: "indirect-prompt-injection",
        title: "Indirect prompt injection through documents, email, tool output or federated bodies",
        prevent: &["SEC-1", "SEC-2", "SEC-22", "SEC-23", "EV-16"],
        limit: &["EV-15", "RC-27", "SEC-27"],
        detect: &["ST-3", "ST-8"],
        recover: &["SEC-19", "CM-34"],
    },
    ThreatRow {
        key: "compromised-agent",
        title: "Compromised or mistaken agent",
        prevent: &["SEC-4", "SEC-26"],
        limit: &["SEC-3", "CM-49"],
        detect: &["EV-1", "EV-7", "CM-38"],
        recover: &["RC-37", "RC-8"],
    },
    ThreatRow {
        key: "memory-poisoning",
        title: "Shared memory poisoning",
        prevent: &["EV-13"],
        limit: &["EV-18"],
        detect: &["EV-11"],
        recover: &["INV-2", "P-24"],
    },
    ThreatRow {
        key: "malicious-federation-peer",
        title: "Malicious federation counterparty",
        prevent: &["FD-1", "FD-16"],
        limit: &["FD-19", "FD-20", "SEC-18"],
        detect: &["FD-24", "FD-25"],
        recover: &["SEC-19", "FD-27"],
    },
    ThreatRow {
        key: "stale-authority",
        title: "Stale authority",
        prevent: &["EV-32", "SEC-14"],
        limit: &["EV-32", "T-28"],
        detect: &["SEC-8"],
        recover: &["EV-32", "T-28"],
    },
    ThreatRow {
        key: "forged-approval",
        title: "Forged approval through notification buttons or agent text",
        prevent: &["SEC-11", "SEC-28"],
        limit: &["SEC-28"],
        detect: &["SEC-27", "SEC-28"],
        recover: &["SEC-27", "SEC-10"],
    },
    ThreatRow {
        key: "secret-leakage",
        title: "Secret leakage",
        prevent: &["SEC-24", "SEC-25"],
        limit: &["SEC-24"],
        detect: &["SEC-13"],
        recover: &["SEC-13", "OP-15"],
    },
];

/// The curated title for `id`, or empty.
pub(crate) fn title(id: &str) -> &'static str {
    TITLES.iter().find(|(i, _)| *i == id).map_or("", |(_, t)| t)
}

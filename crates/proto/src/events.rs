//! The event type catalog (T-98 items 3 to 5, P-38): every (record, affected item) pair is one event; the item a record is about takes the type its wire name gives, `<item>.<past tense>`, and every other item the record touches takes `<item>.changed` with the primary type in `data.cause`. `cargo xtask asyncapi` writes `sdks/asyncapi/work-events.yaml` and the versioned `data` schemas from [`CATALOG`], marks the types of [`DEPRECATED`] (P-39 item 2), and `cargo xtask check event-catalog` refuses a kernel wire name that has no event type and is not listed in [`UNCATALOGUED`]. [`RecordFacts`] is what a thin event takes from its committed record (P-37, P-35 item 3).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use work_kernel::catalog::{ActSubtype, ConditionType, DeclarationSubtype};
use work_kernel::codec::{Decoded, decode_record};
use work_kernel::record::{ClaimType, ParamScalar, ParamValue, Record};

use crate::id::{ExternalId as _, Prefix, format as external};

/// The `datacontenttype` of every event (P-35 item 2).
pub const DATA_CONTENT_TYPE: &str = "application/json";

/// The item type an event is about (T-98 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Item {
    /// A Work.
    Work,
    /// A Commitment.
    Commitment,
    /// A Condition that is not a gate.
    Condition,
    /// A gate, a Condition of the gate kind.
    Gate,
    /// A record.
    Record,
    /// A ledger.
    Ledger,
}

impl Item {
    /// The name the event type starts with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Commitment => "commitment",
            Self::Condition => "condition",
            Self::Gate => "gate",
            Self::Record => "record",
            Self::Ledger => "ledger",
        }
    }
}

/// The shape of an event's thin `data` (P-37).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Data {
    /// The related Party ids only.
    Thin,
    /// Also `kind`, the revoking wire name (T-98 item 5).
    Revoked,
    /// Also `cause`, the primary event type of the record (T-98 item 4).
    Changed,
}

/// One event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventType {
    /// `<item>.<past tense>`.
    pub name: &'static str,
    /// The item the event is about.
    pub item: Item,
    /// The `data` schema version.
    pub version: u32,
    /// The `data` shape.
    pub data: Data,
    /// The kernel wire names whose record gives this type to the item it is about; empty for a
    /// source that has no wire name.
    pub sources: &'static [&'static str],
}

const fn event(
    name: &'static str,
    item: Item,
    data: Data,
    sources: &'static [&'static str],
) -> EventType {
    EventType {
        name,
        item,
        version: 1,
        data,
        sources,
    }
}

/// The stage 3 catalog submitted for approval (T-98 items 5 and 7).
pub const CATALOG: &[EventType] = &[
    event("work.opened", Item::Work, Data::Thin, &[]),
    event(
        "work.updated",
        Item::Work,
        Data::Thin,
        &["observation", "assessment", "assumption", "action"],
    ),
    event(
        "commitment.requested",
        Item::Commitment,
        Data::Thin,
        &["request"],
    ),
    event(
        "commitment.promised",
        Item::Commitment,
        Data::Thin,
        &["promise"],
    ),
    event(
        "commitment.promised_conditionally",
        Item::Commitment,
        Data::Thin,
        &["promise_conditional"],
    ),
    event(
        "commitment.declined",
        Item::Commitment,
        Data::Thin,
        &["decline"],
    ),
    event(
        "commitment.countered",
        Item::Commitment,
        Data::Thin,
        &["counter"],
    ),
    event(
        "commitment.counter_accepted",
        Item::Commitment,
        Data::Thin,
        &["accept_counter"],
    ),
    event(
        "commitment.stated",
        Item::Commitment,
        Data::Thin,
        &["state"],
    ),
    event(
        "commitment.accepted",
        Item::Commitment,
        Data::Thin,
        &["accept"],
    ),
    event(
        "commitment.rejected",
        Item::Commitment,
        Data::Thin,
        &["reject"],
    ),
    event(
        "commitment.cancelled",
        Item::Commitment,
        Data::Thin,
        &["cancel"],
    ),
    event(
        "commitment.released",
        Item::Commitment,
        Data::Thin,
        &["release"],
    ),
    event(
        "commitment.delegated",
        Item::Commitment,
        Data::Thin,
        &["delegate"],
    ),
    event(
        "commitment.assigned",
        Item::Commitment,
        Data::Thin,
        &["assign"],
    ),
    event(
        "commitment.disputed",
        Item::Commitment,
        Data::Thin,
        &["dispute"],
    ),
    event(
        "commitment.deferred",
        Item::Commitment,
        Data::Thin,
        &["defer"],
    ),
    event(
        "commitment.resumed",
        Item::Commitment,
        Data::Thin,
        &["resume"],
    ),
    event(
        "commitment.noticed",
        Item::Commitment,
        Data::Thin,
        &["notice"],
    ),
    event(
        "commitment.refused",
        Item::Commitment,
        Data::Thin,
        &["refuse"],
    ),
    event(
        "commitment.revoked",
        Item::Commitment,
        Data::Revoked,
        &[
            "revoke_request",
            "revoke_promise",
            "revoke_statement",
            "revoke_acceptance",
        ],
    ),
    event(
        "commitment.expired",
        Item::Commitment,
        Data::Thin,
        &["expire"],
    ),
    event(
        "commitment.closed_administratively",
        Item::Commitment,
        Data::Thin,
        &["administrative_close"],
    ),
    event(
        "commitment.claimed",
        Item::Commitment,
        Data::Thin,
        &["claim"],
    ),
    event(
        "commitment.unclaimed",
        Item::Commitment,
        Data::Thin,
        &["unclaim"],
    ),
    event(
        "commitment.forwarded",
        Item::Commitment,
        Data::Thin,
        &["forward"],
    ),
    event(
        "commitment.nominated",
        Item::Commitment,
        Data::Thin,
        &["nominate"],
    ),
    event(
        "commitment.offered",
        Item::Commitment,
        Data::Thin,
        &["offer"],
    ),
    event(
        "commitment.reassigned",
        Item::Commitment,
        Data::Thin,
        &["reassign"],
    ),
    event(
        "commitment.lease_renewed",
        Item::Commitment,
        Data::Thin,
        &["renew_lease"],
    ),
    event(
        "condition.opened",
        Item::Condition,
        Data::Thin,
        &["open_condition"],
    ),
    event(
        "condition.withdrawn",
        Item::Condition,
        Data::Thin,
        &["withdraw_condition"],
    ),
    event("gate.opened", Item::Gate, Data::Thin, &["open_condition"]),
    event(
        "gate.withdrawn",
        Item::Gate,
        Data::Thin,
        &["withdraw_condition"],
    ),
    event("gate.decided", Item::Gate, Data::Thin, &["gate_decision"]),
    event(
        "work.stop_requested",
        Item::Work,
        Data::Thin,
        &["stop_request"],
    ),
    event(
        "work.stop_responded",
        Item::Work,
        Data::Thin,
        &["stop_response"],
    ),
    event(
        "work.resumed_after_stop",
        Item::Work,
        Data::Thin,
        &["resume_after_stop"],
    ),
    event(
        "work.control_leased",
        Item::Work,
        Data::Thin,
        &["control_lease"],
    ),
    event("work.handed_off", Item::Work, Data::Thin, &["handoff_note"]),
    event(
        "work.conflict_resolved",
        Item::Work,
        Data::Thin,
        &["conflict_resolution"],
    ),
    event("work.conflicted", Item::Work, Data::Thin, &[]),
    event(
        "work.autonomy_policy_declared",
        Item::Work,
        Data::Thin,
        &["autonomy_policy"],
    ),
    event("work.waiver_declared", Item::Work, Data::Thin, &["waiver"]),
    event(
        "commitment.implicit_acceptance_declared",
        Item::Commitment,
        Data::Thin,
        &["implicit_acceptance_terms"],
    ),
    event(
        "work.practice_adopted",
        Item::Work,
        Data::Thin,
        &["practice_adoption"],
    ),
    event(
        "work.queue_defined",
        Item::Work,
        Data::Thin,
        &["queue_definition"],
    ),
    event(
        "work.attention_requested",
        Item::Work,
        Data::Thin,
        &["attention_request"],
    ),
    event(
        "work.acknowledged",
        Item::Work,
        Data::Thin,
        &["acknowledgement"],
    ),
    event(
        "record.disclosed",
        Item::Record,
        Data::Thin,
        &["disclosure"],
    ),
    event("record.admitted", Item::Record, Data::Thin, &["admission"]),
    event("record.redacted", Item::Record, Data::Thin, &["redact"]),
    event("record.compromise_marked", Item::Record, Data::Thin, &[]),
    event("ledger.version_activated", Item::Ledger, Data::Thin, &[]),
    event("work.changed", Item::Work, Data::Changed, &[]),
    event("commitment.changed", Item::Commitment, Data::Changed, &[]),
    event("condition.changed", Item::Condition, Data::Changed, &[]),
    event("gate.changed", Item::Gate, Data::Changed, &[]),
];

/// Event types marked deprecated in the catalog before their removal, which only a major
/// version makes (P-39 item 2).
pub const DEPRECATED: &[&str] = &[];

/// Kernel wire names the stage 3 catalog gives no event type yet; each waits for the catalog
/// approval (T-98 item 7).
pub const UNCATALOGUED: &[&str] = &["allow", "amend", "declare_obsolete"];

/// The event type named `name`.
#[must_use]
pub fn find(name: &str) -> Option<&'static EventType> {
    CATALOG.iter().find(|event| event.name == name)
}

impl EventType {
    /// The `dataschema` of the type: `schemas/<type>/<version>.json` (P-38 item 2).
    #[must_use]
    pub fn dataschema(&self) -> String {
        format!("schemas/{}/{}.json", self.name, self.version)
    }

    /// True when the catalog marks the type deprecated (P-39 item 2).
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        DEPRECATED.contains(&self.name)
    }
}

/// The `subject` of an event about the outbox item `kind`/`id`: its prefixed id (P-35 item 2,
/// P-112); `None` for a kind that is not a work item.
#[must_use]
pub fn subject(kind: &str, id: &[u8]) -> Option<String> {
    let prefix = match kind {
        "work" => Prefix::Work,
        "commitment" => Prefix::Commitment,
        "condition" => Prefix::Condition,
        _ => return None,
    };
    Some(external(prefix, id))
}

const GATES: [ConditionType; 4] = [
    ConditionType::Authority,
    ConditionType::Decision,
    ConditionType::Acceptance,
    ConditionType::Resource,
];

/// What a thin event takes from its committed record (P-37, P-35 item 3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordFacts {
    /// The core wire name of the record subtype; `None` for an extension subtype.
    pub wire: Option<&'static str>,
    /// True when the record opens a Condition of a gate type (T-98 item 4).
    pub gate: bool,
    /// The author and its `on_behalf_of` chain as `pty_` ids, in that order, each once.
    pub parties: Vec<String>,
    /// The first `correlation` id of the record, in author order (P-16).
    pub correlation: Option<String>,
}

fn wire(record: &Record) -> Option<&'static str> {
    match record {
        Record::Declaration(d) => {
            let subtype = DeclarationSubtype::from_uri(d.subtype.as_str())?;
            Some(subtype.wire_name())
        }
        Record::Act(a) => {
            let subtype = ActSubtype::from_uri(a.subtype.as_str())?;
            Some(subtype.wire_name())
        }
        Record::Claim(c) => match &c.subtype {
            ClaimType::Core(subtype) => Some(subtype.wire_name()),
            ClaimType::Extension(_) => None,
        },
    }
}

fn opens_gate(record: &Record) -> bool {
    let Some(ParamValue::Scalar(ParamScalar::Text(uri))) = record.param("condition_type") else {
        return false;
    };
    ConditionType::from_uri(uri).is_some_and(|t| GATES.contains(&t))
}

impl RecordFacts {
    /// The facts of `record`.
    #[must_use]
    pub fn of(record: &Record) -> Self {
        let fields = record.core();
        let mut parties: Vec<String> = Vec::new();
        let chain = fields.on_behalf_of.iter().flatten();
        for party in core::iter::once(&fields.author).chain(chain) {
            let id = party.to_external();
            if !parties.contains(&id) {
                parties.push(id);
            }
        }
        Self {
            wire: wire(record),
            gate: opens_gate(record),
            parties,
            correlation: fields
                .correlation
                .as_deref()
                .and_then(<[_]>::first)
                .map(|c| c.id.clone()),
        }
    }

    /// The facts of committed `SignedRecord` bytes; `None` for bytes that are not a protocol
    /// 1.0 record, such as a record quarantined under an unknown protocol version (P-87).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match decode_record(bytes) {
            Ok(Decoded::Record(record)) => Some(Self::of(&record)),
            Ok(Decoded::UnknownProtocol(_)) | Err(_) => None,
        }
    }

    /// The primary event type of the record, the `cause` of its `<item>.changed` events (T-98
    /// item 4): the type whose sources hold the wire name, the gate type for a gate Condition.
    #[must_use]
    pub fn primary(&self) -> Option<&'static EventType> {
        let wire = self.wire?;
        let mut found = CATALOG.iter().filter(|e| e.sources.contains(&wire));
        let first = found.next()?;
        match found.next() {
            None => Some(first),
            Some(second) => [first, second]
                .into_iter()
                .find(|e| (e.item == Item::Gate) == self.gate),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use work_kernel::catalog::ClaimSubtype;
    use work_kernel::id::{Digest, LedgerId, PartyRef, Time};
    use work_kernel::record::{
        Audience, Claim, Correlation, Declaration, Param, ParamName, ProtocolVersion, RecordCore,
        VersionVector, Visibility,
    };
    use work_kernel::uri::TypeUri;

    use super::*;

    fn uri(path: &str) -> TypeUri {
        TypeUri::parse(&format!("https://suiss.app/ns/work/{path}")).unwrap()
    }

    fn party(name: &str) -> PartyRef {
        PartyRef::new(name).unwrap()
    }

    fn fields(params: Option<Vec<Param>>) -> RecordCore {
        RecordCore {
            author: party("party:acme:alice"),
            on_behalf_of: Some(vec![party("party:acme:bob"), party("party:acme:alice")]),
            capacity: None,
            basis: Some(Vec::new()),
            visibility: Visibility {
                see: Audience::Work,
                search_excluded: false,
                agent_context_excluded: false,
            },
            ledger: LedgerId(Digest::sha256([1; 32])),
            concerns: Vec::new(),
            relations: None,
            authority: None,
            producer: None,
            correlation: Some(vec![
                Correlation {
                    scheme: uri("correlation/a2a"),
                    id: "ctx-1".into(),
                },
                Correlation {
                    scheme: uri("correlation/jira"),
                    id: "WRK-2".into(),
                },
            ]),
            evidence: None,
            body: None,
            params,
            versions: VersionVector {
                protocol: ProtocolVersion { major: 1, minor: 0 },
                schema: Digest::sha256([2; 32]),
                practices: None,
            },
            ext: None,
            critical: None,
        }
    }

    fn declaration(wire: &str, params: Option<Vec<Param>>) -> Record {
        Record::Declaration(Declaration {
            subtype: uri(&format!("declaration/{wire}")),
            occurred_at: None,
            core: fields(params),
        })
    }

    fn condition_type(kind: &str) -> Option<Vec<Param>> {
        let text = format!("https://suiss.app/ns/work/condition/{kind}");
        Some(vec![Param {
            name: ParamName::parse("condition_type").unwrap(),
            value: ParamValue::Scalar(ParamScalar::Text(text)),
        }])
    }

    // T-98
    #[test]
    fn t_98_event_names_are_the_item_and_a_past_tense_once_each() {
        for (i, event) in CATALOG.iter().enumerate() {
            let (item, verb) = event.name.split_once('.').unwrap();
            assert_eq!(item, event.item.as_str(), "{}", event.name);
            assert!(
                !verb.is_empty() && verb.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{}",
                event.name
            );
            assert_eq!(event.version, 1);
            assert_eq!(
                event.data == Data::Changed,
                verb == "changed",
                "{}",
                event.name
            );
            assert!(
                CATALOG
                    .iter()
                    .skip(i.saturating_add(1))
                    .all(|other| other.name != event.name),
                "{} repeats",
                event.name
            );
            assert_eq!(find(event.name), Some(event));
        }
        assert_eq!(
            find("commitment.revoked").map(|e| e.data),
            Some(Data::Revoked)
        );
    }

    // T-98
    #[test]
    fn t_98_every_kernel_wire_name_has_an_event_type_or_waits_for_approval() {
        let wires = DeclarationSubtype::ALL
            .iter()
            .copied()
            .map(DeclarationSubtype::wire_name)
            .chain(
                ClaimSubtype::ALL
                    .iter()
                    .copied()
                    .map(ClaimSubtype::wire_name),
            )
            .chain(ActSubtype::ALL.iter().copied().map(ActSubtype::wire_name));
        for wire in wires {
            let typed = CATALOG.iter().any(|event| event.sources.contains(&wire));
            assert!(
                typed != UNCATALOGUED.contains(&wire),
                "{wire} needs exactly one of an event type and an UNCATALOGUED entry"
            );
        }
    }

    // P-37 P-35
    #[test]
    fn p_37_a_thin_event_names_the_author_chain_and_the_first_correlation() {
        let facts = RecordFacts::of(&declaration("promise", None));
        assert_eq!(facts.wire, Some("promise"));
        assert!(!facts.gate);
        assert_eq!(
            facts.parties,
            [
                party("party:acme:alice").to_external(),
                party("party:acme:bob").to_external()
            ]
        );
        assert!(facts.parties.iter().all(|p| p.starts_with("pty_")));
        assert_eq!(facts.correlation.as_deref(), Some("ctx-1"));
        assert_eq!(facts.primary().map(|e| e.name), Some("commitment.promised"));
        let mut bare = fields(None);
        bare.correlation = None;
        bare.on_behalf_of = None;
        let claim = Record::Claim(Claim {
            subtype: ClaimType::Core(ClaimSubtype::Observation),
            occurred_at: Time(1),
            core: bare,
        });
        let facts = RecordFacts::of(&claim);
        assert_eq!(facts.correlation, None);
        assert_eq!(facts.parties.len(), 1);
        assert_eq!(facts.primary().map(|e| e.name), Some("work.updated"));
        assert_eq!(RecordFacts::decode(&[0xd2]), None);
        assert_eq!(RecordFacts::decode(&[]), None);
    }

    // T-98 P-38
    #[test]
    fn t_98_the_primary_type_of_a_gate_condition_is_a_gate_type() {
        let gate = RecordFacts::of(&declaration("open_condition", condition_type("authority")));
        assert!(gate.gate);
        assert_eq!(gate.primary().map(|e| e.name), Some("gate.opened"));
        let wait = RecordFacts::of(&declaration("open_condition", condition_type("time")));
        assert!(!wait.gate);
        assert_eq!(wait.primary().map(|e| e.name), Some("condition.opened"));
        let revoked = RecordFacts::of(&declaration("revoke_promise", None));
        let event = revoked.primary().unwrap();
        assert_eq!(
            (event.name, event.data),
            ("commitment.revoked", Data::Revoked)
        );
        let decided = RecordFacts::of(&declaration("gate_decision", None));
        assert_eq!(decided.primary().map(|e| e.name), Some("gate.decided"));
        let other = RecordFacts::of(&Record::Declaration(Declaration {
            subtype: TypeUri::parse("https://example.com/practice/approve").unwrap(),
            occurred_at: None,
            core: fields(None),
        }));
        assert_eq!((other.wire, other.primary()), (None, None));
    }

    // P-35 P-38 P-112
    #[test]
    fn p_35_subject_and_dataschema_come_from_the_item_and_the_type() {
        assert_eq!(
            subject("work", &[0x0b; 16]).as_deref(),
            Some("wrk_0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        );
        assert_eq!(
            subject("commitment", &[0x0a; 32]),
            Some(format!("cmt_{}", "0a".repeat(32)))
        );
        assert_eq!(
            subject("condition", &[0xff; 32]),
            Some(format!("cnd_{}", "ff".repeat(32)))
        );
        assert_eq!(subject("record", &[1; 32]), None);
        assert_eq!(
            find("commitment.revoked")
                .map(EventType::dataschema)
                .as_deref(),
            Some("schemas/commitment.revoked/1.json")
        );
        assert_eq!(DATA_CONTENT_TYPE, "application/json");
    }

    // P-39
    #[test]
    fn p_39_a_deprecated_type_stays_in_the_catalog_until_a_major_version() {
        for name in DEPRECATED {
            let event = find(name);
            assert!(event.is_some_and(EventType::is_deprecated), "{name}");
        }
        assert!(
            CATALOG
                .iter()
                .filter(|e| e.is_deprecated())
                .all(|e| DEPRECATED.contains(&e.name))
        );
        assert!(find("work.opened").is_some_and(|e| !e.is_deprecated()));
    }
}

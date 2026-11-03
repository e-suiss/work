//! The event type catalog (T-98 items 3 to 5, P-38): every (record, affected item) pair is one event; the item a record is about takes the type its wire name gives, `<item>.<past tense>`, and every other item the record touches takes `<item>.changed` with the primary type in `data.cause`. `cargo xtask asyncapi` writes `sdks/asyncapi/work-events.yaml` and the versioned `data` schemas from [`CATALOG`], and `cargo xtask check event-catalog` refuses a kernel wire name that has no event type and is not listed in [`UNCATALOGUED`].

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

/// Kernel wire names the stage 3 catalog gives no event type yet; each waits for the catalog
/// approval (T-98 item 7).
pub const UNCATALOGUED: &[&str] = &["allow", "amend", "declare_obsolete"];

/// The event type named `name`.
#[must_use]
pub fn find(name: &str) -> Option<&'static EventType> {
    CATALOG.iter().find(|event| event.name == name)
}

#[cfg(test)]
mod tests {
    use work_kernel::catalog::{ActSubtype, ClaimSubtype, DeclarationSubtype};

    use super::*;

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
}

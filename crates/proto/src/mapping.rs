//! The external standard mappings of one record (§15.11; P-48, P-49, P-51, P-52): its W3C PROV-JSON document and its Activity Streams 2.0 activity, read from the record's signed fields only. Both are export vocabularies, never canonical: neither document is record bytes, and nothing maps back into a record.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use serde_json::{Map, Value, json};
use work_kernel::catalog::{BASIS_ROLE_URI, ConditionType, CoreDerivedRole, DeclarationSubtype};
use work_kernel::id::{PartyRef, RecordId};
use work_kernel::record::{ClaimType, Kind, ParamScalar, ParamValue, Record};
use work_kernel::relation::{DerivedRole, DerivedTarget, ReferenceTarget, Relation};
use work_kernel::uri::CORE_ROOT;
use work_kernel::validate::{ActorTypeEntry, ActorTypes};

/// The Activity Streams 2.0 vocabulary.
pub const AS2: &str = "https://www.w3.org/ns/activitystreams";

/// The `ForgeFed` vocabulary, which defines `Assign` (P-51).
pub const FORGEFED: &str = "https://forgefed.org/ns";

const PARTY_PREFIX: &str = "party";
const RECORD_PREFIX: &str = "record";

/// The Activity Streams 2.0 activity a Declaration maps to (P-51).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activity {
    /// The activity type name.
    pub name: &'static str,
    /// The vocabulary that defines it.
    pub vocabulary: &'static str,
}

const fn activity(name: &'static str) -> Activity {
    Activity {
        name,
        vocabulary: AS2,
    }
}

/// The activity of a record: a Declaration carrying `supersedes` is a correction, `Update`; otherwise `request` and `counter` are `Offer`, `promise` `Accept`, `decline` `Reject`, `promise_conditional` `TentativeAccept`, the four revocation requests `Undo`, `assign` the `ForgeFed` `Assign`, and `open_condition` of the core information type `Question`. Acts, Claims, Practice subtypes and every other Declaration map to no activity (P-51).
#[must_use]
pub fn as2_activity(record: &Record) -> Option<Activity> {
    let Record::Declaration(declaration) = record else {
        return None;
    };
    if record.supersedes().next().is_some() {
        return Some(activity("Update"));
    }
    match DeclarationSubtype::from_uri(declaration.subtype.as_str())? {
        DeclarationSubtype::Request | DeclarationSubtype::Counter => Some(activity("Offer")),
        DeclarationSubtype::Promise => Some(activity("Accept")),
        DeclarationSubtype::Decline => Some(activity("Reject")),
        DeclarationSubtype::PromiseConditional => Some(activity("TentativeAccept")),
        DeclarationSubtype::RevokeRequest
        | DeclarationSubtype::RevokePromise
        | DeclarationSubtype::RevokeStatement
        | DeclarationSubtype::RevokeAcceptance => Some(activity("Undo")),
        DeclarationSubtype::Assign => Some(Activity {
            name: "Assign",
            vocabulary: FORGEFED,
        }),
        DeclarationSubtype::Amend => Some(activity("Update")),
        DeclarationSubtype::OpenCondition => match record.param("condition_type") {
            Some(ParamValue::Scalar(ParamScalar::Text(uri)))
                if ConditionType::from_uri(uri) == Some(ConditionType::Information) =>
            {
                Some(activity("Question"))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The `on_behalf_of` actor types do not match the record's principal chain (P-12, INV-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the actor types do not name every party of the on_behalf_of chain")]
pub struct ChainMismatch;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn record_ref(id: &RecordId) -> String {
    format!("{RECORD_PREFIX}:{}", hex(id.0.as_bytes()))
}

fn party_ref(party: &PartyRef) -> String {
    let mut out = String::from(PARTY_PREFIX);
    out.push(':');
    for b in party.as_str().bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn role_uri(role: &DerivedRole) -> String {
    match role {
        DerivedRole::Core(core) => format!("{CORE_ROOT}derived_from/{}", core.wire_name()),
        DerivedRole::Extension(uri) => String::from(uri.as_str()),
    }
}

fn subtype_uri(record: &Record) -> String {
    match record {
        Record::Claim(claim) => match &claim.subtype {
            ClaimType::Core(core) => format!("{CORE_ROOT}claim/{}", core.wire_name()),
            ClaimType::Extension(uri) => String::from(uri.as_str()),
        },
        Record::Act(act) => String::from(act.subtype.as_str()),
        Record::Declaration(declaration) => String::from(declaration.subtype.as_str()),
    }
}

struct Document<'a> {
    me: String,
    withheld: &'a [RecordId],
    agents: Map<String, Value>,
    entities: Map<String, Value>,
    statements: BTreeMap<&'static str, Map<String, Value>>,
    count: u32,
    references: Vec<String>,
}

impl Document<'_> {
    fn emit(&mut self, kind: &'static str, body: Value) {
        self.count = self.count.saturating_add(1);
        let id = format!("_:s{}", self.count);
        self.statements.entry(kind).or_default().insert(id, body);
    }

    fn agent(&mut self, party: &PartyRef, entry: ActorTypeEntry) {
        let key = party_ref(party);
        if !self.agents.contains_key(&key) {
            let value = json!({
                "work:actorType": entry.actor_type.wire_name(),
                "work:actorTypeSource": entry.source.wire_name(),
            });
            self.agents.insert(key, value);
        }
    }

    fn visible(&self, id: &RecordId) -> bool {
        !self.withheld.contains(id)
    }

    fn reference(&mut self, uri: &str) -> String {
        let index = match self.references.iter().position(|r| r == uri) {
            Some(i) => i,
            None => {
                self.references.push(String::from(uri));
                self.references.len().saturating_sub(1)
            }
        };
        let id = format!("_:ref{}", index.saturating_add(1));
        let entity = json!({ "prov:type": "work:Reference", "work:ref": uri });
        self.entities.insert(id.clone(), entity);
        id
    }
}

fn plans(record: &Record) -> Vec<RecordId> {
    record
        .core()
        .relations
        .iter()
        .flatten()
        .filter_map(|r| match r {
            Relation::DerivedFrom {
                source: None,
                target: DerivedTarget::Record(target),
                role: DerivedRole::Core(CoreDerivedRole::Fulfills),
            } => Some(*target),
            _ => None,
        })
        .collect()
}

fn relation(doc: &mut Document<'_>, act: bool, r: &Relation) {
    match r {
        Relation::DerivedFrom {
            source,
            target: DerivedTarget::Record(target),
            role,
        } => {
            if !doc.visible(target) || source.is_some_and(|s| !doc.visible(&s)) {
                return;
            }
            if source.is_none() && act {
                if *role != DerivedRole::Core(CoreDerivedRole::Fulfills) {
                    let body = json!({
                        "prov:activity": doc.me,
                        "prov:entity": record_ref(target),
                        "work:role": role_uri(role),
                    });
                    doc.emit("used", body);
                }
            } else {
                let generated = source.as_ref().map_or_else(|| doc.me.clone(), record_ref);
                let body = json!({
                    "prov:generatedEntity": generated,
                    "prov:usedEntity": record_ref(target),
                    "work:role": role_uri(role),
                });
                doc.emit("wasDerivedFrom", body);
            }
        }
        Relation::Supersedes { target, .. } if doc.visible(target) => {
            let body = json!({
                "prov:generatedEntity": doc.me,
                "prov:usedEntity": record_ref(target),
                "prov:type": "prov:Revision",
            });
            doc.emit("wasDerivedFrom", body);
            let invalidated = json!({ "prov:entity": record_ref(target) });
            doc.emit("wasInvalidatedBy", invalidated);
        }
        Relation::References {
            source: None,
            target: ReferenceTarget::External(uri),
            ..
        } if act => {
            let entity = doc.reference(uri.as_str());
            let body = json!({ "prov:entity": entity, "prov:activity": doc.me });
            doc.emit("wasGeneratedBy", body);
        }
        _ => {}
    }
}

/// The PROV-JSON document of the record `id` (P-49): an Act is a `prov:Activity`, a Declaration or Claim a `prov:Entity`; the author is `wasAssociatedWith` the Act, with the record an Act fulfills as the association's `prov:Plan`, or the record is `wasAttributedTo` the author; every Party is a `prov:Agent` with its actor type; each `on_behalf_of` ring `actedOnBehalfOf` the previous Party; `basis` and `derived_from` record targets are `used` by an Act and otherwise `wasDerivedFrom` with their role; `supersedes` is a `prov:Revision` and the older record `wasInvalidatedBy`; an external object an Act references `wasGeneratedBy` it. Statements naming a record in `withheld`, which the viewer may not see, are left out, so the document does not reveal hidden provenance (EV-12). Statement ids are `_:s<n>` in that order.
///
/// # Errors
///
/// [`ChainMismatch`] when `actors` does not carry one entry per `on_behalf_of` Party.
pub fn prov_document(
    record: &Record,
    id: &RecordId,
    actors: &ActorTypes,
    withheld: &[RecordId],
) -> Result<Value, ChainMismatch> {
    let core = record.core();
    let chain = core.on_behalf_of.as_deref().unwrap_or_default();
    if chain.len() != actors.on_behalf_of.len() {
        return Err(ChainMismatch);
    }
    let act = record.kind() == Kind::Act;
    let mut doc = Document {
        me: record_ref(id),
        withheld,
        agents: Map::new(),
        entities: Map::new(),
        statements: BTreeMap::new(),
        count: 0,
        references: Vec::new(),
    };
    let node = json!({
        "work:kind": record.kind().wire_name(),
        "work:type": subtype_uri(record),
    });
    if !act {
        doc.entities.insert(doc.me.clone(), node.clone());
    }
    doc.agent(&core.author, actors.author);
    let author = party_ref(&core.author);
    if act {
        let visible: Vec<RecordId> = plans(record)
            .into_iter()
            .filter(|p| doc.visible(p))
            .collect();
        for plan in &visible {
            let entity = json!({ "prov:type": "prov:Plan" });
            doc.entities.insert(record_ref(plan), entity);
            let body = json!({
                "prov:activity": doc.me,
                "prov:agent": author,
                "prov:plan": record_ref(plan),
            });
            doc.emit("wasAssociatedWith", body);
        }
        if visible.is_empty() {
            let body = json!({ "prov:activity": doc.me, "prov:agent": author });
            doc.emit("wasAssociatedWith", body);
        }
    } else {
        let body = json!({ "prov:entity": doc.me, "prov:agent": author });
        doc.emit("wasAttributedTo", body);
    }
    let mut previous = &core.author;
    for (party, entry) in chain.iter().zip(&actors.on_behalf_of) {
        doc.agent(party, *entry);
        let body = json!({
            "prov:delegate": party_ref(previous),
            "prov:responsible": party_ref(party),
        });
        doc.emit("actedOnBehalfOf", body);
        previous = party;
    }
    for premise in record.basis() {
        if !doc.visible(premise) {
            continue;
        }
        let body = if act {
            json!({
                "prov:activity": doc.me,
                "prov:entity": record_ref(premise),
                "work:role": BASIS_ROLE_URI,
            })
        } else {
            json!({
                "prov:generatedEntity": doc.me,
                "prov:usedEntity": record_ref(premise),
                "work:role": BASIS_ROLE_URI,
            })
        };
        doc.emit(if act { "used" } else { "wasDerivedFrom" }, body);
    }
    for r in core.relations.iter().flatten() {
        relation(&mut doc, act, r);
    }
    let prefix = json!({
        PARTY_PREFIX: format!("{CORE_ROOT}party/"),
        RECORD_PREFIX: format!("{CORE_ROOT}record/"),
        "work": CORE_ROOT,
    });
    let mut out = Map::new();
    out.insert(String::from("prefix"), prefix);
    out.insert(String::from("agent"), Value::Object(doc.agents));
    if act {
        let mut activities = Map::new();
        activities.insert(doc.me, node);
        out.insert(String::from("activity"), Value::Object(activities));
    }
    if !doc.entities.is_empty() {
        out.insert(String::from("entity"), Value::Object(doc.entities));
    }
    for (kind, group) in doc.statements {
        out.insert(String::from(kind), Value::Object(group));
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use work_kernel::id::Digest;

    fn rid(byte: u8) -> RecordId {
        RecordId(Digest::sha256([byte; 32]))
    }

    // P-49
    #[test]
    fn p_49_party_and_record_identifiers_are_prefixed_and_escaped() {
        let party = PartyRef::new("party:acme:a b/é").unwrap();
        assert_eq!(party_ref(&party), "party:party%3Aacme%3Aa%20b%2F%C3%A9");
        let alice = PartyRef::new("Alice-1._~").unwrap();
        assert_eq!(party_ref(&alice), "party:Alice-1._~");
        assert_eq!(
            record_ref(&rid(0xab)),
            format!("record:{}", "ab".repeat(32))
        );
    }

    // P-51
    #[test]
    fn p_51_the_assign_activity_comes_from_forgefed_and_the_others_from_as2() {
        assert_eq!(activity("Offer").vocabulary, AS2);
        assert_ne!(AS2, FORGEFED);
    }
}

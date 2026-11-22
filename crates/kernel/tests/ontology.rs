//! The ontology core as schema tests: the nine concepts and eight relations, Work opening and continuity, the Party model and its layers, the tool threshold, the Commitment, Condition and Aim core types, Reference, Act, Declaration and Claim, and the extension rule (C-1…C-44, INV-28, PR-9, PR-10).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod fixtures;

use fixtures::*;
use work_kernel::catalog::{
    AimDuration, ClaimSubtype, ConditionClass, ConditionType, Consequence, DeclarationSubtype,
    GateKind, consequence,
};
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, DerivationInputs, Effect, Entry, Ingest, NoEffect,
    ProfileVersion, Restriction, TrustInputs, derive,
};
use work_kernel::id::{PartyRef, RecordId, Time, WorkId, canonical_text_cmp};
use work_kernel::items::{ItemKey, touched};
use work_kernel::ontology::{
    Aim, COUNTERPARTS, Commitment, Concept, Condition, Counterpart, DERIVED, Evaluation, Identity,
    LayerHome, Obligor, PartyLayer, Role, RoleHome, continued_works,
};
use work_kernel::reason::{EnvelopeField, Reason, Schema};
use work_kernel::record::{
    Act, Audience, Capacity, Claim, ClaimType, Kind, Param, ParamScalar, ParamValue, PartName,
    ProducerRef, ProtocolVersion, Record, RecordCore,
};
use work_kernel::relation::{DerivedRole, DerivedTarget, ReferenceTarget, Relation, RelationName};
use work_kernel::uri::ExternalRef;
use work_kernel::validate::{ActorType, Origin, Outcome, validate};

const TOOL: &str = "https://tools.example/agents/summarizer";
const MACHINE: &str = "party:acme:press-7";
const MISMATCH: Reason = Reason::EnvelopeMismatch(EnvelopeField::ActorType);

fn direct(record: &Record) -> Outcome {
    let actors = actor_types(record);
    validate(record, &ctx(Origin::Direct, &actors, &[]))
}

fn as_actor(record: &Record, actor_type: ActorType) -> Outcome {
    let mut actors = actor_types(record);
    actors.author = bound(actor_type);
    validate(record, &ctx(Origin::Direct, &actors, &[]))
}

fn rejected(record: &Record) -> Reason {
    match direct(record) {
        Outcome::Rejected(reason) => reason,
        other => panic!("expected rejection, got {other:?}"),
    }
}

fn mutate(mut record: Record, f: impl FnOnce(&mut RecordCore)) -> Record {
    f(core_mut(&mut record));
    record
}

fn text(s: &str) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Text(s.to_owned()))
}

fn digest_param(n: u8) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Digest(digest(n)))
}

fn params(pairs: Vec<(&str, ParamValue)>) -> Vec<Param> {
    let mut params: Vec<Param> = pairs
        .into_iter()
        .map(|(name, value)| Param {
            name: PartName::parse(name).unwrap(),
            value,
        })
        .collect();
    params.sort_by(|a, b| canonical_text_cmp(a.name.as_str(), b.name.as_str()));
    params
}

fn core_declaration(name: &str, pairs: Vec<(&str, ParamValue)>) -> Record {
    declaration(
        &format!("{CORE}declaration/{name}"),
        RecordCore {
            capacity: Some(Capacity::Own),
            concerns: vec![w1()],
            authority: Some(authority(1)),
            params: Some(params(pairs)).filter(|p| !p.is_empty()),
            ..core(ALICE)
        },
    )
}

fn request(pairs: Vec<(&str, ParamValue)>) -> Record {
    core_declaration("request", pairs)
}

fn aim(pairs: Vec<(&str, ParamValue)>) -> Record {
    core_declaration("aim", pairs)
}

fn open_condition(kind: &str, address: &str) -> Record {
    core_declaration(
        "open_condition",
        vec![
            ("condition_type", text(&format!("{CORE}condition/{kind}"))),
            ("wait_reason", text("internal")),
            ("address", text(address)),
            ("deadline", text("none")),
            ("criterion", text(&format!("{PROC}criterion/ready"))),
        ],
    )
}

fn claim(author: &str, concerns: Vec<WorkId>, relations: Option<Vec<Relation>>) -> Record {
    Record::Claim(Claim {
        subtype: ClaimType::Core(ClaimSubtype::Observation),
        occurred_at: Time(1_792_109_000_000),
        core: RecordCore {
            concerns,
            relations,
            ..core(author)
        },
    })
}

fn external(s: &str) -> ExternalRef {
    ExternalRef::parse(s).unwrap()
}

fn references(target: &str) -> Relation {
    Relation::References {
        source: None,
        target: ReferenceTarget::External(external(target)),
        qualifier: None,
    }
}

fn w3() -> WorkId {
    WorkId::from_bytes([0x33; 16])
}

fn continues(work: WorkId) -> Relation {
    Relation::DerivedFrom {
        source: None,
        target: DerivedTarget::Work(work),
        role: DerivedRole::Core(work_kernel::catalog::CoreDerivedRole::Source),
    }
}

// C-2 C-1 MD-7 C-31
#[test]
fn c_2_nine_concepts_and_eight_relations_are_fixed_kernel_types() {
    assert_eq!(Concept::ALL.len(), 9);
    assert_eq!(RelationName::ALL.len(), 8);
    let names: Vec<&str> = Concept::ALL.iter().map(|c| c.wire_name()).collect();
    assert_eq!(
        names,
        [
            "work",
            "party",
            "aim",
            "commitment",
            "condition",
            "reference",
            "act",
            "declaration",
            "claim"
        ]
    );
    for kind in Kind::ALL {
        assert_eq!(Concept::of_kind(*kind).wire_name(), kind.wire_name());
    }
    for name in ["task", "project", "session", "depends_on", "queue"] {
        assert_eq!(Concept::from_wire_name(name), None, "{name}");
        assert_eq!(RelationName::from_wire_name(name), None, "{name}");
    }
}

// C-1 C-2 P-112
#[test]
fn c_1_every_concept_owns_an_identity_and_is_referred_to() {
    for concept in Concept::ALL {
        let identity = concept.identity();
        match concept {
            Concept::Work => assert_eq!(identity, Identity::Work),
            Concept::Party => assert_eq!(identity, Identity::Party),
            Concept::Reference => assert_eq!(identity, Identity::External),
            Concept::Act | Concept::Declaration | Concept::Claim => {
                assert_eq!(identity, Identity::Record);
            }
            Concept::Aim | Concept::Commitment | Concept::Condition => {
                assert_eq!(identity, Identity::OpeningRecord);
            }
        }
    }
    let opened = |name: &str| {
        Concept::opened_by(&declaration(
            &format!("{CORE}declaration/{name}"),
            core(ALICE),
        ))
    };
    assert_eq!(opened("request"), Some(Concept::Commitment));
    assert_eq!(opened("open_condition"), Some(Concept::Condition));
    assert_eq!(opened("aim"), Some(Concept::Aim));
    let others = DeclarationSubtype::ALL.iter().filter(|s| {
        !matches!(
            s,
            DeclarationSubtype::Request
                | DeclarationSubtype::OpenCondition
                | DeclarationSubtype::Aim
        )
    });
    for subtype in others {
        assert_eq!(opened(subtype.wire_name()), None, "{subtype:?}");
    }
    assert_eq!(Concept::opened_by(&observation()), None);
}

// C-3 C-1 C-2 F-23 MD-7
#[test]
fn c_3_an_application_extension_or_practice_adds_no_concept_or_relation() {
    assert_eq!(Kind::from_wire_name("aim"), None);
    assert_eq!(Kind::from_wire_name("commitment"), None);
    assert_eq!(
        Relation::from_wire(
            "https://procurement.example/ns/relation/blocks",
            None,
            work_kernel::relation::Endpoint::Record(rid(1)),
            None
        ),
        Err(Reason::Schema(Schema::Relation))
    );
    let unpinned = declaration(
        &format!("{PROC}declaration/milestone"),
        RecordCore {
            capacity: Some(Capacity::Own),
            concerns: vec![w1()],
            authority: Some(authority(1)),
            ..core(ALICE)
        },
    );
    assert_eq!(rejected(&unpinned), Reason::UnmappedExtensionValue);
    let pinned_subtype = mutate(unpinned, |c| c.versions = pinned(0x50, PROC));
    assert_eq!(direct(&pinned_subtype), Outcome::Accepted);
    assert_eq!(Concept::opened_by(&pinned_subtype), None);
}

// C-8 PR-9 MD-18 X-19
#[test]
fn c_8_pr_9_a_work_opens_without_practice_template_workflow_or_type() {
    let fresh = WorkId::from_bytes([0x5a; 16]);
    let opening = claim(ALICE, vec![fresh], None);
    assert!(opening.core().versions.practices.is_none());
    assert!(opening.core().params.is_none());
    assert_eq!(direct(&opening), Outcome::Accepted);
    let touches = touched(&opening);
    assert_eq!(touches.len(), 1);
    assert_eq!(touches[0].item, ItemKey::Work(fresh));
    let first_request = mutate(
        request(vec![("acceptor", text(ALICE)), ("obligor", text(SUPPLIER))]),
        |c| c.concerns = vec![fresh],
    );
    assert_eq!(direct(&first_request), Outcome::Accepted);
}

// C-8 PR-9 C-35
#[test]
fn c_8_the_work_identity_outlives_its_close() {
    let close = core_declaration("administrative_close", vec![]);
    assert_eq!(direct(&close), Outcome::Accepted);
    let after = claim(ALICE, vec![w1()], None);
    assert_eq!(direct(&after), Outcome::Accepted);
    assert_eq!(touched(&after)[0].item, ItemKey::Work(w1()));
    assert_eq!(touched(&close)[0].item, ItemKey::Work(w1()));
}

// C-43 C-8 C-27
#[test]
fn c_43_a_split_or_merge_opens_new_works_derived_from_each_earlier_one() {
    let split = claim(ALICE, vec![w3()], Some(vec![continues(w1())]));
    assert_eq!(direct(&split), Outcome::Accepted);
    assert_eq!(continued_works(&split).collect::<Vec<_>>(), [&w1()]);
    let merge = claim(
        ALICE,
        vec![w3()],
        Some(vec![continues(w1()), continues(w2())]),
    );
    assert_eq!(direct(&merge), Outcome::Accepted);
    assert_eq!(continued_works(&merge).collect::<Vec<_>>(), [&w1(), &w2()]);
    assert_eq!(touched(&merge).len(), 1);
    assert!(merge.supersedes().next().is_none());
    let looped = claim(ALICE, vec![w1()], Some(vec![continues(w1())]));
    assert_eq!(rejected(&looped), Reason::Schema(Schema::Relation));
    let unanchored = mutate(claim(ALICE, vec![], Some(vec![continues(w1())])), |c| {
        c.visibility = visibility(Audience::Author);
    });
    assert_eq!(rejected(&unanchored), Reason::Schema(Schema::Relation));
    let earlier = claim(ALICE, vec![w1()], None);
    assert_eq!(direct(&earlier), Outcome::Accepted);
}

// PR-10 MD-18 L-48 C-8
#[test]
fn pr_10_md_18_a_minimal_record_needs_no_unjustified_core_field() {
    let minimal_claim = mutate(claim(ALICE, vec![], None), |c| {
        c.visibility = visibility(Audience::Author);
    });
    assert_eq!(direct(&minimal_claim), Outcome::Accepted);
    let minimal_act = Record::Act(Act {
        subtype: uri(&format!("{CORE}act/action")),
        occurred_at: Time(1),
        core: RecordCore {
            visibility: visibility(Audience::Author),
            ..core(ALICE)
        },
    });
    assert_eq!(direct(&minimal_act), Outcome::Accepted);
    let promise = || core_declaration("promise", vec![]);
    assert_eq!(direct(&promise()), Outcome::Accepted);
    assert_eq!(promise().basis(), &[] as &[RecordId]);
    let unauthorised = mutate(promise(), |c| c.authority = None);
    assert_eq!(rejected(&unauthorised), Reason::AuthorityMissing);
    let without_capacity = mutate(promise(), |c| c.capacity = None);
    assert_eq!(rejected(&without_capacity), Reason::CapacityMissing);
}

// C-9 F-4 MD-7 C-17
#[test]
fn c_9_every_actor_type_writes_through_one_party_model() {
    let note = claim(ALICE, vec![w1()], None);
    for actor_type in ActorType::ALL {
        let outcome = as_actor(&note, *actor_type);
        if *actor_type == ActorType::Agent {
            assert_eq!(outcome, Outcome::Rejected(Reason::ProducerMissing));
        } else {
            assert_eq!(outcome, Outcome::Accepted, "{actor_type:?}");
        }
    }
    let unauthorised = mutate(core_declaration("promise", vec![]), |c| c.authority = None);
    for actor_type in ActorType::ALL {
        let mut record = unauthorised.clone();
        core_mut(&mut record).producer = Some(producer("m-1"));
        assert_eq!(
            as_actor(&record, *actor_type),
            Outcome::Rejected(Reason::AuthorityMissing),
            "{actor_type:?}"
        );
    }
}

fn producer(model: &str) -> ProducerRef {
    ProducerRef {
        version: "procure-agent/3.2.0".to_owned(),
        config: digest(0x12),
        model: ExternalRef::parse(&format!("urn:example:model:{model}")),
        toolset: None,
        instructions: None,
        attestation: None,
    }
}

// C-18 C-23 C-22
#[test]
fn c_18_party_layers_stay_apart_and_the_interaction_session_is_outside_work() {
    assert_eq!(PartyLayer::ALL.len(), 11);
    assert_eq!(PartyLayer::InteractionSession.home(), LayerHome::Outside);
    assert_eq!(PartyLayer::IdentityController.home(), LayerHome::Access);
    assert_eq!(PartyLayer::Principal.home(), LayerHome::OnBehalfOf);
    assert_eq!(PartyLayer::ModelConfiguration.home(), LayerHome::Producer);
    assert_eq!(PartyLayer::ExecutionSession.home(), LayerHome::Reference);
    assert_eq!(PartyLayer::Provider.home(), LayerHome::Reference);
    assert_eq!(PartyLayer::Accountable.home(), LayerHome::Derived);
    for layer in [
        PartyLayer::PartyIdentity,
        PartyLayer::AgentIdentity,
        PartyLayer::Operator,
    ] {
        assert_eq!(layer.home(), LayerHome::Party);
    }
    let promise = promise();
    let producer = promise.core().producer.as_ref().unwrap();
    assert!(producer.model.is_some());
    assert_ne!(
        producer.model.as_ref().map(ExternalRef::as_str),
        Some(promise.core().author.as_str())
    );
}

// C-19 C-23
#[test]
fn c_19_a_model_provider_or_session_change_keeps_the_party() {
    let before = mutate(promise(), |c| c.producer = Some(producer("m-2026-09")));
    let after = mutate(promise(), |c| {
        c.producer = Some(ProducerRef {
            config: digest(0x77),
            ..producer("m-2026-11")
        });
        c.correlation = None;
    });
    assert_eq!(direct(&before), Outcome::Accepted);
    assert_eq!(direct(&after), Outcome::Accepted);
    assert_eq!(before.core().author, after.core().author);
    assert_eq!(actor_types(&before), actor_types(&after));
}

// C-44 C-20 C-13
#[test]
fn c_44_every_attributed_slot_is_a_party_never_a_reference() {
    let tool = PartyRef::new(TOOL).unwrap();
    let author = mutate(comment(), |c| c.author = tool.clone());
    assert_eq!(rejected(&author), MISMATCH);
    let ring = mutate(promise(), |c| {
        c.on_behalf_of = Some(vec![tool.clone()]);
        c.capacity = Some(Capacity::For(tool.clone()));
    });
    assert_eq!(rejected(&ring), MISMATCH);
    let presenter = mutate(delivery(), |c| {
        c.evidence.as_mut().unwrap()[0].presenter = tool.clone();
    });
    assert_eq!(rejected(&presenter), MISMATCH);
    let engaged = claim(
        ALICE,
        vec![w1()],
        Some(vec![Relation::EngagedIn {
            source: tool.clone(),
            target: w1(),
            qualifier: None,
        }]),
    );
    assert_eq!(rejected(&engaged), MISMATCH);
    let represented = claim(
        ALICE,
        vec![w1()],
        Some(vec![Relation::OnBehalfOf {
            source: party(ALICE),
            target: tool,
            qualifier: None,
        }]),
    );
    assert_eq!(rejected(&represented), MISMATCH);
}

// C-44 C-20 C-11 C-10
#[test]
fn c_44_the_obligor_acceptor_and_judge_are_parties() {
    let ok = request(vec![("acceptor", text(ALICE)), ("obligor", text(SUPPLIER))]);
    assert_eq!(direct(&ok), Outcome::Accepted);
    for (key, value) in [
        ("obligor", text(TOOL)),
        ("obligor", digest_param(9)),
        ("acceptor", text(TOOL)),
    ] {
        let mut pairs = vec![("acceptor", text(ALICE)), ("obligor", text(SUPPLIER))];
        pairs.retain(|(k, _)| *k != key);
        pairs.push((key, value));
        assert_eq!(rejected(&request(pairs)), MISMATCH, "{key}");
    }
    let judged = aim(vec![("duration", text("one_shot")), ("judge", text(TOOL))]);
    assert_eq!(rejected(&judged), MISMATCH);
}

// C-20 C-44 C-24
#[test]
fn c_20_a_tool_output_is_the_calling_party_s_claim_about_a_reference() {
    let output = claim(ALICE, vec![w1()], Some(vec![references("mcp:tool/search")]));
    assert_eq!(direct(&output), Outcome::Accepted);
    assert_eq!(output.core().author, party(ALICE));
    assert_eq!(consequence(&output), Consequence::NonConsequential);
}

// C-21 C-36
#[test]
fn c_21_a_machine_is_a_performer_party_a_sharing_target_or_a_reference() {
    let report = Record::Act(Act {
        subtype: uri(&format!("{CORE}act/action")),
        occurred_at: Time(5),
        core: RecordCore {
            concerns: vec![w1()],
            ..core(MACHINE)
        },
    });
    assert_eq!(as_actor(&report, ActorType::Machine), Outcome::Accepted);
    let shared = core_declaration(
        "open_condition",
        vec![
            ("condition_type", text(&format!("{CORE}condition/resource"))),
            ("gate_form", text("approval")),
            ("wait_reason", text("internal")),
            ("address", text(MACHINE)),
            ("deadline", text("none")),
            ("criterion", text(&format!("{PROC}criterion/press_free"))),
        ],
    );
    assert_eq!(direct(&shared), Outcome::Accepted);
    let subject = claim(
        ALICE,
        vec![w1()],
        Some(vec![references("urn:asset:press-7")]),
    );
    assert_eq!(direct(&subject), Outcome::Accepted);
    assert_eq!(Concept::from_wire_name("machine"), None);
    assert_eq!(RelationName::from_wire_name("uses"), None);
}

// C-24 C-16 C-36
#[test]
fn c_24_a_capability_statement_is_a_claim_and_grants_no_authority() {
    let card = Record::Claim(Claim {
        subtype: ClaimType::from_uri(uri(&format!("{PROC}claim/agent_card"))),
        occurred_at: Time(7),
        core: RecordCore {
            concerns: vec![w1()],
            versions: pinned(0x50, PROC),
            ..core(ALICE)
        },
    });
    assert_eq!(direct(&card), Outcome::Accepted);
    assert_eq!(consequence(&card), Consequence::NonConsequential);
    let leaning = mutate(core_declaration("promise", vec![]), |c| {
        c.basis = Some(vec![rid(0x41)]);
        c.authority = None;
    });
    assert_eq!(rejected(&leaning), Reason::AuthorityMissing);
    assert!(
        COUNTERPARTS
            .iter()
            .any(|(n, c)| *n == "capability_statement"
                && *c == Counterpart::Claim(ClaimSubtype::Observation))
    );
    assert!(DERIVED.contains(&"trust"));
    assert_eq!(
        DeclarationSubtype::from_wire_name("autonomy_policy"),
        Some(DeclarationSubtype::AutonomyPolicy)
    );
    for name in ["capability", "trust", "autonomy", "authority"] {
        assert_eq!(Concept::from_wire_name(name), None, "{name}");
    }
}

// C-10 C-25
#[test]
fn c_10_an_aim_is_judged_by_truth_or_by_a_named_party_once_or_maintained() {
    let judged = aim(vec![
        ("criterion", text(&format!("{PROC}criterion/signed_po"))),
        ("duration", text("one_shot")),
        ("judge", text(BUYER)),
    ]);
    assert_eq!(direct(&judged), Outcome::Accepted);
    let judged_aim = Aim::of(&judged).unwrap();
    assert_eq!(judged_aim.evaluation, Evaluation::Judgment(party(BUYER)));
    assert_eq!(judged_aim.duration, AimDuration::OneShot);
    let kept = mutate(aim(vec![("duration", text("maintain"))]), |c| {
        c.relations = Some(vec![Relation::Serves {
            source: None,
            target: rid(0x61),
            qualifier: None,
        }]);
    });
    assert_eq!(direct(&kept), Outcome::Accepted);
    let kept_aim = Aim::of(&kept).unwrap();
    assert_eq!(kept_aim.evaluation, Evaluation::Truth);
    assert_eq!(kept_aim.duration, AimDuration::Maintain);
    assert_eq!(kept_aim.criterion, None);
    assert_eq!(Concept::opened_by(&kept), Some(Concept::Aim));
    for pairs in [
        vec![("judge", text(BUYER))],
        vec![("duration", text("forever"))],
        vec![("duration", text("one_shot")), ("obligor", text(SUPPLIER))],
    ] {
        assert_eq!(rejected(&aim(pairs)), Reason::Schema(Schema::Params));
    }
}

// C-11 C-7 CM-4 CM-5 CM-6
#[test]
fn c_11_a_commitment_is_two_sided_and_names_its_acceptor() {
    let asked = mutate(
        request(vec![
            ("acceptor", text(BUYER)),
            ("aim", digest_param(0x61)),
            (
                "conditions",
                ParamValue::List(vec![
                    ParamScalar::Digest(digest(0x71)),
                    ParamScalar::Digest(digest(0x72)),
                ]),
            ),
            ("obligor", text(SUPPLIER)),
        ]),
        |c| {
            c.author = party(AGENT);
            c.on_behalf_of = Some(vec![party(BUYER)]);
            c.capacity = Some(Capacity::For(party(BUYER)));
            c.producer = Some(producer("m-1"));
        },
    );
    assert_eq!(direct(&asked), Outcome::Accepted);
    let commitment = Commitment::of(&asked).unwrap();
    assert_eq!(commitment.obligee, party(BUYER));
    assert_eq!(commitment.obligor, Obligor::Party(party(SUPPLIER)));
    assert_eq!(commitment.principal, vec![party(BUYER)]);
    assert_eq!(commitment.aim, Some(rid(0x61)));
    assert_eq!(commitment.conditions, vec![rid(0x71), rid(0x72)]);
    assert_eq!(commitment.acceptor, party(BUYER));
    let pooled = request(vec![
        ("acceptor", text(ALICE)),
        ("queue", digest_param(0x81)),
    ]);
    assert_eq!(direct(&pooled), Outcome::Accepted);
    let pool = Commitment::of(&pooled).unwrap();
    assert_eq!(pool.obligor, Obligor::Queue(rid(0x81)));
    assert_eq!(pool.obligee, party(ALICE));
    for pairs in [
        vec![("obligor", text(SUPPLIER))],
        vec![("acceptor", text(ALICE))],
        vec![
            ("acceptor", text(ALICE)),
            ("obligor", text(SUPPLIER)),
            ("queue", digest_param(0x81)),
        ],
        vec![
            ("acceptor", text(ALICE)),
            ("obligor", text(SUPPLIER)),
            (
                "conditions",
                ParamValue::List(vec![
                    ParamScalar::Digest(digest(0x72)),
                    ParamScalar::Digest(digest(0x71)),
                ]),
            ),
        ],
        vec![
            ("acceptor", text(ALICE)),
            ("obligor", text(SUPPLIER)),
            ("state", text("promised")),
        ],
    ] {
        assert_eq!(rejected(&request(pairs)), Reason::Schema(Schema::Params));
    }
    assert_eq!(Commitment::of(&core_declaration("promise", vec![])), None);
}

// C-12 E-9 ST-10 ST-28
#[test]
fn c_12_the_gate_kind_is_declared_when_the_condition_opens() {
    let epistemic = ConditionType::ALL
        .iter()
        .filter(|t| t.class() == ConditionClass::Epistemic)
        .count();
    assert_eq!(epistemic, 5);
    assert_eq!(
        ConditionType::Authority.class(),
        ConditionClass::Gate(GateKind::Authority)
    );
    for t in [
        ConditionType::Decision,
        ConditionType::Acceptance,
        ConditionType::Resource,
    ] {
        assert_eq!(t.class(), ConditionClass::Gate(GateKind::Coordination));
    }
    let authority_gate = open_condition("authority", BUYER);
    assert_eq!(direct(&authority_gate), Outcome::Accepted);
    assert_eq!(
        Condition::of(&authority_gate).unwrap().class,
        Some(ConditionClass::Gate(GateKind::Authority))
    );
    let undeclared = core_declaration(
        "open_condition",
        vec![
            ("wait_reason", text("internal")),
            ("address", text(BUYER)),
            ("deadline", text("none")),
            ("criterion", text(&format!("{PROC}criterion/ready"))),
        ],
    );
    assert_eq!(rejected(&undeclared), Reason::Schema(Schema::Params));
    assert_eq!(Condition::of(&undeclared), None);
    let sla = open_condition("time", BUYER);
    assert_eq!(direct(&sla), Outcome::Accepted);
    assert_eq!(
        Condition::of(&sla).unwrap().class,
        Some(ConditionClass::Epistemic)
    );
}

// C-26 C-12 ST-21
#[test]
fn c_26_waiting_on_y_is_a_condition_addressed_to_y() {
    let waits = open_condition("commitment", SUPPLIER);
    assert_eq!(direct(&waits), Outcome::Accepted);
    assert_eq!(Concept::opened_by(&waits), Some(Concept::Condition));
    assert_eq!(RelationName::from_wire_name("depends_on"), None);
}

// C-30 CM-5 RC-1
#[test]
fn c_30_roles_live_on_commitments_and_relations_never_on_the_party() {
    assert_eq!(Role::ALL.len(), 7);
    for role in Role::ALL {
        assert!(ActorType::from_wire_name(role.wire_name()).is_none());
        match role.home() {
            RoleHome::Commitment => {}
            RoleHome::Relation(name) => assert!(matches!(
                name,
                RelationName::OnBehalfOf | RelationName::EngagedIn
            )),
        }
    }
    assert_eq!(
        Role::Principal.home(),
        RoleHome::Relation(RelationName::OnBehalfOf)
    );
    assert_eq!(
        Role::QueueOwner.home(),
        RoleHome::Relation(RelationName::EngagedIn)
    );
    let same = request(vec![("acceptor", text(ALICE)), ("obligor", text(ALICE))]);
    assert_eq!(direct(&same), Outcome::Accepted);
    let commitment = Commitment::of(&same).unwrap();
    assert_eq!(commitment.obligee, commitment.acceptor);
    assert_eq!(commitment.obligor, Obligor::Party(party(ALICE)));
}

// C-25 C-30 C-36
#[test]
fn c_25_engaged_in_carries_a_role_label_and_no_obligation_or_authority() {
    let label = claim(
        ALICE,
        vec![w1()],
        Some(vec![Relation::EngagedIn {
            source: party(SUPPLIER),
            target: w1(),
            qualifier: Some(uri(&format!("{PROC}role/reviewer"))),
        }]),
    );
    let label = mutate(label, |c| c.versions = pinned(0x50, PROC));
    assert_eq!(direct(&label), Outcome::Accepted);
    assert_eq!(Concept::opened_by(&label), None);
    assert_eq!(consequence(&label), Consequence::NonConsequential);
}

// C-25 L-86
#[test]
fn c_25_part_of_inherits_nothing() {
    let part = claim(
        ALICE,
        vec![w1()],
        Some(vec![Relation::PartOf {
            source: w1(),
            target: w2(),
            qualifier: None,
        }]),
    );
    assert_eq!(direct(&part), Outcome::Accepted);
    let touches = touched(&part);
    assert_eq!(touches.len(), 1);
    assert_eq!(touches[0].item, ItemKey::Work(w1()));
    let unscoped = mutate(part, |c| c.concerns = vec![]);
    assert_eq!(rejected(&unscoped), Reason::VisibilityNoWork);
}

// C-13 C-25
#[test]
fn c_13_a_reference_owns_nothing_and_an_observation_fixes_what_was_seen() {
    assert_eq!(Concept::Reference.identity(), Identity::External);
    let seen = claim(
        ALICE,
        vec![w1()],
        Some(vec![references("https://erp.example/orders/PO-4471")]),
    );
    assert_eq!(direct(&seen), Outcome::Accepted);
    assert_eq!(consequence(&seen), Consequence::NonConsequential);
    assert!(seen.core().body.is_none());
}

// INV-28 F-14 MD-2 C-13
#[test]
fn inv_28_external_state_enters_only_as_a_reference_or_an_observation() {
    for source in [
        "https://relay.example/deliveries/d-17",
        "https://pay.example/payments/p-9",
        "a2a:task/7f3c",
    ] {
        let status = claim(ALICE, vec![w1()], Some(vec![references(source)]));
        assert_eq!(direct(&status), Outcome::Accepted, "{source}");
        assert_eq!(consequence(&status), Consequence::NonConsequential);
    }
    let decided = promise();
    let authority = decided.core().authority.unwrap();
    assert_eq!(authority.digest, digest(0x11));
}

// C-22 C-39 L-52 L-70
#[test]
fn c_22_sessions_and_provider_objects_are_references_work_does_not_depend_on() {
    let bare = claim(ALICE, vec![w1()], None);
    let linked = claim(
        ALICE,
        vec![w1()],
        Some(vec![
            references("a2a:task/7f3c"),
            references("mcp:task/42"),
            references("https://git.example/acme/po/pull/17"),
        ]),
    );
    assert_eq!(direct(&linked), Outcome::Accepted);
    assert_eq!(touched(&linked), touched(&bare));
    assert_eq!(Concept::from_wire_name("session"), None);
}

// C-14 P-82
#[test]
fn c_14_an_act_is_the_performer_s_report_without_normative_effect() {
    let act = delivery();
    assert_eq!(direct(&act), Outcome::Accepted);
    assert_eq!(consequence(&act), Consequence::NonConsequential);
    let records = [(rid(1), act)];
    let d = derive(&entries(&records), &inputs(&[])).unwrap();
    assert_eq!(d.records[0].effect, Effect::None(NoEffect::NotADeclaration));
}

// C-15 C-5 INV-4 P-71
#[test]
fn c_15_every_named_declaration_kind_is_a_typed_subtype() {
    for name in [
        "gate_decision",
        "allow",
        "accept",
        "reject",
        "disclosure",
        "amend",
        "waiver",
        "attention_request",
        "acknowledgement",
        "control_lease",
        "assign",
        "promise",
        "cancel",
        "aim",
    ] {
        assert!(DeclarationSubtype::from_wire_name(name).is_some(), "{name}");
    }
    let late = core_declaration(
        "amend",
        vec![("effective_at", ParamValue::Scalar(ParamScalar::Uint(5)))],
    );
    let actors = actor_types(&late);
    let mut at = ctx(Origin::Direct, &actors, &[]);
    at.recorded_at = Some(Time(6));
    assert_eq!(
        validate(&late, &at),
        Outcome::Rejected(Reason::RetroactiveDeclaration)
    );
}

// C-16 INV-9
#[test]
fn c_16_a_claim_is_no_truth_and_has_no_normative_effect() {
    for subtype in ClaimSubtype::ALL {
        let mut record = claim(ALICE, vec![w1()], None);
        if let Record::Claim(c) = &mut record {
            c.subtype = ClaimType::Core(*subtype);
        }
        assert_eq!(direct(&record), Outcome::Accepted);
        let records = [(rid(1), record)];
        let d = derive(&entries(&records), &inputs(&[])).unwrap();
        assert_eq!(d.records[0].effect, Effect::None(NoEffect::NotADeclaration));
    }
}

// C-36 C-3
#[test]
fn c_36_capabilities_take_their_canonical_counterparts() {
    assert_eq!(COUNTERPARTS.len(), 22);
    for (i, (name, counterpart)) in COUNTERPARTS.iter().enumerate() {
        assert!(
            COUNTERPARTS[i + 1..].iter().all(|(n, _)| n != name),
            "{name}"
        );
        assert_eq!(Concept::from_wire_name(name), None, "{name}");
        assert_eq!(RelationName::from_wire_name(name), None, "{name}");
        assert_eq!(Kind::from_wire_name(name), None, "{name}");
        if let Counterpart::Relation(RelationName::DerivedFrom, role) = counterpart {
            assert!(role.is_some(), "{name}");
        }
    }
    let lookup = |n: &str| {
        COUNTERPARTS
            .iter()
            .find(|(name, _)| *name == n)
            .map(|(_, c)| *c)
    };
    assert_eq!(
        lookup("plan"),
        Some(Counterpart::Claim(ClaimSubtype::Assumption))
    );
    assert_eq!(
        lookup("signal"),
        Some(Counterpart::Claim(ClaimSubtype::Observation))
    );
    assert_eq!(
        lookup("amendment"),
        Some(Counterpart::Declaration(DeclarationSubtype::Amend))
    );
    assert_eq!(lookup("budget"), Some(Counterpart::Condition));
    assert_eq!(lookup("follow_up"), Some(Counterpart::Commitment));
}

// C-40 C-4
#[test]
fn c_40_derived_concepts_are_projections_never_concepts() {
    assert_eq!(DERIVED.len(), 19);
    for name in DERIVED {
        assert_eq!(Concept::from_wire_name(name), None, "{name}");
        assert_eq!(RelationName::from_wire_name(name), None, "{name}");
    }
    assert!(DERIVED.contains(&"shared_work"));
}

fn entries(records: &[(RecordId, Record)]) -> Vec<Entry<'_>> {
    records
        .iter()
        .zip(1_u64..)
        .map(|((id, record), position)| {
            Entry::unverified(
                *id,
                record,
                position,
                Time(position * 1000),
                Ingest::Admitted,
                Restriction::NoObjection,
                AuthorityIssuer::Local,
            )
        })
        .collect()
}

fn inputs(trusted: &[PartyRef]) -> DerivationInputs<'_> {
    DerivationInputs {
        activations: &[(0, ProtocolVersion { major: 1, minor: 0 })],
        profile: ProfileVersion(1),
        practices: &[],
        trust: TrustInputs {
            trusted_publishers: trusted,
        },
        ledger_time: Time(1_000_000),
        calendar: BusinessCalendar::Continuous,
    }
}

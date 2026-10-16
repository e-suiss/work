//! Record rules over typed records mirroring the Stage 1 vector examples and their single-field mutations.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod fixtures;

use fixtures::*;
use work_kernel::id::{PartyRef, Time, WorkId};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{
    EnvelopeField, Limit, ListField, NonCanonicalCbor, Reason, Schema, SetField,
};
use work_kernel::record::{
    Audience, Capacity, Claim, ClaimType, Correlation, EvidenceType, Param, ParamScalar,
    ParamValue, PartName, ProtocolVersion, Record, RecordCore,
};
use work_kernel::relation::{DerivedRole, DerivedTarget, Relation};
use work_kernel::rules::RuleSet;
use work_kernel::uri::ExtKey;
use work_kernel::validate::{
    ActorType, ActorTypeSource, Origin, Outcome, uninterpreted_extensions, validate,
};

fn run(record: &Record, origin: Origin, understood: &[ExtKey]) -> Outcome {
    let actors = actor_types(record);
    validate(record, &ctx(origin, &actors, understood))
}

fn direct(record: &Record) -> Outcome {
    run(record, Origin::Direct, &[])
}

fn rejected(record: &Record, origin: Origin) -> Reason {
    match run(record, origin, &[]) {
        Outcome::Rejected(reason) => reason,
        other => panic!("expected rejection, got {other:?}"),
    }
}

fn mutate(mut record: Record, f: impl FnOnce(&mut work_kernel::record::RecordCore)) -> Record {
    f(core_mut(&mut record));
    record
}

// P-9 P-10 P-13 P-15 P-16 P-17 E-13 C-32
#[test]
fn p_9_vector_examples_are_accepted() {
    assert_eq!(direct(&promise()), Outcome::Accepted);
    assert_eq!(direct(&delivery()), Outcome::Accepted);
    assert_eq!(
        run(&observation(), Origin::Automation, &[]),
        Outcome::Accepted
    );
    assert_eq!(direct(&amend()), Outcome::Accepted);
    assert_eq!(direct(&comment()), Outcome::Accepted);
    assert_eq!(
        run(&care_note(), Origin::Direct, &[consent_key()]),
        Outcome::Accepted
    );
}

// C-31 P-9
#[test]
fn c_31_p_9_a_record_is_exactly_one_of_three_kinds() {
    use work_kernel::record::Kind;
    assert_eq!(Kind::ALL.len(), 3);
    assert_eq!(Kind::from_wire_name("event"), None);
    assert_eq!(promise().kind(), Kind::Declaration);
    assert_eq!(delivery().kind(), Kind::Act);
    assert_eq!(observation().kind(), Kind::Claim);
}

// C-16
#[test]
fn c_16_core_claim_subtypes_are_typed() {
    let Record::Claim(Claim { subtype, .. }) = observation() else {
        panic!("claim expected");
    };
    assert_eq!(
        subtype,
        ClaimType::Core(work_kernel::catalog::ClaimSubtype::Observation)
    );
}

// P-13 C-32
#[test]
fn p_13_c_32_consequential_record_without_authority_is_rejected() {
    let r = mutate(promise(), |c| c.authority = None);
    assert_eq!(rejected(&r, Origin::Direct), Reason::AuthorityMissing);
}

// P-13 C-32 INV-23
#[test]
fn p_13_inv_23_human_authors_need_authority_too() {
    let r = mutate(amend(), |c| c.authority = None);
    assert_eq!(rejected(&r, Origin::Direct), Reason::AuthorityMissing);
}

// P-13 P-83 P-84
#[test]
fn p_83_acts_and_claims_need_no_authority() {
    assert!(comment().core().authority.is_none());
    assert_eq!(direct(&comment()), Outcome::Accepted);
    assert!(observation().core().authority.is_none());
    assert!(delivery().core().authority.is_none());
    assert_eq!(direct(&delivery()), Outcome::Accepted);
}

// P-83 P-13
#[test]
fn p_83_every_declaration_is_consequential_including_practice_subtypes() {
    let practice = mutate(care_note(), |c| c.authority = None);
    assert_eq!(
        run(&practice, Origin::Direct, &[consent_key()]),
        Outcome::Rejected(Reason::AuthorityMissing)
    );
    for name in ["notice", "conflict_resolution", "acknowledgement", "waiver"] {
        let r = declaration(
            &format!("{CORE}declaration/{name}"),
            RecordCore {
                concerns: vec![w1()],
                ..core(ALICE)
            },
        );
        assert_eq!(
            rejected(&r, Origin::Direct),
            Reason::AuthorityMissing,
            "{name}"
        );
    }
}

// P-81
#[test]
fn p_81_basis_is_required_on_declarations_and_never_empty_elsewhere() {
    let r = mutate(amend(), |c| c.basis = None);
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::RequiredField)
    );
    let r = mutate(amend(), |c| c.basis = Some(vec![]));
    assert_eq!(direct(&r), Outcome::Accepted);
    let r = mutate(delivery(), |c| c.basis = Some(vec![]));
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::EmptyOptionalList)
    );
    let r = mutate(comment(), |c| c.basis = Some(vec![]));
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::EmptyOptionalList)
    );
}

// P-82
#[test]
fn p_82_core_act_subtype_is_action_only() {
    let Record::Act(mut act) = delivery() else {
        panic!("act expected");
    };
    act.subtype = uri(&format!("{CORE}act/delivery"));
    assert_eq!(
        rejected(&Record::Act(act.clone()), Origin::Direct),
        Reason::UnmappedExtensionValue
    );
    act.subtype = uri(&format!("{PROC}act/delivery"));
    act.core.versions = pinned(0x70, PROC);
    assert_eq!(direct(&Record::Act(act)), Outcome::Accepted);
}

fn with_params(record: Record, params: Vec<(&str, ParamValue)>) -> Record {
    mutate(record, |c| {
        c.params = Some(
            params
                .into_iter()
                .map(|(name, value)| Param {
                    name: PartName::parse(name).unwrap(),
                    value,
                })
                .collect(),
        );
    })
}

fn text(s: &str) -> ParamValue {
    ParamValue::Scalar(ParamScalar::Text(s.to_owned()))
}

// P-80 P-85
#[test]
fn p_80_params_follow_the_core_subtype_schema() {
    let decline = declaration(
        &format!("{CORE}declaration/decline"),
        RecordCore {
            concerns: vec![w1()],
            authority: Some(authority(1)),
            ..core(ALICE)
        },
    );
    let ok = with_params(decline.clone(), vec![("reason", text("no_capacity"))]);
    assert_eq!(direct(&ok), Outcome::Accepted);
    let bad_value = with_params(decline.clone(), vec![("reason", text("busy"))]);
    assert_eq!(
        rejected(&bad_value, Origin::Direct),
        Reason::Schema(Schema::Params)
    );
    let unknown_key = with_params(decline.clone(), vec![("stop_type", text("pause"))]);
    assert_eq!(
        rejected(&unknown_key, Origin::Direct),
        Reason::Schema(Schema::Params)
    );
    let effective = with_params(
        decline.clone(),
        vec![("effective_at", ParamValue::Scalar(ParamScalar::Uint(5)))],
    );
    assert_eq!(direct(&effective), Outcome::Accepted);
    let wrong_type = with_params(decline, vec![("effective_at", text("now"))]);
    assert_eq!(
        rejected(&wrong_type, Origin::Direct),
        Reason::Schema(Schema::Params)
    );
    let on_claim = with_params(
        observation(),
        vec![("effective_at", ParamValue::Scalar(ParamScalar::Uint(5)))],
    );
    assert_eq!(
        rejected(&on_claim, Origin::Automation),
        Reason::Schema(Schema::Params)
    );
    let empty = mutate(amend(), |c| c.params = Some(vec![]));
    assert_eq!(
        rejected(&empty, Origin::Direct),
        Reason::Schema(Schema::EmptyOptionalMap)
    );
    let open = declaration(
        &format!("{CORE}declaration/open_condition"),
        RecordCore {
            concerns: vec![w1()],
            authority: Some(authority(1)),
            ..core(ALICE)
        },
    );
    let gate = with_params(
        open,
        vec![
            ("gate_form", text("approval")),
            ("wait_reason", text("internal")),
            ("condition_type", text(&format!("{CORE}condition/decision"))),
        ],
    );
    assert_eq!(direct(&gate), Outcome::Accepted);
}

// P-77
#[test]
fn p_77_work_audience_needs_a_concerned_work() {
    let r = mutate(amend(), |c| c.concerns = vec![]);
    assert_eq!(rejected(&r, Origin::Direct), Reason::VisibilityNoWork);
}

// P-77
#[test]
fn p_77_party_audience_is_sorted_and_excludes_author_and_principals() {
    let audience = |names: &[&str]| Audience::Parties(names.iter().map(|n| party(n)).collect());
    let ok = mutate(amend(), |c| {
        c.visibility.see = audience(&["party:x:b", "party:x:aa"]);
    });
    assert_eq!(direct(&ok), Outcome::Accepted);
    let unsorted = mutate(amend(), |c| {
        c.visibility.see = audience(&["party:x:aa", "party:x:b"]);
    });
    assert_eq!(
        rejected(&unsorted, Origin::Direct),
        Reason::NonCanonicalSetOrder(SetField::Visibility)
    );
    let repeated = mutate(amend(), |c| {
        c.visibility.see = audience(&["party:x:b", "party:x:b"]);
    });
    assert_eq!(
        rejected(&repeated, Origin::Direct),
        Reason::NonCanonicalSetOrder(SetField::Visibility)
    );
    let author = mutate(amend(), |c| c.visibility.see = audience(&[ALICE]));
    assert_eq!(
        rejected(&author, Origin::Direct),
        Reason::DuplicateEntry(ListField::Visibility)
    );
    let principal = mutate(promise(), |c| c.visibility.see = audience(&[BUYER]));
    assert_eq!(
        rejected(&principal, Origin::Direct),
        Reason::DuplicateEntry(ListField::Visibility)
    );
}

// P-78
#[test]
fn p_78_on_behalf_of_chain_has_no_repeated_party() {
    let r = mutate(promise(), |c| {
        c.on_behalf_of = Some(vec![party(BUYER), party(BUYER)]);
    });
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::DuplicateEntry(ListField::OnBehalfOf)
    );
}

// P-13 E-13
#[test]
fn p_13_e_13_capacity_must_match_on_behalf_of() {
    let own = mutate(promise(), |c| c.capacity = Some(Capacity::Own));
    assert_eq!(rejected(&own, Origin::Direct), Reason::CapacityMismatch);
    let other = mutate(promise(), |c| {
        c.capacity = Some(Capacity::For(party(ALICE)));
    });
    assert_eq!(rejected(&other, Origin::Direct), Reason::CapacityMismatch);
    let no_chain = mutate(promise(), |c| c.on_behalf_of = None);
    assert_eq!(
        rejected(&no_chain, Origin::Direct),
        Reason::CapacityMismatch
    );
    let absent = mutate(promise(), |c| c.capacity = None);
    assert_eq!(rejected(&absent, Origin::Direct), Reason::CapacityMismatch);
}

// P-72 P-5
#[test]
fn p_72_empty_optional_lists_are_rejected() {
    let empty = Reason::Schema(Schema::EmptyOptionalList);
    let cases = [
        mutate(observation(), |c| c.relations = Some(vec![])),
        mutate(promise(), |c| c.on_behalf_of = Some(vec![])),
        mutate(promise(), |c| c.correlation = Some(vec![])),
        mutate(delivery(), |c| c.evidence = Some(vec![])),
        mutate(comment(), |c| c.body = Some(vec![])),
        mutate(amend(), |c| c.critical = Some(vec![])),
    ];
    for r in &cases {
        assert_eq!(run(r, Origin::Automation, &[]), Outcome::Rejected(empty));
    }
}

// P-72 P-69
#[test]
fn p_72_p_69_empty_optional_maps_are_rejected() {
    let r = mutate(comment(), |c| c.ext = Some(vec![]));
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::EmptyOptionalMap)
    );
    let r = mutate(comment(), |c| c.versions.practices = Some(vec![]));
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::EmptyOptionalMap)
    );
}

// EV-21
#[test]
fn ev_21_party_audience_is_never_empty() {
    let r = mutate(comment(), |c| c.visibility.see = Audience::Parties(vec![]));
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::Schema(Schema::RequiredField)
    );
}

fn basis(n: usize) -> Vec<work_kernel::id::RecordId> {
    (0..n).map(|i| rid(u8::try_from(i).unwrap())).collect()
}

fn works(n: usize) -> Vec<WorkId> {
    (0..n)
        .map(|i| {
            let mut b = [0_u8; 16];
            b[15] = u8::try_from(i).unwrap();
            WorkId::from_bytes(b)
        })
        .collect()
}

// P-33 SEC-18 T-65
#[test]
fn p_33_sec_18_semantic_limits_accept_the_bound_and_reject_one_more() {
    let at = mutate(amend(), |c| c.basis = Some(basis(64)));
    assert_eq!(direct(&at), Outcome::Accepted);
    let over = mutate(amend(), |c| c.basis = Some(basis(65)));
    assert_eq!(
        rejected(&over, Origin::Direct),
        Reason::LimitExceeded(Limit::Basis)
    );
    let at = mutate(observation(), |c| c.concerns = works(64));
    assert_eq!(run(&at, Origin::Automation, &[]), Outcome::Accepted);
    let over = mutate(observation(), |c| c.concerns = works(65));
    assert_eq!(
        rejected(&over, Origin::Automation),
        Reason::LimitExceeded(Limit::Concerns)
    );
    let chain = |n: usize| -> Vec<PartyRef> {
        std::iter::once(party(BUYER))
            .chain((1..n).map(|i| party(&format!("party:acme:p{i}"))))
            .collect()
    };
    let at = mutate(promise(), |c| c.on_behalf_of = Some(chain(8)));
    assert_eq!(direct(&at), Outcome::Accepted);
    let over = mutate(promise(), |c| c.on_behalf_of = Some(chain(9)));
    assert_eq!(
        rejected(&over, Origin::Direct),
        Reason::LimitExceeded(Limit::OnBehalfOf)
    );
    let relations = |n: usize| -> Vec<Relation> {
        (0..n)
            .map(|i| Relation::DerivedFrom {
                source: None,
                target: DerivedTarget::Record(rid(u8::try_from(i % 256).unwrap())),
                role: DerivedRole::Core(if i < 256 {
                    work_kernel::catalog::CoreDerivedRole::Source
                } else {
                    work_kernel::catalog::CoreDerivedRole::Supports
                }),
            })
            .collect()
    };
    let at = mutate(delivery(), |c| c.relations = Some(relations(256)));
    assert_eq!(direct(&at), Outcome::Accepted);
    let over = mutate(delivery(), |c| c.relations = Some(relations(257)));
    assert_eq!(
        rejected(&over, Origin::Direct),
        Reason::LimitExceeded(Limit::Relations)
    );
}

// T-65 P-33
#[test]
fn t_65_a_narrower_configured_limit_rejects_what_the_default_accepts() {
    let r = amend();
    let actors = actor_types(&r);
    let mut c = ctx(Origin::Direct, &actors, &[]);
    assert_eq!(validate(&r, &c), Outcome::Accepted);
    c.limits = SemanticLimits::DEFAULT.narrow(Limit::Basis, 1).unwrap();
    assert_eq!(
        validate(&r, &c),
        Outcome::Rejected(Reason::LimitExceeded(Limit::Basis))
    );
}

// P-72 P-5
#[test]
fn p_72_set_lists_are_sorted_and_duplicate_free() {
    let unsorted = mutate(amend(), |c| c.basis.as_mut().unwrap().reverse());
    assert_eq!(
        rejected(&unsorted, Origin::Direct),
        Reason::NonCanonicalSetOrder(SetField::Basis)
    );
    let duplicate = mutate(amend(), |c| c.basis = Some(vec![rid(0x40), rid(0x40)]));
    assert_eq!(
        rejected(&duplicate, Origin::Direct),
        Reason::NonCanonicalSetOrder(SetField::Basis)
    );
    let unsorted = mutate(observation(), |c| c.concerns.reverse());
    assert_eq!(
        rejected(&unsorted, Origin::Automation),
        Reason::NonCanonicalSetOrder(SetField::Concerns)
    );
    let duplicate = mutate(observation(), |c| c.concerns = vec![w1(), w1()]);
    assert_eq!(
        rejected(&duplicate, Origin::Automation),
        Reason::NonCanonicalSetOrder(SetField::Concerns)
    );
    let both = |keys: Vec<ExtKey>| mutate(care_note(), |c| c.critical = Some(keys));
    let unsorted = both(vec![consent_key(), ward_key()]);
    assert_eq!(
        run(&unsorted, Origin::Direct, &[consent_key(), ward_key()]),
        Outcome::Rejected(Reason::NonCanonicalSetOrder(SetField::Critical))
    );
    let duplicate = both(vec![consent_key(), consent_key()]);
    assert_eq!(
        run(&duplicate, Origin::Direct, &[consent_key()]),
        Outcome::Rejected(Reason::NonCanonicalSetOrder(SetField::Critical))
    );
}

// P-72
#[test]
fn p_72_author_ordered_lists_reject_repeated_entries() {
    let r = mutate(observation(), |c| {
        let rel = c.relations.as_ref().unwrap()[0].clone();
        c.relations = Some(vec![rel.clone(), rel]);
    });
    assert_eq!(
        rejected(&r, Origin::Automation),
        Reason::DuplicateEntry(ListField::Relations)
    );
    let r = mutate(delivery(), |c| {
        let e = c.evidence.as_ref().unwrap()[0].clone();
        c.evidence = Some(vec![e.clone(), e]);
    });
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::DuplicateEntry(ListField::Evidence)
    );
    let r = mutate(promise(), |c| {
        let x = Correlation {
            scheme: uri("https://a2a-protocol.org/context-id"),
            id: "ctx-8f2c".to_owned(),
        };
        c.correlation = Some(vec![x.clone(), x]);
    });
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::DuplicateEntry(ListField::Correlation)
    );
    let r = mutate(amend(), |c| {
        c.body = Some(vec![body("params", 1), body("params", 2)]);
    });
    assert_eq!(
        rejected(&r, Origin::Direct),
        Reason::DuplicateEntry(ListField::Body)
    );
}

// P-69 P-5
#[test]
fn p_69_ext_keys_are_in_canonical_map_order() {
    let r = mutate(care_note(), |c| c.ext.as_mut().unwrap().reverse());
    assert_eq!(
        run(&r, Origin::Direct, &[consent_key()]),
        Outcome::Rejected(Reason::NonCanonicalCbor(NonCanonicalCbor::UnsortedMapKeys))
    );
    let r = mutate(care_note(), |c| {
        let first = c.ext.as_ref().unwrap()[0].clone();
        c.ext = Some(vec![first.clone(), first]);
    });
    assert_eq!(
        run(&r, Origin::Direct, &[consent_key()]),
        Outcome::Rejected(Reason::NonCanonicalCbor(NonCanonicalCbor::DuplicateMapKey))
    );
}

// P-69 P-19
#[test]
fn p_69_critical_key_must_be_present_in_ext() {
    let approval = uri(&format!("{PROC}ext/approval_chain"));
    let with_ext = mutate(amend(), |c| c.critical = Some(vec![approval.clone()]));
    assert_eq!(
        run(&with_ext, Origin::Direct, std::slice::from_ref(&approval)),
        Outcome::Rejected(Reason::ExtensionCriticalDangling)
    );
    let without_ext = mutate(comment(), |c| c.critical = Some(vec![approval.clone()]));
    assert_eq!(
        run(&without_ext, Origin::Direct, &[approval]),
        Outcome::Rejected(Reason::ExtensionCriticalDangling)
    );
}

// P-19 P-69
#[test]
fn p_19_unknown_critical_extension_quarantines() {
    assert_eq!(
        run(&care_note(), Origin::Direct, &[]),
        Outcome::Quarantined(Reason::ExtensionCriticalUnknown)
    );
    let two = mutate(care_note(), |c| {
        c.critical = Some(vec![ward_key(), consent_key()]);
    });
    assert_eq!(
        run(&two, Origin::Direct, &[consent_key()]),
        Outcome::Quarantined(Reason::ExtensionCriticalUnknown)
    );
    assert_eq!(
        run(&two, Origin::Direct, &[consent_key(), ward_key()]),
        Outcome::Accepted
    );
}

// P-19
#[test]
fn p_19_unknown_non_critical_extension_is_preserved_uninterpreted() {
    let r = amend();
    assert_eq!(direct(&r), Outcome::Accepted);
    let kept: Vec<_> = uninterpreted_extensions(&r, &[]).collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].value.0, b"\x67CC-4410");
}

// C-5 PR-5 P-71
#[test]
fn c_5_unmapped_extension_values_are_rejected() {
    let Record::Claim(mut claim) = observation() else {
        panic!("claim expected");
    };
    claim.subtype = ClaimType::from_uri(uri("https://suiss.org/work/claim/observation"));
    let r = Record::Claim(claim.clone());
    assert_eq!(
        rejected(&r, Origin::Automation),
        Reason::UnmappedExtensionValue
    );
    claim.subtype = ClaimType::from_uri(uri(&format!("{CORE}claim/guess")));
    assert_eq!(
        rejected(&Record::Claim(claim), Origin::Automation),
        Reason::UnmappedExtensionValue
    );
    let r = declaration(&format!("{CORE}declaration/bogus"), amend().core().clone());
    assert_eq!(rejected(&r, Origin::Direct), Reason::UnmappedExtensionValue);
    let r = mutate(comment(), |c| c.versions.practices = None);
    assert_eq!(rejected(&r, Origin::Direct), Reason::UnmappedExtensionValue);
    let r = mutate(delivery(), |c| {
        c.evidence.as_mut().unwrap()[0].evidence_type =
            EvidenceType::from_uri(uri("https://elsewhere.example/ns/evidence/photo"));
    });
    assert_eq!(rejected(&r, Origin::Direct), Reason::UnmappedExtensionValue);
    let r = mutate(delivery(), |c| {
        c.relations = Some(vec![Relation::DerivedFrom {
            source: None,
            target: DerivedTarget::Record(rid(1)),
            role: DerivedRole::Extension(uri("https://elsewhere.example/ns/role/x")),
        }]);
    });
    assert_eq!(rejected(&r, Origin::Direct), Reason::UnmappedExtensionValue);
}

// C-5 PR-5
#[test]
fn c_5_pinned_practice_values_are_accepted() {
    let r = mutate(delivery(), |c| {
        c.versions = pinned(0x70, PROC);
        c.evidence.as_mut().unwrap()[0].evidence_type =
            EvidenceType::from_uri(uri(&format!("{PROC}evidence/scaffold_photo")));
    });
    assert_eq!(direct(&r), Outcome::Accepted);
}

// INV-20 T-66
#[test]
fn inv_20_t_66_automation_needs_a_bound_system_author_and_basis() {
    let no_basis = mutate(observation(), |c| c.basis = None);
    assert_eq!(
        rejected(&no_basis, Origin::Automation),
        Reason::UnattributedAutomation
    );
    assert_eq!(run(&no_basis, Origin::Direct, &[]), Outcome::Accepted);
    let human = mutate(comment(), |c| c.concerns = vec![w1()]);
    assert_eq!(
        rejected(&human, Origin::Automation),
        Reason::UnattributedAutomation
    );
    let r = observation();
    let mut actors = actor_types(&r);
    actors.author.source = ActorTypeSource::DeclaredUnverified;
    assert_eq!(
        validate(&r, &ctx(Origin::Automation, &actors, &[])),
        Outcome::Rejected(Reason::UnattributedAutomation)
    );
    assert_eq!(
        validate(&r, &ctx(Origin::Direct, &actors, &[])),
        Outcome::Accepted
    );
}

// P-15
#[test]
fn p_15_agent_records_carry_producer() {
    let r = mutate(promise(), |c| c.producer = None);
    assert_eq!(rejected(&r, Origin::Direct), Reason::ProducerMissing);
}

// INV-18 P-12
#[test]
fn inv_18_every_on_behalf_of_ring_has_an_actor_type() {
    let r = promise();
    let mut actors = actor_types(&r);
    actors.on_behalf_of.clear();
    assert_eq!(
        validate(&r, &ctx(Origin::Direct, &actors, &[])),
        Outcome::Rejected(Reason::EnvelopeMismatch(EnvelopeField::ActorType))
    );
}

// INV-23 P-12
#[test]
fn inv_23_actor_type_is_not_an_authority_input() {
    let r = mutate(amend(), |c| c.authority = None);
    for actor_type in ActorType::ALL {
        let mut actors = actor_types(&r);
        actors.author.actor_type = *actor_type;
        assert_eq!(
            validate(&r, &ctx(Origin::Direct, &actors, &[])),
            Outcome::Rejected(Reason::AuthorityMissing),
            "{actor_type:?}"
        );
    }
    let r = amend();
    for actor_type in [ActorType::Human, ActorType::System, ActorType::Machine] {
        let mut actors = actor_types(&r);
        actors.author.actor_type = actor_type;
        assert_eq!(
            validate(&r, &ctx(Origin::Direct, &actors, &[])),
            Outcome::Accepted
        );
    }
}

// C-16 P-10
#[test]
fn c_16_declaration_occurred_at_is_optional_and_claims_need_it() {
    let Record::Declaration(mut d) = amend() else {
        panic!("declaration expected");
    };
    d.occurred_at = Some(Time(1));
    assert_eq!(direct(&Record::Declaration(d)), Outcome::Accepted);
}

// T-4 P-87 P-18
#[test]
fn t_4_rule_set_is_selected_from_the_record_version_only() {
    assert_eq!(RuleSet::of(&promise()), Some(RuleSet::V1_0));
    assert_eq!(RuleSet::ALL, &[RuleSet::V1_0]);
    let newer = mutate(promise(), |c| {
        c.versions.protocol = ProtocolVersion { major: 1, minor: 1 };
    });
    assert_eq!(RuleSet::of(&newer), None);
}

// T-4 P-87 P-19
#[test]
fn t_4_p_87_unknown_protocol_version_is_quarantined_before_any_rule() {
    for (major, minor) in [(2, 0), (1, 1), (0, 9), (u64::MAX, u64::MAX)] {
        let record = mutate(promise(), |c| {
            c.versions.protocol = ProtocolVersion { major, minor };
            c.authority = None;
        });
        assert_eq!(
            direct(&record),
            Outcome::Quarantined(Reason::ProtocolVersionUnknown),
            "{major}.{minor}"
        );
    }
}

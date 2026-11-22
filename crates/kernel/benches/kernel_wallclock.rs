//! Wall-clock micro-benchmarks for the kernel hot paths: record validation, derivation over supersede chains, the commitment fold, allowed transitions and aggregation, relation parsing and limits narrowing (T-44 rule 1, T-62).

mod support;

use divan::{Bencher, black_box};
use work_kernel::catalog::AggregationRule;
use work_kernel::commitment::{AccessAnswer, Caller, aggregate, allowed, derive_commitments};
use work_kernel::derive::{Effect, derive};
use work_kernel::id::PartyRef;
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Limit, Reason};
use work_kernel::validate::ActorType;
use work_kernel::validate::{Outcome, validate};
use work_kernel::{API_VERSION, ApiVersion};

fn main() {
    let actors = support::actor_types();
    assert_eq!(
        validate(&support::accepted(), &support::context(&actors)),
        Outcome::Accepted
    );
    assert_eq!(
        validate(&support::rejected(), &support::context(&actors)),
        Outcome::Rejected(Reason::AuthorityMissing)
    );
    let records = support::chain(64);
    let derivation = derive(&support::entries(&records), &support::inputs());
    assert!(derivation.is_ok_and(|d| d.records.iter().all(|r| r.effect == Effect::Normative)));
    assert!(support::parse(support::derived_from_wire()).is_some());
    assert!(support::parse(support::engaged_in_wire()).is_some());
    divan::main();
}

/// Kernel API version comparison (T-4 rule 4).
#[divan::bench]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

/// Validation of a record every Stage 1 rule accepts (T-44 rule 1).
#[divan::bench]
fn validate_accept(bencher: Bencher<'_, '_>) {
    let record = support::accepted();
    let actors = support::actor_types();
    let ctx = support::context(&actors);
    bencher.bench_local(|| validate(black_box(&record), black_box(&ctx)));
}

/// Validation of a record rejected by a late rule (T-44 rule 1).
#[divan::bench]
fn validate_reject(bencher: Bencher<'_, '_>) {
    let record = support::rejected();
    let actors = support::actor_types();
    let ctx = support::context(&actors);
    bencher.bench_local(|| validate(black_box(&record), black_box(&ctx)));
}

/// Derivation over one supersede chain of N Declarations (T-44 rule 1).
#[divan::bench(args = support::CHAIN_LENGTHS)]
fn derive_chain(bencher: Bencher<'_, '_>, len: u32) {
    let records = support::chain(len);
    let entries = support::entries(&records);
    let inputs = support::inputs();
    bencher.bench_local(|| derive(black_box(&entries), black_box(&inputs)));
}

/// Relation parsing from decoded wire parts: `derived_from` with a core role (T-44 rule 1).
#[divan::bench]
fn relation_parse_derived_from(bencher: Bencher<'_, '_>) {
    bencher
        .with_inputs(support::derived_from_wire)
        .bench_local_values(support::parse);
}

/// Relation parsing from decoded wire parts: `engaged_in` with a Party source (T-44 rule 1).
#[divan::bench]
fn relation_parse_engaged_in(bencher: Bencher<'_, '_>) {
    bencher
        .with_inputs(support::engaged_in_wire)
        .bench_local_values(support::parse);
}

/// Narrowing all four semantic limits from the defaults (T-44 rule 1, T-65).
#[divan::bench]
fn limits_narrow() -> Option<SemanticLimits> {
    black_box(SemanticLimits::DEFAULT)
        .narrow(Limit::Basis, black_box(32))
        .and_then(|l| l.narrow(Limit::OnBehalfOf, black_box(4)))
        .and_then(|l| l.narrow(Limit::Relations, black_box(128)))
        .and_then(|l| l.narrow(Limit::Concerns, black_box(16)))
        .ok()
}

/// Commitment derivation over one commitment of N records: the chain fold and the per-item lifecycle (T-44 rules 1, 2; CM-2).
#[divan::bench(args = support::CHAIN_LENGTHS)]
fn derive_commitment(bencher: Bencher<'_, '_>, len: u32) {
    let records = support::commitment(len);
    let entries = support::entries(&records);
    let inputs = support::inputs();
    let facts = support::facts();
    bencher.bench_local(|| {
        let derivation = derive(black_box(&entries), black_box(&inputs)).ok()?;
        Some(derive_commitments(&entries, &derivation, &facts))
    });
}

/// The allowed next transitions of a stated commitment for its acceptor (T-44 rules 1, 2; CM-19, P-55).
#[divan::bench]
fn allowed_transitions(bencher: Bencher<'_, '_>) {
    let records = support::commitment(3);
    let entries = support::entries(&records);
    let derivation = derive(&entries, &support::inputs()).ok();
    let views = derivation
        .map(|d| derive_commitments(&entries, &d, &support::facts()))
        .unwrap_or_default();
    let party = PartyRef::new("party:acme:alice");
    bencher.bench_local(|| {
        let party = party.as_ref()?;
        let view = views.first()?;
        let caller = Caller {
            party,
            actor: ActorType::Human,
            step_up: false,
        };
        Some(allowed(black_box(view), &caller, &[], &|_| {
            AccessAnswer::Allow
        }))
    });
}

/// Aggregation over 255 participants under each rule, by its index in `AggregationRule::ALL` (T-44 rules 1, 2; CM-54).
#[divan::bench(args = [0, 1, 2, 3, 4])]
fn aggregate_policy(bencher: Bencher<'_, '_>, rule: usize) {
    let rule = AggregationRule::ALL
        .get(rule)
        .copied()
        .unwrap_or(AggregationRule::All);
    let (policy, answers) = support::participants(255, rule);
    bencher.bench_local(|| aggregate(black_box(&policy), black_box(&answers)));
}

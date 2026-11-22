//! Instruction-count benchmarks for the kernel hot paths: record validation, derivation over supersede chains, the commitment fold, allowed transitions and aggregation, relation parsing and limits narrowing (T-44, T-60).

#![allow(
    missing_docs,
    reason = "gungraun macros generate undocumented public items in this bench binary"
)]

#[cfg(target_os = "linux")]
mod support;

#[cfg(target_os = "linux")]
use std::hint::black_box;

#[cfg(target_os = "linux")]
use gungraun::{library_benchmark, library_benchmark_group, main};
#[cfg(target_os = "linux")]
use work_kernel::catalog::AggregationRule;
#[cfg(target_os = "linux")]
use work_kernel::commitment::{
    AccessAnswer, AggregateError, AggregateOutcome, AggregationPolicy, Allowed, Answer, Caller,
    CommitmentView, aggregate, allowed, derive_commitments,
};
#[cfg(target_os = "linux")]
use work_kernel::derive::{Derivation, DeriveError, derive};
#[cfg(target_os = "linux")]
use work_kernel::id::PartyRef;
#[cfg(target_os = "linux")]
use work_kernel::id::RecordId;
#[cfg(target_os = "linux")]
use work_kernel::limits::{NarrowError, SemanticLimits};
#[cfg(target_os = "linux")]
use work_kernel::reason::Limit;
#[cfg(target_os = "linux")]
use work_kernel::record::Record;
#[cfg(target_os = "linux")]
use work_kernel::relation::Relation;
#[cfg(target_os = "linux")]
use work_kernel::validate::{ActorType, Outcome, validate};
#[cfg(target_os = "linux")]
use work_kernel::{API_VERSION, ApiVersion};

// T-44
#[cfg(target_os = "linux")]
#[library_benchmark]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

// T-44
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::accept(support::accepted())]
#[bench::reject(support::rejected())]
fn validate_record(record: Record) -> Outcome {
    let actors = support::actor_types();
    validate(black_box(&record), black_box(&support::context(&actors)))
}

// T-44
#[cfg(target_os = "linux")]
#[library_benchmark]
#[benches::chain(args = [1, 64, 1024, 10_000], setup = support::chain)]
fn derive_chain(records: Vec<(RecordId, Record)>) -> Result<Derivation, DeriveError> {
    let entries = support::entries(&records);
    derive(black_box(&entries), black_box(&support::inputs()))
}

// T-44 CM-2
#[cfg(target_os = "linux")]
#[library_benchmark]
#[benches::commitment(args = [2, 64, 1024], setup = support::commitment)]
fn derive_commitment(records: Vec<(RecordId, Record)>) -> Option<Vec<CommitmentView>> {
    let entries = support::entries(&records);
    let derivation = derive(black_box(&entries), black_box(&support::inputs())).ok()?;
    Some(derive_commitments(&entries, &derivation, &support::facts()))
}

#[cfg(target_os = "linux")]
fn stated() -> Vec<CommitmentView> {
    let records = support::commitment(3);
    let entries = support::entries(&records);
    derive(&entries, &support::inputs())
        .map(|d| derive_commitments(&entries, &d, &support::facts()))
        .unwrap_or_default()
}

// T-44 CM-19 P-55
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::acceptor(stated())]
fn allowed_transitions(views: Vec<CommitmentView>) -> Option<Vec<Allowed>> {
    let party = PartyRef::new("party:acme:alice")?;
    let caller = Caller {
        party: &party,
        actor: ActorType::Human,
        step_up: false,
    };
    let view = views.first()?;
    Some(allowed(black_box(view), &caller, &[], &|_| {
        AccessAnswer::Allow
    }))
}

// T-44 CM-54
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::all(support::participants(255, AggregationRule::All))]
#[bench::any(support::participants(255, AggregationRule::Any))]
#[bench::k_of_n(support::participants(255, AggregationRule::KOfN))]
#[bench::sequential(support::participants(255, AggregationRule::Sequential))]
#[bench::percentage(support::participants(255, AggregationRule::Percentage))]
fn aggregate_policy(
    input: (AggregationPolicy, Vec<Answer>),
) -> Result<AggregateOutcome, AggregateError> {
    let (policy, answers) = input;
    aggregate(black_box(&policy), black_box(&answers))
}

// T-44
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::derived_from(support::derived_from_wire())]
#[bench::engaged_in(support::engaged_in_wire())]
fn relation_parse(wire: support::WireRelation) -> Option<Relation> {
    support::parse(black_box(wire))
}

// T-44 T-65
#[cfg(target_os = "linux")]
#[library_benchmark]
fn limits_narrow() -> Result<SemanticLimits, NarrowError> {
    black_box(SemanticLimits::DEFAULT)
        .narrow(Limit::Basis, black_box(32))
        .and_then(|l| l.narrow(Limit::OnBehalfOf, black_box(4)))
        .and_then(|l| l.narrow(Limit::Relations, black_box(128)))
        .and_then(|l| l.narrow(Limit::Concerns, black_box(16)))
}

#[cfg(target_os = "linux")]
library_benchmark_group!(
    name = kernel,
    benchmarks = [
        api_version_compare,
        validate_record,
        derive_chain,
        derive_commitment,
        allowed_transitions,
        aggregate_policy,
        relation_parse,
        limits_narrow
    ]
);

#[cfg(target_os = "linux")]
main!(library_benchmark_groups = kernel);

#[cfg(not(target_os = "linux"))]
fn main() {}

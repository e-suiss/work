//! Wall-clock micro-benchmarks for the kernel hot paths: record validation, derivation over supersede chains, relation parsing and limits narrowing (T-44 rule 1, T-62).

mod support;

use divan::{Bencher, black_box};
use work_kernel::derive::{Effect, derive};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Limit, Reason};
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

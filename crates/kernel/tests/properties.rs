//! Property tests over seeded generated cases: the same input gives the same output, and overflow is a typed error rather than a panic (T-37 rule 3, T-4).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod fixtures;

use fixtures::*;
use work_kernel::derive::{
    Admission, AuthorityIssuer, BusinessCalendar, ChainStatus, DerivationInputs, DeriveError,
    Effect, Entry, Ingest, ProfileVersion, Restriction, TrustInputs, derive,
};
use work_kernel::id::{RecordId, Time};
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::Limit;
use work_kernel::record::{Capacity, ProtocolVersion, Record, RecordCore};
use work_kernel::relation::Relation;
use work_kernel::validate::{Origin, validate};

const AUTHORS: [&str; 3] = [ALICE, "party:acme:bob", "party:acme:carol"];
const OPS: [&str; 4] = ["promise", "amend", "accept", "notice"];

#[derive(Clone, Debug)]
struct Step {
    author: usize,
    op: usize,
    targets: Vec<usize>,
    basis: Vec<usize>,
    deny: bool,
}

struct Cases(u64);

impl Cases {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn step(&mut self) -> Step {
        Step {
            author: self.below(AUTHORS.len()),
            op: self.below(OPS.len()),
            targets: (0..self.below(4)).map(|_| self.below(32)).collect(),
            basis: (0..self.below(4)).map(|_| self.below(32)).collect(),
            deny: self.below(5) == 0,
        }
    }

    fn steps(&mut self, min: usize, max: usize) -> Vec<Step> {
        let n = min + self.below(max - min);
        (0..n).map(|_| self.step()).collect()
    }
}

const CASES: usize = 256;

fn build(steps: &[Step]) -> Vec<(RecordId, Record)> {
    steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let n = u8::try_from(i + 1).unwrap();
            let earlier = |k: usize| (i > 0).then(|| rid(u8::try_from(k % i + 1).unwrap()));
            let mut basis: Vec<RecordId> = s.basis.iter().filter_map(|&k| earlier(k)).collect();
            basis.sort();
            basis.dedup();
            let targets: Vec<RecordId> = s.targets.iter().filter_map(|&k| earlier(k)).collect();
            let relations = (!targets.is_empty()).then(|| {
                targets
                    .into_iter()
                    .map(|target| Relation::Supersedes {
                        target,
                        qualifier: None,
                    })
                    .collect()
            });
            let record = declaration(
                &format!("{CORE}declaration/{}", OPS[s.op]),
                RecordCore {
                    capacity: Some(Capacity::Own),
                    basis: Some(basis),
                    relations,
                    authority: Some(authority(0x90)),
                    ..core(AUTHORS[s.author])
                },
            );
            (rid(n), record)
        })
        .collect()
}

fn entries<'a>(records: &'a [(RecordId, Record)], steps: &[Step], start: u64) -> Vec<Entry<'a>> {
    records
        .iter()
        .zip(steps)
        .zip(0_u64..)
        .map(|(((id, record), s), offset)| Entry {
            id: *id,
            record,
            position: start.wrapping_add(offset),
            recorded_at: Time(offset),
            ingest: Ingest::Admitted,
            restriction: if s.deny {
                Restriction::Deny
            } else {
                Restriction::NoObjection
            },
            issuer: AuthorityIssuer::Local,
        })
        .collect()
}

fn inputs() -> DerivationInputs<'static> {
    DerivationInputs {
        protocol: ProtocolVersion { major: 1, minor: 0 },
        profile: ProfileVersion(1),
        practices: &[],
        trust: TrustInputs {
            trusted_publishers: &[],
        },
        ledger_time: Time(u64::MAX),
        calendar: BusinessCalendar::Continuous,
    }
}

// INV-7 P-31 T-6 T-37
#[test]
fn inv_7_derivation_is_a_pure_function() {
    let mut cases = Cases(0x9e37_79b9_7f4a_7c15);
    for _ in 0..CASES {
        let steps = cases.steps(1, 32);
        let records = build(&steps);
        let e = entries(&records, &steps, 0);
        let first = derive(&e, &inputs());
        assert!(first.is_ok(), "{steps:?}");
        assert_eq!(first, derive(&e, &inputs()), "{steps:?}");
    }
}

// P-28 P-86 T-37
#[test]
fn p_28_order_of_the_targets_after_the_first_never_changes_the_result() {
    let mut cases = Cases(0x0123_4567_89ab_cdef);
    for _ in 0..CASES {
        let steps = cases.steps(1, 32);
        let records = build(&steps);
        let mut swapped = records.clone();
        for (_, record) in &mut swapped {
            if let Some(relations) = core_mut(record).relations.as_mut()
                && let Some((_, rest)) = relations.split_first_mut()
            {
                rest.reverse();
            }
        }
        let a = derive(&entries(&records, &steps, 0), &inputs());
        let b = derive(&entries(&swapped, &steps, 0), &inputs());
        assert_eq!(a, b, "{steps:?}");
    }
}

// P-24 P-28 P-86 T-37
#[test]
fn p_24_derived_view_invariants_hold() {
    let mut cases = Cases(0x5851_f42d_4c95_7f2d);
    for _ in 0..CASES {
        let steps = cases.steps(1, 32);
        let records = build(&steps);
        let d = derive(&entries(&records, &steps, 0), &inputs()).unwrap();
        let effect_of = |id: &RecordId| d.records.iter().find(|r| &r.id == id).map(|r| r.effect);
        for r in &d.records {
            let mut seen = r.superseded_by.clone();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), r.superseded_by.len(), "{steps:?}");
            if !r.superseded_by.is_empty() {
                assert_eq!(r.admission, Admission::Admitted, "{steps:?}");
            }
        }
        for c in &d.chains {
            assert!(!c.heads.is_empty(), "{steps:?}");
            assert_eq!(
                c.status == ChainStatus::Conflicted,
                c.heads.len() > 1,
                "{steps:?}"
            );
            for h in &c.heads {
                assert!(
                    matches!(effect_of(h), Some(Effect::Normative | Effect::Conflicted)),
                    "{steps:?}"
                );
            }
        }
    }
}

// T-4 T-37
#[test]
fn t_4_position_overflow_is_typed() {
    let mut cases = Cases(0x2545_f491_4f6c_dd1d);
    for _ in 0..CASES {
        let steps = cases.steps(2, 16);
        let back = u64::try_from(cases.below(16)).unwrap();
        let records = build(&steps);
        let count = u64::try_from(steps.len()).unwrap();
        let e = entries(&records, &steps, u64::MAX - back);
        let result = derive(&e, &inputs());
        if back + 1 < count {
            assert_eq!(result, Err(DeriveError::Overflow), "{steps:?}");
        } else {
            assert!(result.is_ok(), "{steps:?}");
        }
    }
}

// P-31 T-65 T-37
#[test]
fn p_31_validation_is_a_pure_function() {
    for n in 0..80 {
        for narrow in [0, 1, 10, 63, 64, 65, 1000] {
            let mut record = amend();
            core_mut(&mut record).basis =
                Some((0..n).map(|i| rid(u8::try_from(i).unwrap())).collect());
            let actors = actor_types(&record);
            let mut c = ctx(Origin::Direct, &actors, &[]);
            if let Ok(limits) = SemanticLimits::DEFAULT.narrow(Limit::Basis, narrow) {
                c.limits = limits;
            }
            assert_eq!(validate(&record, &c), validate(&record, &c));
        }
    }
}

// T-65
#[test]
fn t_65_wider_limits_cannot_be_constructed() {
    let mut cases = Cases(0xdead_beef_cafe_f00d);
    for _ in 0..CASES {
        let value = cases.below(100_000);
        for limit in [
            Limit::Basis,
            Limit::OnBehalfOf,
            Limit::Relations,
            Limit::Concerns,
        ] {
            let max = SemanticLimits::DEFAULT.max(limit).unwrap();
            assert_eq!(
                SemanticLimits::DEFAULT.narrow(limit, value).is_ok(),
                value <= max
            );
        }
    }
}

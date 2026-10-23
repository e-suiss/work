//! The derivation skeleton: a pure fold over an ordered record sequence and explicit inputs, with no wall clock (T-4, T-6, INV-7, P-31); it fixes supersession, retroactivity, eligibility, conflict and divergence, and keeps a minimal normative state per supersede chain until the commitment lifecycle exists.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::catalog::DeclarationSubtype;
use crate::id::{PartyRef, RecordId, Time};
use crate::reason::{QuarantineReason, Reason};
use crate::record::{Kind, PracticePin, ProtocolVersion, Record};
use crate::rules::RuleSet;

/// The result of the shared restriction engine for one record, supplied as input (T-4 rule 5, T-23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restriction {
    /// `NO_OBJECTION`.
    NoObjection,
    /// `DENY`; an evaluation error is also `DENY`.
    Deny,
    /// `REQUIRE`: a condition is still outstanding.
    Require,
}

/// Who issued the authority proof a record refers to (P-13 item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityIssuer {
    /// This installation's Access.
    Local,
    /// Another organisation's Access, through a portable proof.
    Federated(PartyRef),
}

/// How the ledger admitted a record (P-11, P-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingest {
    /// Admitted.
    Admitted,
    /// Written but quarantined (P-19, P-87).
    Quarantined(QuarantineReason),
}

/// One ledger record with the envelope facts derivation needs.
#[derive(Clone, Debug)]
pub struct Entry<'a> {
    /// The record identifier.
    pub id: RecordId,
    /// The decoded, validated record.
    pub record: &'a Record,
    /// The ledger position; positions are contiguous.
    pub position: u64,
    /// The trusted record time (P-27).
    pub recorded_at: Time,
    /// How the record was admitted.
    pub ingest: Ingest,
    /// The restriction result for this record (T-23).
    pub restriction: Restriction,
    /// The issuer of the authority proof.
    pub issuer: AuthorityIssuer,
}

/// The business calendar input (T-6); only continuous time exists until time Conditions arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusinessCalendar {
    /// Every instant counts.
    Continuous,
}

/// A conformance profile version (P-31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileVersion(pub u32);

/// Declared trust inputs (P-31, T-6).
#[derive(Clone, Copy, Debug)]
pub struct TrustInputs<'a> {
    /// Publishers whose portable authority proofs this verifier trusts.
    pub trusted_publishers: &'a [PartyRef],
}

/// Every input besides the records that the normative result depends on (P-31, T-6).
#[derive(Clone, Copy, Debug)]
pub struct DerivationInputs<'a> {
    /// The active protocol version of the evaluation, set by an activation record (OP-28 rule 3, P-87).
    pub protocol: ProtocolVersion,
    /// The profile version.
    pub profile: ProfileVersion,
    /// Adopted Practice versions.
    pub practices: &'a [PracticePin],
    /// Trust and policy inputs.
    pub trust: TrustInputs<'a>,
    /// The ledger time of evaluation; never the wall clock.
    pub ledger_time: Time,
    /// The business calendar.
    pub calendar: BusinessCalendar,
}

/// Whether a record entered the derived history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Part of the derived history.
    Admitted,
    /// Written, held for attention, without effect.
    Quarantined(QuarantineReason),
    /// Refused by a derivation rule.
    Rejected(Reason),
}

/// Why an admitted record has no normative effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoEffect {
    /// Acts and Claims never change normative state (INV-9, C-14, C-16).
    NotADeclaration,
    /// The record was not admitted.
    NotAdmitted,
    /// The record's protocol version is newer than the active protocol version of the evaluation (OP-28 rule 3, P-87).
    ProtocolVersion,
    /// The restriction result is `DENY`.
    Denied,
    /// The restriction result is `REQUIRE`.
    RequirementPending,
    /// The authority proof comes from a publisher outside the trust inputs.
    UntrustedAuthority,
    /// The effective time is after the evaluation's ledger time.
    NotYetEffective,
    /// The first superseded record is not in any supersede chain: it is absent from this ledger, was not admitted, is not a Declaration, or never took effect (P-86 item 2).
    UnknownTarget,
    /// The chain reached a terminal outcome, which never changes (P-24 item 3, CM-34).
    TerminalOutcome,
    /// The chain is conflicted and the record is not a `conflict_resolution` that saw every conflicting head (P-28).
    Conflicted,
    /// The record replaces an outdated version written by the same author as the current head.
    Stale,
}

/// The normative effect of one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The record changed normative state.
    Normative,
    /// The record is a concurrent incompatible transition; both stay recorded and the chain is conflicted (P-28, P-74).
    Conflicted,
    /// No normative effect.
    None(NoEffect),
}

/// One record in the derived view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedRecord {
    /// The record identifier.
    pub id: RecordId,
    /// Admission.
    pub admission: Admission,
    /// Normative effect.
    pub effect: Effect,
    /// Admitted records of the same kind that supersede this admitted record, each once, in ledger order; the record itself stays readable (P-24 item 1).
    pub superseded_by: Vec<RecordId>,
}

/// The normative status of a supersede chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// Open.
    Open,
    /// Terminal; immutable.
    Terminal,
    /// Conflicted until a resolution cites every head (P-28).
    Conflicted,
}

/// A supersede chain and its minimal normative state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The first record.
    pub root: RecordId,
    /// The highest version a record with normative or conflicting effect took in the chain (P-86).
    pub version: u32,
    /// The records currently in normative effect; more than one while conflicted.
    pub heads: Vec<RecordId>,
    /// The status.
    pub status: ChainStatus,
}

/// The derived view, in input order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    /// One entry per input record.
    pub records: Vec<DerivedRecord>,
    /// Supersede chains in order of their roots.
    pub chains: Vec<Chain>,
}

/// An input sequence the ledger could not have produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeriveError {
    /// A position is not the previous one plus one.
    PositionGap {
        /// The offending position.
        position: u64,
    },
    /// `recorded_at` decreases.
    RecordedAtOutOfOrder {
        /// The offending position.
        position: u64,
    },
    /// A record identifier repeats.
    DuplicateRecord(RecordId),
    /// A record names a different ledger than the first one.
    LedgerMismatch {
        /// The offending position.
        position: u64,
    },
    /// A counter overflowed; the fold stops on the safe side (T-4 rule 2).
    Overflow,
}

impl DeriveError {
    /// The stable `snake_case` code of the error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PositionGap { .. } => "position_gap",
            Self::RecordedAtOutOfOrder { .. } => "recorded_at_out_of_order",
            Self::DuplicateRecord(_) => "duplicate_record",
            Self::LedgerMismatch { .. } => "ledger_mismatch",
            Self::Overflow => "overflow",
        }
    }
}

struct Member {
    kind: Kind,
    author: PartyRef,
    admitted: bool,
    version: Option<(usize, u32)>,
}

enum Place {
    Root,
    Existing { chain: usize, version: u32 },
    Unknown,
}

struct Fold<'i> {
    inputs: &'i DerivationInputs<'i>,
    index: BTreeMap<RecordId, usize>,
    members: Vec<Member>,
    records: Vec<DerivedRecord>,
    chains: Vec<Chain>,
    versions: BTreeMap<(usize, u32), Vec<usize>>,
}

/// Folds an ordered ledger sequence into the derived view (P-31, T-6).
///
/// # Errors
///
/// Returns [`DeriveError`] when the sequence is not a valid ledger order or a counter overflows.
pub fn derive(
    entries: &[Entry<'_>],
    inputs: &DerivationInputs<'_>,
) -> Result<Derivation, DeriveError> {
    let mut fold = Fold {
        inputs,
        index: BTreeMap::new(),
        members: Vec::new(),
        records: Vec::new(),
        chains: Vec::new(),
        versions: BTreeMap::new(),
    };
    let mut previous: Option<&Entry<'_>> = None;
    for entry in entries {
        if let Some(p) = previous {
            let expected = p.position.checked_add(1).ok_or(DeriveError::Overflow)?;
            let position = entry.position;
            if position != expected {
                return Err(DeriveError::PositionGap { position });
            }
            if entry.recorded_at < p.recorded_at {
                return Err(DeriveError::RecordedAtOutOfOrder { position });
            }
            if entry.record.core().ledger != p.record.core().ledger {
                return Err(DeriveError::LedgerMismatch { position });
            }
        }
        fold.step(entry)?;
        previous = Some(entry);
    }
    Ok(Derivation {
        records: fold.records,
        chains: fold.chains,
    })
}

fn saw(record: &Record, head: &RecordId) -> bool {
    record.basis().contains(head) || record.supersedes().any(|t| t == head)
}

impl Fold<'_> {
    fn step(&mut self, entry: &Entry<'_>) -> Result<(), DeriveError> {
        if self.index.contains_key(&entry.id) {
            return Err(DeriveError::DuplicateRecord(entry.id));
        }
        let place = self.place(entry.record)?;
        let admission = match RuleSet::of(entry.record) {
            None => Admission::Quarantined(QuarantineReason::ProtocolVersionUnknown),
            Some(RuleSet::V1_0) => self.admission_v1_0(entry, &place),
        };
        let slot = self.records.len();
        let admitted = admission == Admission::Admitted;
        let (effect, version) = if admitted {
            self.mark_superseded(entry);
            self.effect(entry, &place)
        } else {
            (Effect::None(NoEffect::NotAdmitted), None)
        };
        if let Some(key) = version {
            self.versions.entry(key).or_default().push(slot);
        }
        self.index.insert(entry.id, slot);
        self.members.push(Member {
            kind: entry.record.kind(),
            author: entry.record.core().author.clone(),
            admitted,
            version,
        });
        self.records.push(DerivedRecord {
            id: entry.id,
            admission,
            effect,
            superseded_by: Vec::new(),
        });
        Ok(())
    }

    fn member(&self, id: &RecordId) -> Option<&Member> {
        self.index.get(id).and_then(|&i| self.members.get(i))
    }

    // P-24 P-86
    fn place(&self, record: &Record) -> Result<Place, DeriveError> {
        let Some(first) = record.supersedes().next() else {
            return Ok(Place::Root);
        };
        let Some((chain, _)) = self.member(first).and_then(|m| m.version) else {
            return Ok(Place::Unknown);
        };
        let latest = record
            .supersedes()
            .filter_map(|t| self.member(t).and_then(|m| m.version))
            .filter(|&(c, _)| c == chain)
            .map(|(_, v)| v)
            .max()
            .unwrap_or(0);
        let version = latest.checked_add(1).ok_or(DeriveError::Overflow)?;
        Ok(Place::Existing { chain, version })
    }

    // INV-4 P-24 P-74 P-86
    fn admission_v1_0(&self, entry: &Entry<'_>, place: &Place) -> Admission {
        if let Ingest::Quarantined(reason) = entry.ingest {
            return Admission::Quarantined(reason);
        }
        let record = entry.record;
        if record.effective_at().is_some_and(|t| t < entry.recorded_at) {
            return Admission::Rejected(Reason::RetroactiveDeclaration);
        }
        let kind = record.kind();
        if record
            .supersedes()
            .any(|t| self.member(t).is_some_and(|m| m.kind != kind))
        {
            return Admission::Rejected(Reason::SupersedesKindMismatch);
        }
        if let (Kind::Declaration, Place::Existing { chain, version }) = (kind, place) {
            let author = &record.core().author;
            let repeated = self.versions.get(&(*chain, *version)).is_some_and(|slots| {
                slots
                    .iter()
                    .any(|&m| self.members.get(m).is_some_and(|x| &x.author == author))
            });
            if repeated {
                return Admission::Rejected(Reason::DuplicateVersion);
            }
        }
        Admission::Admitted
    }

    // P-24 C-33
    fn mark_superseded(&mut self, entry: &Entry<'_>) {
        for target in entry.record.supersedes() {
            let Some(&t) = self.index.get(target) else {
                continue;
            };
            if !self.members.get(t).is_some_and(|m| m.admitted) {
                continue;
            }
            if let Some(r) = self.records.get_mut(t)
                && r.superseded_by.last() != Some(&entry.id)
            {
                r.superseded_by.push(entry.id);
            }
        }
    }

    fn author_of(&self, id: &RecordId) -> Option<&PartyRef> {
        self.member(id).map(|m| &m.author)
    }

    // T-23 P-87 P-27
    fn blocked(&self, entry: &Entry<'_>) -> Option<NoEffect> {
        if entry.record.core().versions.protocol > self.inputs.protocol {
            Some(NoEffect::ProtocolVersion)
        } else if entry.restriction == Restriction::Deny {
            Some(NoEffect::Denied)
        } else if entry.restriction == Restriction::Require {
            Some(NoEffect::RequirementPending)
        } else if matches!(&entry.issuer, AuthorityIssuer::Federated(p) if !self.inputs.trust.trusted_publishers.contains(p))
        {
            Some(NoEffect::UntrustedAuthority)
        } else if entry
            .record
            .effective_at()
            .is_some_and(|t| t > self.inputs.ledger_time)
        {
            Some(NoEffect::NotYetEffective)
        } else {
            None
        }
    }

    // INV-9 C-15 C-16 P-24 P-28 P-74 P-86
    fn effect(&mut self, entry: &Entry<'_>, place: &Place) -> (Effect, Option<(usize, u32)>) {
        let Record::Declaration(declaration) = entry.record else {
            return (Effect::None(NoEffect::NotADeclaration), None);
        };
        if let Some(reason) = self.blocked(entry) {
            return (Effect::None(reason), None);
        }
        let subtype = DeclarationSubtype::from_uri(declaration.subtype.as_str());
        let next_status = if subtype.is_some_and(DeclarationSubtype::is_terminal) {
            ChainStatus::Terminal
        } else {
            ChainStatus::Open
        };
        let (index, version) = match *place {
            Place::Root => {
                let index = self.chains.len();
                self.chains.push(Chain {
                    root: entry.id,
                    version: 0,
                    heads: alloc::vec![entry.id],
                    status: next_status,
                });
                return (Effect::Normative, Some((index, 0)));
            }
            Place::Unknown => return (Effect::None(NoEffect::UnknownTarget), None),
            Place::Existing { chain, version } => (chain, version),
        };
        let Some(state) = self.chains.get(index) else {
            return (Effect::None(NoEffect::UnknownTarget), None);
        };
        let record = entry.record;
        let sees_all = state.heads.iter().all(|h| saw(record, h));
        let effect = match state.status {
            ChainStatus::Terminal => return (Effect::None(NoEffect::TerminalOutcome), None),
            ChainStatus::Conflicted
                if sees_all && subtype == Some(DeclarationSubtype::ConflictResolution) =>
            {
                Effect::Normative
            }
            ChainStatus::Conflicted => return (Effect::None(NoEffect::Conflicted), None),
            ChainStatus::Open if sees_all => Effect::Normative,
            ChainStatus::Open => {
                let author = &declaration.core.author;
                let concurrent_other = state
                    .heads
                    .iter()
                    .filter(|h| !saw(record, h))
                    .any(|h| self.author_of(h).is_some_and(|a| a != author));
                if !concurrent_other {
                    return (Effect::None(NoEffect::Stale), None);
                }
                Effect::Conflicted
            }
        };
        if let Some(state) = self.chains.get_mut(index) {
            if effect == Effect::Conflicted {
                state.heads.push(entry.id);
                state.status = ChainStatus::Conflicted;
            } else {
                state.heads.clear();
                state.heads.push(entry.id);
                state.status = next_status;
            }
            state.version = state.version.max(version);
        }
        (effect, Some((index, version)))
    }
}

/// Whether two derivations over the same records agree (T-6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Agreement {
    /// Same normative result.
    Same,
    /// An explicit divergence, listing the records whose result differs; not a protocol error (P-31).
    Diverged(Vec<RecordId>),
}

/// Compares two derivations of the same records, such as under different trust inputs, matching records by identifier (T-6); records whose result differs, or that only one side holds, are listed in the order of `a` and then of `b`.
#[must_use]
pub fn compare(a: &Derivation, b: &Derivation) -> Agreement {
    let index = |d: &Derivation| -> BTreeMap<RecordId, usize> {
        d.records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id, i))
            .collect()
    };
    let (in_a, in_b) = (index(a), index(b));
    let mut differing: Vec<RecordId> = a
        .records
        .iter()
        .filter(|x| {
            in_b.get(&x.id)
                .and_then(|&i| b.records.get(i))
                .is_none_or(|y| y != *x)
        })
        .map(|x| x.id)
        .collect();
    differing.extend(
        b.records
            .iter()
            .filter(|y| !in_a.contains_key(&y.id))
            .map(|y| y.id),
    );
    if differing.is_empty() && a.chains == b.chains {
        Agreement::Same
    } else {
        Agreement::Diverged(differing)
    }
}

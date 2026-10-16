//! The derivation skeleton: a pure fold over an ordered record sequence and explicit inputs, with no wall clock (T-4, T-6, INV-7, P-31); it fixes supersession, retroactivity, eligibility, conflict and divergence, and keeps a minimal normative state per supersede chain until the commitment lifecycle exists.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::catalog::DeclarationSubtype;
use crate::id::{PartyRef, RecordId, Time};
use crate::reason::Reason;
use crate::record::{PracticePin, ProtocolVersion, Record};
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
    /// Written but quarantined.
    Quarantined(Reason),
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
    Quarantined(Reason),
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
    /// The superseded record is not in this ledger's history.
    UnknownTarget,
    /// The chain reached a terminal outcome, which never changes (P-24 item 3, CM-34).
    TerminalOutcome,
    /// The chain is conflicted and the record does not cite every conflicting head (P-28).
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
    /// Records that supersede this one; the record itself stays readable (P-24 item 1).
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
    /// The highest admitted version in the chain (P-86).
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

struct Member {
    chain: Option<usize>,
    version: u32,
    author: PartyRef,
    admitted: bool,
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

impl Fold<'_> {
    fn step(&mut self, entry: &Entry<'_>) -> Result<(), DeriveError> {
        if self.index.contains_key(&entry.id) {
            return Err(DeriveError::DuplicateRecord(entry.id));
        }
        let author = &entry.record.core().author;
        let place = self.place(entry.record)?;
        let admission = match RuleSet::of(entry.record) {
            None => Admission::Quarantined(Reason::ProtocolVersionUnknown),
            Some(RuleSet::V1_0) => self.admission_v1_0(entry, &place),
        };
        let slot = self.records.len();
        let mut member = Member {
            chain: None,
            version: 0,
            author: author.clone(),
            admitted: admission == Admission::Admitted,
        };
        let mut effect = Effect::None(NoEffect::NotAdmitted);
        if member.admitted {
            for target in entry.record.supersedes() {
                if let Some(&t) = self.index.get(target)
                    && let Some(r) = self.records.get_mut(t)
                {
                    r.superseded_by.push(entry.id);
                }
            }
            match place {
                Place::Root => {
                    member.chain = Some(self.chains.len());
                    self.chains.push(Chain {
                        root: entry.id,
                        version: 0,
                        heads: Vec::new(),
                        status: ChainStatus::Open,
                    });
                }
                Place::Existing { chain, version } => {
                    member.chain = Some(chain);
                    member.version = version;
                    if let Some(c) = self.chains.get_mut(chain) {
                        c.version = c.version.max(version);
                    }
                }
                Place::Unknown => {}
            }
            effect = self.effect(entry, member.chain);
        }
        self.index.insert(entry.id, slot);
        self.members.push(member);
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
        let Some(chain) = self.member(first).and_then(|m| m.chain) else {
            return Ok(Place::Unknown);
        };
        let latest = record
            .supersedes()
            .filter_map(|t| self.member(t))
            .filter(|m| m.chain == Some(chain))
            .map(|m| m.version)
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
        let retroactive = entry
            .record
            .effective_at()
            .is_some_and(|t| t < entry.recorded_at);
        if retroactive {
            return Admission::Rejected(Reason::RetroactiveDeclaration);
        }
        if let Place::Existing { chain, version } = *place {
            let author = &entry.record.core().author;
            let repeated = self.members.iter().any(|m| {
                m.admitted && m.chain == Some(chain) && m.version == version && &m.author == author
            });
            if repeated {
                return Admission::Rejected(Reason::DuplicateVersion);
            }
        }
        Admission::Admitted
    }

    fn author_of(&self, id: &RecordId) -> Option<&PartyRef> {
        self.member(id).map(|m| &m.author)
    }

    // INV-9 C-15 C-16 P-28 T-23 P-87
    fn effect(&mut self, entry: &Entry<'_>, chain: Option<usize>) -> Effect {
        let Record::Declaration(declaration) = entry.record else {
            return Effect::None(NoEffect::NotADeclaration);
        };
        let core = &declaration.core;
        let blocked = if core.versions.protocol > self.inputs.protocol {
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
        };
        if let Some(reason) = blocked {
            return Effect::None(reason);
        }
        let Some(index) = chain else {
            return Effect::None(NoEffect::UnknownTarget);
        };
        let Some(state) = self.chains.get(index) else {
            return Effect::None(NoEffect::UnknownTarget);
        };
        let terminal = DeclarationSubtype::from_uri(declaration.subtype.as_str())
            .is_some_and(DeclarationSubtype::is_terminal);
        let next_status = if terminal {
            ChainStatus::Terminal
        } else {
            ChainStatus::Open
        };
        let cites_heads = state.heads.iter().all(|h| entry.record.basis().contains(h));
        let target_is_head = entry
            .record
            .supersedes()
            .next()
            .is_some_and(|t| state.heads.len() == 1 && state.heads.first() == Some(t));
        let concurrent_other = state
            .heads
            .iter()
            .any(|h| self.author_of(h).is_some_and(|a| a != &core.author));
        let (heads, status, effect) = match state.status {
            ChainStatus::Terminal => return Effect::None(NoEffect::TerminalOutcome),
            ChainStatus::Conflicted if !cites_heads => return Effect::None(NoEffect::Conflicted),
            ChainStatus::Open if !(cites_heads || target_is_head) => {
                if !concurrent_other {
                    return Effect::None(NoEffect::Stale);
                }
                let mut heads = state.heads.clone();
                heads.push(entry.id);
                (heads, ChainStatus::Conflicted, Effect::Conflicted)
            }
            ChainStatus::Open | ChainStatus::Conflicted => {
                (alloc::vec![entry.id], next_status, Effect::Normative)
            }
        };
        if let Some(state) = self.chains.get_mut(index) {
            state.heads = heads;
            state.status = status;
        }
        effect
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

/// Compares two derivations, such as the same records under different trust inputs (T-6).
#[must_use]
pub fn compare(a: &Derivation, b: &Derivation) -> Agreement {
    let mut differing: Vec<RecordId> = a
        .records
        .iter()
        .zip(&b.records)
        .filter(|(x, y)| x != y)
        .map(|(x, _)| x.id)
        .collect();
    let longer = if a.records.len() > b.records.len() {
        &a.records
    } else {
        &b.records
    };
    differing.extend(
        longer
            .iter()
            .skip(a.records.len().min(b.records.len()))
            .map(|r| r.id),
    );
    if differing.is_empty() && a.chains == b.chains {
        Agreement::Same
    } else {
        Agreement::Diverged(differing)
    }
}

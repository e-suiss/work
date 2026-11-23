//! The commitments of a ledger as the kernel derives them (CM-2, CM-19, P-55, CM-58, E-8, E-12, T-89, C-6): the canonical log is read back from its stored bytes, every entry is verified along the chain from the genesis, the conflict areas are replayed, and the records are folded by the kernel's derivation and its commitment fold; nothing here decides a rule and nothing is kept, so every answer is recomputed from the records. A signed record's signature was verified at admission against the key Access bound to it, and its bytes are bound to the chain by the envelope's `proof_commit`, so the read-back keeps that verification instead of asking Access for the keys again.

use std::collections::BTreeMap;

use work_kernel::catalog::DeclarationSubtype;
use work_kernel::codec::{Decoded, decode_record, leaf_hash, record_id};
use work_kernel::commitment::{
    self, AccessAnswer, ActiveEnd, Allowed, Caller as Asking, CommitmentView, Facts,
    ImplicitAcceptance, Mover, Operation, Proposed, Refusal, StepOutcome, SupportSignal,
    TimeInputs, TimeProjection, clock_signals, definition_records, project_time, zones_named,
};
use work_kernel::cose::parse_container;
use work_kernel::derive::{
    AuthorityIssuer, BusinessCalendar, DerivationInputs, Entry, ProfileVersion, Restriction,
    TrustInputs, derive,
};
use work_kernel::envelope::{Envelope, decode_envelope};
use work_kernel::id::{LedgerId, PartyRef, RecordId, Time};
use work_kernel::items::{Area, ItemKey};
use work_kernel::ontology::Obligor;
use work_kernel::reason::{Reason, Schema};
use work_kernel::record::{ProtocolVersion, Record};
use work_kernel::validate::ActorType;
use work_kernel::verify::{
    ChainPoint, SignatureCheck, SignatureVerifier, StoredEntry, Verified, VerifiedEntry,
    verify_entry,
};
use work_ledger::Areas;
use work_proto::id::PositionToken;
use work_store::StoredLogEntry;

use crate::domain::reads::ReadRefusal;
use crate::domain::tzdb;

/// The Access action of each commitment operation a caller may write (E-45 item 2); `expire`
/// is the Work service's own record and has none.
#[must_use]
pub const fn action_of(operation: Operation) -> Option<&'static str> {
    match operation {
        Operation::Accept | Operation::Reject => Some("close"),
        Operation::Assign => Some("assign"),
        Operation::AdministrativeClose => Some("administrative_close"),
        Operation::ImplicitAcceptanceTerms => Some("autonomy_policy_set"),
        Operation::Expire => None,
        _ => Some("commit"),
    }
}

/// The commitment operation a record is, if it is one (P-71).
#[must_use]
pub fn operation_of(record: &Record) -> Option<Operation> {
    match record {
        Record::Declaration(d) => {
            DeclarationSubtype::from_uri(d.subtype.as_str()).and_then(Operation::of)
        }
        Record::Act(_) | Record::Claim(_) => None,
    }
}

/// The signature port of a stored entry: the signature was verified at admission against the
/// key Access bound to it and the envelope's `proof_commit` binds these bytes, so the check
/// opens the container and names the record and its author.
struct Admitted;

impl SignatureVerifier for Admitted {
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck {
        let payload = match parse_container(cose_sign1) {
            Ok(sign1) => sign1.payload,
            Err(reason) => return SignatureCheck::Rejected(reason),
        };
        let Some(payload) = payload else {
            return SignatureCheck::Rejected(Reason::Schema(Schema::Container));
        };
        match decode_record(&payload) {
            Ok(Decoded::Record(record)) => SignatureCheck::Valid {
                record: record_id(&payload),
                author: record.core().author.clone(),
            },
            Ok(Decoded::UnknownProtocol(_)) => {
                SignatureCheck::Rejected(Reason::ProtocolVersionUnknown)
            }
            Err(reason) => SignatureCheck::Rejected(reason),
        }
    }
}

/// Why a ledger does not fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FoldError {
    /// The stored genesis does not open the ledger (P-100).
    #[error("the stored genesis does not open the ledger")]
    Genesis,
    /// A stored entry does not verify along the chain (P-11).
    #[error("stored entry {0} does not verify")]
    Entry(u64),
    /// The kernel's fold refused the sequence.
    #[error("the fold refused the ledger: {0}")]
    Derive(&'static str),
}

/// A ledger read back from its log and verified: its record entries in order up to the first
/// one the fold cannot read, its version activations, the conflict areas its records left and
/// its head.
#[derive(Clone, Debug)]
pub struct Folded {
    ledger: LedgerId,
    verified: Vec<VerifiedEntry>,
    activations: Vec<(u64, ProtocolVersion)>,
    areas: Areas,
    head: u64,
    head_at: u64,
}

fn recorded_at(envelope: &[u8]) -> Option<u64> {
    match decode_envelope(envelope).ok()? {
        Envelope::Genesis(g) => Some(g.recorded_at.0),
        Envelope::Activation(a) => Some(a.recorded_at.0),
        Envelope::Ledger(l) => Some(l.recorded_at.0),
    }
}

/// Verifies the stored entries of `ledger` from its genesis on, in position order.
///
/// # Errors
/// [`FoldError::Genesis`] for a first entry that is not the ledger's genesis,
/// [`FoldError::Entry`] for an entry that does not continue the chain.
pub fn fold(ledger: &LedgerId, stored: &[StoredLogEntry]) -> Result<Folded, FoldError> {
    let first = stored.first().ok_or(FoldError::Genesis)?;
    let Ok(Envelope::Genesis(genesis)) = decode_envelope(&first.record_bytes) else {
        return Err(FoldError::Genesis);
    };
    let mut at = ChainPoint::genesis(&first.record_bytes).map_err(|_| FoldError::Genesis)?;
    if first.pos != 0 || at.ledger != *ledger {
        return Err(FoldError::Genesis);
    }
    let mut folded = Folded {
        ledger: *ledger,
        verified: Vec::new(),
        activations: vec![(0, genesis.versions.protocol)],
        areas: Areas::default(),
        head: 0,
        head_at: genesis.recorded_at.0,
    };
    let mut open = true;
    for e in stored.iter().skip(1) {
        folded.areas.replay(&e.record_bytes);
        folded.head = e.pos;
        folded.head_at = recorded_at(&e.envelope_bytes).ok_or(FoldError::Entry(e.pos))?;
        let entry = StoredEntry {
            envelope: &e.envelope_bytes,
            record: &e.record_bytes,
            cose_sign1: e.cose_sign1.as_deref(),
        };
        match verify_entry(&Admitted, &at, &entry) {
            Ok(v) => {
                at = v.next();
                match v {
                    Verified::Activation(a) => folded
                        .activations
                        .push((e.pos, a.envelope().activation.protocol)),
                    Verified::Record(r) if open => folded.verified.push(r),
                    Verified::Record(_) => {}
                }
            }
            Err(_)
                if matches!(
                    decode_record(&e.record_bytes),
                    Ok(Decoded::UnknownProtocol(_))
                ) =>
            {
                open = false;
                at = ChainPoint {
                    ledger: at.ledger,
                    prev: leaf_hash(&e.envelope_bytes),
                };
            }
            Err(_) => return Err(FoldError::Entry(e.pos)),
        }
    }
    Ok(folded)
}

/// One record a caller asks to write, with the facts its validity needs besides its bytes
/// (CM-19).
#[derive(Clone, Copy, Debug)]
pub struct Asked<'r> {
    /// The record.
    pub record: &'r Record,
    /// Its identifier.
    pub id: RecordId,
    /// The author's Access actor type.
    pub author_actor: ActorType,
    /// Whether the author's Access authentication carries a step-up.
    pub step_up: bool,
    /// Whether a side of the commitment is an agent (CM-7).
    pub agent_side: bool,
    /// The ledger time the write takes.
    pub now_ms: u64,
}

/// The facts the commitment rules read besides the records: no Condition is met until the
/// Condition lifecycle derives one, the policy inputs are the defaults and no budget is
/// exhausted until a budget is derived (P-31).
#[must_use]
pub fn facts() -> Facts<'static> {
    Facts::default()
}

impl Folded {
    /// The ledger.
    #[must_use]
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }

    /// The last position and its ledger time.
    #[must_use]
    pub const fn head(&self) -> (u64, u64) {
        (self.head, self.head_at)
    }

    /// The conflict areas the records left (T-89).
    #[must_use]
    pub const fn areas(&self) -> &Areas {
        &self.areas
    }

    /// The conflict area of the record a continuation names first, if it touched one.
    #[must_use]
    pub fn area_for(&self, record: &Record) -> Option<Area> {
        record
            .supersedes()
            .next()
            .and_then(|t| self.areas.area_of(t))
    }

    /// The ledger position of the record `id`, when the fold reads it.
    #[must_use]
    pub fn position_of(&self, id: &RecordId) -> Option<u64> {
        self.entries()
            .iter()
            .find(|e| e.id() == *id)
            .map(Entry::position)
    }

    /// The stored version of the Commitment `root` opened, 0 before its request.
    #[must_use]
    pub fn version_of(&self, root: RecordId) -> u64 {
        self.areas.version(&ItemKey::Commitment(root))
    }

    fn entries(&self) -> Vec<Entry<'_>> {
        self.verified
            .iter()
            .map_while(|r| Entry::verified(r, Restriction::NoObjection, AuthorityIssuer::Local))
            .collect()
    }

    fn inputs(&self) -> DerivationInputs<'_> {
        DerivationInputs {
            activations: &self.activations,
            profile: ProfileVersion(1),
            practices: &[],
            trust: TrustInputs {
                trusted_publishers: &[],
            },
            ledger_time: Time(self.head_at),
            calendar: BusinessCalendar::Continuous,
        }
    }

    /// Every commitment of the ledger, as its records derive it (CM-2).
    ///
    /// # Errors
    /// [`FoldError::Derive`] when the kernel refuses the sequence.
    pub fn views(&self, facts: &Facts<'_>) -> Result<Vec<CommitmentView>, FoldError> {
        self.derived(facts).map(|(_, views)| views)
    }

    fn derived(
        &self,
        facts: &Facts<'_>,
    ) -> Result<(Vec<Entry<'_>>, Vec<CommitmentView>), FoldError> {
        let entries = self.entries();
        let derivation =
            derive(&entries, &self.inputs()).map_err(|e| FoldError::Derive(e.code()))?;
        let views = commitment::derive_commitments(&entries, &derivation, facts);
        Ok((entries, views))
    }

    /// The clock, periodic and budget Condition records of the commitment `root` and of the commitments that support it, each with its position, whose `definition` part its read opens (CM-48, CM-50, CM-53).
    ///
    /// # Errors
    /// [`FoldError::Derive`] when the kernel refuses the sequence.
    pub fn definition_positions(&self, root: &RecordId) -> Result<Vec<(RecordId, u64)>, FoldError> {
        let (entries, views) = self.derived(&facts())?;
        let Some(view) = views.iter().find(|v| v.root == *root) else {
            return Ok(Vec::new());
        };
        let none: BTreeMap<RecordId, Vec<u8>> = BTreeMap::new();
        Ok(definition_records(
            view,
            &TimeInputs {
                entries: &entries,
                views: &views,
                definitions: &none,
                zones: &[],
                now: Time(self.head_at),
            },
        ))
    }

    /// The ends of `commitment.active` `asked` gives once it is written, with the commitment
    /// they end, its `request` (E-8, E-12): those the commitment fold derives for it when it
    /// is applied after the head; none for a record that continues no commitment.
    ///
    /// # Errors
    /// [`FoldError::Derive`] when the kernel refuses the sequence.
    pub fn ends(
        &self,
        asked: &Asked<'_>,
        facts: &Facts<'_>,
    ) -> Result<Option<(RecordId, Vec<ActiveEnd>)>, FoldError> {
        let entries = self.entries();
        let derivation =
            derive(&entries, &self.inputs()).map_err(|e| FoldError::Derive(e.code()))?;
        let views = commitment::derive_commitments(&entries, &derivation, facts);
        let records: BTreeMap<RecordId, &Record> =
            entries.iter().map(|e| (e.id(), e.record())).collect();
        let Some(view) = asked
            .record
            .supersedes()
            .next()
            .and_then(|t| commitment_of(&views, t))
        else {
            return Ok(None);
        };
        let ends = commitment::active_ends_of(view, &self.proposed(asked), &records, facts);
        Ok(Some((view.root, ends)))
    }

    fn proposed<'r>(&self, asked: &Asked<'r>) -> Proposed<'r> {
        Proposed {
            id: asked.id,
            record: asked.record,
            position: self.head.saturating_add(1),
            recorded_at: Time(asked.now_ms.max(self.head_at)),
            author_actor: asked.author_actor,
            step_up: asked.step_up,
            access: AccessAnswer::Allow,
            agent_side: asked.agent_side,
            control_supported: false,
        }
    }

    /// The kernel's validity check of `asked` against the commitment its chain derives (CM-19):
    /// the operation, or the refusal that keeps it out of the ledger. The write has already
    /// been allowed by Access for the operation's action, so Access's answer is an allow, and
    /// a step-up is the authentication context's own.
    ///
    /// # Errors
    /// [`FoldError::Derive`] when the kernel refuses the sequence.
    pub fn check(
        &self,
        asked: &Asked<'_>,
        facts: &Facts<'_>,
    ) -> Result<Result<Operation, Refusal>, FoldError> {
        let entries = self.entries();
        let derivation =
            derive(&entries, &self.inputs()).map_err(|e| FoldError::Derive(e.code()))?;
        let views = commitment::derive_commitments(&entries, &derivation, facts);
        let records: BTreeMap<RecordId, &Record> =
            entries.iter().map(|e| (e.id(), e.record())).collect();
        let view = asked
            .record
            .supersedes()
            .next()
            .and_then(|t| commitment_of(&views, t));
        Ok(commitment::check(
            view,
            &self.proposed(asked),
            &records,
            facts,
        ))
    }
}

/// The commitment `record` opened or continues among `views`.
#[must_use]
pub fn commitment_of<'v>(
    views: &'v [CommitmentView],
    record: &RecordId,
) -> Option<&'v CommitmentView> {
    views
        .iter()
        .find(|v| v.root == *record || v.steps.iter().any(|s| s.record == *record))
}

/// Whether `party` holds a role on `view`, so it may read it (P-56): the obligee, the obligor,
/// the acceptor, a principal, the requester's chain or the Party a pending delegation or
/// assignment proposes.
#[must_use]
pub fn involves(view: &CommitmentView, party: &PartyRef) -> bool {
    let obligor = matches!(&view.obligor, Obligor::Party(p) if p == party);
    let proposed = [&view.pending.delegation, &view.pending.transfer]
        .into_iter()
        .flatten()
        .any(|p| &p.to == party);
    obligor
        || proposed
        || &view.obligee == party
        || &view.acceptor == party
        || view.principal.contains(party)
        || view.requester.contains(party)
        || view.active_ends.iter().any(|e| &e.obligor == party)
}

/// What a caller may do next on one commitment and who holds the next move (P-55, CM-58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Next {
    /// The transitions the caller may make now; Access decides each at the write, so each one
    /// still needs its Exercise.
    pub allowed: Vec<Allowed>,
    /// Who holds the next move.
    pub moves: Vec<Mover>,
}

/// The transitions `caller` may make on `view` now and who holds the next move (P-55, CM-58):
/// Access is asked for each one only when it is written, so its answer here is `require`.
#[must_use]
pub fn next_for(view: &CommitmentView, caller: &Asking<'_>, facts: &Facts<'_>) -> Next {
    Next {
        allowed: commitment::allowed(view, caller, &[], &|_| AccessAnswer::Require),
        moves: commitment::next_moves(view, facts),
    }
}

/// One commitment as a caller may read it, derived from the records at the ledger's head
/// (CM-2, CM-19, P-55, CM-58, CM-41, CM-47).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentRead {
    /// The ledger.
    pub ledger: LedgerId,
    /// The commitment as its records derive it.
    pub view: CommitmentView,
    /// The version of its conflict area, its `ETag`.
    pub version: u64,
    /// What the caller may do next and who holds the next move.
    pub next: Next,
    /// How the implicit acceptance of the statement in force stands at the head's ledger time.
    pub implicit: ImplicitAcceptance,
    /// The signals the commitments that support it raise for it, their clocks and periodic updates included (CM-47).
    pub signals: Vec<SupportSignal>,
    /// Its clocks, periodic updates and budgets at the evaluation time (CM-48, CM-50, CM-53).
    pub time: TimeProjection,
    /// The tzdb release the clocks and periodic updates count in (CM-64).
    pub tzdb: &'static str,
    /// The evaluation time of the time projection, never before the head's ledger time.
    pub evaluated_at_ms: u64,
    /// The ledger time the read reflects.
    pub at_ms: u64,
    /// The position the read reflects.
    pub position: PositionToken,
}

/// What a commitment read evaluates besides the records: the opened `definition` parts of its time Conditions and the evaluation time.
#[derive(Clone, Copy, Debug)]
pub struct Evaluation<'a> {
    /// The `definition` part of each Condition record [`Folded::definition_positions`] named, as opened.
    pub definitions: &'a BTreeMap<RecordId, Vec<u8>>,
    /// The evaluation time, Unix milliseconds; the head's ledger time when it is earlier.
    pub now_ms: u64,
}

/// The read of the commitment `root` of `folded` for `caller`, a Party of `actor` type (P-56,
/// P-55): a caller without a role on it does not see it. Its clocks, periodic updates and budgets
/// are projected at the evaluation time over the vendored tzdb zones; a sub-commitment's clock
/// warning, breach or missed report joins its support signals (CM-47), and an exhausted budget
/// hands the next move to the accountable Party (CM-49).
///
/// # Errors
/// [`ReadRefusal::NotFound`] for no such commitment or one the caller has no role on,
/// [`ReadRefusal::Unavailable`] when the ledger does not fold.
pub fn read(
    folded: &Folded,
    root: &RecordId,
    party: &PartyRef,
    actor: ActorType,
    position: PositionToken,
    evaluation: Evaluation<'_>,
) -> Result<CommitmentRead, ReadRefusal> {
    let base = facts();
    let (entries, views) = folded
        .derived(&base)
        .map_err(|_| ReadRefusal::Unavailable)?;
    let view = views
        .iter()
        .find(|v| v.root == *root && v.opening == StepOutcome::Applied)
        .filter(|v| involves(v, party))
        .ok_or(ReadRefusal::NotFound)?;
    let children: Vec<CommitmentView> = views
        .iter()
        .filter(|c| c.supports.contains(root))
        .cloned()
        .collect();
    let (_, at_ms) = folded.head();
    let now = Time(evaluation.now_ms.max(at_ms));
    let blank = TimeInputs {
        entries: &entries,
        views: &views,
        definitions: evaluation.definitions,
        zones: &[],
        now,
    };
    let zones = tzdb::zones(&zones_named(view, &blank));
    let inputs = TimeInputs {
        zones: &zones,
        ..blank
    };
    let time = project_time(view, &inputs);
    let child_times: Vec<TimeProjection> =
        children.iter().map(|c| project_time(c, &inputs)).collect();
    let pairs: Vec<(&CommitmentView, &TimeProjection)> =
        children.iter().zip(&child_times).collect();
    let mut signals = commitment::support_signals(view, &children);
    signals.extend(clock_signals(view, &pairs));
    let decided = Facts {
        budget_exhausted: time.budget_exhausted(),
        ..base
    };
    let asking = Asking {
        party,
        actor,
        step_up: false,
    };
    Ok(CommitmentRead {
        ledger: *folded.ledger(),
        next: next_for(view, &asking, &decided),
        implicit: commitment::implicit_acceptance(view, Time(at_ms), &base),
        signals,
        time,
        tzdb: tzdb::VERSION,
        evaluated_at_ms: now.0,
        version: folded.version_of(*root),
        view: view.clone(),
        at_ms,
        position,
    })
}

/// The stored entries a fold reads at a time.
pub const LOG_PAGE: u32 = 1024;

#[cfg(test)]
mod tests;

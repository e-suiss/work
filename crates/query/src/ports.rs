//! What the API layer asks of the query service (T-32): the caller of a request from its Access token, the scoped reads and the consequential writes, and what the write path asks of the ledgers' writers and of their body store; all object-safe, so the router holds them without knowing the transport, the clock or the pool behind them.

use std::future::Future;
use std::pin::Pin;

use work_kernel::id::{LedgerId, PartyRef, RecordId, WorkId};
use work_proto::id::{Cursor, PositionToken};

use crate::domain::authority::{ApprovalReturned, AuthorityAnswer, AuthorityAsk};
use crate::domain::caller::{Caller, CallerRefusal, Presented};
use crate::domain::commitments::CommitmentRead;
use crate::domain::reads::{Changes, Deliveries, Evidence, ReadRefusal, WorkView};
use crate::domain::responsibility::{QueueRead, WorkloadRead};
use crate::domain::writes::{DeclarationRequest, WriteRefusal, Written};

/// A future the API layer awaits.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Names the caller of a request (C-9, E-7, SEC-18).
pub trait Authenticate: Send + Sync {
    /// The caller `presented` names, or why it names none.
    fn authenticate<'a>(
        &'a self,
        presented: Presented<'a>,
    ) -> Pending<'a, Result<Caller, CallerRefusal>>;
}

/// The reads scoped to their caller (P-56, T-13, P-57, P-20).
pub trait WorkReads: Send + Sync {
    /// `work` of `ledger` as `caller` may read it; `min` is a `Work-Min-Position` token.
    fn work<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        work: &'a WorkId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<WorkView, ReadRefusal>>;

    /// The Works of `ledger` visible to `caller` that changed after `cursor`, at most `limit`.
    fn changes<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        cursor: Option<&'a Cursor>,
        limit: u32,
    ) -> Pending<'a, Result<Changes, ReadRefusal>>;

    /// The evidence of `record` of `ledger`, each kind apart.
    fn evidence<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        record: &'a RecordId,
    ) -> Pending<'a, Result<Evidence, ReadRefusal>>;

    /// The commitment of `ledger` its `request` `root` opened, as `caller` may read it (CM-2,
    /// CM-19, P-55, P-56); `min` is a `Work-Min-Position` token.
    fn commitment<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        root: &'a RecordId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<CommitmentRead, ReadRefusal>>;

    /// The deliveries of `ledger` addressed to `caller` after the sequence number `after`,
    /// oldest first; with none, waits up to `wait_s` seconds for one (RC-42, T-105).
    fn deliveries<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        after: u64,
        wait_s: u32,
    ) -> Pending<'a, Result<Deliveries, ReadRefusal>>;
    /// The queue `queue` of `ledger`, by the root of its definition chain, as `caller` may read
    /// it (RC-10…RC-14, RC-24); `min` is a `Work-Min-Position` token.
    fn queue<'a>(
        queue: &'a RecordId,
        min: Option<&'a PositionToken>,
    ) -> Pending<'a, Result<QueueRead, ReadRefusal>>;

    /// The open workload of `party` in `ledger` as `caller` may read it (RC-24); `min` is a
    /// `Work-Min-Position` token.
    fn workload<'a>(
        party: &'a PartyRef,
    ) -> Pending<'a, Result<WorkloadRead, ReadRefusal>>;
}

/// The consequential writes of a named caller (P-13, P-21, E-45).
pub trait RecordWrites: Send + Sync {
    /// Writes the commitment Declaration `request` carries into `ledger` for `caller`.
    fn declare<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        request: &'a DeclarationRequest,
    ) -> Pending<'a, Result<Written, WriteRefusal>>;
}

/// What a caller asks Work's PEP to commit at Access before a write (T-101 item 2, E-17).
pub trait AuthorityRequests: Send + Sync {
    /// Commits `ask` for `caller` over `ledger` and answers what Access decided.
    fn request<'a>(
        &'a self,
        caller: &'a Caller,
        ledger: &'a LedgerId,
        ask: &'a AuthorityAsk,
    ) -> Pending<'a, Result<AuthorityAnswer, WriteRefusal>>;

    /// Reads the redirect `query` the Approval Surface sent back for `caller` (T-101 item 7): the
    /// `state` Work issued, used once, and the contribution Exercise Access confirms.
    fn approval<'a>(
        &'a self,
        caller: &'a Caller,
        query: &'a str,
    ) -> Pending<'a, Result<ApprovalReturned, WriteRefusal>>;
}

/// The writer of the ledgers this process leads (OP-31, OP-41).
pub trait Sequence: Send + Sync {
    /// Commits the admitted `record` to `ledger`.
    fn submit<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        record: work_ledger::PendingRecord,
    ) -> Pending<'a, Result<work_ledger::Committed, work_ledger::SubmitError>>;

    /// Keeps the refusal of the request `claim` names in `ledger` with its protocol `reason`
    /// at ledger time `at_ms` (CM-19, OP-8).
    fn reject<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        claim: &'a work_ledger::KeyClaim,
        reason: &'a str,
        at_ms: u64,
    ) -> Pending<'a, Result<(), work_ledger::LedgerError>>;
}

/// The body store of the ledgers (OP-45, OP-13, P-68): seals the openings of a record before
/// its writer commits it, and opens the parts of a written record.
pub trait Bodies: Send + Sync {
    /// Seals `openings` into the encrypted parts of the admitted `record` of `ledger` at ledger
    /// time `now_ms`, after the secret scan (SEC-35 item 2); the parts commit with the record.
    fn seal<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        record: &'a mut work_ledger::PendingRecord,
        openings: &'a [work_ledger::BodyOpening],
        now_ms: u64,
    ) -> Pending<'a, Result<(), work_ledger::BodyError>>;

    /// The parts of the record at `pos` of `ledger` in part order at ledger time `now_ms`,
    /// each readable with its checked content or unreadable once its keys are gone (OP-45
    /// item 5, OP-12 item 3).
    fn parts<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        pos: u64,
        now_ms: u64,
    ) -> Pending<'a, Result<Vec<(String, work_ledger::PartRead)>, work_ledger::BodyError>>;
}

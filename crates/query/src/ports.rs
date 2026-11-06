//! What the API layer asks of the query service (T-32): the caller of a request from its Access token, the scoped reads and the consequential writes, and what the write path asks of the ledgers' writers; all object-safe, so the router holds them without knowing the transport, the clock or the pool behind them.

use std::future::Future;
use std::pin::Pin;

use work_kernel::id::{LedgerId, RecordId, WorkId};
use work_proto::id::{Cursor, PositionToken};

use crate::domain::caller::{Caller, CallerRefusal, Presented};
use crate::domain::reads::{Changes, Evidence, ReadRefusal, WorkView};
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

/// The writer of the ledgers this process leads (OP-31, OP-41).
pub trait Sequence: Send + Sync {
    /// Commits the admitted `record` to `ledger`.
    fn submit<'a>(
        &'a self,
        ledger: &'a work_store::LedgerId,
        record: work_ledger::PendingRecord,
    ) -> Pending<'a, Result<work_ledger::Committed, work_ledger::SubmitError>>;
}

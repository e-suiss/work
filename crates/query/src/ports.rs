//! What the API layer asks of the query service (T-32): the caller of a request from its Access token, and the scoped reads; both object-safe, so the router holds them without knowing the transport, the clock or the pool behind them.

use std::future::Future;
use std::pin::Pin;

use work_kernel::id::{LedgerId, RecordId, WorkId};
use work_proto::id::{Cursor, PositionToken};

use crate::domain::caller::{Caller, CallerRefusal, Presented};
use crate::domain::reads::{Changes, Evidence, ReadRefusal, WorkView};

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

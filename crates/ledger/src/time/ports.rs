//! Ports of the ledger time driver (T-32 rule 2): the monotonic clock, one Roughtime query and
//! the events the NTS adapter sends on a bounded channel.

use std::future::Future;

use crate::time::domain::{NtsSample, RoughtimeAnswer};

/// The monotonic clock; the only clock the driver reads besides its time sources (OP-6).
pub trait Monotonic: Send + Sync + 'static {
    /// Milliseconds since a fixed start of the process; never goes back.
    fn now_ms(&self) -> u64;
}

/// What an NTS source reports (OP-32 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtsEvent {
    /// A verified sample of source `source`.
    Sample {
        /// The configured index of the source.
        source: usize,
        /// The sample.
        sample: NtsSample,
    },
    /// Source `source` lost its NTS session; its last sample is no longer used.
    Lost {
        /// The configured index of the source.
        source: usize,
    },
}

/// A Roughtime query failed: no answer, or an answer that did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct QueryError(pub String);

/// One query to one configured Roughtime server (OP-42 item 3).
pub trait RoughtimeQuery: Send + Sync + 'static {
    /// How many servers are configured.
    fn servers(&self) -> usize;

    /// Queries server `server` once and verifies its answer.
    fn query(
        &self,
        server: usize,
    ) -> impl Future<Output = Result<RoughtimeAnswer, QueryError>> + Send;
}

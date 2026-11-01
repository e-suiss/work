//! Ledger time (OP-6, OP-32, OP-42, OP-43, T-74): the `Clock` adapter that reads two or more NTS
//! servers and the monotonic clock, combines them with the shared `suiss-ledger` combiner and
//! bounds the result by an hourly Roughtime round over three or more servers.

mod adapters;
mod app;
mod domain;
mod ports;
mod wire;

pub use adapters::{
    NTS_KE_PORT, NTS_TIMEOUT, NtsServer, ProcessMonotonic, ROUGHTIME_TIMEOUT, RoughtimeServer,
    RoughtimeUdp, read_roots, spawn_nts,
};
pub use app::{LedgerTime, NTS_EVENT_QUEUE, ROUGHTIME_INTERVAL, TimeConfigError, check_sources};
pub use domain::{
    Discipline, MIN_NTS_SERVERS, MIN_ROUGHTIME_SERVERS, NTS_INTERVAL_MS, NtsSample,
    RoughtimeAnswer, Round, SAMPLE_LIFETIME_MS, TimeFault, majority_covers,
};
pub use ports::{Monotonic, NtsEvent, QueryError, RoughtimeQuery};
pub use wire::Version as RoughtimeVersion;

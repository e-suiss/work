//! I/O of the ledger time driver (T-32 rule 1, T-74): the monotonic clock, the NTS client and
//! the Roughtime client.

mod mono;
mod nts;
mod roughtime;

pub use mono::ProcessMonotonic;
pub use nts::{NTS_KE_PORT, NTS_TIMEOUT, NtsServer, read_roots, spawn_nts};
pub use roughtime::{ROUGHTIME_TIMEOUT, RoughtimeServer, RoughtimeUdp};

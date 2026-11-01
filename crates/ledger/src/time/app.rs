//! The ledger time driver (OP-32, OP-42, OP-43): it gives the `Clock` port its time from the
//! shared state, applies the NTS adapter's events, runs a Roughtime round at start-up and every
//! hour, and raises the alarms; a failed round never blocks start-up or commits on NTS.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::time::domain::{Discipline, MIN_NTS_SERVERS, MIN_ROUGHTIME_SERVERS, Round, TimeFault};
use crate::time::ports::{Monotonic, NtsEvent, RoughtimeQuery};
use crate::{Clock, ClockError};

/// Roughtime query interval (OP-43 item 2, PD).
pub const ROUGHTIME_INTERVAL: Duration = Duration::from_secs(3600);

/// Pending NTS events between the adapter and the driver (T-32 rule 7).
pub const NTS_EVENT_QUEUE: usize = 64;

/// A time source configuration that does not start (OP-32 item 4, OP-43 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeConfigError {
    /// Fewer than two NTS servers.
    #[error("{found} NTS servers configured; at least {MIN_NTS_SERVERS} are required (OP-32)")]
    TooFewNts {
        /// How many are configured.
        found: usize,
    },
    /// Fewer than three Roughtime servers.
    #[error(
        "{found} Roughtime servers configured; at least {MIN_ROUGHTIME_SERVERS} are required (OP-43)"
    )]
    TooFewRoughtime {
        /// How many are configured.
        found: usize,
    },
}

/// Refuses a configuration with fewer than two NTS or three Roughtime servers.
///
/// # Errors
/// [`TimeConfigError`].
pub const fn check_sources(nts: usize, roughtime: usize) -> Result<(), TimeConfigError> {
    if nts < MIN_NTS_SERVERS {
        return Err(TimeConfigError::TooFewNts { found: nts });
    }
    if roughtime < MIN_ROUGHTIME_SERVERS {
        return Err(TimeConfigError::TooFewRoughtime { found: roughtime });
    }
    Ok(())
}

/// Ledger time shared by the `Clock` port, the NTS events and the Roughtime rounds.
#[derive(Debug)]
pub struct LedgerTime<M> {
    state: Arc<Mutex<Discipline>>,
    mono: Arc<M>,
}

impl<M> Clone for LedgerTime<M> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            mono: Arc::clone(&self.mono),
        }
    }
}

impl<M: Monotonic> LedgerTime<M> {
    /// Ledger time over `nts` NTS sources and `roughtime` Roughtime servers.
    ///
    /// # Errors
    /// [`TimeConfigError`] below the required counts.
    pub fn new(nts: usize, roughtime: usize, mono: Arc<M>) -> Result<Self, TimeConfigError> {
        check_sources(nts, roughtime)?;
        Ok(Self {
            state: Arc::new(Mutex::new(Discipline::new(nts))),
            mono,
        })
    }

    fn state(&self) -> MutexGuard<'_, Discipline> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ledger time now, Unix milliseconds; a fault raises its alarm.
    ///
    /// # Errors
    /// [`TimeFault`]; nothing is committed.
    pub fn read(&self) -> Result<u64, TimeFault> {
        let mono = self.mono.now_ms();
        let read = self.state().now(mono);
        match read {
            Err(TimeFault::OutsideRoughtime) => tracing::error!(
                event = "ledger_time.outside_roughtime",
                "ledger time is outside the Roughtime bound; commits stop"
            ),
            Err(fault) => tracing::error!(
                event = "ledger_time.unavailable",
                %fault,
                "no trusted ledger time; commits stop"
            ),
            Ok(_) => {}
        }
        read
    }

    /// Applies one event of the NTS adapter.
    pub fn apply(&self, event: NtsEvent) {
        match event {
            NtsEvent::Sample { source, sample } => self.state().record_sample(source, sample),
            NtsEvent::Lost { source } => {
                tracing::warn!(event = "ledger_time.nts_lost", source, "NTS source lost");
                self.state().lose_source(source);
            }
        }
    }

    /// Applies the NTS adapter's events until its senders are gone.
    pub async fn follow_nts(self, mut events: mpsc::Receiver<NtsEvent>) {
        while let Some(event) = events.recv().await {
            self.apply(event);
        }
    }

    /// Queries every configured Roughtime server once and puts the answers that verified in
    /// force (OP-43 items 1, 4).
    pub async fn round<Q: RoughtimeQuery>(&self, roughtime: &Q) -> Round {
        let servers = roughtime.servers();
        let mut answers = Vec::with_capacity(servers);
        for server in 0..servers {
            match roughtime.query(server).await {
                Ok(answer) => answers.push(answer),
                Err(error) => tracing::warn!(
                    event = "ledger_time.roughtime_failed",
                    server,
                    %error,
                    "Roughtime server did not give a verified answer"
                ),
            }
        }
        let round = self.state().record_round(answers);
        match round {
            Round::Answered(answered) => {
                tracing::info!(
                    event = "ledger_time.roughtime_round",
                    answered,
                    servers,
                    "Roughtime bound in force"
                );
                let mono = self.mono.now_ms();
                if self.state().now(mono) == Err(TimeFault::OutsideRoughtime) {
                    tracing::error!(
                        event = "ledger_time.outside_roughtime",
                        "ledger time is outside the Roughtime bound; commits stop"
                    );
                }
            }
            Round::Unanswered => tracing::warn!(
                event = "ledger_time.roughtime_unreachable",
                servers,
                "no Roughtime server answered; commits continue on NTS without the bound"
            ),
        }
        round
    }

    /// Runs a Roughtime round at once and then every [`ROUGHTIME_INTERVAL`].
    pub async fn run_roughtime<Q: RoughtimeQuery>(self, roughtime: Q) {
        let mut ticks = tokio::time::interval(ROUGHTIME_INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            self.round(&roughtime).await;
        }
    }
}

impl<M: Monotonic> Clock for LedgerTime<M> {
    async fn now(&mut self) -> Result<u64, ClockError> {
        self.read().map_err(|fault| ClockError(fault.to_string()))
    }
}

#[cfg(test)]
mod tests;

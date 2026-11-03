//! Use cases; one transaction each (T-32).

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::sync::watch;
use work_kernel::id::LedgerId;
use work_proto::position::{PositionError, Positions};

/// What a `Work-Min-Position` read sees after its bounded wait (T-97 item 3, T-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// The view reached every asked position; the positions are where it stands.
    Fresh(Positions),
    /// The wait ran out; the positions are where the view stands, and the answer is marked
    /// `freshness = "stale"`.
    Stale(Positions),
}

impl Freshness {
    /// The positions the answer reflects, for its `Work-Position` token.
    #[must_use]
    pub const fn positions(&self) -> &Positions {
        match self {
            Self::Fresh(p) | Self::Stale(p) => p,
        }
    }

    /// True when the wait ran out.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::Stale(_))
    }
}

fn standing(
    wanted: &Positions,
    view: &BTreeMap<LedgerId, u64>,
) -> Result<Positions, PositionError> {
    Positions::new(wanted.entries().map(|(ledger, _)| {
        let at = view.get(ledger).copied().unwrap_or_default();
        (*ledger, at)
    }))
}

/// Waits at most `wait` for the applied positions of the derived view, as its deriver publishes
/// them on `applied`, to reach `wanted` at every ledger (T-97 item 3). A view that does not
/// publish any more is answered at once, stale unless it already reached `wanted`.
///
/// # Errors
/// [`PositionError`] only for a `wanted` set that no token can carry.
pub async fn wait_for(
    wanted: &Positions,
    applied: &mut watch::Receiver<BTreeMap<LedgerId, u64>>,
    wait: Duration,
) -> Result<Freshness, PositionError> {
    let reached = tokio::time::timeout(wait, applied.wait_for(|view| wanted.reached_by(view)))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|view| standing(wanted, &view));
    if let Some(positions) = reached {
        return Ok(Freshness::Fresh(positions?));
    }
    let view = applied.borrow().clone();
    let positions = standing(wanted, &view)?;
    if wanted.reached_by(&view) {
        Ok(Freshness::Fresh(positions))
    } else {
        Ok(Freshness::Stale(positions))
    }
}

#[cfg(test)]
mod tests {
    use work_kernel::id::Digest;

    use super::*;

    fn ledger(byte: u8) -> LedgerId {
        LedgerId(Digest::sha256([byte; 32]))
    }

    // T-97
    #[tokio::test(start_paused = true)]
    async fn t_97_a_write_position_is_read_back_after_waiting() {
        let (deriver, mut applied) = watch::channel(BTreeMap::from([(ledger(1), 3)]));
        let wanted = Positions::new([(ledger(1), 5)]).unwrap();
        let publish = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            deriver.send_replace(BTreeMap::from([(ledger(1), 4)]));
            tokio::time::sleep(Duration::from_millis(300)).await;
            deriver.send_replace(BTreeMap::from([(ledger(1), 6), (ledger(2), 1)]));
            deriver
        });
        let fresh = wait_for(&wanted, &mut applied, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            fresh,
            Freshness::Fresh(Positions::new([(ledger(1), 6)]).unwrap())
        );
        assert!(!fresh.is_stale());
        drop(publish.await.unwrap());
    }

    // T-97
    #[tokio::test(start_paused = true)]
    async fn t_97_the_wait_is_capped_at_five_seconds_and_marked_stale() {
        let (deriver, mut applied) = watch::channel(BTreeMap::from([(ledger(1), 3)]));
        let wanted = Positions::new([(ledger(1), 5), (ledger(2), 1)]).unwrap();
        let cap = crate::domain::ReadWait::default().applied(Some(Duration::from_secs(30)));
        let started = tokio::time::Instant::now();
        let stale = wait_for(&wanted, &mut applied, cap).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert!(stale.is_stale());
        assert_eq!(
            stale.positions(),
            &Positions::new([(ledger(1), 3), (ledger(2), 0)]).unwrap()
        );
        drop(deriver);
        let gone = wait_for(&wanted, &mut applied, cap).await.unwrap();
        assert!(gone.is_stale());
        let reached = Positions::new([(ledger(1), 3)]).unwrap();
        assert!(
            !wait_for(&reached, &mut applied, cap)
                .await
                .unwrap()
                .is_stale()
        );
    }
}

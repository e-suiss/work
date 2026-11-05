//! Port implementations (T-32): Work's Access realm table and stream row in the canonical database, written as `work_access`, behind the pairing step's [`PairingStore`] port (T-103 item 5).

use work_access_client::domain::pairing::{PairState, RealmChange, RealmId, StoredRealm};
use work_access_client::domain::streams::StreamStatus;
use work_access_client::domain::{AccessError, b64url, fixed_b64url};
use work_access_client::ports::{PairingStore, StoredStream};
use work_proto::id::TenantId;
use work_store::{AccessPool, Pairing, RealmRow, RealmState, StoreError, StreamRow, StreamState};

/// Work's realm table and stream row in PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgPairing {
    pool: AccessPool,
}

impl PgPairing {
    /// Over a pool checked to act as `work_access`.
    #[must_use]
    pub const fn new(pool: AccessPool) -> Self {
        Self { pool }
    }
}

fn store(e: &StoreError) -> AccessError {
    AccessError::Transport(format!("store: {e}"))
}

fn stored(row: RealmRow) -> Result<StoredRealm, AccessError> {
    let state = match row.state {
        RealmState::Unpaired => PairState::Unpaired,
        RealmState::Paired => PairState::Paired,
        RealmState::Refused => PairState::Refused,
        RealmState::Retired => PairState::Retired,
    };
    Ok(StoredRealm {
        realm: RealmId::parse(&row.realm)?,
        state,
        kid: row.kid.as_deref().map(fixed_b64url::<32>).transpose()?,
    })
}

const fn status_of(state: StreamState) -> Option<StreamStatus> {
    match state {
        StreamState::Enabled => Some(StreamStatus::Enabled),
        StreamState::Paused => Some(StreamStatus::Paused),
        StreamState::Disabled => Some(StreamStatus::Disabled),
        StreamState::Unreachable => Some(StreamStatus::Unreachable),
        StreamState::Missing => None,
    }
}

const fn state_of(status: Option<StreamStatus>) -> StreamState {
    match status {
        Some(StreamStatus::Enabled) => StreamState::Enabled,
        Some(StreamStatus::Paused) => StreamState::Paused,
        Some(StreamStatus::Disabled) => StreamState::Disabled,
        Some(StreamStatus::Unreachable) => StreamState::Unreachable,
        None => StreamState::Missing,
    }
}

fn stream(row: StreamRow) -> StoredStream {
    StoredStream {
        id: row.stream_id,
        status: status_of(row.state),
        recreated: row.recreated,
    }
}

impl PairingStore for PgPairing {
    async fn realms(&self, tenant: &TenantId) -> Result<Vec<StoredRealm>, AccessError> {
        self.pool
            .realms(tenant.as_str())
            .await
            .map_err(|e| store(&e))?
            .into_iter()
            .map(stored)
            .collect()
    }

    async fn apply(
        &self,
        tenant: &TenantId,
        change: &RealmChange,
        at_ms: u64,
    ) -> Result<Option<u64>, AccessError> {
        let t = tenant.as_str();
        let p = &self.pool;
        let done = match change {
            RealmChange::Seen {
                realm,
                issuer,
                slug,
            } => p
                .seen(t, realm.as_str(), issuer, slug, at_ms)
                .await
                .map(|()| None),
            RealmChange::Retire { live } => {
                let live: Vec<String> = live.iter().map(|r| r.as_str().to_owned()).collect();
                p.retire_missing(t, &live, at_ms).await.map(|_| None)
            }
            RealmChange::Unpaired {
                realm,
                domain,
                party,
                kid,
            } => p
                .unpaired(t, realm.as_str(), domain, party, &b64url(kid), at_ms)
                .await
                .map(|_| None),
            RealmChange::Paired {
                realm,
                domain,
                party,
                instance,
                kid,
            } => {
                let pairing = Pairing {
                    party: *party,
                    instance: *instance,
                    kid: b64url(kid),
                };
                p.paired(t, realm.as_str(), domain.as_ref(), &pairing, at_ms)
                    .await
                    .map(|_| None)
            }
            RealmChange::Refused { realm, code } => p
                .refused(t, realm.as_str(), code, at_ms)
                .await
                .map(|_| None),
            RealmChange::Failed { realm } => p.count_failure(t, realm.as_str(), at_ms).await,
        };
        done.map_err(|e| store(&e))
    }

    async fn stalled(&self, runs: u64) -> Result<u64, AccessError> {
        self.pool.stalled(runs).await.map_err(|e| store(&e))
    }

    async fn stream(&self) -> Result<Option<StoredStream>, AccessError> {
        Ok(self.pool.stream().await.map_err(|e| store(&e))?.map(stream))
    }

    async fn record_stream(
        &self,
        id: Option<&str>,
        status: Option<StreamStatus>,
        recreated: bool,
        at_ms: u64,
    ) -> Result<StoredStream, AccessError> {
        self.pool
            .record_stream(id, state_of(status), recreated, at_ms)
            .await
            .map(stream)
            .map_err(|e| store(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-103
    #[test]
    fn t_103_stream_states_map_both_ways_and_missing_has_no_status() {
        for state in [
            StreamState::Enabled,
            StreamState::Paused,
            StreamState::Disabled,
            StreamState::Unreachable,
            StreamState::Missing,
        ] {
            assert_eq!(state_of(status_of(state)), state);
        }
        assert_eq!(status_of(StreamState::Missing), None);
        let row = RealmRow {
            tenant: "tnt_01".to_owned(),
            realm: "019a0000-0000-7000-8000-0000000000a1".to_owned(),
            issuer: "https://shop1.id.example".to_owned(),
            slug: "shop1".to_owned(),
            domain: None,
            party: None,
            instance: None,
            kid: Some(b64url(&[7; 32])),
            state: RealmState::Refused,
            refusal_code: Some("party-held".to_owned()),
            failed_runs: 1,
            paired_at_ms: None,
            updated_at_ms: 0,
        };
        let s = stored(row.clone()).unwrap();
        assert_eq!(
            (s.state, s.kid, s.realm.as_str()),
            (
                PairState::Refused,
                Some([7; 32]),
                "019a0000-0000-7000-8000-0000000000a1"
            )
        );
        let bad = RealmRow {
            kid: Some("short".to_owned()),
            ..row
        };
        assert!(stored(bad).is_err());
    }
}

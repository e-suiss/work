use work_store::{AccessPool, Pairing, RealmState, StoreError, StreamState};

use crate::env::{Env, fails};

const TENANT: &str = "tnt_01HZ";
const A: &str = "019a0000-0000-7000-8000-0000000000a1";
const B: &str = "019a0000-0000-7000-8000-0000000000a2";
const T0: u64 = 1_793_793_600_000;
const STREAM: &str = "6f1c2a4e-9b0d-4c3e-8a71-2d5f0e9b4c11";

fn at(ms: u64) -> u64 {
    T0.checked_add(ms).unwrap()
}

fn kid(byte: char) -> String {
    std::iter::repeat_n(byte, 43).collect()
}

async fn pool(env: &Env) -> AccessPool {
    AccessPool::new(env.canonical("work_access")).await.unwrap()
}

async fn two_realms(access: &AccessPool) {
    access
        .seen(TENANT, A, "https://shop1.id.example", "shop1", T0)
        .await
        .unwrap();
    access
        .seen(TENANT, B, "https://shop2.id.example", "shop2", T0)
        .await
        .unwrap();
}

// T-103
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_103_a_challenge_outcome_is_stored_and_failures_reset_when_paired() {
    let env = Env::start().await;
    let access = pool(&env).await;
    two_realms(&access).await;
    access
        .seen(TENANT, A, "https://renamed.id.example", "renamed", at(1))
        .await
        .unwrap();
    let row = access.realm(TENANT, A).await.unwrap().unwrap();
    assert_eq!(
        (row.state, row.slug.as_str(), row.domain, row.failed_runs),
        (RealmState::Unpaired, "shop1", None, 0)
    );
    assert!(
        access
            .unpaired(TENANT, A, &[1; 32], &[2; 16], &kid('k'), at(10))
            .await
            .unwrap()
    );
    assert_eq!(
        access.count_failure(TENANT, A, at(20)).await.unwrap(),
        Some(1)
    );
    assert_eq!(
        access.count_failure(TENANT, A, at(30)).await.unwrap(),
        Some(2)
    );
    assert_eq!(access.stalled(2).await.unwrap(), 1);
    assert_eq!(access.stalled(3).await.unwrap(), 0);
    let pairing = Pairing {
        party: [2; 16],
        instance: [3; 16],
        kid: kid('k'),
    };
    assert!(
        access
            .paired(TENANT, A, None, &pairing, at(40))
            .await
            .unwrap()
    );
    let row = access.realm(TENANT, A).await.unwrap().unwrap();
    assert_eq!(row.state, RealmState::Paired);
    assert_eq!(row.domain, Some([1; 32]));
    assert_eq!(row.instance, Some([3; 16]));
    assert_eq!(row.failed_runs, 0);
    assert_eq!(row.paired_at_ms, Some(at(40)));
    assert!(
        access
            .paired(TENANT, A, Some(&[1; 32]), &pairing, at(50))
            .await
            .unwrap()
    );
    let again = access.realm(TENANT, A).await.unwrap().unwrap();
    assert_eq!(again.paired_at_ms, Some(at(40)));
    assert_eq!(again.updated_at_ms, at(50));
    assert_eq!(
        access
            .realm_of_domain(&[1; 32])
            .await
            .unwrap()
            .map(|r| r.realm),
        Some(A.to_owned())
    );
    assert!(access.realm_of_domain(&[9; 32]).await.unwrap().is_none());
    assert!(
        access
            .refused(TENANT, B, "party-held", at(60))
            .await
            .unwrap()
    );
    assert_eq!(
        access.count_failure(TENANT, B, at(61)).await.unwrap(),
        Some(1)
    );
    assert!(access.reset_failures(TENANT, B, at(62)).await.unwrap());
    let refused = access.realm(TENANT, B).await.unwrap().unwrap();
    assert_eq!(refused.state, RealmState::Refused);
    assert_eq!(refused.refusal_code.as_deref(), Some("party-held"));
    assert_eq!(refused.failed_runs, 0);
    assert!(
        !access
            .refused(TENANT, "019a0000-0000-7000-8000-0000000000ff", "x", T0)
            .await
            .unwrap()
    );
    assert_eq!(
        access
            .count_failure(TENANT, "019a0000-0000-7000-8000-0000000000ff", T0)
            .await
            .unwrap(),
        None
    );
}

// T-103 P-115 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_103_a_realm_that_leaves_the_snapshot_is_retired() {
    let env = Env::start().await;
    let access = pool(&env).await;
    two_realms(&access).await;
    assert!(
        access
            .unpaired(TENANT, B, &[5; 32], &[2; 16], &kid('k'), at(1))
            .await
            .unwrap()
    );
    assert_eq!(
        access
            .retire_missing(TENANT, &[A.to_owned()], at(2))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        access
            .retire_missing(TENANT, &[A.to_owned()], at(3))
            .await
            .unwrap(),
        0
    );
    let rows = access.realms(TENANT).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (r.realm.as_str(), r.state))
            .collect::<Vec<_>>(),
        vec![(A, RealmState::Unpaired), (B, RealmState::Retired)]
    );
    assert!(access.realm_of_domain(&[5; 32]).await.unwrap().is_none());
    assert!(
        access
            .unpaired(TENANT, A, &[5; 32], &[2; 16], &kid('k'), at(4))
            .await
            .unwrap()
    );
    assert_eq!(access.stalled(0).await.unwrap(), 1);
}

// T-103 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_103_identity_and_domain_are_immutable_and_nothing_is_deleted() {
    let env = Env::start().await;
    let access = pool(&env).await;
    two_realms(&access).await;
    assert!(
        access
            .unpaired(TENANT, A, &[1; 32], &[2; 16], &kid('k'), at(1))
            .await
            .unwrap()
    );
    let writer = env.canonical("work_access");
    for (sql, code) in [
        ("UPDATE work.access_realm SET slug = 'other'", Some("23514")),
        (
            "UPDATE work.access_realm SET domain = decode(repeat('09', 32), 'hex') WHERE domain IS NOT NULL",
            Some("23514"),
        ),
        (
            "UPDATE work.access_realm SET updated_at = updated_at - interval '1 second'",
            Some("23514"),
        ),
        (
            "UPDATE work.access_realm SET state = 'paired'",
            Some("23514"),
        ),
        ("UPDATE work.access_realm SET kid = 'short'", Some("23514")),
        ("DELETE FROM work.access_realm", Some("42501")),
        ("TRUNCATE work.access_realm", Some("42501")),
        ("DELETE FROM work.access_event_stream", Some("42501")),
    ] {
        fails(&writer, "", &[sql], code).await;
    }
    for role in ["work_owner", "work_app", "work_sequencer"] {
        fails(
            &env.canonical(role),
            "",
            &["DELETE FROM work.access_realm"],
            Some("42501"),
        )
        .await;
    }
    for role in ["work_app", "work_sequencer", "work_erasure"] {
        fails(
            &env.canonical(role),
            "",
            &["UPDATE work.access_realm SET failed_runs = 0"],
            Some("42501"),
        )
        .await;
    }
    assert!(matches!(
        AccessPool::new(env.canonical("work_app")).await,
        Err(StoreError::Role)
    ));
    let app = env.canonical("work_app");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM work.access_realm")
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

// T-103 T-102
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_103_the_stream_row_is_recorded_and_never_goes_back() {
    let env = Env::start().await;
    let access = pool(&env).await;
    assert_eq!(access.stream().await.unwrap(), None);
    let first = access
        .record_stream(Some(STREAM), StreamState::Enabled, false, T0)
        .await
        .unwrap();
    assert_eq!(
        (first.stream_id.as_deref(), first.state, first.recreated),
        (Some(STREAM), StreamState::Enabled, 0)
    );
    let missing = access
        .record_stream(None, StreamState::Missing, false, at(1))
        .await
        .unwrap();
    assert_eq!(
        (missing.stream_id, missing.state),
        (None, StreamState::Missing)
    );
    let reopened = access
        .record_stream(Some(STREAM), StreamState::Enabled, true, at(2))
        .await
        .unwrap();
    assert_eq!(reopened.recreated, 1);
    assert_eq!(reopened.checked_at_ms, at(2));
    let late = access
        .record_stream(Some(STREAM), StreamState::Paused, false, T0)
        .await
        .unwrap();
    assert_eq!(
        (late.state, late.checked_at_ms),
        (StreamState::Paused, at(2))
    );
    assert_eq!(access.stream().await.unwrap(), Some(late));
    assert!(
        access
            .record_stream(None, StreamState::Enabled, false, at(3))
            .await
            .is_err()
    );
    fails(
        &env.canonical("work_access"),
        "",
        &["UPDATE work.access_event_stream SET recreated = 0"],
        Some("23514"),
    )
    .await;
    fails(
        &env.canonical("work_access"),
        "",
        &["INSERT INTO work.access_event_stream (singleton, state, checked_at) VALUES (false, 'missing', now())"],
        Some("23514"),
    )
    .await;
}

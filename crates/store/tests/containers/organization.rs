use work_store::{AccessPool, OrganizationOrigin, OrganizationWrite};

use crate::env::{Env, fails};

const TENANT: &str = "tnt_01HZ";
const OTHER: &str = "tnt_02HZ";
const A: &str = "019a0000-0000-7000-8000-0000000000b1";
const B: &str = "019a0000-0000-7000-8000-0000000000b2";
const T0: u64 = 1_793_793_600_000;

fn at(ms: u64) -> u64 {
    T0.checked_add(ms).unwrap()
}

async fn pool(env: &Env) -> AccessPool {
    AccessPool::new(env.canonical("work_access")).await.unwrap()
}

// E-3
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn e_3_an_organization_is_mapped_once_and_moves_only_forward() {
    let env = Env::start().await;
    let access = pool(&env).await;
    assert_eq!(access.organizations(TENANT).await.unwrap(), Vec::new());
    assert_eq!(
        access
            .organization_event(TENANT, A, (42, 0), T0, at(5))
            .await
            .unwrap(),
        OrganizationWrite::Mapped
    );
    assert_eq!(
        access
            .organization_event(TENANT, A, (42, 0), T0, at(6))
            .await
            .unwrap(),
        OrganizationWrite::Stale
    );
    assert_eq!(
        access
            .organization_event(TENANT, A, (42, 1), at(1), at(7))
            .await
            .unwrap(),
        OrganizationWrite::Moved
    );
    assert_eq!(
        access
            .organization_event(TENANT, A, (41, 9), at(2), at(8))
            .await
            .unwrap(),
        OrganizationWrite::Stale
    );
    assert!(access.organization_listed(TENANT, B, at(9)).await.unwrap());
    assert!(!access.organization_listed(TENANT, B, at(10)).await.unwrap());
    assert!(!access.organization_listed(TENANT, A, at(10)).await.unwrap());
    assert_eq!(
        access
            .organization_event(TENANT, B, (50, 0), at(3), at(11))
            .await
            .unwrap(),
        OrganizationWrite::Moved
    );
    let rows = access.organizations(TENANT).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (
                r.organization.as_str(),
                r.origin,
                r.position,
                r.changed_at_ms,
                r.mapped_at_ms,
                r.updated_at_ms
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                A,
                OrganizationOrigin::Event,
                Some((42, 1)),
                Some(at(1)),
                at(5),
                at(7)
            ),
            (
                B,
                OrganizationOrigin::Snapshot,
                Some((50, 0)),
                Some(at(3)),
                at(9),
                at(11)
            ),
        ]
    );
    assert!(access.organization_listed(OTHER, A, at(12)).await.unwrap());
    assert_eq!(access.organizations(OTHER).await.unwrap().len(), 1);
    assert_eq!(access.organizations(TENANT).await.unwrap().len(), 2);
}

// E-3 Access OP-73
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn e_3_a_mapped_organization_keeps_its_identity_and_is_never_deleted() {
    let env = Env::start().await;
    let access = pool(&env).await;
    assert_eq!(
        access
            .organization_event(TENANT, A, (42, 0), T0, at(5))
            .await
            .unwrap(),
        OrganizationWrite::Mapped
    );
    assert!(
        access
            .organization_listed(TENANT, "not-a-uuid", at(6))
            .await
            .is_err()
    );
    assert!(access.organization_listed("acme", B, at(6)).await.is_err());
    let writer = env.canonical("work_access");
    for (sql, code) in [
        (
            "UPDATE work.access_organization SET tenant = 'tnt_other'",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET origin = 'snapshot'",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET mapped_at = mapped_at - interval '1 second'",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET updated_at = updated_at - interval '1 millisecond'",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET access_pos = 41",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET access_pos = NULL, access_idx = NULL",
            Some("23514"),
        ),
        (
            "UPDATE work.access_organization SET access_idx = NULL",
            Some("23514"),
        ),
        ("DELETE FROM work.access_organization", Some("42501")),
        ("TRUNCATE work.access_organization", Some("42501")),
    ] {
        fails(&writer, "", &[sql], code).await;
    }
    for role in ["work_owner", "work_app", "work_sequencer"] {
        fails(
            &env.canonical(role),
            "",
            &["DELETE FROM work.access_organization"],
            Some("42501"),
        )
        .await;
    }
    for role in ["work_app", "work_sequencer", "work_erasure"] {
        fails(
            &env.canonical(role),
            "",
            &["UPDATE work.access_organization SET access_pos = 99"],
            Some("42501"),
        )
        .await;
    }
    let app = env.canonical("work_app");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM work.access_organization")
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

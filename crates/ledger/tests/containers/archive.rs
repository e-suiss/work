//! The cold archive against real PostgreSQL 18 and versitygw with S3 Object Lock (OP-35, OP-34,
//! OP-37, OP-12): a cold partition is dropped only after every ledger's slice is copied once,
//! read back and found locked, and recorded; a copy the bucket already holds with other bytes
//! stops the archive and the partition stays.

use suiss_crypto::secret::Secret;
use work_ledger::{
    ArchiveError, Retention, S3Config, WormError, WormStore, archive_key, archive_manifest,
    archive_partition,
};
use work_store::{ArchivePool, ArchiveRecord, Cluster, LedgerId, StoreError};
use work_testkit::{S3, S3_KEY_ID, S3_SECRET};

use crate::{Env, statement};

const SEED: &str = include_str!("../../../store/fixtures/archive-seed.sql");

// OP-35 OP-34 OP-12 OP-37 OP-38
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_35_a_cold_partition_is_dropped_only_after_its_worm_copy_verifies() {
    let env = Env::start().await;
    let s3 = S3::start().await.unwrap();
    env.pg
        .client(&[
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            Cluster::Canonical.database(),
            "-c",
            &statement(SEED),
        ])
        .await
        .unwrap();
    let pool = ArchivePool::new(env.pool(Cluster::Canonical, "work_archive"))
        .await
        .unwrap();
    let now = pool.now_ms().await.unwrap();
    let store = WormStore::new(
        S3Config {
            endpoint: s3.endpoint().to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "work-archive".to_owned(),
            key_id: S3_KEY_ID.to_owned(),
            secret: Secret::new(S3_SECRET.to_owned()),
            tls: None,
        },
        Retention::days(1).unwrap(),
    )
    .unwrap();
    store.prepare(now).await.unwrap();
    let a = LedgerId::from_bytes([0xa1; 32]);
    let b = LedgerId::from_bytes([0xb2; 32]);
    let mut keys = None;
    let mut inbound = None;
    for part in pool.cold_partitions().await.unwrap() {
        let ledgers = pool.ledgers(&part).await.unwrap();
        if part.starts_with("work.idempotency_key_p") && ledgers == [a, b] {
            keys = Some(part);
        } else if part.starts_with("work.inbound_seen_p") && ledgers == [a] {
            inbound = Some(part);
        }
    }
    let (keys, inbound) = (keys.unwrap(), inbound.unwrap());

    let slice_a = pool.slice(&keys, &a).await.unwrap();
    let slice_b = pool.slice(&keys, &b).await.unwrap();
    assert_eq!((slice_a.row_count, slice_b.row_count), (3, 3));
    let manifest = archive_manifest(&[(a, 3, slice_a.digest), (b, 3, slice_b.digest)]);
    assert!(matches!(
        pool.drop_partition(&keys, &manifest).await,
        Err(StoreError::Constraint(m)) if m == "archive_record_missing"
    ));
    assert!(matches!(
        pool.drop_partition(&keys, &[0; 32]).await,
        Err(StoreError::Constraint(m)) if m == "archive_manifest_mismatch"
    ));

    let planted = archive_key(&inbound, &a);
    store
        .put_once(&planted, b"not the slice", now)
        .await
        .unwrap();
    assert!(matches!(
        archive_partition(&pool, &store, &inbound).await,
        Err(ArchiveError::Worm(WormError::Diverged(k))) if k == planted
    ));
    assert_eq!(pool.archived(&inbound, &a).await.unwrap(), None);
    assert!(pool.cold_partitions().await.unwrap().contains(&inbound));

    assert_eq!(archive_partition(&pool, &store, &keys).await.unwrap(), 6);
    assert!(!pool.cold_partitions().await.unwrap().contains(&keys));
    for (ledger, slice) in [(a, &slice_a), (b, &slice_b)] {
        let key = archive_key(&keys, &ledger);
        assert_eq!(
            store.get(&key, now).await.unwrap(),
            Some(slice.rows.join("\n").into_bytes())
        );
        assert!(store.locked(&key, now).await.unwrap());
        assert_eq!(
            pool.archived(&keys, &ledger).await.unwrap(),
            Some(ArchiveRecord {
                object_key: key.clone(),
                copy_digest: slice.digest,
                row_count: 3,
            })
        );
        assert_eq!(
            store.put_once(&key, b"rewritten", now).await,
            Err(WormError::Diverged(key))
        );
    }
    assert!(slice_a.rows.iter().all(|r| r.contains("party:bob")));
}

//! The WORM replica end to end against versitygw with S3 Object Lock (§18 OP-33 item 3, OP-46
//! item 9, OP-4 item 3, T-90, OP-2): the log, the received bytes, the checkpoint and the witness
//! cosignatures land as compliance-locked objects written once, the server refuses to replace
//! them, a key holding other bytes stops the mirror before the replica's progress moves, and a
//! bucket without Object Lock is refused.

use work_ledger::{
    MirrorError, ObjectStore as _, Replica as _, Retention, S3Config, S3Store, WormError,
    WormReplica, WormStore, checkpoint_key, cosignature_key, entry_key, received_key,
};
use work_testkit::{S3, S3_KEY_ID, S3_SECRET};

use super::*;

const WALL_CLOCK: &str = include_str!("../../../../crates/store/fixtures/wall-clock.sql");

async fn wall_clock(env: &Env) -> u64 {
    let sql: String = WALL_CLOCK
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    env.pg
        .client(&["psql", "-X", "-q", "-t", "-A", "-d", "work", "-c", &sql])
        .await
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn config(s3: &S3, bucket: &str) -> S3Config {
    S3Config {
        endpoint: s3.endpoint().to_owned(),
        region: "us-east-1".to_owned(),
        bucket: bucket.to_owned(),
        key_id: S3_KEY_ID.to_owned(),
        secret: Secret::new(S3_SECRET.to_owned()),
        tls: None,
    }
}

fn worm(s3: &S3, bucket: &str) -> WormStore {
    WormStore::new(config(s3, bucket), Retention::days(1).unwrap()).unwrap()
}

// OP-33 OP-46 OP-4 T-90 OP-2 SEC-32 OP-49
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn op_33_the_worm_replica_takes_the_log_once_and_moves_only_after_reading_it_back() {
    let env = Env::start().await;
    let s3 = S3::start().await.unwrap();
    let now = wall_clock(&env).await;
    let (opened, _leader) = ledger_with_comment(&env, 0x61).await;
    let ledger = opened.ledger;
    let token = Token::new("worm");
    let signer = Signer::start(&token);
    let local = checkpointer(&env, &signer, WitnessProfile::LocalDependent).await;
    let stored = local.checkpoint(&ledger, AT + 9).await.unwrap().unwrap();
    let note = String::from_utf8(stored.signed_note.clone()).unwrap();

    let replica = WormReplica::new("worm", worm(&s3, "work-replica"), Fixed(now));
    let objects = worm(&s3, "work-replica");
    let keys = KeyStore::open(&module(), &token.label, &Secret::new(PIN.to_owned())).unwrap();
    let first = cosigner(&keys, "witness.v1", "witness_a", "witness.example");
    let witnesses = [first.witness.clone()];
    let cosigned_note = cosigned(&note, &local.origin(&ledger), &token.verifier(), &[&first]);
    assert!(matches!(
        local
            .take_cosignatures(&ledger, 2, &cosigned_note, &replica, &witnesses)
            .await,
        Err(WitnessError::Order(_))
    ));

    assert_eq!(local.mirror(&ledger, &replica).await.unwrap(), 2);
    assert_eq!(local.mirror(&ledger, &replica).await.unwrap(), 2);
    let genesis_key = entry_key(&ledger, 0);
    let context_key = received_key(&ledger, 1, "auth_context");
    let note_key = checkpoint_key(&ledger, 2);
    let genesis_bytes = objects.get(&genesis_key, now).await.unwrap().unwrap();
    assert_eq!(leaf_hash(&genesis_bytes), opened.leaf);
    assert_eq!(
        objects.get(&context_key, now).await.unwrap().unwrap(),
        CONTEXT
    );
    assert_eq!(
        objects.get(&note_key, now).await.unwrap().unwrap(),
        stored.signed_note
    );
    for key in [&genesis_key, &context_key, &note_key] {
        assert!(objects.locked(key, now).await.unwrap(), "{key}");
    }

    let plain = S3Store::new(config(&s3, "work-replica")).unwrap();
    assert!(
        plain
            .put(&genesis_key, b"other".to_vec(), now)
            .await
            .is_err()
    );
    assert_eq!(
        objects.put_once(&genesis_key, b"other", now).await,
        Err(WormError::Diverged(genesis_key.clone()))
    );
    assert_eq!(
        objects.get(&genesis_key, now).await.unwrap().unwrap(),
        genesis_bytes
    );

    assert_eq!(
        local
            .take_cosignatures(&ledger, 2, &cosigned_note, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    let cosign_key = cosignature_key(&ledger, 2, "witness_a");
    let line = objects.get(&cosign_key, now).await.unwrap().unwrap();
    assert!(line.starts_with("\u{2014} witness.example ".as_bytes()));
    assert!(objects.locked(&cosign_key, now).await.unwrap());
    assert_eq!(
        local
            .archive_cosignatures(&ledger, 2, &replica)
            .await
            .unwrap(),
        1
    );

    let (opened, _second) = ledger_with_comment(&env, 0x62).await;
    let planted = opened.ledger;
    local.checkpoint(&planted, AT + 9).await.unwrap().unwrap();
    objects
        .put_once(&entry_key(&planted, 1), b"not the envelope", now)
        .await
        .unwrap();
    assert!(matches!(
        local.mirror(&planted, &replica).await,
        Err(MirrorError::Diverged(k)) if k == entry_key(&planted, 1)
    ));
    let progress = CheckpointerPool::new(env.pool("work_checkpointer"))
        .await
        .unwrap();
    assert_eq!(progress.mirrored(&planted, replica.id()).await.unwrap(), 0);
    assert_eq!(progress.mirrored(&ledger, replica.id()).await.unwrap(), 2);

    let no_lock = S3Store::new(config(&s3, "work-plain")).unwrap();
    no_lock.ensure_bucket(now).await.unwrap();
    assert_eq!(
        worm(&s3, "work-plain").prepare(now).await,
        Err(WormError::Unlocked)
    );
}

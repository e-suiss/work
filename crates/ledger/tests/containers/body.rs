//! The body store against real PostgreSQL 18, a `SoftHSM` token and an S3-compatible store
//! (OP-45, OP-12, OP-13, P-68, T-20).

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::Digest;
use suiss_crypto::secret::Secret;
use work_kernel::codec::body_commitment;
use work_kernel::record::PartName;
use work_kernel::verify::{ChainPoint, StoredEntry, verify_entry};
use work_ledger::{
    BodyEraser, BodyError, BodyKeys, BodyOpening, BodyReader, BodyWriter, PartRead, SubmitError,
    rebuild_diff,
};
use work_store::{Cluster, Durability, ErasurePool, LedgerId, RetentionClass, Shred, StoreError};

use crate::{AT, Directory, Env, comment, human, submission, unsigned, writer};

const PIN: &str = "4711";

fn module() -> PathBuf {
    std::env::var_os("PKCS11_MODULE").map_or_else(
        || PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from,
    )
}

fn keys(test: &str) -> Arc<BodyKeys> {
    let label = format!("ledger-{test}-{}", std::process::id());
    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--so-pin",
            "12345678",
            "--pin",
            PIN,
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    Arc::new(BodyKeys::open(&module(), &label, &Secret::new(PIN.to_owned()), 1).unwrap())
}

fn opening(part: &str, content: &[u8], salt: u8) -> BodyOpening {
    BodyOpening {
        part: part.to_owned(),
        media_type: "text/plain".to_owned(),
        content: content.to_vec(),
        salt: [salt; 32],
    }
}

fn commit(o: &BodyOpening) -> [u8; 32] {
    *body_commitment(
        &o.salt,
        &PartName::parse(&o.part).unwrap(),
        &o.media_type,
        &o.content,
    )
    .unwrap()
    .as_bytes()
}

/// `record` with a `body` committing to `parts` (P-68).
fn with_body(record: &[u8], parts: &[&BodyOpening]) -> Vec<u8> {
    let mut v = dcbor::decode(record, Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    let body = parts
        .iter()
        .map(|o| {
            Value::Map(vec![
                (Value::text("part"), Value::text(&o.part)),
                (Value::text("commit"), Digest(commit(o)).to_value()),
            ])
        })
        .collect();
    fields.push((Value::text("body"), Value::Array(body)));
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

async fn psql(env: &Env, sql: &str) {
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
            sql,
        ])
        .await
        .unwrap();
}

async fn read(reader: &BodyReader, ledger: &LedgerId, pos: u64) -> Vec<(String, PartRead)> {
    reader.read(ledger, pos, AT).await.unwrap()
}

// OP-45 OP-12 OP-13 OP-15 P-68 P-25 EV-33 Access OP-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and SoftHSM"]
async fn op_45_a_shredded_body_is_unreadable_while_its_skeleton_verifies() {
    let env = Env::start().await;
    let keys = keys("shred");
    let (pool, ledger, group, gate) = writer(&env, [0x45; 32]).await;
    gate.permits.add_permits(100);
    let bodies = BodyWriter::in_database(Arc::clone(&keys), pool.clone());
    let note = opening("note", b"the delivery moves to Friday", 1);
    let terms = opening("terms", b"net 30", 2);
    let record = with_body(&comment(&ledger, 1), &[&note, &terms]);
    let actors = human();
    let wrong = opening("note", b"the delivery moves to Monday", 1);
    assert!(matches!(
        group
            .admit_with_body(
                &Directory::golden(),
                submission(unsigned(&record), &actors),
                &[wrong],
                &bodies,
                AT,
            )
            .await,
        Err(SubmitError::Body(BodyError::Commitment(p))) if p == "note"
    ));
    let stray = opening("annex", b"x", 3);
    assert!(matches!(
        group
            .admit_with_body(
                &Directory::golden(),
                submission(unsigned(&record), &actors),
                &[stray],
                &bodies,
                AT,
            )
            .await,
        Err(SubmitError::Body(BodyError::UnknownPart(_)))
    ));
    let committed = group
        .admit_with_body(
            &Directory::golden(),
            submission(unsigned(&record), &actors),
            &[note.clone(), terms.clone()],
            &bodies,
            AT,
        )
        .await
        .unwrap();
    let reader = BodyReader::in_database(
        Arc::clone(&keys),
        env.pool(Cluster::Canonical, "work_app"),
    );
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![
            ("note".to_owned(), PartRead::Readable(note.clone())),
            ("terms".to_owned(), PartRead::Readable(terms.clone())),
        ]
    );
    let eraser = BodyEraser::new(
        Arc::clone(&keys),
        ErasurePool::new(env.pool(Cluster::Canonical, "work_erasure"))
            .await
            .unwrap(),
    );
    assert!(eraser.redact(&ledger, committed.pos, "note").await.unwrap());
    assert!(!eraser.redact(&ledger, committed.pos, "note").await.unwrap());
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![
            ("note".to_owned(), PartRead::Unreadable),
            ("terms".to_owned(), PartRead::Readable(terms.clone())),
        ]
    );
    let hex = ledger.to_hex();
    psql(
        &env,
        &format!(
            "INSERT INTO work.retention_hold (ledger_id, hold_kind, subject_ref, state) \
             VALUES (decode('{hex}', 'hex'), 'litigation', 'party:acme:alice', 'active')"
        ),
    )
    .await;
    let subject = "party:acme:alice";
    assert!(matches!(
        eraser
            .destroy_class(&ledger, subject, RetentionClass::WorkRecord, Shred::SubjectErasure)
            .await,
        Err(BodyError::Store(StoreError::Constraint(_)))
    ));
    assert!(matches!(
        read(&reader, &ledger, committed.pos).await.get(1),
        Some((_, PartRead::Readable(_)))
    ));
    psql(
        &env,
        "UPDATE work.retention_hold SET state = 'released', released_at = now()",
    )
    .await;
    assert!(
        eraser
            .destroy_class(&ledger, subject, RetentionClass::WorkRecord, Shred::SubjectErasure)
            .await
            .unwrap()
    );
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![
            ("note".to_owned(), PartRead::Unreadable),
            ("terms".to_owned(), PartRead::Unreadable),
        ]
    );
    let later = opening("note", b"a new note after the erasure", 4);
    let next = group
        .admit_with_body(
            &Directory::golden(),
            submission(unsigned(&with_body(&comment(&ledger, 2), &[&later])), &actors),
            &[later.clone()],
            &bodies,
            AT,
        )
        .await
        .unwrap();
    assert_eq!(
        read(&reader, &ledger, next.pos).await,
        vec![("note".to_owned(), PartRead::Readable(later))]
    );
    let mut tx = env.read("work_app", &ledger).await;
    let stored = tx.entries(0, 100).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(stored.len(), 3);
    let directory = Directory::golden();
    let mut at = ChainPoint::genesis(&stored[0].record_bytes).unwrap();
    for s in &stored[1..] {
        let entry = StoredEntry {
            envelope: &s.envelope_bytes,
            record: &s.record_bytes,
            cose_sign1: s.cose_sign1.as_deref(),
        };
        at = verify_entry(&directory, &at, &entry).unwrap().next();
    }
    let target = env.target().await;
    let live = env.pool(Cluster::Canonical, "work_app");
    let outcome = rebuild_diff(&live, &target, ledger, Durability::Quorum)
        .await
        .unwrap();
    assert!(outcome.is_clean(), "{outcome:?}");
    assert_eq!(outcome.through(), next.pos);
}

// T-20 OP-2 OP-45 P-104
#[cfg(feature = "s3")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and SoftHSM"]
async fn t_20_a_large_part_is_kept_in_the_object_store_and_reads_back() {
    use work_ledger::{S3Config, S3Store};
    use work_store::Stored;
    use work_testkit::{S3, S3_KEY_ID, S3_SECRET};

    let s3 = S3::start().await.unwrap();
    let config = || S3Config {
        endpoint: s3.endpoint().to_owned(),
        region: "us-east-1".to_owned(),
        bucket: "work-bodies".to_owned(),
        key_id: S3_KEY_ID.to_owned(),
        secret: Secret::new(S3_SECRET.to_owned()),
        tls: None,
    };
    let store = S3Store::new(config()).unwrap();
    store.ensure_bucket(AT).await.unwrap();
    let env = Env::start().await;
    let keys = keys("object");
    let (pool, ledger, group, gate) = writer(&env, [0x46; 32]).await;
    gate.permits.add_permits(100);
    let bodies = BodyWriter::with_objects(Arc::clone(&keys), pool, store);
    let large = opening("note", &vec![0x42; 70_000], 5);
    let small = opening("terms", b"net 30", 6);
    let record = with_body(&comment(&ledger, 1), &[&large, &small]);
    let actors = human();
    let committed = group
        .admit_with_body(
            &Directory::golden(),
            submission(unsigned(&record), &actors),
            &[large.clone(), small.clone()],
            &bodies,
            AT,
        )
        .await
        .unwrap();
    let mut tx = env.read("work_app", &ledger).await;
    let parts = tx.body_parts(committed.pos).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(matches!(&parts[0].stored, Stored::Object(k)
        if *k == work_ledger::object_key(&ledger, &parts[0].ciphertext_digest)));
    assert!(matches!(&parts[1].stored, Stored::Inline(_)));
    let reader = BodyReader::with_objects(
        Arc::clone(&keys),
        env.pool(Cluster::Canonical, "work_app"),
        S3Store::new(config()).unwrap(),
    );
    assert_eq!(
        reader.read(&ledger, committed.pos, AT).await.unwrap(),
        vec![
            ("note".to_owned(), PartRead::Readable(large)),
            ("terms".to_owned(), PartRead::Readable(small)),
        ]
    );
}

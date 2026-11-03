//! The body store against real PostgreSQL 18, a `SoftHSM` token and an S3-compatible store
//! (OP-45, OP-12, OP-13, P-68, T-20), with the secret scan of the parser worker's rule set on
//! the write path (SEC-35).

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, sha256};
use suiss_crypto::secret::Secret;
use work_kernel::codec::body_commitment;
use work_kernel::record::PartName;
use work_kernel::verify::{ChainPoint, StoredEntry, verify_entry};
use work_ledger::{
    BodyEraser, BodyError, BodyKeys, BodyOpening, BodyReader, BodyWriter, PartRead, SubmitError,
    rebuild_diff,
};
use work_parse::secret::SecretScanner;
use work_proto::parser::Scan;
use work_store::{
    Cluster, Durability, Erased, ErasureCause, ErasurePool, ErasureState, ErasureTarget, LedgerId,
    RetentionClass, Shred,
};

use crate::{
    AT, Directory, Env, RECORDS, comment, human, json, node, statement, submission, unhex,
    unsigned, writer,
};

const PIN: &str = "4711";
const FILL36: &str = "Zq8kR2mN4vX7bT1yW9cL3pH6dF0sJ5gA2eUo";
const BACKUP_WINDOW: Duration = Duration::from_hours(24);
const HOLD: &str = include_str!("../../../store/fixtures/body-hold.sql");
const RELEASE: &str = include_str!("../../../store/fixtures/body-release.sql");
#[cfg(feature = "s3")]
const WALL_CLOCK: &str = include_str!("../../../store/fixtures/wall-clock.sql");

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

/// The rule set the parser worker runs, in process (SEC-35).
fn scanner() -> Arc<dyn Scan> {
    Arc::new(SecretScanner::builtin().unwrap())
}

fn opening(part: &str, content: &[u8], tag: u8) -> BodyOpening {
    BodyOpening {
        part: part.to_owned(),
        media_type: "text/plain".to_owned(),
        content: content.to_vec(),
        salt: sha256(&[tag]),
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

/// The golden `redact` record moved to `ledger`, naming `part` of the record `target` (P-111).
fn redaction(ledger: &LedgerId, target: [u8; 32], part: &str) -> Vec<u8> {
    let records = json(RECORDS);
    let template = &records["records"][11];
    assert_eq!(template["id"], "record/declaration-redact");
    let mut v = dcbor::decode(&unhex(template["hex"].as_str().unwrap()), Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    let params = Value::Map(vec![
        (Value::text("parts"), Value::Array(vec![Value::text(part)])),
        (Value::text("reason"), Value::text("personal_data")),
        (Value::text("target"), Digest(target).to_value()),
    ]);
    for (key, value) in fields.iter_mut() {
        match key {
            Value::Text(k) if k == "ledger" => *value = Digest(*ledger.as_bytes()).to_value(),
            Value::Text(k) if k == "params" => *value = params.clone(),
            _ => {}
        }
    }
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

/// The database server's wall clock in Unix milliseconds: the object store refuses requests
/// signed too far from its own time.
#[cfg(feature = "s3")]
async fn wall_clock(env: &Env) -> u64 {
    env.pg
        .client(&[
            "psql",
            "-X",
            "-q",
            "-t",
            "-A",
            "-d",
            Cluster::Canonical.database(),
            "-c",
            &statement(WALL_CLOCK),
        ])
        .await
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

async fn read(reader: &BodyReader, ledger: &LedgerId, pos: u64) -> Vec<(String, PartRead)> {
    reader.read(ledger, pos, AT).await.unwrap()
}

// OP-45 OP-12 OP-13 OP-15 P-68 P-25 EV-33 Access OP-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and SoftHSM"]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from the write through the shred to the rebuild-diff"
)]
async fn op_45_a_shredded_body_is_unreadable_while_its_skeleton_verifies() {
    let env = Env::start().await;
    let keys = keys("shred");
    let (pool, ledger, group, gate) = writer(&env, [0x45; 32]).await;
    gate.permits.add_permits(100);
    let bodies = BodyWriter::in_database(Arc::clone(&keys), pool.clone(), scanner());
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
    let reader =
        BodyReader::in_database(Arc::clone(&keys), env.pool(Cluster::Canonical, "work_app"));
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
        BACKUP_WINDOW,
    );
    let asked = redaction(&ledger, sha256(&record), "note");
    let request = group
        .admit(&Directory::golden(), submission(unsigned(&asked), &actors))
        .await
        .unwrap();
    let redacted = eraser.redact_record(&ledger, request.pos).await.unwrap();
    assert!(matches!(redacted.as_slice(), [(p, Erased::Shredded { .. })] if p == "note"));
    let replayed = eraser.redact_record(&ledger, request.pos).await.unwrap();
    assert_eq!(replayed, vec![("note".to_owned(), Erased::Nothing)]);
    let again = eraser
        .redact(&ledger, request.pos, committed.pos, "note")
        .await
        .unwrap();
    assert_eq!(again, Erased::Nothing);
    assert!(matches!(
        eraser
            .redact_parts(&ledger, request.pos, committed.pos, &["terms", "terms"])
            .await,
        Err(BodyError::DuplicatePart(p)) if p == "terms"
    ));
    assert!(matches!(
        eraser.redact_record(&ledger, committed.pos).await,
        Err(BodyError::NotARedaction(p)) if p == committed.pos
    ));
    let elsewhere = redaction(&ledger, [0x5e; 32], "note");
    let unknown = group
        .admit(&Directory::golden(), submission(unsigned(&elsewhere), &actors))
        .await
        .unwrap();
    assert!(
        eraser
            .redact_record(&ledger, unknown.pos)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![
            ("note".to_owned(), PartRead::Unreadable),
            ("terms".to_owned(), PartRead::Readable(terms.clone())),
        ]
    );
    psql(&env, &statement(HOLD)).await;
    let subject = "party:acme:alice";
    let held = eraser
        .destroy_class(
            &ledger,
            subject,
            RetentionClass::WorkRecord,
            Shred::SubjectErasure,
        )
        .await
        .unwrap();
    let waiting = match held {
        Erased::Held { erasure_id } => erasure_id,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        read(&reader, &ledger, committed.pos).await.get(1),
        Some((_, PartRead::Readable(_)))
    ));
    assert_eq!(eraser.resume(&ledger).await.unwrap(), 0);
    psql(&env, &statement(RELEASE)).await;
    assert_eq!(eraser.resume(&ledger).await.unwrap(), 1);
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![
            ("note".to_owned(), PartRead::Unreadable),
            ("terms".to_owned(), PartRead::Unreadable),
        ]
    );
    let settle = i64::try_from(eraser.settle().as_millis()).unwrap();
    assert_eq!(settle, 86_700_000);
    let erasures = eraser.erasures(&ledger).await.unwrap();
    assert_eq!(erasures.len(), 2);
    assert_eq!(erasures[0].cause, ErasureCause::Redaction);
    assert_eq!(
        erasures[0].target,
        ErasureTarget::Part {
            pos: committed.pos,
            part: "note".to_owned(),
        }
    );
    assert_eq!(erasures[0].request_pos, Some(request.pos));
    assert_eq!(erasures[1].erasure_id, waiting);
    assert_eq!(erasures[1].cause, ErasureCause::SubjectRequest);
    assert_eq!(erasures[1].target, ErasureTarget::Class);
    for e in &erasures {
        let ErasureState::Shredded { settles_at_ms } = e.state else {
            panic!("{e:?}")
        };
        assert!(settles_at_ms >= e.requested_at_ms.saturating_add(settle));
    }
    assert_eq!(
        eraser.settle_due(&ledger).await.unwrap(),
        Vec::<String>::new()
    );
    let later = opening("note", b"a new note after the erasure", 4);
    let next = group
        .admit_with_body(
            &Directory::golden(),
            submission(
                unsigned(&with_body(&comment(&ledger, 2), &[&later])),
                &actors,
            ),
            std::slice::from_ref(&later),
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
    assert_eq!(stored.len(), 5);
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
    let outcome = rebuild_diff(&live, &target, &node(), ledger, Durability::Quorum)
        .await
        .unwrap();
    assert!(outcome.is_clean(), "{outcome:?}");
    assert_eq!(outcome.through(), next.pos);
}

// SEC-35 P-95 SEC-13 OP-45
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and SoftHSM"]
async fn sec_35_a_body_carrying_a_secret_is_refused_and_writes_nothing() {
    let env = Env::start().await;
    let keys = keys("secret");
    let (pool, ledger, group, gate) = writer(&env, [0x47; 32]).await;
    gate.permits.add_permits(100);
    let bodies = BodyWriter::in_database(Arc::clone(&keys), pool.clone(), scanner());
    let leak = ["ghp_", FILL36].concat();
    let leaky = opening("note", leak.as_bytes(), 7);
    let record = with_body(&comment(&ledger, 1), &[&leaky]);
    let actors = human();
    let refused = group
        .admit_with_body(
            &Directory::golden(),
            submission(unsigned(&record), &actors),
            &[leaky],
            &bodies,
            AT,
        )
        .await;
    let error = match refused {
        Err(SubmitError::Body(e @ BodyError::SecretDetected { .. })) => e,
        other => panic!("{other:?}"),
    };
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains(FILL36), "{shown}");
    assert!(matches!(
        &error,
        BodyError::SecretDetected { part, rule } if part == "note" && rule == "github-pat"
    ));
    let mut tx = env.read("work_app", &ledger).await;
    let stored = tx.entries(0, 100).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(stored.len(), 1);
    let subject = "party:acme:alice";
    let dek = pool
        .active_dek(&ledger, subject, RetentionClass::WorkRecord)
        .await
        .unwrap();
    assert!(dek.is_none());
    let fine = opening("note", b"the delivery moves to Friday", 8);
    let record = with_body(&comment(&ledger, 1), &[&fine]);
    let committed = group
        .admit_with_body(
            &Directory::golden(),
            submission(unsigned(&record), &actors),
            std::slice::from_ref(&fine),
            &bodies,
            AT,
        )
        .await
        .unwrap();
    let reader =
        BodyReader::in_database(Arc::clone(&keys), env.pool(Cluster::Canonical, "work_app"));
    assert_eq!(
        read(&reader, &ledger, committed.pos).await,
        vec![("note".to_owned(), PartRead::Readable(fine))]
    );
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
    let env = Env::start().await;
    let now = wall_clock(&env).await;
    store.ensure_bucket(now).await.unwrap();
    let keys = keys("object");
    let (pool, ledger, group, gate) = writer(&env, [0x46; 32]).await;
    gate.permits.add_permits(100);
    let bodies = BodyWriter::with_objects(Arc::clone(&keys), pool, store, scanner());
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
            now,
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
        reader.read(&ledger, committed.pos, now).await.unwrap(),
        vec![
            ("note".to_owned(), PartRead::Readable(large)),
            ("terms".to_owned(), PartRead::Readable(small)),
        ]
    );
}

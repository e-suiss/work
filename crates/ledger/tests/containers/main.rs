//! The admission path and the leader against real PostgreSQL 18 (P-100, T-85, T-74, T-89,
//! T-90, §18 OP-5, OP-7, OP-10; T-36 rule 7, T-37 rule 9): opening a ledger with its genesis,
//! admitting kernel-verified records into batches behind the head compare-and-set, keeping the
//! signed bytes as received, versioning the Works they concern, fencing an earlier leader and
//! refusing a record without stepping down. These tests need Docker; `just test-containers`
//! runs them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash, sha256};
use tokio::sync::Semaphore;
use work_kernel::cose::{Algorithm, AuthorKeys, KeySet, PublicKey, verify_record_signature};
use work_kernel::id::PartyRef;
use work_kernel::limits::SemanticLimits;
use work_kernel::reason::{Reason, Schema};
use work_kernel::uri::TypeUri;
use work_kernel::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin};
use work_kernel::verify::{
    ChainPoint, SignatureCheck, SignatureVerifier, StoredEntry, verify_entry,
};
use work_ledger::{
    Arrival, AuthContext, Clock, ClockError, GenesisInput, GroupCommit, GroupConfig, Leader,
    LedgerError, PendingRecord, Submission, SubmitError, admit, genesis,
};
use work_store::{
    Cluster, Durability, Genesis, ItemRef, LedgerId, LedgerTx, Pool, SequencerPool, StoreError,
};
use work_testkit::Postgres;

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = "ALTER ROLE work_owner LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_sequencer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_app LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_publisher LOGIN PASSWORD 'test-only-not-a-secret';";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const AT: u64 = 1_792_749_600_123;
const COSE: &str = include_str!("../../../../conformance/vectors/records/cose-sign1.json");
const GENESIS: &str = include_str!("../../../../conformance/vectors/records/genesis.json");
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
const QUARANTINE: &str =
    include_str!("../../../../conformance/vectors/records/records-quarantine.json");
const CONTEXT: &[u8] = b"work-vector:access:auth-context:alice";

struct Env {
    pg: Postgres,
}

impl Env {
    async fn start() -> Self {
        let pg = Postgres::start().await.unwrap();
        let psql = |db: &'static str| ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db];
        let mut roles = psql("postgres").to_vec();
        roles.extend(["-c", work_store::BOOTSTRAP_ROLES, "-c", LOGINS]);
        pg.client(&roles).await.unwrap();
        let statements: Vec<String> = work_store::BOOTSTRAP_DATABASES
            .split(';')
            .map(|s| {
                s.lines()
                    .filter(|l| !l.trim_start().starts_with("--"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .filter(|s| !s.trim().is_empty())
            .collect();
        let mut databases = psql("postgres").to_vec();
        for stmt in &statements {
            databases.extend(["-c", stmt.as_str()]);
        }
        pg.client(&databases).await.unwrap();
        for cluster in Cluster::ALL {
            let mut bootstrap = psql(cluster.database()).to_vec();
            bootstrap.extend(["-c", cluster.bootstrap()]);
            pg.client(&bootstrap).await.unwrap();
        }
        let env = Self { pg };
        for cluster in Cluster::ALL {
            work_store::migrate(&env.pool(cluster, "work_owner"), cluster)
                .await
                .unwrap();
        }
        env
    }

    fn pool(&self, cluster: Cluster, role: &str) -> Pool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            cluster.database()
        );
        Pool::connect_lazy(&url).unwrap()
    }

    async fn sequencer(&self) -> SequencerPool {
        SequencerPool::new(self.pool(Cluster::Canonical, "work_sequencer"))
            .await
            .unwrap()
    }

    async fn read(&self, role: &str, ledger: &LedgerId) -> LedgerTx<'static> {
        LedgerTx::begin(&self.pool(Cluster::Canonical, role), ledger)
            .await
            .unwrap()
    }
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn json(text: &str) -> Json {
    serde_json::from_str(text).unwrap()
}

/// The signature port over the golden keys: the keys bound to whichever Party signed.
struct Directory(BTreeMap<String, KeySet>);

impl Directory {
    fn golden() -> Self {
        let mut sets: BTreeMap<String, KeySet> = BTreeMap::new();
        for key in json(COSE)["keys"].as_array().unwrap() {
            let kid: [u8; 32] = unhex(key["kid_hex"].as_str().unwrap()).try_into().unwrap();
            let bytes = unhex(key["public_key_hex"].as_str().unwrap());
            let public = match key["alg"].as_i64().unwrap() {
                -19 => PublicKey::Ed25519(bytes.try_into().unwrap()),
                _ => PublicKey::P256(bytes),
            };
            let set = sets
                .entry(key["party"].as_str().unwrap().to_owned())
                .or_insert_with(|| KeySet {
                    allowed: BTreeSet::from([
                        Algorithm::Ed25519,
                        Algorithm::Esp256,
                        Algorithm::Es256,
                    ]),
                    ..KeySet::default()
                });
            set.insert(kid, public).unwrap();
        }
        Self(sets)
    }
}

impl SignatureVerifier for Directory {
    fn check(&self, cose_sign1: &[u8]) -> SignatureCheck {
        let Some((author, keys)) = self
            .0
            .iter()
            .find(|(_, keys)| verify_record_signature(cose_sign1, keys).is_ok())
        else {
            return SignatureCheck::Rejected(Reason::Schema(Schema::Container));
        };
        let author = PartyRef::new(author).unwrap();
        AuthorKeys {
            author: &author,
            keys,
        }
        .check(cose_sign1)
    }
}

fn human() -> ActorTypes {
    ActorTypes {
        author: ActorTypeEntry {
            actor_type: ActorType::Human,
            source: ActorTypeSource::AccessBinding,
        },
        on_behalf_of: vec![],
    }
}

fn submission<'a>(arrival: Arrival<'a>, actors: &'a ActorTypes) -> Submission<'a> {
    Submission {
        arrival,
        actor_types: actors,
        origin: Origin::Direct,
        understood_extensions: &[],
        limits: SemanticLimits::default(),
        event_type: "work.recorded",
        traceparent: TRACE,
        idempotency: None,
        inbound: None,
    }
}

fn unsigned(record: &[u8]) -> Arrival<'_> {
    Arrival::Unsigned {
        record,
        auth_context: AuthContext {
            bytes: CONTEXT,
            assurance: "aal2",
            step_up: false,
        },
    }
}

/// The golden unsigned human comment Claim, declared in `ledger` and concerning `work`.
fn comment(ledger: &LedgerId, work: u8) -> Vec<u8> {
    let records = json(RECORDS);
    let template = &records["records"][4];
    assert_eq!(template["id"], "record/claim-comment-private");
    let mut v = dcbor::decode(&unhex(template["hex"].as_str().unwrap()), Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    for (key, value) in fields.iter_mut() {
        match key {
            Value::Text(k) if k == "ledger" => *value = Digest(*ledger.as_bytes()).to_value(),
            Value::Text(k) if k == "concerns" => {
                *value = Value::Array(vec![Value::Bytes(vec![work; 16])]);
            }
            _ => {}
        }
    }
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

fn pending(ledger: &LedgerId, record: &[u8]) -> PendingRecord {
    let actors = human();
    admit(
        &Directory::golden(),
        ledger,
        submission(unsigned(record), &actors),
    )
    .unwrap()
}

fn opening(nonce: u8, durability: Durability) -> Genesis {
    genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x5c; 32],
            nonce: [nonce; 32],
        },
        durability,
    )
    .unwrap()
}

async fn pointers(env: &Env, ledger: &LedgerId) -> Vec<(u64, ItemRef, u64)> {
    let mut tx = env.read("work_publisher", ledger).await;
    let rows = tx.outbox_pending(1000).await.unwrap();
    tx.rollback().await.unwrap();
    rows.iter()
        .map(|p| (p.key.pos, p.item, p.version))
        .collect()
}

// P-100 T-85 T-74 OP-5 OP-10 OP-3 P-79
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_85_a_leader_opens_commits_and_is_fenced_by_the_next() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let opened = opening(0x7e, Durability::SingleNode);
    let ledger = opened.ledger;
    Leader::open(&pool, &opened).await.unwrap();
    assert!(matches!(
        Leader::open(&pool, &opened).await,
        Err(LedgerError::Store(StoreError::AlreadyOpened))
    ));

    let mut first = Leader::acquire(pool.clone(), ledger).await.unwrap();
    assert_eq!(first.epoch(), 1);
    assert_eq!(first.head().pos, 0);
    assert_eq!(first.head().leaf, opened.leaf);
    assert_eq!(first.head().frontier.nodes(), [opened.leaf]);

    let at = AT.checked_add(1000).unwrap();
    let one = pending(&ledger, &comment(&ledger, 1));
    let two = pending(&ledger, &comment(&ledger, 2));
    assert_eq!(first.commit(at, &[one.clone(), two]).await.unwrap(), 2);
    assert!(first.fence().allows(2));
    assert_eq!(first.head().recorded_at, at);

    assert!(matches!(
        first.commit(at, std::slice::from_ref(&one)).await,
        Err(LedgerError::Refused(StoreError::RecordExists))
    ));
    let three = pending(&ledger, &comment(&ledger, 3));
    assert_eq!(first.commit(at, &[three]).await.unwrap(), 3);

    let mut second = Leader::acquire(pool.clone(), ledger).await.unwrap();
    assert_eq!(second.epoch(), 2);
    assert_eq!(second.head(), first.head());

    let four = pending(&ledger, &comment(&ledger, 4));
    assert!(matches!(
        first.commit(at, std::slice::from_ref(&four)).await,
        Err(LedgerError::Failed(_))
    ));
    assert!(matches!(
        first.commit(at, std::slice::from_ref(&four)).await,
        Err(LedgerError::SteppedDown)
    ));

    assert_eq!(second.commit(AT, &[four]).await.unwrap(), 4);
    assert_eq!(second.head().recorded_at, at);
    let third = Leader::acquire(pool, ledger).await.unwrap();
    assert_eq!(third.head(), second.head());
}

// INV-33 OP-3 T-17 T-81
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn inv_33_a_refused_or_failed_commit_leaves_no_pointer() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let opened = opening(0x6a, Durability::Quorum);
    let ledger = opened.ledger;
    Leader::open(&pool, &opened).await.unwrap();
    let mut first = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let one = pending(&ledger, &comment(&ledger, 1));
    first.commit(AT, std::slice::from_ref(&one)).await.unwrap();
    let committed = pointers(&env, &ledger).await;
    assert_eq!(committed, vec![(1, ItemRef::Work([1; 16]), 1)]);

    let again = [one, pending(&ledger, &comment(&ledger, 2))];
    assert!(matches!(
        first.commit(AT, &again).await,
        Err(LedgerError::Refused(StoreError::RecordExists))
    ));
    assert_eq!(pointers(&env, &ledger).await, committed);

    let _second = Leader::acquire(pool, ledger).await.unwrap();
    let fenced = pending(&ledger, &comment(&ledger, 3));
    assert!(matches!(
        first.commit(AT, &[fenced]).await,
        Err(LedgerError::Failed(_))
    ));
    assert_eq!(pointers(&env, &ledger).await, committed);
    let mut tx = env.read("work_app", &ledger).await;
    assert_eq!(tx.entries(0, 10).await.unwrap().len(), 2);
    tx.rollback().await.unwrap();
}

/// A virtual ledger clock (T-32 rule 2): each reading takes one permit, so a test can hold the
/// writer between batches.
struct Gate {
    permits: Arc<Semaphore>,
    at: u64,
}

impl Clock for Gate {
    async fn now(&mut self) -> Result<u64, ClockError> {
        self.permits
            .acquire()
            .await
            .map_err(|e| ClockError(e.to_string()))?
            .forget();
        self.at = self
            .at
            .checked_add(1)
            .ok_or(ClockError("overflow".to_owned()))?;
        Ok(self.at)
    }
}

async fn writer(env: &Env, nonce: u8) -> (SequencerPool, LedgerId, GroupCommit, Gate) {
    let pool = env.sequencer().await;
    let g = opening(nonce, Durability::Quorum);
    Leader::open(&pool, &g).await.unwrap();
    let leader = Leader::acquire(pool.clone(), g.ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(0));
    let gate = Gate {
        permits: permits.clone(),
        at: AT,
    };
    let (group, task) =
        GroupCommit::spawn(leader, Gate { permits, at: AT }, GroupConfig::default());
    drop(task);
    (pool, g.ledger, group, gate)
}

fn admit_spawned(
    group: &GroupCommit,
    record: Vec<u8>,
) -> tokio::task::JoinHandle<Result<work_ledger::Committed, SubmitError>> {
    let g = group.clone();
    tokio::spawn(async move {
        let actors = human();
        g.admit(&Directory::golden(), submission(unsigned(&record), &actors))
            .await
    })
}

// OP-31 OP-5 OP-3 T-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_31_concurrent_requests_share_batches_and_get_contiguous_positions() {
    let env = Env::start().await;
    let (pool, ledger, group, gate) = writer(&env, 0x3d).await;
    let waiting: Vec<_> = (1..=100_u8)
        .map(|n| admit_spawned(&group, comment(&ledger, n)))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.permits.add_permits(1000);
    let mut positions = Vec::new();
    for w in waiting {
        positions.push(w.await.unwrap().unwrap().pos);
    }
    positions.sort_unstable();
    assert_eq!(positions, (1..=100).collect::<Vec<u64>>());
    drop(group);
    let head = Leader::acquire(pool, ledger).await.unwrap();
    assert_eq!(head.head().pos, 100);
    assert!(head.head().recorded_at <= AT.checked_add(100).unwrap());
}

// OP-41 OP-31
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_41_a_full_queue_answers_busy_at_once_and_writes_nothing() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let g = opening(0x3e, Durability::Quorum);
    Leader::open(&pool, &g).await.unwrap();
    let ledger = g.ledger;
    let leader = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(0));
    let clock = Gate {
        permits: permits.clone(),
        at: AT,
    };
    let config = GroupConfig::new(256, 1 << 20, 2, Duration::from_secs(1)).unwrap();
    let (group, task) = GroupCommit::spawn(leader, clock, config);
    let first = admit_spawned(&group, comment(&ledger, 1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let queued: Vec<_> = (2..=3_u8)
        .map(|n| admit_spawned(&group, comment(&ledger, n)))
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        group.submit(pending(&ledger, &comment(&ledger, 4))).await,
        Err(SubmitError::Busy { retry_after }) if retry_after == Duration::from_secs(1)
    ));
    permits.add_permits(10);
    assert_eq!(first.await.unwrap().unwrap().pos, 1);
    for q in queued {
        q.await.unwrap().unwrap();
    }
    drop(group);
    task.await.unwrap().unwrap();
    assert_eq!(Leader::acquire(pool, ledger).await.unwrap().head().pos, 3);
}

// OP-31 P-79 T-74
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_31_a_refused_record_does_not_sink_its_batch() {
    let env = Env::start().await;
    let (pool, ledger, group, gate) = writer(&env, 0x3f).await;
    let waiting: Vec<_> = [1, 2, 2, 4]
        .into_iter()
        .map(|n| admit_spawned(&group, comment(&ledger, n)))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.permits.add_permits(100);
    let mut results = Vec::new();
    for w in waiting {
        results.push(w.await.unwrap());
    }
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(SubmitError::Refused(StoreError::RecordExists))))
            .count(),
        1
    );
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    drop(group);
    assert_eq!(Leader::acquire(pool, ledger).await.unwrap().head().pos, 3);
}

/// The golden comment concerning `work`, made distinct by its `occurred_at`.
fn comment_at(ledger: &LedgerId, work: u8, n: u64) -> Vec<u8> {
    let mut v = dcbor::decode(&comment(ledger, work), Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    for (key, value) in fields.iter_mut() {
        if matches!(key, Value::Text(k) if k == "occurred_at") {
            *value = Value::Unsigned(AT.checked_add(n).unwrap());
        }
    }
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

// OP-7 T-89 P-29 T-81 C-34
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn op_7_work_writes_never_refuse_each_other() {
    let env = Env::start().await;
    let (_pool, ledger, group, gate) = writer(&env, 0x40).await;
    let waiting: Vec<_> = (1..=20_u64)
        .map(|n| admit_spawned(&group, comment_at(&ledger, 9, n)))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.permits.add_permits(100);
    for w in waiting {
        w.await.unwrap().unwrap();
    }
    let work = ItemRef::Work([9; 16]);
    let mut tx = env.read("work_app", &ledger).await;
    assert_eq!(tx.item_version(&work).await.unwrap(), Some(20));
    assert_eq!(tx.concerning(&[9; 16]).await.unwrap(), 20);
    tx.rollback().await.unwrap();
    let seqs: Vec<(u64, u64)> = pointers(&env, &ledger)
        .await
        .into_iter()
        .map(|(pos, item, version)| {
            assert_eq!(item, work);
            (pos, version)
        })
        .collect();
    assert_eq!(seqs, (1..=20).map(|v| (v, v)).collect::<Vec<_>>());
}

// T-32 OP-41
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_32_a_dropped_submit_is_withdrawn_before_its_batch() {
    let env = Env::start().await;
    let (pool, ledger, group, gate) = writer(&env, 0x41).await;
    let first = admit_spawned(&group, comment(&ledger, 1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let dropped = admit_spawned(&group, comment(&ledger, 2));
    tokio::time::sleep(Duration::from_millis(100)).await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());
    gate.permits.add_permits(10);
    assert_eq!(first.await.unwrap().unwrap().pos, 1);
    let last = admit_spawned(&group, comment(&ledger, 3));
    assert_eq!(last.await.unwrap().unwrap().pos, 2);
    drop(group);
    assert_eq!(pointers(&env, &ledger).await.len(), 2);
    let head = Leader::acquire(pool, ledger).await.unwrap();
    assert_eq!(head.head().pos, 2);
}

/// One golden ledger entry: record, envelope, `COSE_Sign1` and verifier context.
struct Golden {
    record: Vec<u8>,
    envelope: Vec<u8>,
    cose: Option<Vec<u8>>,
    actors: ActorTypes,
    origin: Origin,
    understood: Vec<TypeUri>,
}

fn actor(v: &Json) -> ActorTypeEntry {
    ActorTypeEntry {
        actor_type: ActorType::from_wire_name(v[0].as_str().unwrap()).unwrap(),
        source: ActorTypeSource::from_wire_name(v[1].as_str().unwrap()).unwrap(),
    }
}

/// The golden ledger: its genesis and the entries at positions 1 to 14.
fn golden() -> (Vec<u8>, Vec<Golden>) {
    let mut cose = BTreeMap::new();
    for case in json(COSE)["cases"].as_array().unwrap() {
        if let Some(name) = case.get("envelope").and_then(Json::as_str) {
            cose.insert(name.to_owned(), unhex(case["cose_hex"].as_str().unwrap()));
        }
    }
    let records = json(RECORDS);
    let quarantine = json(QUARANTINE);
    let mut cases = Vec::new();
    for (r, e) in records["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records["envelopes"].as_array().unwrap())
    {
        cases.push((r, e, format!("records.json {}", e["id"].as_str().unwrap())));
    }
    for c in quarantine["cases"].as_array().unwrap().iter().take(3) {
        let id = c["id"].as_str().unwrap();
        cases.push((
            c,
            &c["envelope"],
            format!("records-quarantine.json {id} envelope"),
        ));
    }
    let entries = cases
        .into_iter()
        .map(|(r, e, name)| {
            let ctx = &r["context"];
            Golden {
                record: unhex(r["hex"].as_str().unwrap()),
                envelope: unhex(e["hex"].as_str().unwrap()),
                cose: cose.get(&name).cloned(),
                actors: ActorTypes {
                    author: actor(&ctx["actor_type"]["author"]),
                    on_behalf_of: ctx["actor_type"]["on_behalf_of"]
                        .as_array()
                        .map(|rings| rings.iter().map(actor).collect())
                        .unwrap_or_default(),
                },
                origin: Origin::from_wire_name(ctx["origin"].as_str().unwrap()).unwrap(),
                understood: ctx["understood_extensions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| TypeUri::parse(k.as_str().unwrap()).unwrap())
                    .collect(),
            }
        })
        .collect();
    (
        unhex(json(GENESIS)["cases"][0]["hex"].as_str().unwrap()),
        entries,
    )
}

fn recorded_at(envelope: &[u8]) -> u64 {
    match dcbor::decode(envelope, Limits::CEILING)
        .unwrap()
        .get("recorded_at")
    {
        Some(Value::Unsigned(t)) => *t,
        _ => panic!("recorded_at"),
    }
}

// P-5 T-90 P-75 P-100 P-11 T-10 OP-13 T-89
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_5_the_golden_ledger_is_stored_as_received_and_reverifies() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let (bytes, entries) = golden();
    let opened = Genesis {
        ledger: LedgerId::from_bytes(sha256(&bytes)),
        recorded_at_ms: recorded_at(&bytes),
        leaf: leaf_hash(&bytes),
        bytes: bytes.clone(),
        durability: Durability::SingleNode,
    };
    let ledger = opened.ledger;
    Leader::open(&pool, &opened).await.unwrap();
    let mut leader = Leader::acquire(pool, ledger).await.unwrap();
    let directory = Directory::golden();
    let mut kept = Vec::new();
    for (n, g) in entries.iter().enumerate() {
        let arrival = g
            .cose
            .as_deref()
            .map_or(unsigned(&g.record), Arrival::Signed);
        let mut s = submission(arrival, &g.actors);
        s.origin = g.origin;
        s.understood_extensions = &g.understood;
        let record = admit(&directory, &ledger, s).unwrap();
        let committed = leader.commit(recorded_at(&g.envelope), &[record]).await;
        if n == 11 {
            assert!(matches!(
                committed,
                Err(LedgerError::Refused(StoreError::RecordExists))
            ));
        } else {
            committed.unwrap();
            kept.push((n, g));
        }
    }
    let mut tx = env.read("work_app", &ledger).await;
    let stored = tx.entries(0, 100).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(stored.len(), 14);
    assert_eq!(stored[0].record_bytes, bytes);
    let mut at = ChainPoint::genesis(&bytes).unwrap();
    for (s, (n, g)) in stored[1..].iter().zip(kept) {
        assert_eq!(s.record_bytes, g.record);
        assert_eq!(s.cose_sign1, g.cose);
        if n < 11 {
            assert_eq!(s.envelope_bytes, g.envelope);
        }
        let entry = StoredEntry {
            envelope: &s.envelope_bytes,
            record: &s.record_bytes,
            cose_sign1: s.cose_sign1.as_deref(),
        };
        at = verify_entry(&directory, &at, &entry).unwrap().next();
    }
}

// P-80 P-27 T-9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn p_80_a_declaration_effective_before_its_ledger_time_is_rejected_in_the_sequencer() {
    let env = Env::start().await;
    let pool = env.sequencer().await;
    let (bytes, entries) = golden();
    let opened = Genesis {
        ledger: LedgerId::from_bytes(sha256(&bytes)),
        recorded_at_ms: recorded_at(&bytes),
        leaf: leaf_hash(&bytes),
        bytes,
        durability: Durability::SingleNode,
    };
    let ledger = opened.ledger;
    Leader::open(&pool, &opened).await.unwrap();
    let leader = Leader::acquire(pool.clone(), ledger).await.unwrap();
    let permits = Arc::new(Semaphore::new(100));
    let late = AT.checked_mul(2).unwrap();
    let (group, task) =
        GroupCommit::spawn(leader, Gate { permits, at: late }, GroupConfig::default());
    let amend = &entries[3];
    let mut s = submission(unsigned(&amend.record), &amend.actors);
    s.understood_extensions = &amend.understood;
    assert!(matches!(
        group.admit(&Directory::golden(), s).await,
        Err(SubmitError::Rejected(Reason::RetroactiveDeclaration))
    ));
    drop(group);
    task.await.unwrap().unwrap();
    assert_eq!(Leader::acquire(pool, ledger).await.unwrap().head().pos, 0);
}

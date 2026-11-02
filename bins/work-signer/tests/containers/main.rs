//! The ledger acknowledgement end to end against real PostgreSQL 18, a `SoftHSM` token and the
//! signer process (P-20, T-7, T-88, T-90, §18 OP-4, OP-33): the checkpointer signs the head's
//! checkpoint through `work-signer`, stores it as `work_checkpointer`, the records below it
//! become `included`, and the replica takes the log with the received bytes before its progress
//! moves. These tests need Docker, `SoftHSM` and `sudo -n`; `just test-containers` runs them.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

#[path = "../support/mod.rs"]
mod support;

use std::time::Duration;

use serde_json::Value as Json;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash};
use suiss_crypto::note::Verifier;
use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, cosign};
use work_kernel::limits::SemanticLimits;
use work_kernel::proof::verify_checkpoint;
use work_kernel::reason::{Reason, Schema};
use work_kernel::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin};
use work_kernel::verify::{SignatureCheck, SignatureVerifier};
use work_ledger::{
    Arrival, AuthContext, Checkpointer, DirectoryReplica, GenesisInput, Leader, SignerClient,
    Submission, Witness, WitnessError, admit, genesis,
};
use work_store::{
    CheckpointerPool, Cluster, Durability, LedgerId, LedgerTx, Pool, RecordDurability,
    SequencerPool,
};
use work_testkit::Postgres;

use support::{PIN, PREFIX, Signer, Token, module};

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = "ALTER ROLE work_owner LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_sequencer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_checkpointer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_app LOGIN PASSWORD 'test-only-not-a-secret';";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const AT: u64 = 1_792_749_600_123;
const RECORDS: &str = include_str!("../../../../conformance/vectors/records/records.json");
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
            work_store::migrate(&env.pool_on(cluster, "work_owner"), cluster)
                .await
                .unwrap();
        }
        env
    }

    fn pool_on(&self, cluster: Cluster, role: &str) -> Pool {
        let url = format!(
            "postgres://{role}:{PASSWORD}@{}:{}/{}",
            self.pg.host(),
            self.pg.port(),
            cluster.database()
        );
        Pool::connect_lazy(&url).unwrap()
    }

    fn pool(&self, role: &str) -> Pool {
        self.pool_on(Cluster::Canonical, role)
    }
}

/// Signed arrivals are not used here; every check refuses.
struct Unsigned;

impl SignatureVerifier for Unsigned {
    fn check(&self, _cose_sign1: &[u8]) -> SignatureCheck {
        SignatureCheck::Rejected(Reason::Schema(Schema::Container))
    }
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

/// The golden unsigned human comment Claim, declared in `ledger`.
fn comment(ledger: &LedgerId) -> Vec<u8> {
    let records: Json = serde_json::from_str(RECORDS).unwrap();
    let template = &records["records"][4];
    assert_eq!(template["id"], "record/claim-comment-private");
    let mut v = dcbor::decode(&unhex(template["hex"].as_str().unwrap()), Limits::CEILING).unwrap();
    let Value::Map(fields) = &mut v else {
        panic!("record")
    };
    for (key, value) in fields.iter_mut() {
        if matches!(key, Value::Text(k) if k == "ledger") {
            *value = Digest(*ledger.as_bytes()).to_value();
        }
    }
    dcbor::encode(&v, Limits::CEILING).unwrap()
}

// P-20 T-88 OP-4 OP-33 T-90 SEC-32
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn p_20_the_signer_acknowledges_the_head_and_the_replica_takes_the_log() {
    let env = Env::start().await;
    let sequencer = SequencerPool::new(env.pool("work_sequencer"))
        .await
        .unwrap();
    let opened = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x5c; 32],
            nonce: [0x2a; 32],
        },
        Durability::SingleNode,
    )
    .unwrap();
    let ledger = opened.ledger;
    Leader::open(&sequencer, &opened).await.unwrap();
    let mut leader = Leader::acquire(sequencer, ledger).await.unwrap();
    let actors = ActorTypes {
        author: ActorTypeEntry {
            actor_type: ActorType::Human,
            source: ActorTypeSource::AccessBinding,
        },
        on_behalf_of: vec![],
        evidence: vec![],
    };
    let record = comment(&ledger);
    let pending = admit(
        &Unsigned,
        &ledger,
        Submission {
            arrival: Arrival::Unsigned {
                record: &record,
                auth_context: AuthContext {
                    bytes: CONTEXT,
                    assurance: "aal2",
                    step_up: false,
                },
            },
            actor_types: &actors,
            origin: Origin::Direct,
            understood_extensions: &[],
            limits: SemanticLimits::default(),
            event_type: "work.recorded",
            traceparent: TRACE,
            idempotency: None,
            inbound: None,
        },
    )
    .unwrap();
    assert_eq!(leader.commit(AT + 5, &[pending]).await.unwrap(), 1);

    let token = Token::new("containers");
    let signer = Signer::start(&token);
    let pool = CheckpointerPool::new(env.pool("work_checkpointer"))
        .await
        .unwrap();
    let checkpointer = Checkpointer::connect(
        pool,
        SignerClient::new(signer.socket.clone(), Duration::from_secs(5)),
        PREFIX,
    )
    .await
    .unwrap();
    assert_eq!(checkpointer.log_key(), &token.verifier());

    let mut read = LedgerTx::begin(&env.pool("work_app"), &ledger)
        .await
        .unwrap();
    assert_eq!(
        read.durability(1).await.unwrap(),
        Some(RecordDurability::Recorded)
    );
    read.rollback().await.unwrap();

    let stored = checkpointer
        .checkpoint(&ledger, AT + 9)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.size, 2);
    assert_eq!(stored.head_leaf, leader.head().leaf);
    assert_eq!(stored.issued_at_ms, AT + 9);
    let note = String::from_utf8(stored.signed_note.clone()).unwrap();
    let signed =
        verify_checkpoint(&note, &checkpointer.origin(&ledger), &token.verifier(), &[]).unwrap();
    assert_eq!(signed.checkpoint.root, leader.head().frontier.root());
    assert!(signed.cosignatures.is_empty());
    assert!(
        checkpointer
            .checkpoint(&ledger, AT + 10)
            .await
            .unwrap()
            .is_none()
    );

    let mut read = LedgerTx::begin(&env.pool("work_app"), &ledger)
        .await
        .unwrap();
    for pos in [0, 1] {
        assert_eq!(
            read.durability(pos).await.unwrap(),
            Some(RecordDurability::Included)
        );
    }
    read.rollback().await.unwrap();

    let root = token.dir.join("replica");
    let replica = DirectoryReplica::new("local", &root);
    let store = KeyStore::open(&module(), &token.label, &Secret::new(PIN.to_owned())).unwrap();
    let cosigner = store.generate_ed25519("witness.v1").unwrap();
    let PublicKey::Ed25519(witness_key) = cosigner.public_key() else {
        panic!("an Ed25519 key");
    };
    let witnesses = [Witness {
        id: "witness_a".to_owned(),
        key: Verifier::cosigner("witness.example", witness_key).unwrap(),
    }];
    let body = signed.checkpoint.to_body().unwrap();
    let (_, cosignature) = cosign(&cosigner, "witness.example", AT / 1000 + 20, &body).unwrap();
    let cosigned = format!("{note}{cosignature}");
    assert!(matches!(
        checkpointer
            .take_cosignatures(&ledger, 2, &cosigned, &replica, &witnesses)
            .await,
        Err(WitnessError::Order(_))
    ));
    assert_eq!(checkpointer.mirror(&ledger, &replica).await.unwrap(), 2);
    assert_eq!(checkpointer.mirror(&ledger, &replica).await.unwrap(), 2);
    let dir = root.join(ledger.to_hex());
    assert_eq!(
        leaf_hash(&std::fs::read(dir.join("log").join(format!("{:020}", 0))).unwrap()),
        opened.leaf
    );
    assert_eq!(
        std::fs::read(dir.join("received").join(format!("{:020}.auth_context", 1))).unwrap(),
        CONTEXT
    );
    assert_eq!(
        std::fs::read(dir.join("checkpoint").join(format!("{:020}", 2))).unwrap(),
        stored.signed_note
    );

    assert_eq!(
        checkpointer
            .take_cosignatures(&ledger, 2, &cosigned, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        checkpointer
            .take_cosignatures(&ledger, 2, &cosigned, &replica, &witnesses)
            .await
            .unwrap(),
        0
    );
    let mut read = LedgerTx::begin(&env.pool("work_app"), &ledger)
        .await
        .unwrap();
    assert_eq!(
        read.durability(1).await.unwrap(),
        Some(RecordDurability::Witnessed)
    );
    read.rollback().await.unwrap();
}

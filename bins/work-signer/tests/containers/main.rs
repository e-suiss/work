//! The ledger acknowledgement end to end against real PostgreSQL 18, a `SoftHSM` token and the
//! signer process (P-20, T-7, T-88, T-90, §18 OP-4, OP-33, OP-46): the checkpointer signs the
//! head's checkpoint with its profile lines through `work-signer`, stores it as
//! `work_checkpointer`, the records below it become `included`, the replica takes the log with
//! the received bytes before its progress moves, and a record becomes `witnessed` only under
//! `witness independent k` with k configured witnesses' cosignatures. A real C2SP witness,
//! litewitness in the container the local environment builds, cosigns each mirrored checkpoint
//! from the size it holds, its cosignature times check ledger time, and the gossip comparison
//! decides what it holds against the ledger's tree (OP-32, OP-33, OP-46 item 10, SEC-32). These
//! tests need Docker, `SoftHSM` and `sudo -n`; `just test-containers` runs them.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    reason = "test code"
)]

#[path = "../support/mod.rs"]
mod support;
mod worm;

use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value as Json;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::{Digest, leaf_hash};
use suiss_crypto::note::Verifier;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, cosign};
use work_kernel::limits::SemanticLimits;
use work_kernel::proof::{Accepted, TimeSources, WitnessProfile, verify_checkpoint};
use work_kernel::reason::{Reason, Schema};
use work_kernel::validate::{ActorType, ActorTypeEntry, ActorTypeSource, ActorTypes, Origin};
use work_kernel::verify::{SignatureCheck, SignatureVerifier};
use work_ledger::time::WitnessRound;
use work_ledger::{
    Arrival, AuthContext, Cadence, CheckpointSetup, CheckpointStats, Checkpointer, Clock,
    ClockError, Comparison, DEFAULT_WITNESS_TIMEOUT, Declaration, Deployment, DirectoryReplica,
    GenesisInput, GroupConfig, Leader, Ledgers, Node, PendingRecord, Rng, RngError, SignerClient,
    Submission, Witness, WitnessClient, WitnessEndpoint, WitnessError, WitnessPass, WitnessRole,
    WitnessStates, admit, genesis, run_checkpoints,
};
use work_store::{
    CellId, CheckpointerPool, Cluster, Durability, Genesis, LedgerId, LedgerTx, Pool,
    RecordDurability, SequencerPool, WitnessObservation,
};
use work_testkit::{LiteWitness, Postgres};

use support::{PIN, PREFIX, Signer, Token, module};

#[derive(Debug)]
struct Holder(u8);

impl Rng for Holder {
    fn fill(&self, out: &mut [u8]) -> Result<(), RngError> {
        out.fill(self.0);
        Ok(())
    }
}

fn cell() -> CellId {
    CellId::new("local").unwrap()
}

fn node() -> Node {
    Node::new(cell(), &Holder(1)).unwrap()
}

const PASSWORD: &str = "test-only-not-a-secret";
const LOGINS: &str = "ALTER ROLE work_owner LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_sequencer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_checkpointer LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_app LOGIN PASSWORD 'test-only-not-a-secret';\nALTER ROLE work_deriver LOGIN PASSWORD 'test-only-not-a-secret';";
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

/// A ledger opened with the schema digest byte `schema`, only its genesis, and its leader.
async fn opened_ledger(env: &Env, schema: u8) -> (Genesis, Leader) {
    let sequencer = SequencerPool::new(env.pool("work_sequencer"))
        .await
        .unwrap();
    let opened = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [schema; 32],
            nonce: [0x2a; 32],
        },
        Durability::SingleNode,
    )
    .unwrap();
    Leader::open(&sequencer, &opened, &cell()).await.unwrap();
    let leader = Leader::acquire(sequencer, opened.ledger, &node())
        .await
        .unwrap();
    (opened, leader)
}

/// The golden human comment admitted into `ledger`.
fn admitted_comment(ledger: &LedgerId) -> PendingRecord {
    let actors = ActorTypes {
        author: ActorTypeEntry {
            actor_type: ActorType::Human,
            source: ActorTypeSource::AccessBinding,
        },
        on_behalf_of: vec![],
        evidence: vec![],
    };
    let record = comment(ledger);
    admit(
        &Unsigned,
        ledger,
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
    .unwrap()
}

/// A ledger opened with the schema digest byte `schema` and one human comment after its
/// genesis, and its leader.
async fn ledger_with_comment(env: &Env, schema: u8) -> (Genesis, Leader) {
    let (opened, mut leader) = opened_ledger(env, schema).await;
    let pending = admitted_comment(&opened.ledger);
    assert_eq!(leader.commit(AT + 5, &[pending]).await.unwrap(), 1);
    (opened, leader)
}

/// A checkpointer whose checkpoints declare `witness` under dependent time sources.
async fn checkpointer(env: &Env, signer: &Signer, witness: WitnessProfile) -> Checkpointer {
    let pool = CheckpointerPool::new(env.pool("work_checkpointer"))
        .await
        .unwrap();
    let declared = Declaration::new(Deployment::SelfHost, TimeSources::Dependent, witness).unwrap();
    Checkpointer::connect(
        pool,
        SignerClient::new(signer.socket.clone(), Duration::from_secs(5)),
        PREFIX,
        declared,
    )
    .await
    .unwrap()
}

async fn durability(env: &Env, ledger: &LedgerId, pos: u64) -> Option<RecordDurability> {
    let mut read = LedgerTx::begin(&env.pool("work_app"), ledger)
        .await
        .unwrap();
    let state = read.durability(pos).await.unwrap();
    read.rollback().await.unwrap();
    state
}

/// A configured witness with its key in the token.
struct Cosigner {
    key: HsmSigner,
    name: &'static str,
    witness: Witness,
}

fn cosigner(store: &KeyStore, label: &str, id: &str, name: &'static str) -> Cosigner {
    let key = store.generate_ed25519(label).unwrap();
    let PublicKey::Ed25519(public) = key.public_key() else {
        panic!("an Ed25519 key");
    };
    Cosigner {
        key,
        name,
        witness: Witness {
            id: id.to_owned(),
            key: Verifier::cosigner(name, public).unwrap(),
        },
    }
}

/// `note` with the cosignatures of `by` appended.
fn cosigned(note: &str, origin: &str, log: &Verifier, by: &[&Cosigner]) -> String {
    let body = verify_checkpoint(note, origin, log, &[])
        .unwrap()
        .checkpoint
        .to_body()
        .unwrap();
    let mut out = note.to_owned();
    for witness in by {
        let (_, line) = cosign(&witness.key, witness.name, AT / 1000 + 20, &body).unwrap();
        out.push_str(&line);
    }
    out
}

fn one() -> WitnessProfile {
    WitnessProfile::Independent(NonZeroU8::MIN)
}

// P-20 T-88 OP-4 OP-33 OP-46 T-90 SEC-32
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn p_20_the_signer_acknowledges_the_head_and_the_replica_takes_the_log() {
    let env = Env::start().await;
    let (opened, leader) = ledger_with_comment(&env, 0x5c).await;
    let ledger = opened.ledger;

    let token = Token::new("containers");
    let signer = Signer::start(&token);
    let local = checkpointer(&env, &signer, WitnessProfile::LocalDependent).await;
    assert_eq!(local.log_key(), &token.verifier());
    assert_eq!(
        durability(&env, &ledger, 1).await,
        Some(RecordDurability::Recorded)
    );

    let stored = local.checkpoint(&ledger, AT + 9).await.unwrap().unwrap();
    assert_eq!(stored.size, 2);
    assert_eq!(stored.head_leaf, leader.head().leaf);
    assert_eq!(stored.issued_at_ms, AT + 9);
    let note = String::from_utf8(stored.signed_note.clone()).unwrap();
    let verified =
        verify_checkpoint(&note, &local.origin(&ledger), &token.verifier(), &[]).unwrap();
    assert_eq!(verified.checkpoint.root, leader.head().frontier.root());
    assert_eq!(verified.cosignatures, Vec::<Accepted>::new());
    assert_eq!(
        verified.profile,
        local.declaration().profile(Durability::SingleNode)
    );
    assert!(local.checkpoint(&ledger, AT + 10).await.unwrap().is_none());
    for pos in [0, 1] {
        assert_eq!(
            durability(&env, &ledger, pos).await,
            Some(RecordDurability::Included)
        );
    }

    let root = token.dir.join("replica");
    let replica = DirectoryReplica::new("local", &root);
    let store = KeyStore::open(&module(), &token.label, &Secret::new(PIN.to_owned())).unwrap();
    let first = cosigner(&store, "witness.v1", "witness_a", "witness.example");
    let second = cosigner(&store, "witness.v2", "witness_b", "witness-b.example");
    let witnesses = [first.witness.clone(), second.witness.clone()];
    let witnessed_note = cosigned(&note, &local.origin(&ledger), &token.verifier(), &[&first]);
    assert!(matches!(
        local
            .take_cosignatures(&ledger, 2, &witnessed_note, &replica, &witnesses)
            .await,
        Err(WitnessError::Order(_))
    ));
    assert_eq!(local.mirror(&ledger, &replica).await.unwrap(), 2);
    assert_eq!(local.mirror(&ledger, &replica).await.unwrap(), 2);
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
        local
            .take_cosignatures(&ledger, 2, &witnessed_note, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        local
            .take_cosignatures(&ledger, 2, &witnessed_note, &replica, &witnesses)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        durability(&env, &ledger, 1).await,
        Some(RecordDurability::Included)
    );

    let (opened, _leader) = ledger_with_comment(&env, 0x5d).await;
    let single = opened.ledger;
    let hosted = checkpointer(&env, &signer, one()).await;
    let stored = hosted.checkpoint(&single, AT + 9).await.unwrap().unwrap();
    let note = String::from_utf8(stored.signed_note).unwrap();
    assert_eq!(hosted.mirror(&single, &replica).await.unwrap(), 2);
    let first_only = cosigned(&note, &hosted.origin(&single), &token.verifier(), &[&first]);
    assert_eq!(
        hosted
            .take_cosignatures(&single, 2, &first_only, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        durability(&env, &single, 1).await,
        Some(RecordDurability::Witnessed)
    );

    let (opened, _leader) = ledger_with_comment(&env, 0x5e).await;
    let pair = opened.ledger;
    let two = WitnessProfile::Independent(NonZeroU8::MIN.saturating_add(1));
    let saas_like = checkpointer(&env, &signer, two).await;
    let stored = saas_like.checkpoint(&pair, AT + 9).await.unwrap().unwrap();
    let note = String::from_utf8(stored.signed_note).unwrap();
    assert_eq!(saas_like.mirror(&pair, &replica).await.unwrap(), 2);
    let origin = saas_like.origin(&pair);
    let first_only = cosigned(&note, &origin, &token.verifier(), &[&first]);
    assert_eq!(
        saas_like
            .take_cosignatures(&pair, 2, &first_only, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        durability(&env, &pair, 1).await,
        Some(RecordDurability::Included)
    );
    let second_only = cosigned(&note, &origin, &token.verifier(), &[&second]);
    assert_eq!(
        saas_like
            .take_cosignatures(&pair, 2, &second_only, &replica, &witnesses)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        durability(&env, &pair, 1).await,
        Some(RecordDurability::Witnessed)
    );
}

/// Ledger time fixed at one instant.
#[derive(Clone)]
struct Fixed(u64);

impl Clock for Fixed {
    fn now(&mut self) -> impl Future<Output = Result<u64, ClockError>> + Send {
        std::future::ready(Ok(self.0))
    }
}

// OP-33 P-20 OP-4 T-90 T-85
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn op_33_a_led_ledger_is_checkpointed_on_its_cadence_and_mirrored() {
    let env = Env::start().await;
    let sequencer = SequencerPool::new(env.pool("work_sequencer"))
        .await
        .unwrap();
    let opened = genesis(
        &GenesisInput {
            recorded_at_ms: AT,
            protocol: (1, 0),
            schema: [0x3c; 32],
            nonce: [0x2a; 32],
        },
        Durability::SingleNode,
    )
    .unwrap();
    let ledger = opened.ledger;
    Leader::open(&sequencer, &opened, &cell()).await.unwrap();
    let clock = Fixed(AT + 5);
    let ledgers = Arc::new(Ledgers::new(
        sequencer,
        node(),
        clock,
        GroupConfig::default(),
    ));
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
    assert_eq!(ledgers.submit(&ledger, pending).await.unwrap().pos, 1);
    assert_eq!(ledgers.led().await, [ledger]);

    let token = Token::new("cadence");
    let signer = Signer::start(&token);
    let root = token.dir.join("replica");
    let setup = CheckpointSetup {
        pool: CheckpointerPool::new(env.pool("work_checkpointer"))
            .await
            .unwrap(),
        signer: SignerClient::new(signer.socket.clone(), Duration::from_secs(5)),
        origin_prefix: PREFIX.to_owned(),
        replica: DirectoryReplica::new("local", &root).into(),
        cadence: Cadence::new(Duration::from_secs(3600), 1).unwrap(),
        declaration: Declaration::new(
            Deployment::SelfHost,
            TimeSources::Dependent,
            WitnessProfile::LocalDependent,
        )
        .unwrap(),
    };
    let stats = Arc::new(CheckpointStats::default());
    let task = tokio::spawn(run_checkpoints(
        Arc::clone(&ledgers),
        setup,
        Arc::clone(&stats),
    ));
    let mirrored = tokio::time::timeout(Duration::from_secs(30), async {
        while stats.mirrored() == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    task.abort();
    assert!(mirrored.is_ok(), "nothing was mirrored");
    assert!(stats.signer_connected());
    assert_eq!(stats.stored(), 1);
    assert_eq!(stats.failed(), 0);
    let dir = root.join(ledger.to_hex());
    assert!(dir.join("checkpoint").join(format!("{:020}", 2)).exists());
    assert!(dir.join("log").join(format!("{:020}", 1)).exists());
    let mut read = LedgerTx::begin(&env.pool("work_app"), &ledger)
        .await
        .unwrap();
    assert_eq!(
        read.durability(1).await.unwrap(),
        Some(RecordDurability::Included)
    );
    read.rollback().await.unwrap();
}

fn endpoint(witness: &LiteWitness, id: &str, role: WitnessRole) -> WitnessEndpoint {
    WitnessEndpoint {
        witness: Witness {
            id: id.to_owned(),
            key: Verifier::parse(witness.vkey()).unwrap(),
        },
        role,
        client: WitnessClient::new(witness.url(), None, DEFAULT_WITNESS_TIMEOUT).unwrap(),
    }
}

async fn pending_observations(derived: &Pool, ledger: &LedgerId) -> Vec<WitnessObservation> {
    let mut tx = LedgerTx::begin(derived, ledger).await.unwrap();
    let rows = tx.pending_observations(100).await.unwrap();
    tx.commit().await.unwrap();
    rows
}

// OP-46 OP-33 OP-4 OP-32 SEC-32 T-41 OP-48
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker, SoftHSM and sudo"]
async fn op_46_a_real_witness_cosigns_each_mirrored_checkpoint_from_the_size_it_holds() {
    let env = Env::start().await;
    let token = Token::new("witness");
    let signer = Signer::start(&token);
    let (opened, mut leader) = opened_ledger(&env, 0x6a).await;
    let ledger = opened.ledger;
    let hosted = checkpointer(&env, &signer, one()).await;
    let (local_opened, _local_leader) = ledger_with_comment(&env, 0x6b).await;
    let local_ledger = local_opened.ledger;
    let local = checkpointer(&env, &signer, WitnessProfile::LocalDependent).await;
    let vkey = token.verifier().to_vkey();
    let (origin, local_origin) = (hosted.origin(&ledger), local.origin(&local_ledger));
    let witness = LiteWitness::start(&[(&origin, &vkey), (&local_origin, &vkey)])
        .await
        .unwrap();
    let derived = env.pool_on(Cluster::Derived, "work_deriver");
    let replica = DirectoryReplica::new("local", token.dir.join("replica"));
    let counted = [endpoint(&witness, "local_witness", WitnessRole::Counted)];
    let mut states = WitnessStates::default();

    let first = hosted.checkpoint(&ledger, AT + 1).await.unwrap().unwrap();
    assert_eq!(first.size, 1);
    let unmirrored = hosted
        .witness_pass(&ledger, &replica, &derived, &counted, &mut states, false)
        .await
        .unwrap();
    assert_eq!(unmirrored, WitnessPass::default());
    assert_eq!(hosted.mirror(&ledger, &replica).await.unwrap(), 1);
    let pass = hosted
        .witness_pass(&ledger, &replica, &derived, &counted, &mut states, false)
        .await
        .unwrap();
    assert_eq!(pass.size, Some(1));
    assert_eq!((pass.asked, pass.stored, pass.observed), (1, 1, 1));
    assert_eq!(pass.time_round(), Some(WitnessRound::Agreed(1)));
    assert_eq!(
        durability(&env, &ledger, 0).await,
        Some(RecordDurability::Witnessed)
    );
    let idle = hosted
        .witness_pass(&ledger, &replica, &derived, &counted, &mut states, false)
        .await
        .unwrap();
    assert_eq!((idle.asked, idle.stored), (0, 0));

    let pending = admitted_comment(&ledger);
    assert_eq!(leader.commit(AT + 5, &[pending]).await.unwrap(), 1);
    let second = hosted.checkpoint(&ledger, AT + 9).await.unwrap().unwrap();
    assert_eq!(second.size, 2);
    assert_eq!(hosted.mirror(&ledger, &replica).await.unwrap(), 2);
    let grown = hosted
        .witness_pass(&ledger, &replica, &derived, &counted, &mut states, false)
        .await
        .unwrap();
    assert_eq!((grown.size, grown.stored), (Some(2), 1));
    assert_eq!(
        durability(&env, &ledger, 1).await,
        Some(RecordDurability::Witnessed)
    );

    let mut forgotten = WitnessStates::default();
    let conflict = hosted
        .witness_pass(&ledger, &replica, &derived, &counted, &mut forgotten, false)
        .await
        .unwrap();
    assert_eq!((conflict.asked, conflict.stored), (1, 0));
    assert_eq!(conflict.cosigned_seconds.len(), 1);

    let both = [
        endpoint(&witness, "local_witness", WitnessRole::Counted),
        endpoint(&witness, "suiss_gossip", WitnessRole::Gossip),
    ];
    let local_cp = local
        .checkpoint(&local_ledger, AT + 9)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        local.mirror(&local_ledger, &replica).await.unwrap(),
        local_cp.size
    );
    let local_pass = local
        .witness_pass(&local_ledger, &replica, &derived, &both, &mut states, false)
        .await
        .unwrap();
    assert_eq!(local_pass.asked, 1);
    assert_eq!(local_pass.stored, 1);
    assert_eq!(local_pass.cosigned_seconds.len(), 1);
    assert_eq!(
        durability(&env, &local_ledger, 1).await,
        Some(RecordDurability::Included)
    );

    let tampered = WitnessObservation {
        witness_id: "suiss_gossip".to_owned(),
        size: 1,
        root: [0xee; 32],
    };
    let beyond = WitnessObservation {
        witness_id: "suiss_gossip".to_owned(),
        size: 99,
        root: second.root,
    };
    let mut tx = LedgerTx::begin(&derived, &ledger).await.unwrap();
    assert!(tx.observe_checkpoint(&tampered).await.unwrap());
    assert!(tx.observe_checkpoint(&beyond).await.unwrap());
    tx.commit().await.unwrap();
    assert_eq!(pending_observations(&derived, &ledger).await.len(), 4);
    assert_eq!(
        hosted
            .compare_observations(&ledger, &derived)
            .await
            .unwrap(),
        Comparison {
            consistent: 2,
            inconsistent: 2,
        }
    );
    assert_eq!(
        pending_observations(&derived, &ledger).await,
        Vec::<WitnessObservation>::new()
    );
    assert_eq!(
        local
            .compare_observations(&local_ledger, &derived)
            .await
            .unwrap(),
        Comparison {
            consistent: 2,
            inconsistent: 0,
        }
    );
}

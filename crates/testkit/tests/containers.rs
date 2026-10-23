//! Real PostgreSQL 18 and NATS JetStream through the testkit (T-36 rule 7, T-37
//! rule 9). These tests need Docker; `just test-containers` runs them.

#![allow(clippy::unwrap_used, reason = "test code")]

use futures_util::StreamExt;
use work_testkit::{Nats, Postgres, TestDatabase};

const LARGE_OBJECT_SOURCE: &str = "/etc/hostname";

async fn large_objects(pg: &Postgres, db: &str) -> usize {
    pg.client(&["psql", "-X", "-tA", "-d", db, "-c", "\\lo_list"])
        .await
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

async fn assert_copies_are_isolated() {
    let pg = Postgres::start().await.unwrap();
    let (a, b): (TestDatabase, TestDatabase) =
        tokio::try_join!(pg.database(), pg.database()).unwrap();
    assert_ne!(a.name(), b.name());
    assert_ne!(a.url(), b.url());
    let import = format!("\\lo_import {LARGE_OBJECT_SOURCE}");
    pg.client(&[
        "psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        a.name(),
        "-c",
        &import,
    ])
    .await
    .unwrap();
    assert_eq!(large_objects(&pg, a.name()).await, 1);
    assert_eq!(large_objects(&pg, b.name()).await, 0);
    assert_eq!(large_objects(&pg, "work_template").await, 0);
    let c = pg.database().await.unwrap();
    assert_eq!(large_objects(&pg, c.name()).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_parallel_test_one_gets_its_own_database_copies() {
    assert_copies_are_isolated().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_parallel_test_two_gets_its_own_database_copies() {
    assert_copies_are_isolated().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_postgres_major_version_is_18() {
    let pg = Postgres::start().await.unwrap();
    assert_eq!(pg.server_major_version().await.unwrap(), "18");
    let db = pg.database().await.unwrap();
    let version = pg
        .client(&[
            "psql",
            "-X",
            "-tA",
            "-d",
            db.name(),
            "-c",
            "SHOW server_version_num",
        ])
        .await
        .unwrap();
    assert!(version.trim().starts_with("18"), "{version}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker"]
async fn t_36_jetstream_publish_and_consume() {
    let nats = Nats::start().await.unwrap();
    let js = nats.jetstream().await.unwrap();
    assert!(js.query_account().await.is_ok());
    let stream = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "TESTKIT".to_owned(),
            subjects: vec!["testkit.>".to_owned()],
            ..Default::default()
        })
        .await
        .unwrap();
    let ack = js
        .publish("testkit.probe", "probe-1".into())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(ack.stream, "TESTKIT");
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            durable_name: Some("testkit".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut batch = consumer.fetch().max_messages(1).messages().await.unwrap();
    let message = batch.next().await.unwrap().unwrap();
    assert_eq!(message.subject.as_str(), "testkit.probe");
    assert_eq!(message.payload.as_ref(), b"probe-1");
    message.ack().await.unwrap();
}

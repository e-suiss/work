//! Shared test helpers: real PostgreSQL 18, NATS JetStream and S3-compatible containers pinned to
//! the digests of the local environment, the C2SP witness the local environment builds, a
//! template database with a fresh copy per test, a virtual clock, seeded generators and record
//! builders (T-36, T-37).

mod database;
mod error;
mod images;
mod nats;
mod s3;
mod witness;

pub use database::{Postgres, TestDatabase};
pub use error::TestkitError;
pub use images::{ImageRef, compose_image};
pub use nats::Nats;
pub use s3::{S3, S3_KEY_ID, S3_SECRET};
pub use witness::{LiteWitness, WITNESS_IMAGE, WITNESS_NAME};

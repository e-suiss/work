//! Shared test helpers: real PostgreSQL 18 and NATS JetStream containers pinned to
//! the digests of the local environment, a template database with a fresh copy per
//! test, a virtual clock, seeded generators and record builders (T-36, T-37).

mod database;
mod error;
mod images;
mod nats;

pub use database::{Postgres, TestDatabase};
pub use error::TestkitError;
pub use images::{ImageRef, compose_image};
pub use nats::Nats;

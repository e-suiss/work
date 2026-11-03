//! Query service, permitted next transitions, incremental sync (T-13, T-14, T-26), and the read
//! position token with its bounded wait (T-97).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

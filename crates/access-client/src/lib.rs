//! Access public API client (T-8, T-28, T-96, T-99, T-101; Access OP-149): the single Access issuer setting and Suiss discovery, Relay's discovery document, the PEP client certificate from the PKCS#11 token, Instance key lookup verified under the domain's operational key with its `Access-Key-Excerpt`, the eligibility check, the realm token keys an `auth_context` artifact verifies under, and the tenant snapshots with their reconciliation.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

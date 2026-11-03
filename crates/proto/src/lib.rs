//! Record, event and API types, checked against the CDDL and test vectors (T-35), the external
//! standard mappings of a record (P-48), the frames of the `work-signer` socket (T-7), the
//! frames of the parser worker's pipes (T-72), the prefixed external identifiers (P-112) and the
//! Access action catalog (E-45).

#![no_std]

extern crate alloc;

pub mod action;
pub mod id;
pub mod mapping;
pub mod parser;
pub mod signer;

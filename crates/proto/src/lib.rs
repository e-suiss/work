//! Record, event and API types, checked against the CDDL and test vectors (T-35), the frames of
//! the `work-signer` socket (T-7) and the frames of the parser worker's pipes (T-72).

#![no_std]

extern crate alloc;

pub mod parser;
pub mod signer;

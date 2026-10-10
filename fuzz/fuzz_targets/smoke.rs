//! Harness smoke target; parser targets are added with their parsers (T-37).

#![no_main]

use libfuzzer_sys::fuzz_target;
use work_kernel::ApiVersion;

fuzz_target!(|data: [u8; 4]| {
    let [a, b, c, d] = data;
    let left = ApiVersion {
        major: u16::from_le_bytes([a, b]),
        minor: u16::from_le_bytes([c, d]),
    };
    let right = ApiVersion {
        major: left.minor,
        minor: left.major,
    };
    let _ = left.cmp(&right) == right.cmp(&left).reverse();
});

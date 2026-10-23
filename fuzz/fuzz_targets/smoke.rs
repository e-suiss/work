//! Harness smoke target: `ApiVersion` ordering is antisymmetric and lexicographic over (major, minor); parser targets are added with their parsers (T-37).

#![no_main]

use libfuzzer_sys::fuzz_target;
use work_kernel::ApiVersion;

fuzz_target!(|data: [u8; 8]| {
    let [a, b, c, d, e, f, g, h] = data;
    let left = ApiVersion {
        major: u16::from_le_bytes([a, b]),
        minor: u16::from_le_bytes([c, d]),
    };
    let right = ApiVersion {
        major: u16::from_le_bytes([e, f]),
        minor: u16::from_le_bytes([g, h]),
    };
    assert_eq!(left.cmp(&right), right.cmp(&left).reverse());
    assert_eq!(
        left.cmp(&right),
        (left.major, left.minor).cmp(&(right.major, right.minor))
    );
    assert_eq!(left == right, left.cmp(&right).is_eq());
});

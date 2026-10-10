//! Wall-clock micro-benchmarks for the kernel (T-44, T-62).

use divan::black_box;
use work_kernel::{API_VERSION, ApiVersion};

fn main() {
    divan::main();
}

/// Kernel API version comparison, the first hot path until derivation lands (T-44 rule 1).
#[divan::bench]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

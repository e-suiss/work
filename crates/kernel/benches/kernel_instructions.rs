//! Instruction-count benchmarks for the kernel (T-44, T-60).

#![allow(
    missing_docs,
    reason = "gungraun macros generate undocumented public items in this bench binary"
)]

#[cfg(target_os = "linux")]
use std::hint::black_box;

#[cfg(target_os = "linux")]
use gungraun::{library_benchmark, library_benchmark_group, main};
#[cfg(target_os = "linux")]
use work_kernel::{API_VERSION, ApiVersion};

// T-44
#[cfg(target_os = "linux")]
#[library_benchmark]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

#[cfg(target_os = "linux")]
library_benchmark_group!(name = kernel, benchmarks = [api_version_compare]);

#[cfg(target_os = "linux")]
main!(library_benchmark_groups = kernel);

#[cfg(not(target_os = "linux"))]
fn main() {}

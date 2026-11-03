//! Prints the `OpenAPI` document that `cargo xtask openapi` writes to `sdks/openapi/work-v1.json` (T-98 item 1).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the document goes to standard output for xtask"
)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match work_http::openapi::document() {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openapi: {error}");
            ExitCode::FAILURE
        }
    }
}

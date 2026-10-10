//! Work signer process: ledger acknowledgements, checkpoints and event signatures through PKCS#11 (T-7, T-56).

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    #[allow(
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "command line output"
    )]
    if arg.as_deref() == Some("--version") {
        println!("work-signer {}", env!("CARGO_PKG_VERSION"));
        ExitCode::SUCCESS
    } else {
        eprintln!("usage: work-signer --version");
        ExitCode::from(2)
    }
}

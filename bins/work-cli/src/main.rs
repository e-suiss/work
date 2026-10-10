//! Work command line: administration, export, replay and offline verification.

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    #[allow(
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "command line output"
    )]
    if arg.as_deref() == Some("--version") {
        println!("work-cli {}", env!("CARGO_PKG_VERSION"));
        ExitCode::SUCCESS
    } else {
        eprintln!("usage: work-cli --version");
        ExitCode::from(2)
    }
}

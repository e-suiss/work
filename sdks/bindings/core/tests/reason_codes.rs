//! The TypeScript reason code union in `packages/kernel/src/reasons.ts` is the kernel's `Reason::ALL`, rendered by this test; `WORK_WRITE_GENERATED=1` rewrites the file (T-41, T-69, P-11).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::fmt::Write as _;
use std::path::Path;

use work_kernel::reason::{QuarantineReason, Reason};

const FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../packages/kernel/src/reasons.ts"
);

const PRINT_WIDTH: usize = 100;

fn list(out: &mut String, name: &str, codes: impl Iterator<Item = String>) {
    let quoted: Vec<String> = codes.map(|c| format!("\"{c}\"")).collect();
    let line = format!("export const {name} = [{}] as const;", quoted.join(", "));
    if line.len() <= PRINT_WIDTH {
        writeln!(out, "{line}").unwrap();
        return;
    }
    writeln!(out, "export const {name} = [").unwrap();
    for code in quoted {
        writeln!(out, "  {code},").unwrap();
    }
    writeln!(out, "] as const;").unwrap();
}

fn render() -> String {
    let mut out = String::from("// T-69 P-11 P-19 P-71\n");
    list(
        &mut out,
        "REASON_CODES",
        Reason::ALL.iter().map(ToString::to_string),
    );
    out.push('\n');
    list(
        &mut out,
        "QUARANTINE_CODES",
        QuarantineReason::ALL.iter().map(ToString::to_string),
    );
    out.push_str(
        "\n/** A reason code the kernel decides with (P-11). */\n\
         export type ReasonCode = (typeof REASON_CODES)[number];\n\
         \n\
         /** A reason that quarantines a record and never rejects it (P-19, P-87). */\n\
         export type QuarantineCode = (typeof QUARANTINE_CODES)[number];\n\
         \n\
         /** A code as a caller may write it: a kernel code, optionally with a namespaced sub-code that reads as its parent (P-71). */\n\
         export type WithSubCode<Code extends string> = Code | `${Code}:https://${string}`;\n",
    );
    out
}

// T-41 T-69 P-11
#[test]
fn t_69_typescript_reason_codes_are_the_kernel_codes() {
    let expected = render();
    if std::env::var_os("WORK_WRITE_GENERATED").is_some() {
        std::fs::write(Path::new(FILE), &expected).unwrap();
    }
    let actual = std::fs::read_to_string(FILE).unwrap_or_default();
    assert!(
        actual == expected,
        "packages/kernel/src/reasons.ts is stale: WORK_WRITE_GENERATED=1 cargo test -p work-bindings-core --test reason_codes"
    );
}

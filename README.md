# Work

**Open-source coordination of work between people, AI agents, systems and machines.**

Work answers the questions every team and every agent fleet keeps asking: who has this, what was promised to whom, what are we waiting on, what is blocked, which decision is pending — and whose attention is needed right now. It records commitments, not just tasks, and keeps a signed history of who said what, when, and on whose behalf.

[![CI](https://github.com/e-suiss/work/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/e-suiss/work/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)

---

## Status

Work is pre-alpha and not ready for production use; 0.x releases are published as pre-releases. What exists today:

- **Kernel** — `work-kernel`, a `no_std` Rust library that validates records and derives state from them, with no I/O, no `unsafe` and checked arithmetic
- **Record format** — a CDDL schema with golden test vectors in JSON and CBOR that every implementation must reproduce byte for byte
- **Bindings** — WebAssembly with a TypeScript wrapper, and uniffi for Swift and Kotlin; differential tests run the same vectors through Rust, Node.js, Swift, Chromium, Firefox and WebKit
- **CI gates** — formatting, Clippy, repository rules, cargo-deny, cargo-vet, a 7-day dependency cooldown, CodeQL, Semgrep, secret scanning, instruction-count benchmarks, and signed releases with provenance and SBOM attestations
- **Local environment** — PostgreSQL, NATS, SoftHSM, an observability stack and the real Access and Relay services, started with one command

Everything under [What Work is designed to do](#what-work-is-designed-to-do) is the target design; it lands stage by stage.

## Why Work

Task boards track cards in columns. Real work is made of promises: someone asks, someone commits, someone delivers, and someone accepts. When a promise slips, the people who depend on it should know — before the deadline, not after.

AI agents make this harder. An agent can take work, run for hours on another machine, get stuck on a question, or need a human to approve a step. Work gives humans and agents one shared record of commitments, waits and decisions, and puts the few things that actually need a person in front of that person.

Work is not designed around any profession or tool. Software teams, operations, support, finance and robot fleets use the same core; domain vocabulary is added as Practices on top.

## What Work is designed to do

**Commitments, not just tasks**
- Request → promise → deliver → accept, with counter-offers, conditional promises and four-eyes acceptance
- Delegation keeps the original promise visible; sub-commitments roll risk up the chain
- Budgets, SLAs, periodic updates, implicit acceptance windows and amendments
- Every change is a typed, signed record; state is derived from records, never edited by hand

**Attention**
- Needs Attention: only items that need *you*, why now, and what happens if you wait
- Briefing: what meaningfully changed while you were away — and then it ends
- Addressed waits: every "waiting on…" names who or what it waits for
- Escalation policies delivered through Relay; muting never stops the clock

**People and AI agents together**
- Give work to an agent fleet across machines, watch progress live, and step in when needed
- Accountable owner, single driver and control hand-off; stop requests and takeover through Access Executor
- Gates for decisions, delivery acceptance and plan approval; approvals are never inferred from a chat message
- Agent output is evidence, never authority; agent rationale is visible to the people who own the work

**Trust and history**
- Append-only, signed ledger with checkpoints and independent witnesses
- Evidence and provenance on every claim; offline verification of any record
- Cross-organization work where the origin owns its records, with selective disclosure and receipts
- No physical deletes; personal data erasure by crypto-shredding

**Open and extensible**
- Practices: domain templates, record subtypes and rules — authored in a visual editor, as YAML, or with an SDK
- REST API, CloudEvents, signed webhooks, A2A and MCP
- Import from Jira, Linear or CSV
- Web app and mobile app with an offline queue for signed statements

## How it works

```mermaid
flowchart LR
    ask(["Request<br/>person · agent · system"]) --> promise["Promise<br/>scope · due · acceptor"]
    promise --> work["Work in progress<br/>waits · gates · sub-commitments"]
    work --> deliver["Deliver<br/>evidence"]
    deliver --> accept{"Accept?"}
    accept -- yes --> done(["Closed"])
    accept -- no --> work
    work -. "slipping · blocked · decision needed" .-> attention["Needs Attention<br/>the right person, now"]
```

```mermaid
flowchart TB
    people["People<br/>web · mobile"] <--> work
    agents["AI agents<br/>A2A · MCP"] <--> work
    systems["Systems and machines<br/>API · CloudEvents"] --> work
    subgraph work["Work"]
        api["API"] --- ledger["Signed ledger"] --- views["Derived views<br/>state · attention · briefing"]
    end
    work --> pg[("PostgreSQL")]
    work --> nats[("NATS")]
    work <-->|"identity · authority<br/>approvals · stop/takeover"| access["Access"]
    work <-->|"notifications · real time<br/>waits · escalation"| relay["Relay"]
```

Work records and derives; it does not execute. Identity, authority and the actual stopping of an agent live in Access; delivery, real-time streams, waits and escalation timing live in Relay. The three are deployed together as one system.

## Getting started

You need Rust (the toolchain in `rust-toolchain.toml` installs itself), [`just`](https://github.com/casey/just) and Docker. `just check` also uses Node.js (version in `.node-version`), Python 3, [uv](https://docs.astral.sh/uv/) for Semgrep, and `wasm-bindgen-cli` at the version in `Cargo.lock`; CDDL validation runs when Ruby and Bundler are available.

```sh
git clone https://github.com/e-suiss/work.git
cd work
just dev           # PostgreSQL, NATS, SoftHSM, observability, Access and Relay
just test          # the Rust test suite CI runs on every change
just web-install   # npm dependencies for the TypeScript packages (lockfile only)
just check         # the core CI gates: format, Clippy, repository rules, vectors, migrations, supply chain, Semgrep, web checks, CDDL, compose
```

CI additionally runs the browser, Swift, `no_std` and benchmark jobs, CodeQL and secret scanning. `just --list` shows every command.

## Tech stack

Rust (server and a `no_std` core shared by server, web and mobile through WebAssembly and native bindings), PostgreSQL, NATS JetStream, React and React Native.

## Related projects

- **[Access](https://github.com/e-suiss/access)** — identity and authority. Work uses Access for sign-in, permissions, approvals and stopping agents.
- **[Relay](https://github.com/e-suiss/relay)** — notification, messaging and event delivery. Work uses Relay to reach people and agents, wait for answers and escalate.

Access, Relay and Work are parts of one system and are always deployed together.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Work is open source under the [Apache License 2.0](LICENSE). Self-hosted and Suiss-hosted Work run the same code; no feature is cloud-only.

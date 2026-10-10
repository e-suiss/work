# Contributing to Work

Thank you for your interest in Work. This guide explains how to set up a development environment, the rules code must follow, and how changes get merged.

The project is pre-alpha. The rules below are binding and enforced in CI.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Development environment

You need Rust (installed from `rust-toolchain.toml` on first use), [`just`](https://github.com/casey/just), Docker and, for the pre-commit hook, [`gitleaks`](https://github.com/gitleaks/gitleaks).

```sh
git clone https://github.com/e-suiss/work.git
cd work
git config core.hooksPath .githooks
just dev    # PostgreSQL 18, NATS JetStream, SoftHSM, OpenTelemetry Collector, Jaeger, Prometheus, Grafana
just test   # the same tests CI runs on pull requests
just check  # the same checks CI runs: format, clippy, repository rules, cargo-deny, compose
```

`just dev` prints the local addresses. Local Access and Relay run in the same environment; until their images are published, `compat.toml` marks them `unpublished` and their services stay off. Other commands: `just --list`.

There is no "development mode": security checks are never disabled locally, and Access and Relay are never faked. Local equivalents replace production services: SoftHSM stands in for the HSM (keys are reached only through PKCS#11), and each product has its own database and role on the shared PostgreSQL server.

## Code rules (summary)

- Code, comments, commit messages and pull requests are in English.
- Rust: `rustfmt`, workspace lints, warnings are errors, `clippy` in CI. `work-kernel` is `no_std`, has no I/O, forbids `unsafe` and never panics on the request path; arithmetic is checked.
- Architecture: `domain` / `ports` / `app` / `adapters`. Time and randomness come only from injected ports. A record, its derived rows and its outbox event commit in one transaction.
- Derivation logic exists once, in `work-kernel`. Web and mobile use it through WebAssembly and native bindings; it is never reimplemented in TypeScript.
- A rule outcome is a result, not an error. Errors use RFC 9457 problem details.
- Secrets and personal data use self-redacting types and are never logged.
- SQL lives only in the `store` crate (`sqlx`, no ORM). There are no physical deletes (`DELETE`/`TRUNCATE`); migrations are forward-only.
- TypeScript: every package is an independent npm project with `strict` mode, the shared design system and the generated API client; there are no JavaScript files at the repository root.
- No explanatory comments. Allowed: `// SAFETY:` notes, `///` docs and a one-paragraph `//!` per module, bare specification ID lines such as `// CM-25`, `// TODO(#123): short text`, and tool directives. The reasoning lives in the specification.
- Tests carry the rule ID they prove in their name or on a bare ID line above them (`cargo xtask check rule-coverage`); tests run against real PostgreSQL, NATS, Access and Relay; flaky tests are quarantined, never retried until green.

## Commits and changes

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), with the crate or area as scope: `feat(kernel): derive commitment state from records`.
- Commits must be signed. `main` has a linear history; force pushes are not allowed.
- External contributions come as pull requests, are kept small and are merged with squash merge after CI passes. The maintainer pushes signed commits to `main` directly; CI runs after the push.
- Changes that add or change a specification decision carry the `decision` label and update the decision register.

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

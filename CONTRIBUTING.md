# Contributing to Work

Thank you for your interest in Work. This guide explains how to set up a development environment, the rules code must follow, and how changes get merged.

The project is in active design; implementation has not started. The rules below are already binding.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Development environment

Once the codebase exists, getting started will take three steps:

```sh
git clone https://github.com/e-suiss/work.git
cd work
just dev    # starts PostgreSQL, NATS, a local Access and a local Relay (with their dependencies) and sample data
just test   # runs the same tests as CI on pull requests
```

Other commands: `just check` (the same checks as CI) and `just gen` (regenerate the OpenAPI document, SDKs and kernel bindings).

There is no "development mode": security checks are never disabled locally, and Access and Relay are never faked. Local equivalents replace production services instead.

## Code rules (summary)

- Code, comments, commit messages and pull requests are in English.
- Rust: `rustfmt`, workspace lints, warnings are errors, `clippy` in CI. `work-kernel` is `no_std`, has no I/O, forbids `unsafe` and never panics on the request path; arithmetic is checked.
- Architecture: `domain` / `ports` / `app` / `adapters`. Time and randomness come only from injected ports. A record, its derived rows and its outbox event commit in one transaction.
- Derivation logic exists once, in `work-kernel`. Web and mobile use it through WebAssembly and native bindings; it is never reimplemented in TypeScript.
- A rule outcome is a result, not an error. Errors use RFC 9457 problem details.
- Secrets and personal data use self-redacting types and are never logged.
- SQL lives only in the `store` crate (`sqlx`, no ORM). There are no physical deletes (`DELETE`/`TRUNCATE`); migrations are forward-only.
- TypeScript: `strict` mode, the shared lint config, the shared design system, and the generated API client.
- Code that implements a specification rule names its ID in a comment, e.g. `// CM-25: fulfilment is a separate record`.
- `TODO` comments must reference an issue.
- Tests are named after behavior; tests run against real PostgreSQL, NATS, Access and Relay; flaky tests are quarantined, never retried until green.

## Commits and changes

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), with the crate or area as scope: `feat(kernel): derive commitment state from records`.
- Commits must be signed. `main` has a linear history; force pushes are not allowed.
- External contributions come as pull requests, are kept small and are merged with squash merge after CI passes.
- Changes that add or change a specification decision carry the `decision` label and update the decision register.

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

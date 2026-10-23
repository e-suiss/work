# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Do not open a public issue, pull request or discussion for a suspected vulnerability.

Please include:
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected versions or components, if known.

## What to expect

- We acknowledge reports and keep you informed while we investigate.
- We follow coordinated vulnerability disclosure with a default embargo of 90 days, shortened when a vulnerability is actively exploited.
- Fixes are always released in the open-source version; security fixes are never limited to a paid offering.
- Advisories are published as GitHub Security Advisories, and reporters are credited unless they ask otherwise.

## Supported versions

Work is pre-alpha. 0.x releases are published as GitHub pre-releases for evaluation and testing; they are not intended for production use and receive no backported fixes. Report issues against `main` or the latest tag; fixes land on `main` and ship in the next release.

## Scope

Everything in this repository: the kernel and its bindings, the server binaries, release artifacts and their attestations, the CI and release workflows, and the local environment configuration. Reports about the security design are welcome through the same private channel.

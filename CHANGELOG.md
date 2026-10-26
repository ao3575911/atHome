# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- A1 identity/trust boundary packages (provisional): `@athome/identity-core`, `@athome/creator-proof`, `@athome/registry-client`, and `@athome/cli`, with JSON schemas under `schemas/` and migration notes in `docs/migration/a1-identity-trust-consolidation.md`.
- `CHANGELOG.md`, `CONTRIBUTING.md` (Conventional Commit and PR-title conventions, label taxonomy), and `.github/labels.yml`.
- `Dependency Review` GitHub Actions workflow for pull requests.

### Changed

- README rewritten as a durable entry point separating the atHome protocol implementation from provisional A1 contracts.
- Issue and pull-request templates prompt for taxonomy labels, verification, and security impact.
- `Verify` workflow uses least-privilege permissions and concurrency control.
- `docs/operational-gates.md` distinguishes current verification from historical audit context.

### Fixed

- Missing product name in `SECURITY.md`, the API startup log message, and the web page title.

# Contributing to atHome

## Setup and gates

```bash
npm install
npm run typecheck && npm run typecheck:web
npm test
npm run lint        # npm run format to fix
npm run audit:high
npm run build:web
```

See [docs/operational-gates.md](docs/operational-gates.md). Report vulnerabilities per [SECURITY.md](SECURITY.md), never in public issues.

## Commit messages and PR titles

Format: `type(optional-scope): imperative summary` — lowercase type, no trailing period.

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`, `security`.

Examples: `feat(sdk): add passkey signer`, `docs: update README`. PR titles follow the same format (squash-merge uses the title).

## Label taxonomy

Labels are lower-case and namespaced; definitions live in [`.github/labels.yml`](.github/labels.yml).

- `type:` bug, feature, documentation, security, maintenance
- `area:` protocol, api, sdk, web, identity, registry, cli, docs, ops
- `priority:` p0, p1, p2, p3
- `status:` needs-triage, blocked, ready

Apply one `type:`, at least one `area:`, and a `priority:` where known. The checked-in file does not change GitHub by itself: maintainers must synchronize labels via repository settings or the GitHub API/CLI. GitHub Discussions do not use labels like issues/PRs; use categories.

## Maintainer follow-ups

See the runbook in [docs/operational-gates.md](docs/operational-gates.md#maintainer-runbook-github-administration).

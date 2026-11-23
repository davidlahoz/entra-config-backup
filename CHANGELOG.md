# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-23

### Added
- `ca-backup.sh`: read-only export of Conditional Access policies, named locations and
  authentication strengths via Microsoft Graph v1.0, with `@odata.nextLink` paging.
- Certificate-based OAuth2 client credentials (RS256 client assertion built with openssl).
- Stable output: one sorted-key JSON file per object; folders rebuilt each run so
  deletions show up in git.
- Empty-export guard: refuses to commit when 0 CA policies are returned but the repo
  previously had some.
- Commit messages enriched with Conditional Access audit events from the last 26 hours.
- Push with a single rebase-and-retry for multi-tenant snapshot repositories.
- Optional ntfy notifications (high on drift, urgent on failure).
- Rootless, read-only Alpine container pinned by digest; GitHub SSH host keys pinned.
- systemd template service and timer (02:30 Europe/Berlin, per tenant).
- CI: shellcheck, hadolint, gitleaks (full history), docker build; actions pinned by SHA.

[0.1.0]: https://github.com/davidlahoz/entra-config-backup/releases/tag/v0.1.0

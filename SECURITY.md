# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) on this repository.
Do not open a public issue. You can expect an acknowledgement within 7 days.

Please include affected version/tag, impact, and reproduction steps. **Never include
real tenant IDs, tokens, keys or policy exports** in a report.

## Supported versions

Only the latest tagged release receives fixes. Production deployments should pin a tag,
never `main`.

## Security model (summary)

- Read-only Graph permissions only (`Policy.Read.All`, `AuditLog.Read.All`).
  The tool cannot change tenant configuration.
- Certificate-based client credentials; no client secrets. The private key is generated
  on the server and never leaves it.
- Rootless (UID 10001), read-only container with all capabilities dropped and
  `no-new-privileges`; base image pinned by digest; GitHub SSH host keys pinned.
- The git deploy key has write access to the snapshot repository only.

The snapshot repository contains your security configuration (excluded users and groups,
trusted IP ranges). Treat it as confidential and keep it private.

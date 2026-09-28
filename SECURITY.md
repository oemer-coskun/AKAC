# Security policy

This is a draft reference implementation. No version currently has a production
support commitment or independent security certification.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.3.x   | Yes |
| < 0.3   | No |

Only the latest `0.3.x` release receives security fixes; earlier draft
releases (including the `0.2.x` line) do not. This table reflects the
current draft's support window, not a long-term-support commitment -- it
will move forward as the specification and reference implementation
progress, with no guaranteed backport policy across major draft revisions.

Report suspected vulnerabilities through GitHub's private vulnerability reporting
feature when enabled. If unavailable, open an issue requesting a private channel
without including exploit details, secrets or real company data. The maintainer
will arrange a private disclosure path. No response-time SLA is promised.

Include affected commit, deployment profile, trust assumptions, minimal synthetic
reproduction, expected versus actual authorization and disclosure impact. Never
test against systems you do not own or have permission to assess.

Do not rely on the gateway alone to isolate model sessions, block direct network
access, enforce retention or protect compromised administrative credentials. Read
`docs/THREAT-MODEL.md` before any deployment.

For deploying a specific instance (Compose or Helm, secrets, backups,
scaling), see `docs/DEPLOYMENT.md`. For incident response on a running
deployment (revocation, key compromise, audit anchoring, tenant
offboarding), see `docs/SECURITY-OPERATIONS.md`.

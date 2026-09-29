# Contributing

Start with the specification and threat model. Open a focused issue before a
normative change. Keep policy decisions deterministic and enforcement outside the
model. Supply an allowed control and a denied attack case for each boundary.

Run `npm ci`, `npm run check`, `npm run lint:spec`, `npm run conformance` and `opa test policies/`.
Database changes also require the PostgreSQL integration job. Do not skip failing
checks or weaken denial to make a test pass. Update schemas, examples, traceability
and status documentation with the implementation.

Use conventional descriptive commit messages. Include a DCO Signed-off-by line
only when you can personally make its certifications. AI tools must not sign a
DCO or assert a human review on someone's behalf. Disclose AI assistance and
record real test results, including skipped checks.

Never include secrets, real customer documents or private reference material.
Third-party source must retain its license and required attribution.

Not even synthetic credentials: connection URLs in code, tests, Compose, CI and
docs never carry a password. Supply database passwords as files
(`AKAC_DATABASE_PASSWORD_FILE` and its companions, Docker/Kubernetes secrets) and,
in tests, generate them at runtime with `crypto.randomBytes`. Install the
pre-commit hook (`pip install pre-commit && pre-commit install`, configured in
`.pre-commit-config.yaml`); CI runs the pinned gitleaks over the full history.

## Process documents

Specification changes: [spec/CHANGE-CONTROL.md](spec/CHANGE-CONTROL.md) (change classes,
review period, deprecation) and [spec/ERRATA.md](spec/ERRATA.md). Vulnerabilities: do not open
an issue; follow [SECURITY.md](SECURITY.md). Decision rules and maintainers:
[GOVERNANCE.md](GOVERNANCE.md), [MAINTAINERS.md](MAINTAINERS.md). GitHub Actions added to a
workflow must be pinned by full commit SHA with the version in a trailing comment and run with the
minimum `permissions`; the one exception (slsa-github-generator, referenced by tag) is explained in
[governance/ADR-017](governance/ADR-017-supply-chain-and-release-integrity.md).

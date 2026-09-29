# Security policy

AKAC is a draft specification with a reference implementation. No version carries a
production support commitment, an independent security review, a penetration test or a
certification. The response times below are project targets, not guarantees or a service
level agreement.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.6.x | Yes (current) |
| 0.5.x | Yes, security fixes only |
| < 0.5 | No |

The table is the support window of the draft series, not a long-term-support promise. It
moves forward with each release; see [MAINTAINERS.md](MAINTAINERS.md) for who can act on a
report.

## Scope

In scope: the specification text under `spec/` (a requirement that permits an authorization
bypass, an information leak or an unsafe default), the reference implementation under
`reference/`, `adapters/`, `sdk/`, `migrations/` and `policies/`, the conformance vectors, the container image and the
Helm chart under `deploy/`, and the release integrity chain (signatures, provenance, SBOM).

Out of scope: `bonus/` and `implementations/` code is best effort and reported the same way
but is not a supported deployment; model-session isolation, egress enforcement, sandboxing and
unlearning are operator or runtime responsibilities (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md));
findings that need a compromised administrative credential or a host you already control;
denial of service through volumes beyond the documented single-node limits; social engineering
of maintainers; reports against deployments you do not own.

## How to report

1. Preferred: GitHub private vulnerability reporting for this repository:
   <https://github.com/oemer-coskun/AKAC/security/advisories/new>
2. Alternative contact: [OWNER TO SET SECURITY CONTACT]
3. Machine-readable contact data: [.well-known/security.txt](.well-known/security.txt)
   (RFC 9116). See [docs/process/SECURITY-TXT.md](docs/process/SECURITY-TXT.md) for how it is served.

Do not open a public issue or pull request for a suspected vulnerability. Include the affected
version or commit, the deployment profile and trust assumptions, a minimal synthetic
reproduction, and the expected versus actual authorization and disclosure result. Use synthetic
data only. Never test against systems you do not own or have written permission to assess.

## Response targets

Business days, measured from receipt. Project targets, not commitments.

| Step | Target |
|---|---|
| Acknowledge receipt | within 3 business days |
| Triage (confirm or reject, assign severity) | within 7 business days |
| Fix or mitigation, critical severity (CVSS 9.0-10.0) | 14 days |
| Fix or mitigation, high (7.0-8.9) | 30 days |
| Fix or mitigation, medium (4.0-6.9) | 90 days |
| Fix, low (0.1-3.9) | next regular release |

A single maintainer runs the project ([MAINTAINERS.md](MAINTAINERS.md)); targets can slip and
the reporter is told when they do. Severity uses CVSS v3.1/v4.0 base scores as a guide, adjusted
for the deployment assumptions in the threat model.

## Disclosure and CVE

Coordinated disclosure: the report stays private until a fix is released or 90 days have passed,
whichever comes first; the reporter and the maintainer may agree a different date, for example to
extend for a complex fix. CVE identifiers are requested through GitHub Security Advisories (GitHub is
a CVE Numbering Authority) for confirmed vulnerabilities in a released version. Advisories
credit the reporter unless they ask not to be named. The embargo procedure is in
[GOVERNANCE.md](GOVERNANCE.md).

Good-faith research that follows this policy will not be pursued. No bug bounty exists; one may
be considered after an external review has taken place.

## Verifying what you run

Releases carry a cosign signature, SLSA provenance and a CycloneDX SBOM:
[docs/process/VERIFY-RELEASE.md](docs/process/VERIFY-RELEASE.md). Deployment hardening is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md); incident handling for a running deployment
(revocation, key compromise, audit anchoring, tenant offboarding) is in
[docs/SECURITY-OPERATIONS.md](docs/SECURITY-OPERATIONS.md).

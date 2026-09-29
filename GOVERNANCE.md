# Governance

AKAC is maintained by the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) (currently one,
by GitHub handle). Maintainer status is a project-management role, not ownership of contributors'
work or a claim of recognition by a standards organization. The decision record for this process is
[governance/ADR-018](governance/ADR-018-governance-and-spec-process.md).

## Decisions

Ordinary changes use lazy consensus: a proposal (issue or pull request) that receives no
maintainer objection within 7 days, and at least one maintainer approval other than the author
once two maintainers exist, is accepted. Silence is consent for ordinary changes only; an
objection with a reason blocks until resolved. Every decision is recorded in the issue or pull
request, never in private.

Specification changes follow [spec/CHANGE-CONTROL.md](spec/CHANGE-CONTROL.md): an issue stating
the problem, security consequences, interoperability impact, alternatives and migration plan; a
pull request that includes changed requirements and conformance vectors; and a review period
before the change is frozen into a release. Maintainers record an architecture decision (ADR
under `governance/`) before merging a security-semantic change.

Draft versions may change. A future 1.0 must freeze its normative requirements, publish
compatibility rules and document evidence from at least two independent implementations
(criteria in [spec/CHANGE-CONTROL.md](spec/CHANGE-CONTROL.md)). Independence means no shared
decision-engine implementation. Errata to released text are logged in [spec/ERRATA.md](spec/ERRATA.md).

## Security embargo

Vulnerability reports ([SECURITY.md](SECURITY.md)) are private. While a report is under
embargo: only maintainers and the reporter (and people the maintainers add for the fix) see the
details; the fix is developed in a private fork or a GitHub Security Advisory temporary private
fork; no public commit, issue, pull request title or CI log names the vulnerability before
release; the fix ships with tests that fail without it, and the advisory credits the reporter.
Disclosure happens when the fix is released or after 90 days, whichever comes first, unless the
reporter and a maintainer agree otherwise in writing. Maintainers do not share embargoed details
with their employers or downstream users unless the reporter consents. The embargo overrides
the 7-day lazy-consensus rule and the public-record rule until disclosure; the record is added
afterwards.

## Releases

Release identifiers distinguish specification, implementation and vector revisions.
Publish test commands, environment, results, limitations and source commit. No
"certified", "production secure" or "industry standard" badge is issued by tests.
Breaking changes require a new specification version and migration guidance. Release artifacts
are built, signed and attested by CI ([docs/process/VERIFY-RELEASE.md](docs/process/VERIFY-RELEASE.md)).

## Contributions

Contributors retain their rights. Contributions must use the applicable file
license and include a Signed-off-by line confirming the Developer Certificate of
Origin at https://developercertificate.org/. No copyright assignment is implied.
AI-assisted submissions must be disclosed and reviewed by the contributor.

## Conduct

Participants are expected to be respectful and to keep technical discussion on the merits.
A maintainer may remove content or restrict participation for abuse. Conduct concerns go to the
maintainers through the contact in [SECURITY.md](SECURITY.md) marked as a conduct report.

# ADR 018: governance and specification process

Status: proposed for AKAC 0.6 (draft). Documents: [GOVERNANCE.md](../GOVERNANCE.md),
[MAINTAINERS.md](../MAINTAINERS.md), [SECURITY.md](../SECURITY.md),
[spec/CHANGE-CONTROL.md](../spec/CHANGE-CONTROL.md), [spec/ERRATA.md](../spec/ERRATA.md).

## Context

The project has one maintainer, a security policy without response targets or a supported-version
table matching the current line, no errata mechanism for published specification text, and no
automatic check of normative language. Cross-references and requirement numbers were checked by
hand; three documentation defects (a conformance-vector tagging rule that disagreed with R105, a duplicated sentence, a broken link) shipped
in 0.5.0 (see the errata log).

## Decision

1. **Vulnerability process.** SECURITY.md defines scope, GitHub private vulnerability reporting
   as the channel, an owner-set alternative contact, response targets (acknowledge 3, triage 7
   business days, fix targets by severity), 90-day coordinated disclosure, CVE numbers through
   GitHub Security Advisories, and supported versions 0.6.x and 0.5.x (security fixes only).
   All times are project targets, not commitments. `.well-known/security.txt` follows RFC 9116.
2. **Governance.** Lazy consensus for ordinary changes; a security embargo procedure that
   overrides the public-record rule until disclosure; maintainer criteria and an explicit goal
   of two or more maintainers. Today there is one; every document says so.
3. **Specification change control.** Four change classes with review periods, staged
   proposal-draft-review-merge-freeze flow, versioning rules, deprecation policy and 1.0 freeze
   criteria, modelled on IETF and OpenID working-group practice without claiming affiliation.
4. **Errata.** Published text is frozen; corrections that change no behaviour go in
   `spec/ERRATA.md`, which never deletes entries.
5. **Automated language lint.** `scripts/lint-spec.ts` (run in CI) checks that RFC 2119/8174
   keywords are uppercase in requirement lines, that requirement identifiers are unique and
   contiguous, and that relative links in `spec/` and `docs/` resolve. It does not judge whether
   a requirement is well formed or testable.

## Consequences

The process is only as strong as the people in it: with one maintainer, "review" is
self-review plus a waiting period, and the documents say so. Evidence that would justify a
stronger claim (external review, second implementation, a second maintainer) is prepared in
[docs/process/EXTERNAL-ASSURANCE.md](../docs/process/EXTERNAL-ASSURANCE.md), not asserted.

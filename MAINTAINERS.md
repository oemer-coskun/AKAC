# Maintainers

| GitHub handle | Role | Areas |
|---|---|---|
| @oemer-coskun | Maintainer (sole) | All, including security response and releases |

The project currently has one maintainer. That is a known weakness: a single person is a single
point of failure for review, releases and security response, and no change is independently
reviewed today. The goal is at least two maintainers with commit rights and a security response
team of at least two people, so that no release or advisory depends on one person.

## Becoming a maintainer

Criteria (project rules, not an external standard):

- Sustained, high-quality contributions over at least six months: merged changes to the
  specification, reference, conformance vectors or process documents, and review of others' work.
- Demonstrated understanding of the normative invariants in `spec/AKAC-0.1.md` and of
  [governance/ADR-018](governance/ADR-018-governance-and-spec-process.md); no pattern of
  weakening denial or hiding skipped tests.
- Agreement to follow [SECURITY.md](SECURITY.md), the embargo rules in [GOVERNANCE.md](GOVERNANCE.md)
  and two-factor authentication on the GitHub account.
- Nomination by an existing maintainer in a public issue; no objection from a maintainer within
  14 days (lazy consensus). Nominees affiliated with the same employer as the majority of
  maintainers do not count towards the independence goal in the 1.0 criteria.

A maintainer who is inactive for 12 months, or who asks to step down, moves to an emeritus list
by the same process. Access is removed on the same day.

## Decision rules

- Ordinary changes: one maintainer approval, not the author. While only one maintainer exists,
  the change waits at least 72 hours after publication for objection, and the pull request states
  that it had no independent review.
- Normative specification changes: [spec/CHANGE-CONTROL.md](spec/CHANGE-CONTROL.md) applies; two
  maintainers approve once the project has two.
- Security-semantic changes: an ADR is recorded first ([GOVERNANCE.md](GOVERNANCE.md)).
- Disagreement between maintainers: the change does not merge until they agree; if they cannot
  agree the more restrictive (deny) behaviour stays.
- Changing the licence or this file's rules needs unanimous maintainer consent.

Contributors do not become maintainers by inactivity of others.

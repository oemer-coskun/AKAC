# Specification change control

Status: project process, draft. It is modelled on published working-group practice (IETF
BCP 9 "The Internet Standards Process", IETF Working Group processes in RFC 2418, and the OpenID
Foundation working-group and implementer's-draft process) but AKAC is not an IETF or OpenID
Foundation work item and this document claims no recognition by either. Decision record:
[governance/ADR-018](../governance/ADR-018-governance-and-spec-process.md). Keyword
interpretation in this document: RFC 2119 and RFC 8174.

## Change classes

| Class | Definition | Examples | Minimum review period |
|---|---|---|---|
| Editorial | No change in meaning: typos, links, formatting | Broken link | none; logged in [ERRATA.md](ERRATA.md) if the text was in a release |
| Clarification | Wording made unambiguous; every previously conforming implementation still conforms | Added example | 7 days |
| Normative | Adds, removes or changes a MUST, MUST NOT, SHOULD, reason code, profile or vector | New requirement R197 | 14 days |
| Breaking | A previously conforming implementation could stop conforming, or a decision could change from deny to allow or the reverse | Changed default | 30 days, migration guide required |

A change that could turn a deny into an allow is treated as breaking and needs an ADR and a
security-consequence statement.

## Stages

1. Proposal. An issue using the specification template: problem, security consequences,
   interoperability impact, alternatives, migration plan, change class.
2. Draft. New normative text goes to `spec/drafts/<version>-<topic>.md` with topic-scoped
   identifiers (`R-<TOPIC>-n`), together with conformance vectors that fail without the change
   and a positive control. An ADR is recorded for security-semantic changes.
3. Review period. The pull request stays open for at least the period in the table above and
   is announced in the issue. Objections are answered in writing; an unresolved objection blocks.
4. Merge into the versioned specification. The orchestrating maintainer assigns the final
   `R` numbers. Requirement numbers are never reused and never renumbered.
5. Freeze. A release tag freezes the text of that version. After a freeze only errata
   ([ERRATA.md](ERRATA.md)) may change it; anything else goes into the next version.

## Versioning

Specification versions are `0.N` while the project is a draft and `MAJOR.MINOR` from 1.0. From
1.0: a MAJOR increase may break conformance; a MINOR increase only adds optional behaviour or
profiles and never changes an existing decision. The specification version, reference
implementation version and vector revision are separate identifiers and are all stated in a
conformance report. Conformance profiles are named `<Profile>/<version>`.

## Deprecation

A requirement, reason code or profile is deprecated by an entry in the specification stating
the replacement and the first version in which it may be removed, at least two MINOR (or, before
1.0, two draft) versions later. Deprecated behaviour stays testable by vectors until removal.
Removal is a breaking change. Security-motivated removal may be faster, with the advisory
explaining why ([SECURITY.md](../SECURITY.md)).

## Requirement identifiers and language

- Each requirement has one identifier `R<number>` (published) or `R-<TOPIC>-<n>` (drafts),
  defined once.
- Uppercase MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have their RFC 2119/8174 meaning and are
  used only in normative text; lowercase "must" or "should" inside a requirement line is
  flagged. `npm run lint:spec` ([scripts/lint-spec.ts](../scripts/lint-spec.ts)) checks the
  keywords, duplicate or missing requirement identifiers and broken relative links in `spec/` and
  `docs/`, and CI runs it.
- Every normative MUST has a vector or, for operator-only obligations, a written test
  procedure (rule coverage matrix, tracked in the roadmap as machine-enforced).

## Criteria for freezing 1.0

All of these must hold and be documented in the release notes; none holds today.

1. Every published normative requirement is covered by a portable vector or an operator test
   procedure, and CI enforces the mapping.
2. At least two independent implementations (no shared decision-engine code) pass 100 % of the
   shared vectors, at least one written by someone other than the maintainers; results published
   per implementation.
3. A formal model of the core invariants (delegation narrowing, derivation labels, revocation)
   published and checked.
4. An external security review and cryptography review of the specification and reference have
   been carried out, published, and all high and critical findings closed.
5. AuthZEN interoperability results with at least one third-party implementation published.
6. The errata log has had no normative-affecting entry for 90 days and no open objection blocks.
7. Deprecation rules above and this document are in force, and at least two maintainers approve
   the freeze ([MAINTAINERS.md](../MAINTAINERS.md)).

Thresholds such as 90 days are project proposals, not values from a standard.

# Public publication boundary

This repository publishes the AKAC Community specification and reference implementation
under MIT-0. It is not a mirror of private development, delivery or commercial systems.

## What stays public

- Decision semantics, normative requirements, schemas and public API/hook contracts.
- Reference implementations and synthetic examples sufficient to exercise those contracts.
- Conformance vectors, tests, formal-model artifacts and reproducible engineering evidence.
- Safe-use requirements, operator responsibilities, threat assumptions, vulnerabilities
  disclosed through the security process, and known limitations of the public code.
- Community installation, migration and release-verification instructions.

These materials make the Community edition reviewable and usable. Public security
decisions are not protected by hiding how they work. A separately offered component
cannot widen a core denial or replace missing public semantics with an undisclosed rule.

## What stays outside this repository

- Source or detailed implementation recipes belonging exclusively to private extensions.
- Internal repository names, private commit/revision anchors, mirrors and internal paths.
- Detection datasets, private thresholds, tuning recipes, private policy packs and
  customer-specific configurations that are not needed to understand the public contract.
- Credentials, private keys, tokens, customer data, production dumps and internal URLs.
- Commercial terms, private delivery runbooks, module inventories and internal roadmaps.
- Screenshots, AI transcripts and exports carrying any of those details.

Private work belongs in a separate, access-controlled repository. Gitignore rules are
convenience protections, not access control; force-adding a file can bypass them.
Public contact information and a short description of separately scoped services are
appropriate. Specific delivery scope and terms are discussed directly.

## Review before publication

1. Review the complete diff, including assets, generated files, workflows and examples.
2. Keep public contracts complete; remove private recipes and internal metadata instead
   of removing safety requirements or concealing limitations.
3. Use synthetic data and runtime-generated secrets. Do not paste private material into
   public issues, PR descriptions, logs, CI summaries or build artifacts.
4. Run `npm run check:publication` and the existing secret scan. The publication check
   inspects tracked files plus non-ignored additions; the pre-commit form `--staged`
   inspects the Git index so an unstaged edit cannot hide staged private material.
5. Review any new image or opaque attachment manually before approving its path in the
   checker. Only the two existing public branding assets are allowed as binary files.
6. Link assurance claims to executed evidence for the exact scope. AI output is review
   assistance, not independent verification, certification or a test-execution record.

The automated gate detects known patterns and out-of-scope paths. It does not perform
semantic IP classification, inspect the contents of approved images, or prove absence
of secrets. Gitleaks remains the dedicated credential scanner. A passing job is not
permission to publish a new private implementation; human review remains necessary.

## History and released rights

Current-tree cleanup does not erase old commits, forks, clones, caches or released
artifacts, and it does not retract existing MIT-0 permissions. No history rewrite is
performed by this policy. If a real credential is exposed, rotate/revoke it first and
handle affected history and artifacts through the incident process in
[SECURITY.md](../../SECURITY.md).

Do not copy a private incident inventory or removed content into a public cleanup
report. Record incident details in an access-controlled system and publish only the
necessary impact and remediation information.

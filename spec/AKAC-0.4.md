# AKAC 0.4 draft

Status: project specification, not a ratified external standard. Reference: 0.4.0.
This revision incorporates R01–R16 of [AKAC 0.1](AKAC-0.1.md), R17–R21 of
[AKAC 0.2](AKAC-0.2.md) and R22–R31 of [AKAC 0.3](AKAC-0.3.md) by reference and
without weakening any of them: a requirement below only adds conditions, obligations
or evidence, and an implementation of 0.4 MUST still satisfy R01–R31. The following
requirements apply to the AKAC-Evidence, AKAC-Lifecycle, AKAC-Destinations,
AKAC-AuthZEN and AKAC-RedTeam 0.4 draft profiles ([conformance](CONFORMANCE.md)).
MUST, SHOULD and MAY retain their RFC 2119/8174 meanings.

No external review, legal review or independent interoperability test has taken
place. Where this document cites a standard it cites its primary source and status:
RFC 8785, RFC 9162, RFC 9449, RFC 7638 and RFC 7800 are published RFCs; the OpenID
AuthZEN Authorization API 1.0 is a Final specification (11 January 2026); the
AuthZEN working-group work on obligations is a draft, so AKAC's obligation shape is
described as **draft-aligned** and no conformance to it is claimed. The OWASP Top 10
for LLM Applications 2025 and the OWASP agentic-application threat list are risk
catalogues, and MITRE ATLAS is a knowledge base; none of them is a conformance
target.

Numbering continues from 0.3. The drafts in [drafts/](drafts/) were merged here; the
table at the end maps every draft identifier to its R number. The R numbers are
stable: they are not reused or reordered in later revisions.

## Decisions and obligations (R32–R39)

The decision shape (a decision plus obligations) is aligned with the OpenID AuthZEN
Authorization API 1.0 and with the AuthZEN working-group draft on obligations. The
closed reason-code enumeration extends the R29 codes; adding a code is a
specification change. Decision: [ADR-006](../governance/ADR-006-decisions-and-evidence.md).

**R32 — Decision identifiers.** Every decision of the engine and of the
control plane MUST carry a `decisionId` (reference: UUIDv4) that is returned to
the caller and recorded in the audit entry of that decision. A request rejected
before a tenant transaction (for example a malformed binding) still receives an
identifier, which then has no audit entry.

**R33 — Closed reason codes.** Every decision MUST carry a reason code from a
closed enumeration (reference: `REASON_CODES` in `reference/decision.ts`): the
allow codes `AUTHORIZED`, `PROTECTED_DERIVATION`, `AUTHORIZED_RECIPIENT`,
`ATTENUATED`, `IDEMPOTENT_REPLAY`; the R29 codes; `POLICY_DENIED`,
`POLICY_UNAVAILABLE`; the operation codes `STALE_CONTEXT`, `STALE_SOURCE`,
`EXPIRED`, `RECIPIENT`, `CANDIDATES_UNAVAILABLE`, `BUDGET_EXCEEDED`,
`STORE_ERROR`; and the control-plane codes `NOT_ADMIN`, `CONFLICT`,
`IDEMPOTENCY_KEY_REUSED`. A denial also carries its R29 category (`deny` or
`defer`). An implementation MUST NOT record a reason outside the enumeration; an
administrative attempt submitted with an unknown reason MUST be refused.
Adding a code is a specification change.

**R34 — Policy identity.** Every decision MUST record the policy revision (the
existing revision string: core version, state policy version, supplemental policy
or bundle revision) and `policyDigest`, the lowercase hex SHA-256 of the RFC 8785
form of the array of those components (the control plane uses `control-plane` as
its third component).

**R35 — Non-distinguishing denials.** A denial returned over the agent API
MUST consist of exactly `ok: false`, `code: "NOT_AUTHORIZED"` and `decisionId`.
The reason code and category MUST NOT be returned; they are recorded in audit
only (R29). The decision identifier is random and MUST NOT encode the reason.

**R36 — Obligations.** An allow MUST carry `obligations`, an array (possibly
empty) drawn from the closed set: `{type: "audit_level", value: "full"}` (record
the decision id with every downstream use), `{type: "max_context_ttl_ms", value}`
(do not use the disclosed content after that many milliseconds), `{type:
"no_persist"}` (do not persist the content, or content derived from it, outside
AKAC) and `{type: "destination_restricted", value: [ids]}` (only the listed
destination classes or profile ids may receive it; issued by the destinations profile, R66).
A denial carries no obligations. The reference engine attaches `audit_level` when
the highest transitive effective classification (R25) of the disclosed or
derived-from material is at least `confidential`, `no_persist` when it is
`restricted`, and `max_context_ttl_ms` (the remaining context lifetime) to every
context projection. Obligations combine restrictively: the shortest lifetime,
the intersection of destinations, one entry per type.

**R37 — Supplemental policy obligations.** A supplemental policy (R29, for
example OPA) MAY add obligations. They MUST be validated strictly: an array of at
most 16 known, well-formed obligations. An unknown type, an unknown or malformed
value, an extra member or a hole in an array MUST deny with `UNSUPPORTED_OBLIGATION` (category
`deny`). So MUST `destination_restricted` obligations whose intersection is empty,
whether they come from one verdict or from the verdicts for several records of one
operation: an unsatisfiable restriction is a clean, audited denial, never an allow
and never a store error. A policy response whose `obligations` member is not an array is unusable
(`POLICY_UNAVAILABLE`). A deny from the policy wins over any obligation. The OPA
decision document `{allow, revision}` without obligations remains valid.

**R38 — Enforcement points fail closed.** A caller (policy enforcement point)
that cannot enforce every obligation of an allow MUST treat the decision as a
deny. The reference runtime enforces `audit_level`, `max_context_ttl_ms` (it
aborts the model provider call at the deadline and never releases output produced
at or after it), `no_persist` (it persists nothing and passes the obligation
on with its answer) and `destination_restricted` (content goes only to the
destination the release gate authorized, and the answer only to the subject), and
denies any decision carrying another obligation before the provider receives
content. A boolean policy interface that cannot convey
obligations MUST report an allow with obligations as not allowed.

**R39 — Trace context.** Engine and control-plane entry points MAY accept a
W3C Trace Context trace-id (32 lowercase hex digits, not all zero). A valid one
MUST be recorded in the audit entry as `traceId`; an invalid one MUST be ignored
and never recorded. A trace id is never authority.

## Audit evidence (R40–R44)

Audit evidence uses RFC 8785 (JSON Canonicalization Scheme), the Merkle tree,
inclusion-proof and consistency-proof algorithms of RFC 9162 section 2.1 (SHA-256),
and W3C Trace Context trace-ids. Checkpoint format 2 is Ed25519 over a JCS form.
Format 1 entries and checkpoints (0.3) remain valid and verifiable. PostgreSQL
migration `004_audit_evidence.sql` adds the evidence columns and the node table.

**R40 — Audit format 2.** New audit entries MUST use format 2: the format 1
members plus `formatVersion: 2`, `decisionId`, `reasonCode` (consistent with
`reason` and with the effect), `policyDigest`, `obligations` and, where
applicable, `runId` (the run grant) and `traceId`. The set of members is closed.
The entry hash MUST be the SHA-256 of the RFC 8785 form of all other members, over
the JSON subset of strings, safe integers, booleans, null, arrays and objects;
anything else (fractions, non-finite or unsafe numbers, lone surrogates, arrays
with holes) MUST be rejected, never approximated.

**R41 — Continuous chain across formats.** The hash chain MUST continue
across the format change: the first format 2 entry's `previous` is the hash of
the last format 1 entry. Verifiers MUST select the hash rule per entry (format 1:
sorted-key JSON, as in 0.3; format 2: RFC 8785) and MUST reject a format 1 entry
that follows a format 2 entry in the same stream (downgrade) and a format 2
entry that is not closed or not internally consistent.

**R42 — Merkle tree.** Each tenant audit stream MUST also be committed to by
an RFC 9162 Merkle tree (SHA-256) whose leaf `sequence - 1` is
`SHA-256(0x00 || JCS(entry))` for the complete entry including its hash, in both
formats. Implementations SHOULD store leaf hashes and complete perfect subtrees
so that appends cost O(log n) and proofs O(log² n) node reads without reading
entry content; the stored nodes MUST be append-only and tenant-isolated like the
audit entries. A store upgraded from a format 1 history MUST compute the leaves
of the existing entries exactly as a verifier would.

**R43 — Proofs.** An auditor MUST be able to obtain, as audited operations,
the current tree head, an RFC 9162 §2.1.3 inclusion proof for any entry in any
tree size up to the current one, and an RFC 9162 §2.1.4 consistency proof between
any two sizes. Verification MUST follow the RFC algorithms and MUST be performed
against an independently trusted root (a checkpoint), never against a root
returned together with the proof alone.

**R44 — Checkpoints format 2.** A format 2 checkpoint (`akac-audit-checkpoint/2`)
MUST sign, with Ed25519, the RFC 8785 form of `{format, stream, treeSize,
rootHash, issuedAt, keyId}`, where `stream` is the tenant and `rootHash` the RFC
9162 root of the first `treeSize` entries. A verifier holding a trusted earlier
checkpoint MUST require a valid consistency proof before accepting a later one;
a rewritten, reordered, truncated or rolled-back stream then fails. Format 1
checkpoints MUST remain verifiable. A checkpoint signed with a key held by the
serving process attests only what that process saw; independent evidence
requires a key held outside it and external anchoring.

## Knowledge lifecycle (R45–R59)

Quarantine, lineage, retention, legal hold and erasure. Threats and obligations
addressed: poisoned knowledge and everything derived from it (OWASP LLM04 and the
OWASP agentic memory-and-context-poisoning item ASI06) must be containable without
first finding every derived record; and a deployment must be able to remove content,
including content derived from it, and to suspend removal while a hold applies
(GDPR Art. 17 and legal hold practice). AKAC supplies mechanisms; whether a given
deployment meets a legal obligation is outside this specification and no legal
review has taken place. A knowledge record MAY carry `lifecycle` (`quarantined`,
reversible, or `erased`, a terminal tombstone), `retainUntil` and `legalHolds`,
all orthogonal to `active`. The *lineage* of a record is every record whose `sources`
include it, transitively and at any referenced version. Decision:
[ADR-007](../governance/ADR-007-knowledge-lifecycle.md); operator guide:
the retention and erasure guide. Migration `005_knowledge_lifecycle.sql`.

**R45 — Lifecycle denies.** decide() MUST deny any action on a record whose
`lifecycle` is present, whatever its value (an unknown value denies). The denial
code is `KNOWLEDGE_BOUNDARY`; responses remain non-distinguishing.

**R46 — Transitive denial.** decide() MUST deny any action on a record if any
record in its transitive provenance (sources, recursively) has a `lifecycle`
value or is inactive. Quarantining one record therefore hides its whole lineage
at every gate (read, derive, write_memory, share, export and every retrieval
path, which re-checks each candidate) without rewriting the lineage.

**R47 — Quarantine and release.** Quarantine MUST be available to the
kb-admin and security-admin roles; release MUST require security-admin
(separation of duty). Both MUST be audited with a decision id, MUST be idempotent
and MUST advance the tenant epoch so open contexts end (R49). Quarantine
reasons MUST come from a closed, content-free set. An erased record cannot be
quarantined or released (CONFLICT).

**R48 — Blast radius.** An auditor or security-admin MUST be able to list the
lineage of a record: metadata only (id, version, kind, classification, active,
lifecycle), bounded (reference: at most 1000 per call, traversal depth 128,
8192 visited edges), with an explicit `truncated` flag. A record of another tenant
MUST read as absent.

**R49 — Epoch and durable revocation.** Quarantine, release, lineage revocation,
reinstatement and erasure that change a record MUST advance the tenant epoch; a
context of an older epoch is stale and its run (grant) cannot continue. A record
revoked by a security-admin (knowledge revocation or lineage revocation) MUST carry
a durable marker (`revokedAt`) that keeps it inactive across new document versions:
a new version with `active: true` MUST be refused (CONFLICT) until a security-admin
reinstates the record (audited `reinstate`, which clears the marker and reactivates
that record only). A kb-admin therefore cannot undo a security revocation. A kb-admin
retirement (document removal) sets no marker.

**R50 — Ingestion scanning fails closed.** When an ingestion scanner is
configured, a document MUST NOT be indexed unless the scanner returned `clean`
within its deadline. `quarantine` stores the document quarantined; `reject`
stores nothing and is audited as a refused write. A scanner error, timeout or
unknown verdict MUST be treated as `quarantine` (default) or `reject`
(configurable); never as `clean`.

**R51 — Memory review.** A deployment MAY require review of model-origin
memory: memory written by derive() is then stored quarantined until released. A
failure to determine the review mode MUST quarantine. Default: no review (0.3
behavior).

**R52 — Index hygiene.** The vector index MUST NOT hold chunks of a record
that is inactive, quarantined, erased, or whose lineage ancestry is not live;
reconciliation MUST remove them and MUST NOT re-add them. Because every index hit
is re-checked (R46), a stale chunk can cost recall, never disclose content.

**R53 — Erasure.** Erasure (security-admin) MUST replace the record's content
by the empty string, clear its reader list, set it inactive and set `lifecycle` to
`erased`. With cascade (the default) it MUST do the same for the whole lineage,
since derived content may contain the erased data; without cascade it MUST refuse
(CONFLICT) while a non-erased descendant exists. It MUST be idempotent. An erased
id MUST NOT be reused by a later document version (CONFLICT). The vector chunks
of every erased document MUST be removed.

**R54 — Erased forever.** No gate may disclose content of an erased record
or of any record in its lineage, now or later (R45, R46, R53).

**R55 — Legal hold.** A legal hold (security-admin; hold ids from the
identifier grammar; at most 64 per record; audited) on a record or on ANY record
in its lineage MUST block its erasure and its retention erasure. The refusal MUST
be CONFLICT carrying only the number of held records, never which. A hold also
preserves the held record's content: a new document version that changes its
`content` or `sources` MUST be refused with CONFLICT carrying `held` (the count);
a version that changes only metadata (labels, readers, activity, retention) is
allowed. A new document version MUST keep existing holds and an existing quarantine.

**R56 — Retention is not access expiry.** `retainUntil` marks when a record
is due for erasure; it MUST NOT by itself deny access (`accessExpiresAt` does
that, and does not erase). A derived record MUST inherit the earliest
`retainUntil` of its direct sources.

**R57 — Retention job.** The retention job (security-admin) MUST erase, with
cascade, records whose `retainUntil` is at or before its `now` and whose lineage
holds no legal hold, in bounded batches (reference: 100) that are resumable by
cursor, re-checking the deadline inside each erasure transaction. Each erasure
MUST be its own audited decision.

**R58 — Bounded cascades fail closed.** An operation that changes a
whole lineage (erasure, lineage revocation) MUST either establish the complete
lineage within its bound (reference: 1000 records) or change nothing and return a
deferred denial (`BUDGET_EXCEEDED`). Quarantine remains available for lineages of
any size.

**R59 — Audit is content-free and retained.** Erasure MUST NOT delete or
rewrite audit entries. Audit entries carry pseudonymous identifiers and closed
codes, never content; their retention is governed separately (the retention and erasure guide).

Not covered: erasure from backups, replica WAL history and storage-level remnants
(for example PostgreSQL dead tuples before VACUUM); crypto-shredding is not
implemented and is a deployment option.

## Destinations (R60–R71)

A *Destination* is a tenant-scoped record `{id, tenant, class, maxClassification,
purposes, active}`; `class` is one of `internal-user`, `internal-service`,
`model-provider`, `tool`, `external`. A principal MAY reference one through
`Actor.destination`; a grant MAY carry `destinations` (classes or Destination ids)
and `maxResults` (1..64). The profile addresses sensitive-information disclosure to
model providers, tools and external services (OWASP LLM02, excessive agency LLM06):
reading a document does not authorize sending it anywhere (0.1 R10). The AuthZEN
facade accepts the optional `context.destination` member (a Destination id) for
`share` and `export`, with the semantics of R67. Decision:
[ADR-008](../governance/ADR-008-destinations.md); integration contract:
the integration guide. Migration `006_destinations.sql`.

**R60 — Tenant scope.** Destinations MUST be keyed by (tenant, id); a
record of another tenant MUST be indistinguishable from an absent one. A
Destination id MUST NOT equal a class name.

**R61 — Target of a release.** The destination of a share/export is: the
recipient's Destination record when `Actor.destination` is present; otherwise
the implicit class `internal-user` for a principal of kind `user`; otherwise
none.

**R62 — Profile gate.** When the recipient references a Destination, the
release MUST be denied unless the record exists in the binding's tenant, is
active and well-formed, the highest transitive effective classification (R25)
of everything released is at most `maxClassification`, and the context purpose
is in `purposes`. An unknown, inactive, foreign or malformed profile denies.

**R63 — Run restriction.** When the grant carries `destinations`, the
release MUST be denied unless the destination's class or id is listed; a
recipient without a destination (R61 "none") is denied; the implicit
`internal-user` destination matches the class `internal-user` only.

**R64 — Legacy behaviour.** Without `Actor.destination` and without
`Grant.destinations`, releases MUST behave exactly as in 0.3.

**R65 — Only narrowing.** R62 and R63 add conditions to the 0.3
recipient checks and MUST NOT allow any release those checks deny.

**R66 — Obligation.** An allowed release governed by a Destination MUST
carry `destination_restricted` with the destination class and id; one to the
implicit `internal-user` under a restricted run carries `["internal-user"]`. If
the intersection with another `destination_restricted` obligation is empty, the
release MUST be denied. Whatever its origin (run, profile or supplemental policy),
every `destination_restricted` obligation of an allowed release MUST admit the actual
recipient: its Destination class or id, or `internal-user` for a user without a
profile; a recipient without a destination (R61 "none") is admitted by none.
Otherwise the release MUST be denied (`RECIPIENT`), also under an unrestricted run.

**R67 — Read-only evaluation.** A read-only evaluation (Engine.evaluate,
the AuthZEN `context.destination` member) for share/export that names a
Destination MUST apply R62 and R63. One that names none, under a
restricted run, MUST be allowed only with `destination_restricted` listing the
run's destinations; the enforcement point MUST then send only there.
(AKAC 0.6: an evaluation of share/export that names no Destination is denied
under every run, [R121](AKAC-0.6.md).)

**R68 — Attenuation.** A child grant of a parent with `destinations` MUST
carry `destinations` that are a subset of the parent's; a child of a parent
with `maxResults` MUST carry `maxResults` not greater than the parent's.
Violations deny with `INVALID_DELEGATION`.

**R69 — Result limit.** With `maxResults`, one openContext MUST NOT
disclose more distinct documents than `maxResults` (deny `OUT_OF_SCOPE`), and
retrieval MUST cap its result limit at `maxResults`.

**R70 — Enforcement boundary.** AKAC decides; transport is enforced by the
integration (egress proxy, gateway, runtime). A policy enforcement point that
cannot keep content to the destination named by `destination_restricted` MUST
treat the decision as a deny (R38). AKAC makes no claim of enforcing egress
by itself.

**R71 — Administration.** Destination changes MUST be security-admin
operations, audited, and an update MUST advance the tenant epoch.

Denials under R62, R63, R66 and R67 use the existing reason code `RECIPIENT`; public responses stay
non-distinguishing.

## Token binding (R72–R78)

Optional sender-constrained access tokens. Normative sources: RFC 9449 (OAuth 2.0
Demonstrating Proof of Possession), RFC 7638 (JWK Thumbprint) and RFC 7800 (`cnf`).
R19 leaves bearer-token replay to deployment controls; a sender-constrained token
shrinks that window without changing what a verified subject may do. Binding never
grants authority: the verified subject still maps to a server-side identity (R19) and
every decision remains subject to grants, labels, policy and revocation. Decision:
[ADR-009](../governance/ADR-009-token-binding.md). Migration `007_token_binding.sql`
(shared replay store).

**R72 — Configuration.** DPoP MUST be a per-listener setting with the values `off` (default), `optional` and
`required`. The agent listener and the administrative listener MUST be configured independently. A listener with
DPoP enabled MUST have an operator-configured public base URL and MUST NOT derive the expected request URI from the
`Host` header or from forwarding headers. Combining DPoP with opaque service credentials MUST be refused at start-up.
Deployments with signed tokens SHOULD use `required` on the administrative listener and on any listener reachable
from outside a trusted network.

**R73 — Scheme handling.** With DPoP enabled, a request bound to a key MUST carry `Authorization: DPoP <token>`
and one `DPoP` header. In `required` mode the `Bearer` scheme MUST be refused. In `optional` mode `Bearer` MUST be
accepted only for access tokens without a `cnf` claim. An access token that carries `cnf` MUST NOT authenticate as a
bearer token in any mode, including `off` (downgrade protection). An access token without `cnf` MUST NOT authenticate
with the `DPoP` scheme.

**R74 — Token binding.** The access token's `cnf` MUST be an object whose only member is `jkt`, equal to the
RFC 7638 SHA-256 thumbprint of the proof key. Other confirmation methods (for example `x5t#S256`) are unsupported and
MUST fail closed.

**R75 — Proof validation.** The gateway MUST accept a proof only if all of the following hold: the JWS is at most
8192 characters and has three parts; `typ` is `dpop+jwt`; `alg` is in the configured allowlist (`ES256`, `EdDSA`,
`PS256`; never `none` or a MAC); the header carries a `jwk` that contains public members only and whose key type,
curve and size match `alg` (P-256, Ed25519, RSA 2048 to 4096 bits); the header carries no `jku`, `x5u`, `x5c`, `x5t`,
`x5t#S256` or `crit`; the signature verifies with that `jwk`; `jti` is a string of at most 256 characters; `htm` equals
the request method; `htu` equals the public base URL plus the request path, without query or fragment; `iat` is within
the configured skew (default 60 seconds, at most 300) of the gateway clock; and `ath` equals the base64url SHA-256 of
the access token. A proof that names only a `kid` MUST be refused.

**R76 — Replay.** A `jti` MUST be accepted at most once per proof-key thumbprint while the proof can still pass
the time check. The replay decision MUST be recorded only for a request whose access token authenticated and matched
the proof key. If the replay store cannot decide (unavailable or full), the request MUST fail closed. The default
store is per instance; a deployment with more than one instance MUST use a shared store to obtain the guarantee.

**R77 — Errors.** A refusal MUST be `401` with a `WWW-Authenticate` challenge for the `DPoP` scheme (and `Bearer`
in `optional` mode) using `error="invalid_dpop_proof"` for a bad, replayed or mismatched proof and
`error="invalid_token"` for a token that failed authentication. The response body MUST NOT reveal which check failed.
Server-provided nonces (`use_dpop_nonce`) are not supported by this profile.

**R78 — Bounds.** Verification MUST NOT perform network fetches for keys, MUST bound proof size, and MUST NOT
allow token-supplied key locations.

Non-goals and residual risk: DPoP does not protect against a compromised holder key
or client process and does not bind the request body. Without server nonces a proof
can be pre-generated with a future `iat` inside the skew window, and a proof captured
before use can be replayed elsewhere until the skew expires unless the replay store is
shared. Mutual-TLS binding (RFC 8705) and token issuance are not covered.

## AuthZEN profile (R79–R90)

An optional policy decision point facade. Normative source: OpenID AuthZEN
Authorization API 1.0 (Final, 11 January 2026): Access Evaluation (section 6), Access
Evaluations (section 7), PDP metadata (section 9) and the HTTPS binding (section 10).
The obligations carried in `context.obligations` are an AKAC extension: AuthZEN 1.0
defines no obligation member and the working-group obligations work is a draft, so the
extension is only draft-aligned (R36–R38). The facade is an implementation profile of
that API, not a claim of AuthZEN conformance certification, and it has not been tested
against third-party enforcement points. The optional `context.destination` member is
accepted for `share` and `export` (R67). Search APIs, signed metadata and
capability URNs are not implemented. Optional; the default is off. Decision:
[ADR-011](../governance/ADR-011-authzen-profile.md); mapping table:
[AUTHZEN.md](../docs/AUTHZEN.md).

**R79 — Separate, optional listener.** The PDP facade MUST be a listener of its
own, disabled unless configured, that serves no agent, administrative or SCIM
route, and that the agent and administrative listeners do not serve. Its default
bind address SHOULD be loopback.

**R80 — PEP authentication.** Callers are trusted enforcement points and MUST
authenticate with credentials of their own: opaque tokens (at least 32 characters,
never equal to an agent or administrative token) or verified `at+jwt` tokens with
an audience distinct from the agent and administrative audiences. A verified
subject MUST map, through operator configuration only, to a PEP identity
`{tenant, pep}`. Token claims MUST NOT select a tenant. Optional DPoP (R72 to
R75) MAY be enabled for signed tokens. Agent and administrative credentials
MUST be refused (401).

**R81 — Tenant pinning.** The tenant of an evaluation MUST be the tenant of the
PEP identity. No request member (top level, subject, resource, action, context,
properties) may select, override or influence it. A PEP therefore reaches only the
identities and records of its own tenant.

**R82 — Profile mapping.** An evaluation maps to a policy input as follows and
in no other way: `subject.type` `user` (`subject.id` is the user,
`subject.properties.agent` the agent) or `agent` (`subject.id` is the agent,
`subject.properties.subject` the user); `subject.properties.grant` the run grant;
`resource.type` `knowledge` and `resource.id` the record; `action.name` one of
`read`, `derive`, `write_memory`, `share`, `export`; `context.purpose` the purpose;
optional `context.destination` the Destination profile id the enforcement point
sends to (R67; a present but invalid value is `decision:false`).
The binding is `{tenant, user, agent, grant}` (R81). The mapping table is
normative in `docs/AUTHZEN.md`.

**R83 — Message handling.** Unknown members of a request MUST be ignored
(AuthZEN 1.0 section 10.1.1). A missing or mistyped required member MUST be
refused with 400 (Access Evaluation) or, inside a batch, produce `decision: false`
with `context.error {status: 400}` for that evaluation. A well-formed request that
the profile does not support (an unknown action name including `declassify`, a
resource type other than `knowledge`, a subject type other than `user` or `agent`,
an identifier outside the identifier syntax, a purpose that is empty or longer
than 128 characters) MUST yield `decision: false`; such an evaluation MUST NOT be
distinguishable by status from an ordinary denial. An unknown
`evaluations_semantic` MUST be refused with 400 (the specification does not define
it). The PEP's `X-Request-ID`, if present and well-formed, MUST be echoed; a
malformed one MUST be refused with 400.

**R84 — Same decision function.** The decision MUST be the result of the pure
decision function of R29 over the hydrated authoritative snapshot of the tenant,
followed by the supplemental policy, applied exactly as the engine applies them
(including strict validation of policy obligations). An evaluation MUST NOT open a
context, read a document, or change any record other than appending audit entries.
An allow means "the engine would permit this request now"; it is not a disclosure
and does not replace the engine's own decision at the time of use, which also
checks run contexts, freshness and the tenant epoch (R18, R28).

**R85 — Audit.** Every evaluation that reaches the PDP MUST be audited in the
tenant stream (format 2, operation `authzen_evaluate`, actor the mapped user when
valid, `runId` the grant, `traceId` when a valid W3C `traceparent` was supplied),
allowed or not, with a `decisionId` that is returned to the PEP as `context.id`.
Audit entries MUST NOT contain request content beyond identifiers already defined
for audit. A request refused with 400 before evaluation is not an evaluation and
has no audit entry; it is counted by request metrics.

**R86 — Response minimisation.** The response MUST consist of `decision` and a
`context` containing only `id`, and, where applicable, `obligations`,
`reason_admin` (only when configured) and `error` (batch, malformed evaluation).
Reason codes MUST NOT be returned unless reasons are configured to `admin`
(default `none`), in which case `context.reason_admin` is `{code}` with a code from
the closed enumeration of R33.

**R87 — Obligations.** An allow MUST carry the obligations of R36 that apply
to the record (`audit_level` from confidential, `no_persist` from restricted, plus
those of the supplemental policy), merged restrictively, in `context.obligations`
when non-empty. `max_context_ttl_ms` is not issued: no context is created. A PEP
that cannot enforce every listed obligation MUST treat the decision as a deny
(R38). A PEP that does not understand `context.obligations` at all cannot be
assumed to enforce them and therefore MUST NOT be offered the facade for records
that may carry obligations.

**R88 — Access Evaluations.** The batch endpoint MUST accept at most 64
evaluations, apply top-level `subject`, `action`, `resource` and `context` as
defaults overridden per evaluation (section 7.1.1), support `execute_all` (default),
`deny_on_first_deny` and `permit_on_first_permit` (remaining evaluations omitted),
return decisions in request order and omit the top-level `decision`. Each
evaluation is a separate audited decision in its own transaction.

**R89 — Metadata.** The metadata document (`/.well-known/authzen-configuration`)
MUST be served only when an externally visible public origin is configured, and
MUST contain `policy_decision_point` (the origin) and the evaluation endpoints. It
contains no policy, tenant or credential information. The PDP identifier MUST be
an `https` URL in production.

**R90 — Limits.** The facade MUST bound concurrent requests (64), request body
(262144 bytes), evaluations per batch (64) and evaluations per PEP per minute
(1200; each batch item counts), and MUST fail closed: a store or policy failure is
500/503 (or a deferred denial) and never an allow.

Compatibility: additive; nothing in the agent, administrative or SCIM APIs changes.
The facade does not issue tokens, does not federate identities and does not weaken any
invariant: model-written content cannot alter identities, grants, labels or policy, and
an evaluation cannot be used to enumerate content.

## Cache isolation (R91–R99)

**Operator obligations.** These requirements apply to runtime operators integrating
AKAC-KB engines with model providers and inference platforms. The reference
implementation supplies the signals (decision outcome, effective classification,
tenant epoch, lineage and expiry) and cannot enforce them: it does not operate the
caches. Conformance to this section is therefore a deployment statement, not a
property of the reference gateway, and no conformance vector covers it.

Caches that hold protected context, derived model state or principal-specific
intermediate results (prompt, KV, response, embedding, retrieval and session caches)
are protected derivatives under R26. Shared hardware and multi-tenant inference
endpoints create two residual risks: cross-tenant leakage through a reusable entry,
and timing side channels that reveal cache hits.

**R91 — Mandatory partitioning.** Any cache holding protected context or derived model state (including but not limited to prompt cache, prefix cache, KV cache, response cache, embedding cache, retrieval-result cache, session cache, or request-scoped cache) MUST be partitioned by at least:
- **tenant** (enforced via AKAC context binding),
- **effective classification** of its inputs (supplied via decision context; R25), and
- **model/provider revision** (versioned with each model or inference endpoint upgrade).

Partitions MUST NOT share entries across any of these dimensions.

**R92 — No unauthorized reuse within a tenant.** Within a single tenant and classification, a cache entry MUST NOT be reused across principals (user identities, agent identities) unless every principal who could read the entry is explicitly authorized for all sources and content that contributed to it. An entry generated under one grant or principal's clearance MUST NOT be served to a principal with different clearance or purpose.

**R93 — Epoch invalidation.** When the operator advances a tenant's epoch (e.g., on revocation, deprovisioning, or classification change per R28), all entries in that tenant's cache partitions MUST be invalidated or made permanently unusable. Entries older than the tenant's current epoch MUST NOT be served. A context bound to an earlier epoch MUST NOT access caches of a later epoch.

**R94 — Cache keys not derived from protected content alone.** Cache keys MUST NOT be computable solely from protected content (e.g., a SHA-256 hash of plaintext retrieval results, embeddings, or model output). The purpose is that an adversary who observes a key does not thereby learn what content is cached. Keys MUST incorporate non-content elements such as tenant, principal, classification, or a server-held salt, making keys non-invertible without access control context.

**R95 — Quantization and compression preserve classification.** Quantization, compression, or lossy embedding of protected content does not lower its classification. A quantized vector, compressed embedding, cached embedding, or dimensionally-reduced activation inherits the classification of its source and is subject to the same partitioning and invalidation rules as the original content.

**R96 — Caches as protected derivatives.** Embeddings stored in a cache, cached query results, cached model activations, and any persistent or cross-request cached derivative of protected content are themselves protected derivatives and MUST be:
- classified at or above the classification of their source (R26),
- retained and erased under the same lifecycle policy as their sources,
- never exported or moved outside the operator's physical or logical infrastructure without going through the release gate, and
- accompanied by lineage or provenance tracking back to their source.

**R97 — Revocation and expiry handling.** When a source document, grant, or principal's authorization expires or is revoked:
- Any cache entry derived from that source MUST be invalidated, expunged, or made uncacheable within the next request-serving cycle (not deferred).
- A revoked principal's session cache or temporary results MUST be discarded immediately.
- An expired grant's derived state (e.g., outputs, memory, embeddings) MUST be invalidated when the operator detects expiry.

**R98 — Operator verification and logging.** The operator MUST:
- document which caches are implemented (prompt, KV, response, embedding, retrieval result, etc.),
- verify partitioning configuration in a production readiness checklist,
- log cache invalidations due to epoch advance or expiry (without logging the cached content), and
- make cache partition strategy and rotation policy auditable to compliance or security review.

**R99 — Timing side channels: acknowledged residual risk.** Perfect constant-time cache behavior is not required and is not feasible in shared hardware. Latency differences that reveal cache hits are an acknowledged residual risk in multi-tenant or shared inference environments. Operators SHOULD use:
- per-request cache salting (an inference-server cache-salt parameter) to prevent reuse prediction,
- jittered response times or noise injection (as policy permits), and
- dedicated inference hardware for the highest-classification compartments (`restricted`).

An adversary with timing access to a shared inference endpoint may infer the presence of cached entries even if not able to read their content. Mitigation is deployment responsibility.

Operator checklist: enumerate every cache in the integration; define partition keys
(tenant, classification, model revision) for each; validate entries against the current
tenant epoch; verify keys incorporate tenant and principal context and are not
invertible from content alone; use a per-request cache salt or equivalent principal
isolation for prefix and KV cache reuse; test invalidation on source revocation,
principal revocation and grant expiry; consider a dedicated embedding model and cache
for `restricted`; document the cache strategy, rotation, retention and audit logging;
log evictions without content.

This section does not amend R01–R31. It applies R26 (protected derivatives) and R28
(tenant-scoped revocation) to the runtime boundary.

## Hardening and conformance outcome classes (R100–R108)

Threat classes follow the OWASP Top 10 for LLM Applications 2025 (prompt injection,
sensitive information disclosure, excessive agency, vector and embedding weaknesses,
unbounded consumption) and MITRE ATLAS techniques for poisoning of persistent
memory. The requirements below are the AKAC-specific controls, not a claim of coverage
of those lists. R100–R103 concern the gateway; R104–R108 define the AKAC-RedTeam/0.4 profile,
which is a set of checks on the implementation under test, not an additional
access-control requirement.

**R100 — Per-run budgets.** A gateway MUST enforce request budgets per (tenant, agent, grant) run in addition to any per-credential budget. Retrieval (`/v1/retrieve`), context opening (`/v1/contexts`) and writing operations (`/v1/derive` and `/v1/release`) MUST have separate budgets, so that exhausting one class does not consume another. The run key MUST be taken from the authenticated binding, never from request content.

**R101 — Refusal semantics.** A request over budget MUST be refused before any engine work and MUST NOT reach the audited decision path as an allow. The response MUST be 429 with a `Retry-After` header (whole seconds until the window ends) and a body carrying no more than `{"error":"RATE_LIMITED"}`.

**R102 — Bounded state, fail closed.** The gateway MUST bound the memory used by limiter state. When the bound is reached and a request would require a new bucket, the gateway MUST refuse it with 503 and `Retry-After`; it MUST NOT evict another caller's counter to make room, and MUST NOT admit the request unmetered.

**R103 — Documented scope.** Limiter state is per gateway instance. A deployment with N instances behind a balancer MAY see up to N times a configured budget; an operator that needs a global bound MUST enforce it at a shared layer (edge or API gateway) and SHOULD treat the in-process limits as defense in depth. The reference gateway defaults are 120 requests per credential, 60 retrieve, 60 contexts and 30 write per minute per run, with 10,000 tracked buckets per limiter; all are configurable and validated at start-up.

### Outcome classes

Every decision, context, lifecycle, AuthZEN and scenario vector states whether the
request MUST be allowed or denied (for AuthZEN only `allow` is an allow; `deny`,
`malformed` and `unsupported` MUST NOT be allowed):

| Outcome | Expected | Observed | Meaning |
|---|---|---|---|
| SUCCESS | allow | allowed | correct availability |
| SAFE_BLOCK | deny | denied | correct protection |
| FAILURE | allow | denied, a wrong reason code, a failed setup step or a harness error | availability or correctness defect |
| UNSAFE_SUCCESS | deny | allowed | leak; never acceptable |

Pure-function vectors (RFC 9162 trees, RFC 8785 canonical form, audit formats,
obligations, reason codes) have no allow or deny meaning: a match is SUCCESS, a
mismatch FAILURE. Verification vectors (RFC 9162 inclusion and consistency proof
verification, format 2 checkpoint verification) are accept or reject: accepting is
an allow, so accepting a forged proof, a wrong tree size, a tampered consistency
proof, a tampered signature or a rolled-back checkpoint is UNSAFE_SUCCESS, and
rejecting a valid control is FAILURE. The hard gates of R105 apply to all of them.

**R104 — Four-way outcome.** A conformance runner MUST classify every vector with a stated allow or deny expectation as exactly one of SUCCESS (expected allow, allowed), SAFE_BLOCK (expected deny, denied), FAILURE (expected allow but denied, a wrong reason code, or a harness error) or UNSAFE_SUCCESS (expected deny but allowed, that is, a leak).

**R105 — Hard gates.** A run MUST exit non-zero when any vector is UNSAFE_SUCCESS or FAILURE. Independently, the count of UNSAFE_SUCCESS among vectors that exercise the tenant boundary MUST be zero, and the suite MUST contain at least one such vector (an empty set cannot satisfy the gate). A vector exercises the tenant boundary only when it is explicitly tagged `cross-tenant`; its id or description does not count.

**R106 — Reproducibility manifest.** A runner MUST be able to emit a machine-readable summary containing, at least, the runner version, the runtime version, the SHA-256 digest of every specification file and every vector file used, the SHA-256 digest of the dependency lock file, the outcome counts and the gate results. The summary MUST NOT contain host-specific paths or secrets.

**R107 — Broken-oracle evidence.** An implementation of the runner MUST be accompanied by tests that inject deliberately permissive implementations (decision function that always allows, ignores tenant, ignores classification, ignores quarantine lifecycle; engine that skips delegation attenuation, derives with a lowered label and no provenance, ignores epoch advance; inclusion-proof, consistency-proof or checkpoint verifier that accepts everything) and assert that the runner reports UNSAFE_SUCCESS and a non-zero exit code for each. A blanket-deny implementation MUST be reported as FAILURE, not as safe.

**R108 — Attack-class coverage.** The adversarial vectors MUST include, each with at least one allow control proving the setup is otherwise permitted: trust laundering (a restricted source summarized into memory or an artifact and read by a lower-clearance principal), delayed memory injection (model-origin memory used after quarantine, source revocation or grant revocation), child grant escalation (a delegated grant that widens actions, resources, purposes, expiry, active roles or subject), sub-agent trust laundering (a grant delegated to a lower-clearance agent reading the derived artifact of the parent run), lexical or candidate bypass (a candidate source that names unauthorized or quarantined records), stale context after a tenant epoch advance, and cross-tenant access.

## Compatibility and evidence

Wire routes remain `/v1` and the response envelopes stay closed. Successful agent
responses gain `decisionId` and `obligations`; denials gain `decisionId`
(R32–R36); administrative results gain `decisionId`. Storage stays `akac-state/0.3`;
PostgreSQL migrations 004–007 add the evidence, lifecycle, destination and replay
tables and columns (existing rows keep their 0.3 meaning: NULL means no lifecycle, no
destination, no run restriction). `CORE_VERSION` changes for 0.4.0, so contexts opened
by an earlier core revision deny and runs MUST be re-provisioned. New audit entries
use format 2; format 1 entries and checkpoints remain valid. Every new listener,
feature and enforcement mode that has a default is off or restrictive by default.
See the [migration notes](../docs/MIGRATION-0.4.md), [conformance](CONFORMANCE.md) and
the [changelog](../CHANGELOG.md).

## Draft identifier mapping

| Draft id | Requirement | Draft file |
|---|---|---|
| R-DE-1 | R32 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-2 | R33 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-3 | R34 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-4 | R35 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-5 | R36 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-6 | R37 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-7 | R38 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-8 | R39 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-9 | R40 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-10 | R41 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-11 | R42 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-12 | R43 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-DE-13 | R44 | [0.4-decisions-evidence](drafts/0.4-decisions-evidence.md) |
| R-LIFE-1 | R45 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-2 | R46 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-3 | R47 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-4 | R48 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-5 | R49 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-6 | R50 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-7 | R51 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-8 | R52 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-9 | R53 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-10 | R54 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-11 | R55 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-12 | R56 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-13 | R57 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-14 | R58 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-LIFE-15 | R59 | [0.4-knowledge-lifecycle](drafts/0.4-knowledge-lifecycle.md) |
| R-DEST-1 | R60 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-2 | R61 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-3 | R62 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-4 | R63 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-5 | R64 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-6 | R65 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-7 | R66 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-8 | R67 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-9 | R68 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-10 | R69 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-11 | R70 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DEST-12 | R71 | [0.4-destinations](drafts/0.4-destinations.md) |
| R-DPOP-1 | R72 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-2 | R73 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-3 | R74 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-4 | R75 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-5 | R76 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-6 | R77 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-DPOP-7 | R78 | [0.4-token-binding](drafts/0.4-token-binding.md) |
| R-AZ-1 | R79 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-2 | R80 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-3 | R81 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-4 | R82 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-5 | R83 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-6 | R84 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-7 | R85 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-8 | R86 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-9 | R87 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-10 | R88 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-11 | R89 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-AZ-12 | R90 | [0.4-authzen](drafts/0.4-authzen.md) |
| R-CACHE-1 | R91 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-2 | R92 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-3 | R93 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-4 | R94 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-5 | R95 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-6 | R96 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-7 | R97 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-8 | R98 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-CACHE-9 | R99 | [0.4-cache-isolation](drafts/0.4-cache-isolation.md) |
| R-HARD-1 | R100 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-2 | R101 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-3 | R102 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-4 | R103 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-5 | R104 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-6 | R105 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-7 | R106 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-8 | R107 | [0.4-hardening](drafts/0.4-hardening.md) |
| R-HARD-9 | R108 | [0.4-hardening](drafts/0.4-hardening.md) |

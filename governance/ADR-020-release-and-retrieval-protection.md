# ADR 020: release and retrieval protection

Status: proposed for AKAC 0.6 (draft). No external review has taken place.
Requirements: [AKAC 0.6](../spec/AKAC-0.6.md) (R167..R181).
Guide: [RELEASE-PROTECTION.md](../docs/RELEASE-PROTECTION.md).
Vectors: `conformance/vectors-0.6-release.json`.

## Context

AKAC decides whether content may be read, derived or released and records the
decision. Three gaps remained after 0.5. First, once a release was allowed, nothing
between the decision and the recipient could look at the text: redaction of personal
data, cleaning of content that is about to become memory, and any other content-level
control had no place to run, and such controls must never be able to widen what the
decision allowed. Second, the way a request is answered leaks: a denial and a no-match
differ in time, a caller learns nothing useful from an opaque denial, and a caller can
drain a corpus in small allowed steps. Third, the vector path had two weaknesses of its
own: the index pre-filter used the user's audience only (candidates the agent cannot see
were fetched and crowded out visible ones), and a changed embedding model behind a
stable name degraded retrieval silently.

## Decision

1. **Hooks, not filters in the core.** `reference/hooks.ts` defines `ReleaseFilter`
   (`pass`, `redact`, `deny`) and `DeriveSanitizer` (`pass`, `clean`, `deny`). The engine
   takes ordered lists and runs them after every other check of a release or a
   derivation, so they can only narrow. Their results are validated (closed actions,
   bounded content growth, closed finding strings); an error, timeout or malformed result
   denies. `failure: 'skip'` is an explicit operator choice and never applies to a
   required filter. AKAC ships no filter or sanitizer implementation; an operator supplies
   them in code or through `AKAC_HOOKS_MODULE`.
2. **`release_filter` and `approval_required` obligations.** `release_filter` (a list of
   filter ids) is enforced by the engine at share/export: an unconfigured required
   filter denies, a satisfied one is recorded in audit and not handed on. It comes from the
   supplemental policy, from an operator function per tenant and classification, or from a
   caller that requires more (ProtectedRuntime passes the context's ids to its releases).
   `approval_required` states that an approval is needed; no built-in enforcement point
   has a workflow, so each denies it. Both extend the closed obligation set, with Python
   parity for parsing and audit verification.
3. **Closed audit findings.** An optional audit member `findings` (at most 32 strings of
   `A-Z a-z 0-9 . _ : -`) records what hooks and budgets did. It carries no content. New
   reason codes: `RELEASE_FILTER`, `SANITIZER`, `VOLUME_EXCEEDED`, `APPROVAL_REQUIRED`,
   `RETRIEVAL_DISABLED`.
4. **Equalised time, not silence.** The agent listener and the AuthZEN listener can hold
   every post-authentication response of the equalised routes until a floor plus jitter has
   passed. On the AuthZEN listener that includes protocol errors (400), unknown routes,
   limits (413, 429, 503) and internal errors (500), not only decisions (0.6 review). Denial and no-match already share one response shape; the floor removes the
   timing difference below it. It is a mitigation with a stated limit (work above the floor
   is visible), and holding connections costs concurrency.
5. **Hints from caller state only.** Off by default. A hint is emitted only when a fact
   about the caller's grant chain, the requested action and purpose, the caller's volume
   state or the listener and tenant configuration denies the request whatever the resource
   is. Tests compare the hint of existing, forbidden, protected and missing resources.
   `RUNTIME_ENFORCER_REQUIRED` is deliberately a listener/tenant fact, not "this resource is
   protected". A volume hint is not emitted for the operation that consumed the budget.
6. **Volume budgets and backoff, in the community core.** Per (tenant, user, agent) and
   classification, bytes and documents per window, on the rate-limit store the listeners
   already use (shared through PostgreSQL when configured; no new table). The window is fixed
   (documented up-to-twice burst across a boundary), a refused charge still counts, and a
   store error denies. Exceeding denies or, in approval mode, defers with
   `APPROVAL_REQUIRED`. Backoff doubles the 429 time after a run of denials, bounded,
   per process. Adaptive throttling and behavioural scoring are not part of the core.
7. **Embedding anchors.** A monitor compares fresh anchor embeddings with a baseline
   (file-backed so that it survives restarts, digests of texts only). Drift, a changed
   model or anchor set, or no baseline disables vector retrieval (deferral
   `RETRIEVAL_DISABLED`, before the index is touched) until an administrator re-baselines; a
   drifted monitor is sticky. The baseline is never taken implicitly (0.6 review): a missing
   or unreadable baseline file leaves the monitor `pending` until an administrator
   re-baselines (`POST /admin/v1/index/anchors/rebaseline`) or the operator starts once with
   `AKAC_ANCHOR_BOOTSTRAP=true`, which creates a baseline only when none exists. A baseline
   file is required when anchors are enabled. Before, a restart without the file adopted
   whatever embedder was running, including one swapped while the gateway was down. Metrics `akac_embedding_drift`, `..._anchor_min_cosine`,
   `..._anchor_checks_total`; each deferred request is audited.
8. **Both audiences in the pre-filter.** `VectorQuery.agent` carries the agent's tokens and
   projects; the in-memory and pgvector indexes admit a chunk only when both audiences do.
   The authoritative re-check stays, and an index that ignores `agent` remains correct.
9. **Decision cache, allows only.** An optional in-process cache of `evaluate()` allows,
   keyed by tenant, epoch, policy digest, principal, resource, action, purpose and
   destination; the epoch is read in the same transaction; TTL at most one context
   lifetime and never beyond a grant or access expiry; denials are not cached; cached
   decisions are audited. Not shared between instances.
10. **Extensions only narrow.** The public text of R181 fixes the contract for anything
    added behind these seams.

## Consequences

- No semantic of decide() changes. Every addition denies, redacts, delays or defers; none
  allows. The Python implementation gains the closed sets (codes, obligation types,
  `findings` in audit verification) and its vectors stay green.
- A required filter that is not deployed makes releases at that classification fail. That is
  the point, and it is visible as `RELEASE_FILTER` in audit.
- Filters run inside the tenant transaction with a deadline (default 2 s); a slow filter holds
  the transaction and, on PostgreSQL, a connection. Operators size the deadline.
- Hints, timing and backoff reduce side channels only against the stated signals. Timing
  above the floor, traffic analysis, and any signal from content itself remain.
- The volume budget bounds a principal's disclosure rate; it does not detect collusion between
  principals or slow exfiltration below the budget.

## Alternatives considered

- **Filters as policy (OPA) output.** Policy sees classification and purpose, not the text.
  Content-level controls need the text, so they are hooks; policy names which are required.
- **Hints that name the failing check.** Rejected: reason codes by resource are an oracle.
- **A new migration for volume counters.** Not needed: the shared rate-limit store already
  keys by tenant, scope and identity digest and accepts a cost.
- **Sliding windows.** The shared store is fixed-window; a sliding implementation would need a
  new table or per-event rows. Documented as a limit instead.
- **Failing open on hook errors by default.** Rejected; the operator can opt out explicitly, per
  deployment, and never for required filters.

## Amendment (0.6b, second review round)

The decision cache key gains the audited operation (evaluate vs AuthZEN) and the
RiskProvider's current levels; entries end at the expiry of any session-scoped record they
read and are evicted when a session of their run closes. The AuthZEN PDP engine receives the
configured risk provider, and every post-authentication AuthZEN response is padded to the
timing floor. Embedding anchors never baseline implicitly (see R177).

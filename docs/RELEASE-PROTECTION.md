# Release and retrieval protection (0.6)

**This is guidance, not a certification.** It describes the extension points and the
secure default behaviour AKAC 0.6 adds around release, derivation and retrieval, and
what an operator must build and test around them. Requirements:
[R167..R181](../spec/AKAC-0.6.md). Decision:
[ADR-020](../governance/ADR-020-release-and-retrieval-protection.md).

AKAC decides and records. It does not detect personal data, judge content or score
behaviour. It offers the places where an operator's own components run, forces them
to fail closed, and lets them only narrow the outcome.

## What runs where

| Step | Component | Can do | Cannot do |
|---|---|---|---|
| after authorization of a share/export | release filters | pass, redact, deny | allow, widen content |
| after authorization of a derive | derive sanitizers | pass, clean, deny | change labels, sources, readers |
| after a read/release is otherwise allowed | volume budget | deny, defer to approval | allow |
| answer of retrieve/contexts/AuthZEN | response-time floor | delay | change the answer |
| any denial | hints (opt-in) | add one closed code | name a resource |
| repeated denials | backoff | refuse for a growing time | allow |
| vector retrieval | embedding anchors | disable retrieval | enable it |
| AuthZEN `evaluate` | decision cache (opt-in) | reuse an allow | reuse a denial, outlive an epoch |

## Release filters and derive sanitizers

```ts
import type { ReleaseFilter, DeriveSanitizer } from './reference/hooks.ts';
const pii: ReleaseFilter = {
  id: 'pii',
  async filter({ tenant, content, classification, recipient, purpose }) {
    return { action: 'pass' }; // or { action: 'redact', content } or { action: 'deny', reason: 'contains-pii' }
  }
};
new Engine(store, { releaseFilters: [pii], deriveSanitizers: [], hooks: { timeoutMs: 2000, failure: 'deny' } });
```

- Filters run in order, each on the previous output. A redaction must be non-empty, at most
  100000 characters and at most twice the input plus 256 characters; a `deny` reason and every
  sanitizer finding match `A-Za-z0-9._:-` (1-128 characters). Anything else is a malformed
  result and denies.
- An error, a timeout (default 2000 ms, at most 10000 ms) or a malformed result denies the
  operation (`RELEASE_FILTER`, `SANITIZER`). `failure: 'skip'` ignores broken hooks, except a
  filter that is required.
- `release_filter` obligation: a policy verdict for `share`/`export`
  (`{"type":"release_filter","value":["pii"]}`), an operator function
  `requiredFilters(tenant, classification)`, or `AKAC_RELEASE_REQUIRED_FILTERS`
  (`confidential=pii,dlp;restricted=pii`, applies to that classification and above) name the
  filters a release must pass. If one is not configured, the release is denied with
  `RELEASE_FILTER` before any filter runs. The satisfied obligation is recorded in audit and
  not returned to the caller.
- `ProtectedRuntime` passes the `release_filter` ids of the context to the provider-gate release
  and the final release, so a filter that a context requires applies to the prompt too. A
  redaction that breaks the prompt payload denies before the provider is called.
- An external enforcement point that performs the release itself (an AuthZEN client) receives
  `release_filter` in the decision and must either run the filters or treat it as a deny.
- `AKAC_HOOKS_MODULE` names an ES module exporting `releaseFilters` and `deriveSanitizers`
  arrays for the server process. AKAC ships none; loading arbitrary code is the operator's
  decision.
- Audit: `findings` on the entry (for example `pii:redact`, `pii:deny`, `reason:contains-pii`,
  `pii:timeout`, `required:pii:missing`). Metric `akac_release_hook_outcomes_total`.
- Hooks run inside the tenant transaction. Keep them fast and bounded; a slow hook holds a
  connection for up to its deadline.

## Response-time equalisation

`AKAC_MIN_RESPONSE_MS` and `AKAC_RESPONSE_JITTER_MS` (0-5000 and 0-1000). Every answer to an
authenticated `/v1/retrieve` or `/v1/contexts` request and every AuthZEN evaluation waits until the
floor plus a random jitter has passed. A denial and a no-match already have the same body shape
(`ok`, `code`, `decisionId`). Choose the floor above the p99 latency you measure (see
[PERFORMANCE.md](PERFORMANCE.md)): work that takes longer than the floor is still visible.
Held connections count against the listener's concurrency, so a large floor lowers throughput.
This does not hide network-level timing, response sizes of allowed answers or work done before
the request reaches AKAC.

## Denial hints (off by default)

`AKAC_DENIAL_HINTS=true` adds one `hint` to a denial when a fact about the caller denies the
request whatever the resource is:

| Hint | Emitted when |
|---|---|
| `GRANT_EXPIRED` | the grant or an ancestor is past its expiry |
| `PURPOSE_NOT_GRANTED` | the grant does not list the requested purpose |
| `ACTION_NOT_GRANTED` | the grant does not list the requested action |
| `RATE_LIMITED` | a 429 (rate limit or backoff), or the principal's volume budget is spent (deny mode) |
| `APPROVAL_REQUIRED` | the principal's volume budget is spent (approval mode) |
| `RUNTIME_ENFORCER_REQUIRED` | the listener has no runtime enforcer and the tenant uses runtime profile policies |

Never a resource, its existence, labels or ACL. The hint of a request is the same for an existing,
a forbidden and a missing resource; `tests/release-protection.test.ts` and vectors `REL-H01..H05`
check that. The operation that itself spends the last of a budget carries no volume hint, so that
the hint does not show that something matched. A hint tells a caller what to fix in its own
credentials; it does not tell it why a particular resource was refused.

## Volume budgets

`AKAC_VOLUME_LIMITS=confidential:bytes=1048576,documents=100;restricted:bytes=65536,documents=10`,
`AKAC_VOLUME_WINDOW_SECONDS` (default 3600), `AKAC_VOLUME_ON_EXCEED=deny|approval`.

- Per (tenant, user, agent) and classification; a classification without a limit is not counted.
  Counted: documents returned by a read projection (retrieve, contexts), at each document's highest
  transitive classification, and the bytes of a share/export output at the sources' highest
  classification.
- Counters live in the rate-limit store (`AKAC_SHARED_STATE`), so instances share them with
  PostgreSQL. The window is fixed, not sliding: a principal can spend up to twice a budget across a
  window boundary. A charge that is refused still counts, so a principal that hit the budget stays
  refused until the window ends. A store error denies (`STORE_ERROR`).
- Exceeding denies (`VOLUME_EXCEEDED`) or defers (`APPROVAL_REQUIRED`); the audit entry has the
  finding `volume:<classification>`. There is no approval workflow in AKAC: `approval` mode only
  labels the refusal so that an operator's own process can act on it.
- This bounds the rate at which one principal can pull content out. It does not correlate several
  principals and does not judge behaviour.

## Progressive backoff

`AKAC_BACKOFF_FREE_DENIALS` (enables), `AKAC_BACKOFF_BASE_SECONDS` (default 1),
`AKAC_BACKOFF_MAX_SECONDS` (default 300). After the free denials of one (tenant, user, agent), each
denial doubles the time until the principal's next request to retrieve, contexts, derive or release
is answered with 429 and `Retry-After`; a success resets the streak, an idle period of ten minutes
ends it. Denials and no-matches count alike. State is per process.

## Embedding anchors

`AKAC_ANCHOR_TEXTS_FILE` (JSON array of 1-32 anchor texts), `AKAC_ANCHOR_THRESHOLD` (default 0.98),
`AKAC_ANCHOR_INTERVAL_SECONDS` (default 300), `AKAC_ANCHOR_BASELINE_FILE` (required: the baseline must
survive restarts), `AKAC_ANCHOR_BOOTSTRAP` (default false). The anchors are embedded at
start-up and on the interval and compared with the baseline. Drift below the threshold, a different
model name, dimension count or anchor set, or no baseline yet, disables vector retrieval: requests are
deferred (`RETRIEVAL_DISABLED`) before the index is queried, the gauge `akac_embedding_drift` is 1 and
each deferred request is audited. It stays disabled until an administrator re-baselines:
`POST /admin/v1/index/anchors/rebaseline` (security-admin, audited), or write a new baseline file with the
current model; a running gateway adopts a newer baseline file on its next check. The baseline is never taken
implicitly: when the file is missing or unreadable at start-up, retrieval stays disabled (state `pending`)
until an administrator re-baselines. For the very first start, set `AKAC_ANCHOR_BOOTSTRAP=true` once: it
creates the baseline only when no file exists and never replaces an existing or unreadable one; remove the
flag after that start (the gateway logs a reminder), or a later loss of the file would be re-baselined
silently. Keep the file on a persistent volume. The baseline file holds digests of the anchor texts and the anchor vectors; protect it
like configuration. Choose anchors that resemble your content; a handful of fixed sentences detects a changed
model, not subtle degradation. It does not re-embed your corpus after a deliberate model change: reconcile
the index and then re-baseline.

## Retrieval pre-filter

The engine hands the index the tokens of the user and of the agent. A chunk is a candidate only if both
admit it (document readers and roles, every ancestor folder, required projects). Before this change the
agent's audience was applied only after the fetch, so documents the agent cannot see could fill the
candidate list. The decision for every candidate is still taken by `decide()`; the metric
`akac_filter_mismatch_total` now counts only real inconsistencies (a stale index, a changed policy), not
candidates the agent could never see. A third-party index that
ignores `VectorQuery.agent` stays correct and only loses recall.

## Decision cache (off by default)

`AKAC_DECISION_CACHE_TTL_MS` (1-300000) and `AKAC_DECISION_CACHE_MAX`. AuthZEN evaluations of an allowed
request are served from memory: the tenant epoch is read in the same transaction, so a revocation,
deactivation, quarantine, role or label change (each advances the epoch) makes older entries
unreachable; an entry also ends at the earliest grant or access expiry it read. Denials are not cached,
every cached decision is audited with its own decision id. A supplemental policy that changes its
answers without changing its revision is bounded by the TTL only. The cache is per process.

## Operator checklist

- Decide which classifications need which filters; set `AKAC_RELEASE_REQUIRED_FILTERS` and deploy the
  module before enabling it (a missing filter denies).
- Measure p99 latency before choosing a response-time floor.
- Keep denial hints off unless callers need self-service fixes; review the table above first.
- Size volume budgets from real usage; start in `deny` mode on the highest classification only.
- Monitor `akac_embedding_drift`, `akac_volume_budget_exceeded_total`,
  `akac_release_hook_outcomes_total`, `akac_retrieval_disabled_total`.
- What this does not cover: content-level detection quality (yours), collusion, slow exfiltration below a
  budget, a compromised runtime after release (see [RUNTIME-CONTAINMENT.md](RUNTIME-CONTAINMENT.md)).

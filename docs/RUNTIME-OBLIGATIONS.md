# Runtime operator obligations checklist

**This is guidance, not a certification.** Each item describes a control, its purpose, and the AKAC reference vs. operator responsibility split. Operators are responsible for implementing, testing, and auditing these controls in their own deployments.

## Complete mediation

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Every knowledge read gated by authorization decision | Prevents unauthorized disclosure of protected context | Audit log shows `decide()` on all retrieval paths; zero unchecked corpus access | `decide()` with full context (R04, R08) | HTTP gateway integrity, no direct database access for agents, request binding |
| Every generated disclosure subject to recipient authorization | Prevents "I wrote output without knowing who reads it" | Test: release gate denies unauthorized recipient, audit log shows recipient check | Release gate logic (R15) | Recipient binding in TLS transport, no agent-to-user direct messaging |
| No model or agent access to authority data | Prevents model-written labels or grants | Audit log shows zero role assignments or label changes from `model` origin | Admin API segregation (R06, R31) | Separate admin listener, firewall rules, no credential reuse |
| Policy revisions supplied fresh on every request | Prevents stale role or SoD decisions | Policy hydration log, per-request timestamps, no cached decisions across role changes | Per-tenant epochs, fresh closure hydration (R18, R28) | Cache invalidation on policy update, no persistent decision memoization across requests |

## Isolation and containment

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Each request runs in isolated context with its own KV cache, session state, and tool invocation scope | Prevents context leakage between requests and principal activation scope violations | Per-request context fixture in tests; audit trace shows independent contexts; timing does not correlate sessions | Context binding and grant activation (R24, R30) | No global model state, per-request cache salt, session scoping, memory isolation between agent runs |
| Isolated provider threads for parallel requests | Prevents cross-request model state pollution | Load-test harness confirms KV cache per request; sampling of concurrent requests shows no interference | Engine request boundary | Model provider integration (shared library vs. remote), thread-local storage, request queuing |
| Container network segregation | Prevents control-plane credential leakage to agents | Network policy: admin listener on separate pod/network, ingress rules deny agent→admin traffic | Separate listeners and ports (admin 9000, agent 8000, metrics 9090) | Kubernetes NetworkPolicy or firewall rules; Docker networks; no overlapping port ranges |

## Egress control (model provider and embedding provider boundary)

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Approved providers only receive approved classifications | Prevents `restricted` context routed to public cloud inference | Operator policy: provider X approved for classifications {public, internal} → test denies restricted query to X | Provider whitelist in configuration (R04) | Model selection logic enforces classification floor, embedding provider check, OPA policy optional override |
| No content sent to unapproved providers | Prevents accidental leakage to free tier or logging endpoint | Audit log shows provider name with every query; test confirms denial on provider not in whitelist | Provider boundary in decision output | Runtime provider routing, URL filtering, no fallback to untrusted endpoint |
| Embeddings and activations never returned by agent API | Prevents exfiltration of protected derivatives | API schema validation, response content inspection in testing, no `embeddings` field in agent responses | Vector exclusion from agent response (R26) | Endpoint validation, no embedding model token accessible to agents, strict response schemas |
| Embedding provider approved for the content's classification | Prevents `restricted` text sent to external embedder | Policy rule or runtime check: `restricted` docs → local embedder only | Classification-aware embedding selection (R26) | Embedder selection logic, model provider approval matrix, local vs. remote toggles per classification |
| Model provider informed of data classification when required | Allows provider to enforce their own controls | Documented policy agreement with provider; contract language; test confirms header or request body includes classification | Classification in decision context, optional to expose | Contract language, API request enrichment (optional per provider), compliance documentation |

## Cache isolation (per spec/drafts/0.4-cache-isolation.md)

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Cache partitioned by tenant + classification + model/provider version | Prevents cross-tenant or cross-classification reuse | Enumerate all caches (KV, prompt, embedding, response, retrieval); audit configuration; test confirms `restricted` never reuses a `public` cache entry | Tenant + classification in context, version tracking | Partition key derivation, per-tenant cache instances or tagged entries, model version gates |
| Cache invalidated on tenant epoch advance | Prevents stale entries after revocation | Trigger epoch advance (e.g., via revoke principal), confirm cache entry not served in next request, audit log records invalidation | Epoch signals via tenant state (R28) | Epoch validator on cache lookup, TTL-based expiry, event-driven eviction handlers |
| Per-request cache salt for KV/prefix cache reuse | Mitigates timing side channels revealing cache hits | Test with an inference server that supports cache salting: different principals on same prompt, confirm KV blocks not reused (via timing or logging) | Tenant + principal in context | Cache salt derivation (e.g., `hash(tenant:user:grant)`), the inference server's cache-salt parameter, request routing |
| Cached embeddings, query results, and activations classified as protected derivatives | Enforces same retention and erasure as source | Audit trail shows cached entry deleted on source deletion, embedded vector retention matches document retention | Classification assignment (R26) | Lifecycle tracking, cache TTL tied to source retention, purge job on source expiry |

## Revocation and epoch handling

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Revoked principal's sessions discarded immediately | Prevents use-after-revoke | Revoke a principal, attempt next request with their token, receive denial or stale-session error | Epoch advance signal (R28) | Session store invalidation, token binding to epoch, no session recovery after epoch change |
| Document or source expiry invalidates cached derivatives | Prevents serving obsolete content after expiry | Set document expiry, request after expiry, confirm cache not served, audit log shows cache eviction | Expiry metadata in decision output | TTL-based cache eviction, expiry check before cache hit, source-cache binding |
| Revocation of grant does not require app restart | Allows fast credential rotation | Revoke a grant, new request with same user but different grant, confirm isolation | Grant activation in decision (R24) | Grant hydration on every request, no grant caching across requests, separate cache for each active grant |
| All in-flight contexts for a revoked run discarded | Prevents reuse-after-revocation | Revoke a run (simulation: mark epoch), running agent context can no longer read or ingest | Tensor-scoped epoch (R28) | Context cleanup handlers, no cross-epoch context reuse, event-driven revocation (e.g., SCIM deprovisioning) |

## Provider integration and trust

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Model provider credentials not passed to agent process | Prevents agent from making unapproved calls or leaking credential | Audit: agent process environment, memory, logs do not contain provider API keys | No agent read of configuration (R31) | Credentials in operator-controlled configuration or secret store, sidecar inference proxy, no env var exposure |
| Model provider and embedder selection based on approved whitelist, not user request | Prevents user-directed exfiltration | Policy rule: user cannot name an embedding provider; test confirms denial if override attempted | Whitelist in operator config | Provider selection logic in gateway, no user-controlled endpoint override, runtime enforcement |
| Inference endpoint not exposed to untrusted networks | Prevents external enumeration or hijacking | Network policy: model inference endpoint accessible only from AKAC pod, firewall blocks external | Separate listener ports | Kubernetes ingress rules, VPC/security groups, private model endpoints, no public inference URL |
| Provider API rate limits and quota enforced | Prevents resource exhaustion attacks or billing surprises | Rate limiter per principal/tenant/model; test confirms denial on quota hit | Per-request context and identity | Token bucket or sliding window per principal, quota enforcement at gateway, alerts on approach to limits |

## Logging without content

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Audit log contains decision, principal, classification, but no plaintext | Prevents sensitive data leakage through logs | Sample audit log; no content, no embeddings, no model output; IDs and categories only | Audit record structure (R05, R07) | Log schema validation, redaction on write, structured logging (NDJSON), no stringification of content |
| Error responses do not reveal codes, categories, or policy logic | Prevents inference of authorization structure | Test with forbidden principal, receive generic 403; no "you lack SoD constraint role X" | Public error messages (R29) | Generic error templates, category-only logs, no policy explanation to user |
| Metrics do not leak individual request content or decision outcome | Prevents privacy inference from cardinality or timing | Prometheus metrics named by category (e.g., `akac_decision_total{category="deny"}`), no per-user or per-document counters | Metrics structure (per the operations guide) | Metric aggregation levels, no high-cardinality user or document labels, cardinality limits |
| Credentials (tokens, passwords, provider keys) never logged | Prevents credential theft from log inspection | Audit log redaction or masking rules; test confirms token values replaced with `[REDACTED]` | Token binding without storing value (R29) | Explicit redaction on all credential fields, no echo of Authorization headers, secret-scanning in logs CI |

## Deployment readiness

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Separate HTTP listeners for admin, agent, and metrics | Prevents credential confusion and unauthenticated access to authority | Network diagram; listener ports hardcoded; test confirms admin endpoint rejects agent credentials | Listener separation (R31) | Docker Compose with separate services/ports, firewall ingress rules, no shared port |
| TLS for all external communication (admin and agent) | Prevents credential or context interception | Endpoint inspection: curl receives certificate, http denied | Not built in; loopback demo only | TLS termination proxy (nginx, ingress), certificate management, mTLS for inter-pod (optional for agent, required for admin) |
| Readiness checks refuse bypass-RLS or superuser roles | Prevents silent misconfiguration | Operator runs `npm run check` and deploy-readiness scripts; test database role cannot execute `SELECT ... WHERE false` | Runtime role validation (R29) | PostgreSQL role configuration, readiness probe that checks role privileges, startup failure if misconfigured |
| Production database encrypted at rest | Prevents data theft from stolen drives | Operator documentation: list encryption mechanism (AWS RDS encryption, pgcrypto, dm-crypt) | Not provided | PostgreSQL encryption (pgcrypto, at-rest), managed database encryption (AWS RDS, Azure, GCP), backup encryption |
| Admin and agent API keys rotated periodically | Prevents long-lived credential exposure | Operator procedure and audit: keys rotated monthly or on event, old keys revoked | Token structure and validation | JWT signing key rotation, credential store updates, no hardcoded secrets in images |
| Database backups encrypted and access-controlled | Prevents backup-theft exfiltration | Operator documentation: backup encryption, restore procedure, access restrictions | Not provided | Encrypted backups, separate backup vault credentials, tested restore procedure, retention policy |

## Runtime containment (0.5, spec/AKAC-0.5.md)

Applies once a tenant has an active runtime profile policy. Contract and bypass checklist: [RUNTIME-CONTAINMENT.md](RUNTIME-CONTAINMENT.md).

| Obligation | Why | How to verify | AKAC supply | Operator implements |
|---|---|---|---|---|
| Apply every `runtime_profile` before anything protected happens, or deny | No mandatory obligation may disappear in translation to runtime controls (R112, R113) | Checklist item 9: a profile without a template denies before the provider is called; audit shows `runtimeRevision` on allowed answers | Derivation, `RuntimeEnforcer` seam in `ProtectedRuntime`, vectors `RTC-R01` to `RTC-R12` | An enforcer for the chosen runtime, running outside the agent's control |
| Profile ids reference operator-reviewed templates only | Model-generated policy must never become runtime policy (R114) | Checklist items 7 and 8; template repository with review history | Ids only, validated; security-admin human changes, audited, epoch advance | Template review and versioning; approval process for template changes |
| Label outputs at least `max_output_classification` | Derived output must not be treated as less sensitive than its sources (R111) | Sample downstream records; labels never below the obligation | Transitive classification in the obligation | Labelling in every downstream system that stores or forwards output |
| Non-bypassable enforcement point | Direct store, provider or credential access skips every decision (R118) | Checklist items 1, 2, 6 and 12 | Mediated reads and releases | Network and credential isolation of the sandbox |
| Correlate evidence | Runtime activity must be attributable to decisions (R117) | Execution ids appear in AKAC audit and runtime logs; revisions match | `x-akac-execution-id`, `executionId`, `runtimeRevision` in audit format 2 | Pass execution ids; retain runtime logs with the applied revision |
| Discard content after an epoch advance | Stale authorization (R119) | Checklist item 10 | Epoch advance on every runtime policy change | Sandbox teardown or reconfinement on denial |

## Architecture decision record

This checklist operationalizes requirements R01–R31 (AKAC 0.1, 0.2, 0.3), R-CACHE-1..9 (0.4 cache isolation), R109–R120 (AKAC 0.5, [ADR-012](../governance/ADR-012-runtime-containment-contract.md)), and the threat model mitigations listed in [docs/THREAT-MODEL.md](THREAT-MODEL.md). It is not a substitute for operator security review or an industry compliance standard. See the security operations guide for runbooks and incident response.

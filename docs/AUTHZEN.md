# AuthZEN PDP facade (optional, draft)

AKAC can answer the OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026) Access
Evaluation and Access Evaluations calls for trusted enforcement points (API gateways, agent
frameworks). Requirements: `spec/drafts/0.4-authzen.md`. Decision: `governance/ADR-011-authzen-profile.md`.
Wire description: `docs/openapi-authzen.json`. This is an implementation profile with unit,
property and vector tests; it has not been interoperability-tested against third-party AuthZEN
enforcement points and makes no certification claim. Search APIs, signed metadata and capability
URNs are not implemented.

An evaluation is a read-only, audited "would AKAC permit this now?". It never opens a context,
returns content or changes state other than audit. An allow is not a lease: at the time of use the
engine decides again (run contexts, freshness, tenant epoch).

## Enabling

The listener is off unless `AKAC_AUTHZEN_PORT` is set (default bind `127.0.0.1`).

| Variable | Meaning |
|---|---|
| `AKAC_AUTHZEN_PORT` | Enables the listener. Must differ from the other listener ports. |
| `AKAC_AUTHZEN_HOST` | Bind address (default `127.0.0.1`). |
| `AKAC_AUTHZEN_CREDENTIALS_FILE` | JSON array of `{token, binding: {tenant, pep}}` (token at least 32 characters). |
| `AKAC_AUTHZEN_JWT_CONFIG_FILE` | Alternative: `{issuer, audience, jwksUrl, algorithms, peps: {<verified subject>: {tenant, pep}}}`. Exactly one of the two files. |
| `AKAC_AUTHZEN_REASONS` | `none` (default) or `admin`: return the closed reason code in `context.reason_admin`. |
| `AKAC_AUTHZEN_PUBLIC_URL` | Public origin. Enables `/.well-known/authzen-configuration`; https in production. |
| `AKAC_AUTHZEN_DPOP` | `off` (default), `optional`, `required` for signed tokens (uses `AKAC_AUTHZEN_PUBLIC_URL` as the `htu` base; DPoP settings shared with the other listeners). |

A credential is valid on exactly one listener: PEP tokens must not equal any agent or admin token,
and the PEP JWT audience must differ from the agent and admin audiences (start-up refuses
otherwise). Agent and admin credentials return 401 here; PEP credentials return 401 on the other
listeners. Rate limit: 1200 evaluations per PEP per minute (each batch item counts), 64 concurrent
requests, 262144-byte bodies, at most 64 evaluations per batch. Metrics: the standard request
series with `listener="authzen"`; decisions are counted with operation label `other` unless the
metrics allow-list names `authzen_evaluate`.

## Mapping profile

The AKAC binding is `{tenant, user, agent, grant}`. The tenant is the PEP credential's tenant and is
never read from a request.

| AKAC | AuthZEN member | Rule |
|---|---|---|
| tenant | (PEP credential) | Never from the request; any tenant member anywhere in the request is ignored. |
| user | `subject.id` when `subject.type` is `user`; otherwise `subject.properties.subject` | Identifier syntax; else `decision:false`. |
| agent | `subject.properties.agent` when `subject.type` is `user`; otherwise `subject.id` | Same. |
| grant (run) | `subject.properties.grant` | Required. |
| resource | `resource.id`, `resource.type` = `knowledge` | Other types: `decision:false`. |
| action | `action.name` in `read`, `derive`, `write_memory`, `share`, `export` | Any other name, including `declassify`: `decision:false`. |
| purpose | `context.purpose` | Required string of 1 to 128 characters (longer: `decision:false`). |
| destination | `context.destination` | Destination profile id (ADR-008) the PEP sends to. Required for `share` and `export` (0.6 R121): without it the evaluation is `decision:false` (reason `RECIPIENT`), also for an unrestricted run, because a read-only evaluation has no recipient whose access could be checked. Applies R62/R63 when present. Present but not a valid identifier: `decision:false`. |
| decision id | response `context.id` | UUIDv4 of the audit entry. |
| obligations | response `context.obligations` | AKAC extension, only on an allow. Includes `runtime_profile` (one per domain) and `max_output_classification` when the tenant has an active runtime profile policy (0.5, [RUNTIME-CONTAINMENT.md](RUNTIME-CONTAINMENT.md)). |
| reason code | response `context.reason_admin.code` | Only with `AKAC_AUTHZEN_REASONS=admin`. |

Handling of malformed input follows AuthZEN 1.0: unknown members are ignored (section 10.1.1); a
missing or mistyped required member (`subject`, `resource`, `action`, `context`, `context.purpose`,
`subject.properties.grant`, the agent or user counterpart, string types) is 400; in a batch it is
`decision:false` with `context.error {status: 400, message: "Bad Request"}` for that item. Requests that
are well formed but outside the profile are `decision:false` and indistinguishable from a denial.

Example (request and response):

```json
{ "subject": { "type": "user", "id": "chief", "properties": { "agent": "chief-agent", "grant": "chief-run" } },
  "resource": { "type": "knowledge", "id": "strategy" }, "action": { "name": "read" }, "context": { "purpose": "work" } }
```

```json
{ "decision": true, "context": { "id": "3f1c9a0e-7d52-4b9b-8a4e-2d6f5f2a9b11",
  "obligations": [ { "type": "audit_level", "value": "full" }, { "type": "no_persist" } ] } }
```

(identifiers above are synthetic). Batch: `POST /access/v1/evaluations` with `evaluations` plus optional
top-level `subject`, `action`, `resource`, `context` defaults and
`options.evaluations_semantic` (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`).
Short-circuited requests omit the remaining evaluations.

## PEP contract (obligations)

1. Treat any transport error, non-200 status, timeout and `decision:false` as deny.
2. On an allow, enforce every entry of `context.obligations` or treat the decision as a deny:
   `audit_level full` (log `context.id` with every downstream use), `no_persist` (do not persist the
   content or anything derived from it outside AKAC), `max_context_ttl_ms` (not issued by this
   facade), `destination_restricted` (only listed destination profiles may receive the content),
   `runtime_profile` (0.5: apply the operator-reviewed profile named for the domain in the runtime
   that holds the content, before using it; no enforcer or no template for the profile is a deny; two
   different profiles for one domain never occur in one decision) and `max_output_classification`
   (0.5: label every output derived from the content at least this high).
   An obligation of an unknown type is a deny. The core provides `enforceable(obligations, supported)`
   (`reference/decision.ts`); `ProtectedRuntime` and the passages bonus runtime show the pattern.
3. A PEP that does not understand `context.obligations` at all must not be used for records that can
   carry them (confidential and above always do). AuthZEN 1.0 defines no obligation member; the
   AuthZEN working-group obligations work is a draft, so this member is an AKAC extension.
4. Send `X-Request-ID` to correlate; it is echoed. A W3C `traceparent` is recorded in audit.

## Audit and evidence

Every evaluation that reaches the PDP is one audit entry (operation `authzen_evaluate`, actor the mapped
user, `runId` the grant, allow or deny with a closed reason code, obligations of an allow), included in
the tenant Merkle tree and provable with the routes in `docs/OPERATIONS.md` (audit proofs). A 400 for a
missing required member is not an evaluation and has no audit entry. Request content is not recorded.

## Verification

`node --test --test-concurrency=1 tests/authzen.test.ts tests/config-authzen.test.ts tests/conformance-authzen.test.ts`
and `npm run conformance` (profile `AKAC-AuthZEN/0.4-draft`, `conformance/vectors-authzen.json`). The property
test compares the facade with `decide()` over 400 generated requests and the obligations test compares
them with `Engine.openContext`.

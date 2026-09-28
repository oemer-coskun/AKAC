# Migrating reference 0.1 to 0.2

1. Stop new agent runs, drain in-flight operations and back up the state and audit
   log under the existing access policy. Test restore in an isolated environment.
2. Install locked dependencies using Node.js 24. Keep the existing storage schema;
   no data-format rewrite is required. Never reset audit history to bypass errors.
3. Deploy the bundled OPA policy and change `OPA_URL` to
   `http://opa:8181/v1/data/akac/decision`. Set `OPA_REVISION=akac-company/0.2`.
   Custom policies must return the exact `{allow, revision}` result contract and
   increment their revision whenever semantics change. Old boolean responses deny.
4. Invalidate existing runs and provision fresh bounded grants and model sessions.
   Existing context handles carry the old core/policy revision and deny. Do not
   edit stored contexts to make them appear current or recycle a run's history.
5. Keep `AKAC_CREDENTIALS_FILE` for opaque tokens, or configure
   `AKAC_JWT_CONFIG_FILE` for signed access tokens. Exactly one must be set.
   JWT mode requires trusted subject-to-binding provisioning; it is not automatic
   SSO or a migration of arbitrary identity-provider claims into permissions.
6. Exercise `/ready` with a service credential and test allowed handbook, denied
   executive-document, provider-recipient and revocation cases before serving runs.

Logical expiry is optional metadata, checked transitively. It does not schedule
deletion. Audit checkpoint signing is opt-in and needs an externally managed key
and independent retention. Do not generate private keys in source control.

Custom in-process `PolicyHook` adapters now require a nonempty `revision`. The
compiled core version is included in context and audit revision identifiers even
when an older persisted state carries its prior administrative policy version.

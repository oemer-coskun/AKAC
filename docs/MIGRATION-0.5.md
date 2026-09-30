# Migrating reference 0.4 to 0.5

0.5 adds the runtime containment contract ([AKAC 0.5](../spec/AKAC-0.5.md), R109-R120, [ADR-012](../governance/ADR-012-runtime-containment-contract.md)). It is additive and off by default: a tenant without an active runtime profile policy sees exactly the 0.4 behavior. The core revision still changes, so open contexts deny. Read the [changelog](../CHANGELOG.md) first. An upgrade of a real deployment has not been rehearsed by the project.

## Steps

1. Back up the database and your latest audit checkpoints. There are no down migrations.
2. Stop new agent runs and drain in-flight operations. The `CORE_VERSION` bump (`akac-reference/0.5.0`) is part of every context's policy revision, so contexts opened by 0.4 deny; provision fresh runs.
3. Run `npm run migrate` (or start with `AKAC_AUTO_MIGRATE`). Migration `008_runtime_profiles.sql` adds the runtime profile policy table (key `(tenant, id)`, forced RLS) and the optional audit columns `execution_id` and `runtime_revision`. Migrations 001-007 are unchanged. Grant the runtime role the usual table privileges on the new table.
4. Upgrade external audit verifiers together with the gateway: entries may now carry the optional members `executionId` and `runtimeRevision` (hash-covered); older verifiers reject them. Entries without them are unchanged.
5. SQLite and memory stores upgrade on load; snapshots without `runtimeProfiles` mean none.

## Enabling the contract (optional)

1. Write and review one runtime template per profile id in your runtime.
2. A security administrator stores runtime profile policies with `PUT /admin/v1/runtime-profiles/{id}`; each change advances the tenant epoch. Give higher classification tiers templates at least as restrictive as lower ones.
3. Give `ProtectedRuntime` a `RuntimeEnforcer` (`apply(profiles, {executionId})` returning a lease, `current(executionId)`; declare `isolation: 'per-execution'` only for one runtime per execution, otherwise executions are serialized). Without one, every decision that carries a `runtime_profile` obligation is denied before the provider. Runtimes built on `RUNTIME_OBLIGATIONS` also deny them.
4. Label every output at least as high as `max_output_classification`, send `x-akac-execution-id` for correlation, and run the [bypass checklist](RUNTIME-CONTAINMENT.md#bypass-test-checklist).

Rollback: stop 0.5, restore the backup taken in step 1 and the 0.4 build; runtime profile policies and the new audit members are unknown to 0.4.

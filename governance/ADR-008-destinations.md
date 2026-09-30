# ADR 008: destination profiles and run result limits

Status: proposed for reference 0.4.0; internal review only, external security
review outstanding. Requirements: [0.4 destinations draft](../spec/drafts/0.4-destinations.md).
Integration contract: the integration guide.

## Context

0.1 R10 requires the destination of a disclosure to be authorized, but through
0.3 the only destination check was that the recipient principal could itself
read every released source. A model provider or tool modelled as a fully
cleared service could therefore receive anything its tenant holds, and a run
could not say "this work may only go back to people". ADR-006 reserved the
`destination_restricted` obligation for this profile.

## Decision

1. **Destination is a separate, tenant-scoped record** (`Destination {id,
   tenant, class, maxClassification, purposes, active}`), referenced from the
   receiving principal by `Actor.destination`. Principals already are what
   release names; attaching a profile to them keeps the release API unchanged
   and lets many principals (for example several provider credentials) share
   one profile. We rejected naming destinations in release requests: a caller
   could then choose a more permissive profile than the recipient really is.
2. **Backward compatibility by absence.** Without `Actor.destination` a user is
   the implicit `internal-user` destination and other principals have none;
   without `Grant.destinations` there is no run restriction. Both absent gives
   exactly the 0.3 behaviour, so all 0.3 vectors and tests are unchanged.
3. **Only narrowing.** The gate runs after the 0.3 recipient check and never
   replaces it. A property test checks that adding a run restriction or a
   profile never turns a deny into an allow.
4. **Classification is transitive** (R25): the gate uses the highest effective
   classification of every released source and their sources, so a mislabelled
   derived artifact cannot carry restricted content to a confidential-only
   provider.
5. **Class or id in the grant.** `Grant.destinations` lists classes (coarse:
   "model providers") or profile ids (exact). Ids never equal class names, so a
   list entry is unambiguous. Child grants must list a subset (string subset:
   a child listing an id under a parent that lists only its class is refused,
   which is conservative).
6. **Obligation carries class and id.** `destination_restricted` names both, so
   it intersects meaningfully with a supplemental policy that names profile
   ids. An empty intersection denies instead of issuing an unsatisfiable
   obligation. `ProtectedRuntime` enforces the obligation (it sends only to the
   provider the gate authorized, and the answer only to the subject).
7. **No new reason code.** Destination denials use `RECIPIENT`; the audit keeps
   the decision id, and public responses remain non-distinguishing.
8. **Result limit (`Grant.maxResults`, 1..64).** It bounds one disclosure, not
   the whole run; openContext above it is `OUT_OF_SCOPE`, retrieval is capped.
   Children may only lower it.
9. **Storage.** Migration 006 adds `akac_destinations` ((tenant, id) key, forced
   RLS), `akac_actors.destination` and `akac_grants.destinations/max_results`.
   There is no foreign key from actors to destinations: a dangling reference
   denies at decision time instead of blocking administration.

## Consequences

- Operators model providers, tools and gateways as service principals with a
  profile; a provider profile capped at `confidential` keeps restricted content
  from ever being sent to it, whatever the service's own clearance.
- Enforcement of egress remains an integration duty (egress proxy, MCP gateway,
  runtime); AKAC decides and records.
- Changing a profile advances the tenant epoch, ending open contexts.
- The AuthZEN facade gains an optional `context.destination` member.

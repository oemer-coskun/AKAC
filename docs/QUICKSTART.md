# Quickstart

Requires Node.js 24; tests additionally require Python 3.10+. All data below is synthetic. Do not paste real credentials, secrets or company documents into examples, prompts or commits.

## Local, no external services

```sh
npm ci
npm run check
npm run demo
npm run seed
AKAC_CREDENTIALS_FILE=data/credentials.json AKAC_ADMIN_CREDENTIALS_FILE=data/admin-credentials.json npm start
```

On PowerShell: `$env:AKAC_CREDENTIALS_FILE='data/credentials.json'; $env:AKAC_ADMIN_CREDENTIALS_FILE='data/admin-credentials.json'; npm start`.

The gateway starts three listeners: the agent API on `127.0.0.1:8787`, the admin API on `127.0.0.1:8788` (only when admin credentials are configured) and metrics on `127.0.0.1:9464`. `seed` writes two files, both mode 0600:

* `data/credentials.json`: agent credentials, one per synthetic user (`intern`, `chief`, `lead`);
* `data/admin-credentials.json`: administrator credentials `demo-security-admin`, `demo-kb-admin` and `demo-auditor`.

Read these files only in your trusted server process or shell. The two populations are not interchangeable: an agent token is refused by the admin API and an admin token by the agent API.

## Ingest a knowledge base, a folder and documents (admin API)

Container and document changes need the `kb-admin` role. Extract that token (this example uses `jq`; any JSON tool works):

```sh
ADMIN=http://127.0.0.1:8788
KB_ADMIN=$(jq -r '.[] | select(.binding.admin=="demo-kb-admin") | .token' data/admin-credentials.json)
auth=(-H "Authorization: Bearer $KB_ADMIN" -H "Content-Type: application/json")

# A knowledge base readable by staff, and a restricted folder for executives inside it
curl -sS -X PUT "${auth[@]}" $ADMIN/admin/v1/containers/kb-handbook -d '{
  "kind":"knowledge-base","classification":"internal",
  "readerRoles":["staff"],"readers":[],"projects":[],"active":true}'
curl -sS -X PUT "${auth[@]}" $ADMIN/admin/v1/containers/f-board -d '{
  "kind":"folder","parent":"kb-handbook","classification":"restricted",
  "readerRoles":["executive"],"readers":[],"projects":[],"active":true}'

# Two documents: one for staff, one inside the restricted folder
curl -sS -X PUT "${auth[@]}" $ADMIN/admin/v1/knowledge/vacation-policy -d '{
  "version":1,"kind":"document","origin":"human",
  "content":"Vacation policy: staff request leave through the synthetic portal.",
  "classification":"internal","projects":[],"readerRoles":["staff"],"readers":[],
  "sources":[],"active":true,"container":"kb-handbook"}'
curl -sS -X PUT "${auth[@]}" $ADMIN/admin/v1/knowledge/board-minutes -d '{
  "version":1,"kind":"document","origin":"human",
  "content":"Board minutes: synthetic reserve review and vacation budget.",
  "classification":"restricted","projects":[],"readerRoles":["executive"],"readers":[],
  "sources":[],"active":true,"container":"f-board"}'
```

Rules to know: the tenant comes from your credential and a body naming another tenant is rejected; a document's `version` must be the next one; `origin` is `human` or `system` (model-written content is refused); a container's or document's effective label is the strictest of its own and every ancestor's. With vector retrieval enabled the document is chunked, embedded and indexed as part of the call; if indexing fails after the authoritative write, the API answers 202 `INDEX_PENDING` and the document stays unindexed until `POST /admin/v1/index/reconcile` (kb-admin) repairs it. The complete contract is [openapi-admin.json](openapi-admin.json).

## Retrieve through the agent API

Use an agent credential; identity is bound to it by the server.

```sh
AGENT=http://127.0.0.1:8787
tok() { jq -r --arg s "$1" '.[] | select(.binding.subject==$s) | .token' data/credentials.json; }

# The intern (role staff, clearance internal) finds the staff document only
curl -sS -X POST -H "Authorization: Bearer $(tok intern)" -H "Content-Type: application/json" \
  $AGENT/v1/retrieve -d '{"query":"vacation","purpose":"work","limit":5}'

# The chief (roles staff and executive, clearance restricted) may also see the board minutes
curl -sS -X POST -H "Authorization: Bearer $(tok chief)" -H "Content-Type: application/json" \
  $AGENT/v1/retrieve -d '{"query":"vacation","purpose":"work","limit":5}'
```

The intern's result omits `board-minutes` and does not reveal that it exists; a document's absence and a denial look the same. The seeded grants cover all resources for purpose `work` for one hour. Every request is audited by the engine.

Read the audit trail with the auditor credential:

```sh
AUDITOR=$(jq -r '.[] | select(.binding.admin=="demo-auditor") | .token' data/admin-credentials.json)
curl -sS -H "Authorization: Bearer $AUDITOR" "$ADMIN/admin/v1/audit?limit=20"
```

## Call the API

Every route is in [openapi.json](openapi.json). Request a context with an agent credential and use it for a release:

```sh
TOKEN=$(jq -r '.[] | select(.binding.subject=="intern") | .token' data/credentials.json)
curl -sS -X POST http://127.0.0.1:8787/v1/contexts -H "Authorization: Bearer $TOKEN"   -H 'content-type: application/json' -d '{"resources":["vacation-policy"],"purpose":"work"}'
```

The admin API ([openapi-admin.json](openapi-admin.json)) is a separate listener with separate credentials.

## Revoke through the trusted control plane

Either call the admin API (`security-admin` for a grant, actor or knowledge revocation; `kb-admin` retires a document with `DELETE /admin/v1/knowledge/{id}`) or use the CLI:

`node scripts/revoke.ts acme admin knowledge strategy`

The CLI requires OS/database access and is deliberately not an agent endpoint; use the same database configuration as the gateway. After revocation, start a fresh isolated model session and issue a new run grant through your trusted provisioning integration. Do not reuse provider threads. Revocation advances only that tenant's epoch.

## PostgreSQL, pgvector and OPA (Docker Compose)

Create the two database password files (Compose mounts them as secrets; the connection URLs contain no password), then:

```sh
umask 077 && mkdir -p secrets   # untracked (.gitignore); directory readable only by you
openssl rand -hex 24 > secrets/pg_owner_password
openssl rand -hex 24 > secrets/pg_app_password
chmod 0444 secrets/pg_*_password   # readable by the container users
docker compose up -d postgres opa
docker compose run --rm migrate      # schema owner applies migrations
docker compose run --rm seed         # synthetic identities and documents; refuses nonempty state
docker compose up -d gateway
docker compose exec gateway cat /app/data/admin-credentials.json   # read only in a trusted shell
```

The seed writes documents directly to the store, so they are not yet in the vector index. Index them once with `POST /admin/v1/index/reconcile` using the `demo-kb-admin` token (or `docker compose run --rm gateway node scripts/reconcile.ts acme demo-kb-admin`, which needs the gateway's database variables). Documents created through the admin API are indexed as they are written.

The compose file enables `AKAC_RETRIEVAL=vector` with the synthetic `HashEmbedder`, which is lexical feature hashing, not a semantic model; use it for synthetic data only. Set `AKAC_EMBEDDINGS_URL` and `AKAC_EMBEDDINGS_MODEL` (and a key file through `AKAC_EMBEDDINGS_API_KEY_FILE`) for a real provider. All three ports are published on loopback only; PostgreSQL and OPA are on the internal network. For production, supply managed identities, TLS, network separation of the agent and admin listeners and the integration controls in the [threat model](THREAT-MODEL.md). Production deployment requires the relevant operator controls and tested integration implementations. Availability of separately scoped assistance is discussed through [CONTACT.md](../CONTACT.md).

## SK-1 deployment

The Compose setup above is the public SK-1 deployment; see [SK-1.md](SK-1.md).

## Validation

- `npm run check`: strict type check and Node tests.
- `npm run conformance`: portable JSON results.
- `npm run test:opa`: requires the `opa` executable.
- `OPA_BIN=/path/to/opa npm test`: includes a real OPA server test.
- `AKAC_TEST_DATABASE_URL=postgresql://... npm run test:postgres` (a shell-only value; use `AKAC_DATABASE_PASSWORD_FILE`-style files for anything persistent): uses and resets the dedicated test database. Never point it at a production database. It needs PostgreSQL with the pgvector extension, and without it the PostgreSQL tests are skipped.

## Development security

No authentication bypass mode is provided. Example grants expire after one hour. The CLI seed is not a general identity-management service. All demonstration documents are synthetic; private company material must never be added to examples or test fixtures.

# SK-1 Basis deployment (Docker Compose)

The Docker Compose setup in this repository is the public **SK-1 Basis** deployment
([security classes](profiles/SECURITY-CLASSES.md)): gateway, PostgreSQL 17 with pgvector and OPA, nothing else. Steps:
[QUICKSTART.md](QUICKSTART.md#postgresql-pgvector-and-opa-docker-compose).

## Configuration

`compose.yaml` sets these; `.env.example` lists what you may override. All values below are settings, not secrets.

| Setting | SK-1 value |
|---|---|
| `DATABASE_URL` | runtime role `akac_app` (no superuser, no `BYPASSRLS`) |
| `AKAC_DATABASE_PASSWORD_FILE`, `AKAC_MIGRATION_DATABASE_PASSWORD_FILE` | password files mounted as secrets; no password in any URL or variable |
| `AKAC_AUTO_MIGRATE` | `false`; the `migrate` service runs migrations as the schema owner |
| `AKAC_CREDENTIALS_FILE`, `AKAC_ADMIN_CREDENTIALS_FILE` | separate agent and admin credential files |
| `AKAC_RETRIEVAL`, `AKAC_VECTOR_BACKEND` | `vector`, `pgvector` |
| `AKAC_EMBEDDINGS` | `hash` for synthetic data only; set `AKAC_EMBEDDINGS_URL` and `AKAC_EMBEDDINGS_MODEL` for a real embedder |
| `AKAC_RUNTIME_OBLIGATIONS` | `deny` (default) |
| `AKAC_SHARED_STATE` | `postgres` (default) |

Generate the two database passwords locally with `openssl rand -hex 24` into `secrets/` (untracked); never commit them.

## What SK-1 covers

Decision semantics on every read, derivation and release; tenant and compartment separation; permission-aware
retrieval; the per-tenant audit chain. This is the full open core: nothing in the decision path is reduced for SK-1.

## Limits

- Single node, no high availability or failover.
- Software keys only; no HSM or KMS custody.
- Loopback-only listeners; TLS, network segmentation and identity provisioning are yours.
- The hash embedder is not semantic; use a real embedding model for real content.
- No external review or certification; SK-1 is a configuration bundle, not an assurance level of its own.

For other classes, supply the deployment-specific implementations and operator controls required by the public [security-class matrix](profiles/SECURITY-CLASSES.md). Separately scoped adoption assistance can be discussed through [CONTACT.md](../CONTACT.md).

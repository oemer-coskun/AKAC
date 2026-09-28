-- AKAC PostgreSQL bootstrap: runtime role, extension and grants.
--
-- The owner role (akac_owner) is provisioned by the postgres image itself
-- from POSTGRES_USER/POSTGRES_PASSWORD_FILE (see compose.yaml) and owns the
-- database; it is the role the application uses to run SQL migrations
-- (advisory-locked, applied at startup) via AKAC_MIGRATION_DATABASE_URL.
--
-- This script additionally creates the runtime role the gateway connects as
-- (DATABASE_URL -> akac_app): no BYPASSRLS, no DDL rights, so row-level
-- security applies to every query it issues, and it cannot alter or drop
-- schema objects even if the process running it is compromised.
--
-- Mounted as a docker-entrypoint-initdb.d script in compose.yaml (runs once,
-- against a fresh data volume, with the postgres image's own env available).
-- For managed PostgreSQL (RDS, Cloud SQL, etc.) where
-- docker-entrypoint-initdb.d does not apply, run the equivalent statements
-- once against the target database with an admin connection, supplying
-- the password out of band the same way (a file named by AKAC_APP_PASSWORD_FILE). Idempotent: safe to re-run.

\set app_password `cat "$AKAC_APP_PASSWORD_FILE"`

DO
$$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'akac_app') THEN
    CREATE ROLE akac_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;
END
$$;

ALTER ROLE akac_app WITH PASSWORD :'app_password' NOBYPASSRLS;

CREATE EXTENSION IF NOT EXISTS vector;

-- akac_owner owns the schema; akac_app gets scoped, non-DDL privileges only.
-- Migrations (run by akac_owner) are expected to enable row-level security
-- on every tenant-scoped table and to define policies keyed off a
-- session/role claim set by the application. Default privileges below apply
-- automatically to tables and sequences that migrations create later, so
-- akac_app never needs manual re-granting after a schema change.

GRANT CONNECT ON DATABASE akac TO akac_app;
GRANT USAGE ON SCHEMA public TO akac_app;
REVOKE CREATE ON SCHEMA public FROM akac_app;

ALTER DEFAULT PRIVILEGES FOR ROLE akac_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO akac_app;
ALTER DEFAULT PRIVILEGES FOR ROLE akac_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO akac_app;

-- Re-apply retroactively in case migrations already ran once (re-running
-- this init script against an existing schema). Ignored on a fresh
-- database where no tables exist yet.
DO
$$
BEGIN
  EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO akac_app';
  EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO akac_app';
EXCEPTION WHEN OTHERS THEN
  NULL;
END
$$;

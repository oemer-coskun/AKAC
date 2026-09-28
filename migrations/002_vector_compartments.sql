-- AKAC 0.3 permission-aware vector storage (ADR-004). Applied once by the
-- migration runner; never edit after release.
--
-- Layout: one physical table per classification compartment and, inside it,
-- the tenant as an RLS-protected column. A query names the compartments the
-- caller may see (min of user and agent clearance) and touches no other table,
-- so a defective row filter cannot reach a higher tier. Fine-grained ACLs are
-- stored on every chunk as tokens and applied as a WHERE pre-filter inside the
-- same statement as the nearest-neighbour ORDER BY; chunk text is not stored.
--
-- Vector dimension. The column is fixed at vector(256), matching the default
-- HashEmbedder. HNSW needs a fixed dimension, and a typed column makes pgvector
-- reject any mismatching write instead of silently mixing embedding spaces.
-- PgVectorIndex verifies the column dimension at start-up and refuses to run on a
-- mismatch. To use another dimension (for example 1024 or 1536, at most 2000 for
-- `vector` HNSW), add a NEW migration (003_...) that TRUNCATEs the four
-- akac_chunks_* tables, ALTERs the embedding column to vector(N) and recreates the
-- HNSW indexes. Index state is derived from these tables (no separate outbox
-- table), so an empty index is re-embedded in full by Ingestor.reconcile().
--
-- The `vector` extension may live in any schema; its schema is resolved at run
-- time so this migration does not depend on the search_path.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
    CREATE EXTENSION vector SCHEMA public;
  END IF;
END
$$;

-- Every container level (any-of) must match the caller's tokens. Fails closed:
-- an empty level, NULL input or a malformed value admits nothing.
CREATE FUNCTION akac_levels_ok(levels jsonb, tokens text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT jsonb_typeof(levels) = 'array' AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(levels) AS lvl(v)
    WHERE NOT COALESCE(ARRAY(SELECT jsonb_array_elements_text(lvl.v)) && tokens, false))
$$;

DO $$
DECLARE
  ext text;
  t text;
BEGIN
  SELECT n.nspname INTO ext FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'vector';
  FOREACH t IN ARRAY ARRAY['public', 'internal', 'confidential', 'restricted']
  LOOP
    EXECUTE format($f$CREATE TABLE akac_chunks_%1$s (
      tenant text NOT NULL,
      doc_id text NOT NULL,
      doc_version integer NOT NULL CHECK (doc_version >= 1),
      chunk_id text NOT NULL,
      ordinal integer NOT NULL CHECK (ordinal >= 0),
      read_tokens text[] NOT NULL,
      required_projects text[] NOT NULL,
      container_tokens jsonb NOT NULL CHECK (jsonb_typeof(container_tokens) = 'array'),
      model text NOT NULL,
      embedding %2$I.vector(256) NOT NULL,
      PRIMARY KEY (tenant, chunk_id)
    )$f$, t, ext);
    EXECUTE format('CREATE INDEX akac_chunks_%s_doc ON akac_chunks_%s (tenant, doc_id)', t, t);
    EXECUTE format('CREATE INDEX akac_chunks_%s_read ON akac_chunks_%s USING gin (read_tokens)', t, t);
    EXECUTE format('CREATE INDEX akac_chunks_%s_projects ON akac_chunks_%s USING gin (required_projects)', t, t);
    EXECUTE format('CREATE INDEX akac_chunks_%1$s_hnsw ON akac_chunks_%1$s USING hnsw (embedding %2$I.vector_cosine_ops) WITH (m = 16, ef_construction = 64)', t, ext);
    -- Same tenant isolation as migration 001: FORCE applies to the owner; the runtime role must not bypass RLS.
    EXECUTE format('ALTER TABLE akac_chunks_%s ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE akac_chunks_%s FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY akac_tenant_isolation ON akac_chunks_%1$s USING (tenant = current_setting(''akac.tenant'', true)) WITH CHECK (tenant = current_setting(''akac.tenant'', true))', t);
  END LOOP;
END
$$;

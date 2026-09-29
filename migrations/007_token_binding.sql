-- AKAC 0.4 DPoP replay cache (ADR-009). Applied once by the migration runner;
-- never edit after release.
--
-- Holds single-use proof identifiers (jti) per proof-key thumbprint (jkt) until
-- the proof can no longer pass the time-window check. It carries no tenant data
-- and no token material. The runtime role needs SELECT, INSERT, UPDATE and
-- DELETE. FORCE ROW LEVEL SECURITY with an unconditional policy keeps the
-- table consistent with the runtime-role posture check (every akac_ table has
-- forced RLS) without adding a tenant dimension it does not have.

CREATE TABLE akac_dpop_replay (
  jti text NOT NULL CHECK (length(jti) BETWEEN 1 AND 256),
  jkt text NOT NULL CHECK (length(jkt) = 43),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (jti, jkt)
);
CREATE INDEX akac_dpop_replay_expiry ON akac_dpop_replay (expires_at);

ALTER TABLE akac_dpop_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE akac_dpop_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY akac_dpop_replay_all ON akac_dpop_replay USING (true) WITH CHECK (true);

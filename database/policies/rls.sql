-- database/policies/rls.sql
-- Row-Level Security policies for tenant-owned tables.
--
-- Reference only: database/migrations/versions/0007_phase1_rls.py is the
-- authoritative schema-evolution mechanism. Do not apply this file after
-- running Alembic migrations; doing so attempts to recreate the same policies.
--
-- FAIL-CLOSED: if app.tenant_id is not set, NO rows are visible.
-- This prevents accidental cross-tenant access when the API forgets
-- to set the tenant context.
--
-- The API sets the tenant context per-transaction using:
--   SET LOCAL app.tenant_id = '<uuid>';
--
-- A restricted application role should be used (separate from the
-- migration owner / superuser). Superusers bypass RLS by default in
-- PostgreSQL, so the application role must NOT be a superuser.
--
-- Helper function: returns the tenant_id from the session context.
-- Returns NULL if not set — policies below fail-closed on NULL.
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
$$ LANGUAGE sql STABLE;

-- Enable and force RLS so table owners cannot bypass these policies.
ALTER TABLE gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateways FORCE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
ALTER TABLE event_ingestion_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_ingestion_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE detection_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE action_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE commands FORCE ROW LEVEL SECURITY;
ALTER TABLE execution_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_certificates FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE execution_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_journal FORCE ROW LEVEL SECURITY;

-- FAIL-CLOSED policies: rows are visible ONLY when tenant_id matches.
-- If current_tenant_id() returns NULL, no rows are returned.
-- This is the opposite of fail-open — missing context = no access.

CREATE POLICY tenant_isolation ON gateways
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON enrollment_tokens
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON assets
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON events
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON event_ingestion_keys
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON detection_findings
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON alerts
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON incidents
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON evidence
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON action_proposals
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON approvals
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON commands
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON execution_attempts
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON audit_events
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON policy_versions
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON outbox
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON gateway_certificates
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON memberships
  USING (tenant_id = current_tenant_id());

CREATE POLICY tenant_isolation ON execution_journal
  USING (tenant_id = current_tenant_id());

-- database/policies/rls.sql
-- Row-Level Security policies for tenant-owned tables.
--
-- Every tenant-owned table gets:
--   1. ENABLE ROW LEVEL SECURITY
--   2. A policy that allows the application role to see only rows
--      matching the current tenant context (set via SET LOCAL).
--
-- The API sets the tenant context per-request using:
--   SET LOCAL app.tenant_id = '<uuid>';
--
-- This provides defense-in-depth: even if the API forgets to filter
-- by tenant_id, RLS prevents cross-tenant data leakage.
--
-- Run once after migrations:
--   psql "$DATABASE_URL" -f database/policies/rls.sql

-- Enable RLS on all tenant-owned tables
ALTER TABLE gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;

-- Create a helper function to read the current tenant context
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
$$ LANGUAGE sql STABLE;

-- Policies: application role can see rows matching the current tenant
-- or all rows if no tenant context is set (for superuser/admin operations).

-- Gateways
CREATE POLICY tenant_isolation ON gateways
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Enrollment tokens
CREATE POLICY tenant_isolation ON enrollment_tokens
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Assets
CREATE POLICY tenant_isolation ON assets
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Events
CREATE POLICY tenant_isolation ON events
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Detection findings
CREATE POLICY tenant_isolation ON detection_findings
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Alerts
CREATE POLICY tenant_isolation ON alerts
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Incidents
CREATE POLICY tenant_isolation ON incidents
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Evidence
CREATE POLICY tenant_isolation ON evidence
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Action proposals
CREATE POLICY tenant_isolation ON action_proposals
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Approvals
CREATE POLICY tenant_isolation ON approvals
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Commands
CREATE POLICY tenant_isolation ON commands
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Execution attempts
CREATE POLICY tenant_isolation ON execution_attempts
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Audit events
CREATE POLICY tenant_isolation ON audit_events
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Policy versions
CREATE POLICY tenant_isolation ON policy_versions
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Outbox
CREATE POLICY tenant_isolation ON outbox
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Gateway certificates (filtered via gateway's tenant)
CREATE POLICY tenant_isolation ON gateway_certificates
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

-- Memberships (filtered by tenant_id)
CREATE POLICY tenant_isolation ON memberships
  USING (current_tenant_id() IS NULL OR tenant_id = current_tenant_id());

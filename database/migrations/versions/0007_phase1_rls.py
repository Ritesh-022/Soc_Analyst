"""Apply fail-closed tenant isolation and atomic gateway authorization."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0007_phase1_rls"
down_revision: str | None = "0006_phase1_identity_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "gateways",
    "enrollment_tokens",
    "assets",
    "events",
    "event_ingestion_keys",
    "detection_findings",
    "alerts",
    "incidents",
    "evidence",
    "action_proposals",
    "approvals",
    "commands",
    "execution_attempts",
    "audit_events",
    "policy_versions",
    "outbox",
    "gateway_certificates",
    "memberships",
    "execution_journal",
)


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid
        LANGUAGE sql STABLE
        AS $$
          SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
        $$
        """
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = current_tenant_id())
            WITH CHECK (tenant_id = current_tenant_id())
            """
        )

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'ascense_gateway_auth'
            ) THEN
                CREATE ROLE ascense_gateway_auth NOLOGIN BYPASSRLS;
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        GRANT SELECT, UPDATE ON gateway_certificates, gateways, tenants
        TO ascense_gateway_auth
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION authenticate_gateway_certificate(
            p_fingerprint text
        )
        RETURNS TABLE (
            certificate_id uuid,
            gateway_id uuid,
            tenant_id uuid,
            certificate_fingerprint text,
            certificate_expires_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public
        AS $$
        DECLARE
            v_certificate gateway_certificates%ROWTYPE;
            v_gateway gateways%ROWTYPE;
            v_tenant tenants%ROWTYPE;
        BEGIN
            SELECT * INTO v_certificate
            FROM gateway_certificates
            WHERE fingerprint = p_fingerprint
            FOR UPDATE;

            IF NOT FOUND THEN
                RETURN;
            END IF;

            SELECT * INTO v_gateway
            FROM gateways
            WHERE id = v_certificate.gateway_id
            FOR UPDATE;

            SELECT * INTO v_tenant
            FROM tenants
            WHERE id = v_gateway.tenant_id
            FOR UPDATE;

            IF v_certificate.tenant_id <> v_gateway.tenant_id
               OR v_certificate.status <> 'ACTIVE'
               OR v_certificate.revoked_at IS NOT NULL
               OR clock_timestamp() < v_certificate.issued_at
               OR clock_timestamp() > v_certificate.expires_at
               OR v_gateway.status NOT IN ('ACTIVE', 'DEGRADED', 'TELEMETRY_STALE')
               OR v_tenant.status <> 'active' THEN
                RETURN;
            END IF;

            certificate_id := v_certificate.id;
            gateway_id := v_gateway.id;
            tenant_id := v_tenant.id;
            certificate_fingerprint := v_certificate.fingerprint;
            certificate_expires_at := v_certificate.expires_at;
            RETURN NEXT;
        END
        $$
        """
    )
    op.execute(
        """
        ALTER FUNCTION authenticate_gateway_certificate(text)
        OWNER TO ascense_gateway_auth
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION authenticate_gateway_certificate(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION authenticate_gateway_certificate(text) TO CURRENT_USER"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS authenticate_gateway_certificate(text)")
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

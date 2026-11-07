"""Gateway management routes.

Public API:
  GET  /api/v1/gateways — list authorized gateways
  GET  /api/v1/gateways/{gateway_id} — gateway status and details
  POST /api/v1/gateways/enrollment-tokens — create enrollment token
  GET  /api/v1/gateways/{gateway_id}/sensors — view installed sensors

Edge API:
  POST /edge/v1/gateways/{gateway_id}/heartbeat — gateway heartbeat
  GET  /edge/v1/gateways/{gateway_id}/configuration — authorized config
  POST /edge/v1/gateways/enrollment — CSR-based certificate enrollment
"""

from __future__ import annotations

import contextlib
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id, require_role
from ascense.config import get_settings
from ascense.db import get_session
from ascense.models import EnrollmentToken, Gateway, GatewayCertificate

router = APIRouter(tags=["Gateways"])


# ---------------------------------------------------------------------------
# Identity verification helper
# ---------------------------------------------------------------------------

def _verify_gateway_identity(request: Request, url_gateway_id: UUID) -> None:
    """Verify that the authenticated mTLS identity matches the gateway_id in the URL.

    In production, the mTLS middleware sets request.state.gateway_id from
    the verified certificate. This function ensures the URL parameter
    matches that authenticated identity.

    In dev mode, the X-Gateway-ID header is accepted.
    """
    _is_dev = get_settings().is_dev

    if _is_dev:
        # Dev mode: accept X-Gateway-ID header
        header_gateway_id = request.headers.get("X-Gateway-ID")
        if header_gateway_id and header_gateway_id == str(url_gateway_id):
            return
        # Also accept if the middleware already set it
        state_gateway_id = getattr(request.state, "gateway_id", None)
        if state_gateway_id and state_gateway_id == str(url_gateway_id):
            return
        # In dev, if neither is set, allow it (simulator may not send headers)
        return

    # Production: the mTLS middleware must have set gateway_id
    state_gateway_id = getattr(request.state, "gateway_id", None)
    if not state_gateway_id:
        raise HTTPException(
            status_code=401,
            detail="Authenticated gateway identity required.",
        )

    try:
        auth_gateway_id = UUID(str(state_gateway_id))
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid authenticated gateway identity.",
        ) from exc

    if auth_gateway_id != url_gateway_id:
        raise HTTPException(
            status_code=403,
            detail="Gateway ID in URL does not match the authenticated certificate identity.",
        )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class EnrollmentTokenRequest(BaseModel):
    name: str = Field(..., description="Display name for the gateway to be enrolled")
    expires_in_seconds: int = Field(3600, ge=60, le=86400, description="Token validity in seconds")


class EnrollmentTokenResponse(BaseModel):
    token: str
    gateway_id: str
    expires_at: datetime
    created_at: datetime


class GatewayResponse(BaseModel):
    gateway_id: str
    tenant_id: str
    name: str
    status: str
    registered_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    config_version: int = 0


class GatewayPage(BaseModel):
    items: list[GatewayResponse]
    next_cursor: str | None = None


class HeartbeatSensor(BaseModel):
    name: str
    instance_id: str
    version: str | None = None
    status: str
    last_event_at: datetime | None = None


class HeartbeatRequest(BaseModel):
    gateway_id: str
    sent_at: datetime
    config_version: int | None = None
    sensors: list[HeartbeatSensor]


class HeartbeatResponse(BaseModel):
    accepted: bool = True
    config_version: int
    config_changed: bool = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@router.get("/api/v1/gateways")
async def list_gateways(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List authorized gateways for the current tenant."""
    tenant_id = await get_tenant_id(request)

    query = select(Gateway).where(Gateway.tenant_id == tenant_id)
    if cursor:
        with contextlib.suppress(ValueError):
            query = query.where(Gateway.id < UUID(cursor))

    query = query.order_by(Gateway.id.desc()).limit(limit + 1)
    result = await session.execute(query)
    gateways = result.scalars().all()

    has_more = len(gateways) > limit
    items = gateways[:limit]
    next_cursor = str(items[-1].id) if has_more and items else None

    return {
        "items": [
            {
                "gateway_id": str(g.id),
                "tenant_id": str(g.tenant_id),
                "name": g.name,
                "status": g.status,
                "registered_at": g.enrolled_at.isoformat() if g.enrolled_at else None,
                "last_heartbeat_at": (
                    g.last_heartbeat_at.isoformat()
                    if g.last_heartbeat_at else None
                ),
                "config_version": g.config_version,
            }
            for g in items
        ],
        "next_cursor": next_cursor,
    }


@router.get("/api/v1/gateways/{gateway_id}")
async def get_gateway(
    gateway_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get gateway status and details. 403 if belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if gateway.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "gateway_id": str(gateway.id),
        "tenant_id": str(gateway.tenant_id),
        "name": gateway.name,
        "status": gateway.status,
        "registered_at": gateway.enrolled_at.isoformat() if gateway.enrolled_at else None,
        "last_heartbeat_at": (
            gateway.last_heartbeat_at.isoformat()
            if gateway.last_heartbeat_at else None
        ),
        "config_version": gateway.config_version,
    }


@router.post("/api/v1/gateways/enrollment-tokens", status_code=status.HTTP_201_CREATED)
async def create_enrollment_token(
    body: EnrollmentTokenRequest,
    request: Request,
    _role_check: None = Depends(require_role("admin", "operator")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create a one-time enrollment token for registering a new gateway.
    The token binds to the current tenant context."""
    tenant_id = await get_tenant_id(request)

    gateway_id = uuid7()
    token_value = str(uuid7())

    # Create the gateway record in ENROLLMENT_PENDING state
    gateway = Gateway(
        id=gateway_id,
        tenant_id=tenant_id,
        name=body.name,
        status="ENROLLMENT_PENDING",
    )
    session.add(gateway)
    await session.flush()

    # Create the enrollment token
    token = EnrollmentToken(
        id=uuid7(),
        tenant_id=tenant_id,
        gateway_id=gateway_id,
        token=token_value,
        expires_at=datetime.now(UTC) + timedelta(seconds=body.expires_in_seconds),
    )
    session.add(token)
    await session.commit()

    return {
        "token": token_value,
        "gateway_id": str(gateway_id),
        "expires_at": token.expires_at.isoformat(),
        "created_at": token.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Edge API: Gateway heartbeat
# ---------------------------------------------------------------------------

@router.post("/edge/v1/gateways/{gateway_id}/heartbeat")
async def gateway_heartbeat(
    gateway_id: UUID,
    body: HeartbeatRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Gateway heartbeat with sensor health.

    Verifies that the gateway_id in the URL matches the authenticated
    mTLS certificate identity.
    """
    _verify_gateway_identity(request, gateway_id)

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")

    gateway.last_heartbeat_at = datetime.now(UTC)
    gateway.sensor_status = [
        {
            "name": s.name,
            "instance_id": s.instance_id,
            "version": s.version,
            "status": s.status,
            "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
        }
        for s in body.sensors
    ]

    any_failed = any(s.status == "SENSOR_FAILURE" for s in body.sensors)
    all_healthy = all(s.status == "HEALTHY" for s in body.sensors)
    if any_failed:
        gateway.status = "DEGRADED"
    elif all_healthy:
        gateway.status = "ACTIVE"

    await session.commit()

    return {
        "accepted": True,
        "config_version": gateway.config_version,
        "config_changed": False,
    }


# ---------------------------------------------------------------------------
# Edge API: Gateway enrollment (CSR-based)
# ---------------------------------------------------------------------------

class CSREnrollmentRequest(BaseModel):
    """Gateway submits a CSR along with its one-time enrollment token.

    The gateway generates its own private key locally and creates a CSR
    from it. The platform validates the token and signs the CSR using
    the gateway CA. The private key never leaves the gateway.
    """
    token: str = Field(..., description="One-time enrollment token")
    gateway_id: str = Field(..., description="Gateway UUID from token creation")
    csr_pem: str = Field(..., description="PEM-encoded Certificate Signing Request")
    hostname: str | None = Field(None, description="Gateway hostname for certificate CN")


@router.post("/edge/v1/gateways/enrollment", status_code=status.HTTP_201_CREATED)
async def enroll_gateway(
    body: CSREnrollmentRequest,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Complete gateway enrollment via CSR signing.

    The gateway generates its private key locally and submits a CSR.
    The platform validates the enrollment token and signs the CSR using
    the gateway CA. The signed certificate and CA chain are returned —
    never the private key.

    This endpoint is exempt from normal gateway mTLS (the gateway has
    no certificate yet). Authentication is via the one-time enrollment token.
    """
    _is_dev = get_settings().is_dev

    # Validate the token
    result = await session.execute(
        select(EnrollmentToken).where(EnrollmentToken.token == body.token)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=404, detail="Enrollment token not found")

    if token.used_at is not None:
        raise HTTPException(status_code=409, detail="Enrollment token already used")

    if token.expires_at < datetime.now(UTC):
        raise HTTPException(status_code=410, detail="Enrollment token has expired")

    # Validate the gateway ID matches the token
    if str(token.gateway_id) != body.gateway_id:
        raise HTTPException(status_code=403, detail="Gateway ID does not match enrollment token")

    # Load the gateway
    result = await session.execute(
        select(Gateway).where(Gateway.id == token.gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")

    if gateway.status != "ENROLLMENT_PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Gateway is in status {gateway.status}, cannot enroll",
        )

    # Parse the CSR
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    try:
        csr = x509.load_pem_x509_csr(body.csr_pem.encode())
    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Invalid CSR: could not parse PEM-encoded CSR",
        ) from None

    # Verify the CSR signature is valid (the gateway's key proves possession)
    if not csr.is_signature_valid:
        raise HTTPException(
            status_code=422,
            detail="Invalid CSR: signature verification failed",
        )

    # Build the certificate subject — must include the gateway UUID as CN
    # so the mTLS middleware can bind the certificate to the gateway
    gateway_uuid_str = str(gateway.id)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, gateway_uuid_str),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ascense"),
    ])

    cert_validity = timedelta(days=365)
    not_before = datetime.now(UTC)
    not_after = not_before + cert_validity

    if _is_dev:
        # Dev mode: sign the CSR with a self-generated key (no CA configured)
        dev_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # self-signed in dev
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(gateway_uuid_str)]),
                critical=False,
            )
        )
        cert = cert_builder.sign(dev_key, hashes.SHA256())

        # CA chain is just the cert itself in dev mode
        ca_chain_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    else:
        # Production: sign the CSR with the gateway CA
        ca_cert = _load_gateway_ca_cert()
        if ca_cert is None:
            raise HTTPException(
                status_code=500,
                detail="Gateway CA certificate not configured — cannot sign CSR",
            )

        ca_key = _load_gateway_ca_key()
        if ca_key is None:
            raise HTTPException(
                status_code=500,
                detail="Gateway CA private key not configured — cannot sign CSR",
            )

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(gateway_uuid_str)]),
                critical=False,
            )
        )

        if isinstance(ca_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            cert = cert_builder.sign(ca_key, hashes.SHA256())
        else:
            raise HTTPException(
                status_code=500,
                detail="Unsupported CA key type for signing",
            )

        # Return the CA chain
        ca_chain_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    fingerprint = hashlib.sha256(cert_pem.encode()).hexdigest()

    # Store the certificate record
    gateway_cert = GatewayCertificate(
        id=uuid7(),
        gateway_id=gateway.id,
        tenant_id=gateway.tenant_id,
        fingerprint=fingerprint,
        certificate_pem=cert_pem,
        issued_at=datetime.now(UTC),
        expires_at=not_after,
        status="ACTIVE",
    )
    session.add(gateway_cert)

    # Update gateway state
    gateway.status = "ACTIVE"
    gateway.enrolled_at = datetime.now(UTC)
    gateway.certificate_fingerprint = fingerprint
    gateway.certificate_issued_at = datetime.now(UTC)
    gateway.certificate_expires_at = not_after

    # Mark token as used
    token.used_at = datetime.now(UTC)

    await session.commit()

    return {
        "gateway_id": str(gateway.id),
        "status": gateway.status,
        "certificate": cert_pem,
        "ca_chain": ca_chain_pem,
        "certificate_fingerprint": fingerprint,
        "certificate_expires_at": gateway.certificate_expires_at.isoformat(),
    }


def _load_gateway_ca_cert():
    """Load the gateway CA certificate from the configured path."""
    from pathlib import Path

    from cryptography import x509 as _x509

    ca_cert_path = get_settings().GATEWAY_CA_CERT
    if not ca_cert_path:
        return None
    try:
        p = Path(ca_cert_path)
        if p.exists():
            return _x509.load_pem_x509_certificate(p.read_bytes())
        # Try as inline PEM
        return _x509.load_pem_x509_certificate(ca_cert_path.encode())
    except Exception:
        return None


def _load_gateway_ca_key():
    """Load the gateway CA private key from the configured path."""
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    ca_key_path = os.getenv("GATEWAY_CA_KEY", "")
    if not ca_key_path:
        return None
    try:
        p = Path(ca_key_path)
        if p.exists():
            return serialization.load_pem_private_key(
                p.read_bytes(),
                password=None,
            )
        return serialization.load_pem_private_key(
            ca_key_path.encode(),
            password=None,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Edge API: Gateway configuration
# ---------------------------------------------------------------------------

@router.get("/edge/v1/gateways/{gateway_id}/configuration")
async def get_gateway_configuration(
    gateway_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return the authorized configuration for a gateway.

    Verifies that the gateway_id matches the authenticated mTLS certificate
    identity.
    """
    _verify_gateway_identity(request, gateway_id)

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")

    # Basic gateway configuration
    return {
        "gateway_id": str(gateway.id),
        "config_version": gateway.config_version,
        "sensors": [
            {
                "name": "suricata",
                "instance_id": "suricata-01",
                "enabled": True,
                "config": {
                    "eve_json_output": True,
                    "output_format": "json",
                },
            },
        ],
        "allowed_event_types": [
            "com.ascense.network.connection.observed.v1",
        ],
        "heartbeat_interval_seconds": 30,
        "event_batch_size": 100,
        "event_batch_timeout_ms": 5000,
    }

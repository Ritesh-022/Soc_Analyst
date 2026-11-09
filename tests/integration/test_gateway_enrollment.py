"""Integration tests for the one-time gateway enrollment flow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid7

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import select

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def db_session():
    try:
        from ascense.db import async_session_factory

        async with async_session_factory() as session:
            yield session
    except Exception as exc:
        pytest.skip(f"Database not available: {exc}")


def _create_csr(gateway_id: UUID) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(gateway_id))])
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


async def _create_enrollment_fixture(session):
    from ascense.models import EnrollmentToken, Gateway, Tenant

    tenant_id = uuid7()
    gateway_id = uuid7()
    token_value = f"enrollment-{uuid7()}"
    session.add(Tenant(id=tenant_id, name="Enrollment Test Tenant"))
    await session.flush()
    session.add(
        Gateway(
            id=gateway_id,
            tenant_id=tenant_id,
            name="Enrollment Test Gateway",
            status="ENROLLMENT_PENDING",
        )
    )
    await session.flush()
    session.add(
        EnrollmentToken(
            id=uuid7(),
            tenant_id=tenant_id,
            gateway_id=gateway_id,
            token=token_value,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await session.commit()
    return gateway_id, token_value


async def test_gateway_enrollment_persists_certificate_and_consumes_token(db_session):
    from ascense.api.routes.gateways import CSREnrollmentRequest, enroll_gateway
    from ascense.models import EnrollmentToken, Gateway, GatewayCertificate

    gateway_id, token_value = await _create_enrollment_fixture(db_session)
    response = await enroll_gateway(
        CSREnrollmentRequest(
            token=token_value,
            gateway_id=str(gateway_id),
            csr_pem=_create_csr(gateway_id),
        ),
        db_session,
    )

    assert response["gateway_id"] == str(gateway_id)
    assert response["status"] == "ACTIVE"
    certificate = x509.load_pem_x509_certificate(response["certificate"].encode())
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == str(
        gateway_id
    )
    assert response["certificate_fingerprint"] == sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()

    gateway = await db_session.get(Gateway, gateway_id)
    assert gateway is not None
    assert gateway.status == "ACTIVE"
    assert gateway.certificate_fingerprint == response["certificate_fingerprint"]

    certificate_row = (
        await db_session.execute(
            select(GatewayCertificate).where(
                GatewayCertificate.gateway_id == gateway_id
            )
        )
    ).scalar_one()
    assert certificate_row.status == "ACTIVE"
    token = (
        await db_session.execute(
            select(EnrollmentToken).where(EnrollmentToken.token == token_value)
        )
    ).scalar_one()
    assert token.used_at is not None


async def test_gateway_enrollment_rejects_replay(db_session):
    from ascense.api.routes.gateways import CSREnrollmentRequest, enroll_gateway

    gateway_id, token_value = await _create_enrollment_fixture(db_session)
    request = CSREnrollmentRequest(
        token=token_value,
        gateway_id=str(gateway_id),
        csr_pem=_create_csr(gateway_id),
    )
    await enroll_gateway(request, db_session)

    with pytest.raises(HTTPException) as exc_info:
        await enroll_gateway(request, db_session)
    assert exc_info.value.status_code == 409


async def test_gateway_enrollment_rejects_gateway_mismatch(db_session):
    from ascense.api.routes.gateways import CSREnrollmentRequest, enroll_gateway

    gateway_id, token_value = await _create_enrollment_fixture(db_session)
    with pytest.raises(HTTPException) as exc_info:
        await enroll_gateway(
            CSREnrollmentRequest(
                token=token_value,
                gateway_id=str(uuid7()),
                csr_pem=_create_csr(gateway_id),
            ),
            db_session,
        )
    assert exc_info.value.status_code == 403


async def test_gateway_enrollment_rejects_expired_token(db_session):
    from ascense.api.routes.gateways import CSREnrollmentRequest, enroll_gateway
    from ascense.models import EnrollmentToken

    gateway_id, token_value = await _create_enrollment_fixture(db_session)
    token = (
        await db_session.execute(
            select(EnrollmentToken).where(EnrollmentToken.token == token_value)
        )
    ).scalar_one()
    token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await enroll_gateway(
            CSREnrollmentRequest(
                token=token_value,
                gateway_id=str(gateway_id),
                csr_pem=_create_csr(gateway_id),
            ),
            db_session,
        )
    assert exc_info.value.status_code == 410

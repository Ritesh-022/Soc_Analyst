from __future__ import annotations

import time
from typing import Any, cast
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from ascense.api.middleware import auth
from ascense.api.middleware import tenant as tenant_middleware
from ascense.api.middleware.tenant import TenantMiddleware


def _make_request(token: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/events",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "query_string": b"",
            "scheme": "https",
            "server": ("testserver", 443),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
        }
    )


def _make_oidc_token(
    private_key: rsa.RSAPrivateKey,
    *,
    issuer: str = "https://idp.example",
    audience: str = "ascense-api",
    subject: str = "provider-subject-123",
    algorithm: str = "RS256",
) -> str:
    now = int(time.time())
    signing_key: Any = (
        private_key if algorithm == "RS256" else "test-signing-secret-for-hs256-only"
    )
    return jwt.encode(
        {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + 300,
        },
        signing_key,
        algorithm=algorithm,
        headers={"kid": "test-key"},
    )


@pytest.mark.asyncio
async def test_oidc_token_requires_rs256_and_valid_claims(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk: dict[str, Any] = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})

    monkeypatch.setattr(auth.settings, "JWT_ISSUER", "https://idp.example")
    monkeypatch.setattr(auth.settings, "JWT_AUDIENCE", "ascense-api")

    async def fetch_jwks(*, force_refresh: bool = False):
        assert force_refresh is False
        return {"keys": [jwk]}

    monkeypatch.setattr(auth, "_fetch_jwks", fetch_jwks)

    valid_token = _make_oidc_token(private_key)
    decoded = await auth._decode_oidc_token(valid_token)
    assert decoded is not None
    assert decoded["sub"] == "provider-subject-123"

    invalid_issuer = _make_oidc_token(private_key, issuer="https://attacker.example")
    assert await auth._decode_oidc_token(invalid_issuer) is None

    unsupported_algorithm = _make_oidc_token(private_key, algorithm="HS256")
    assert await auth._decode_oidc_token(unsupported_algorithm) is None


@pytest.mark.asyncio
async def test_production_jwks_fetch_requires_https(monkeypatch):
    monkeypatch.setattr(auth, "_IS_DEV", False)
    monkeypatch.setattr(auth.settings, "JWKS_URL", "http://idp.example/jwks")
    monkeypatch.setattr(auth, "_jwks_cache", None)

    assert await auth._fetch_jwks() is None


@pytest.mark.asyncio
async def test_oidc_subject_maps_to_registered_user_and_membership(monkeypatch):
    user_id = uuid4()
    tenant_id = uuid4()

    class Result:
        def __init__(self, value: Any):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, _statement):
            self.calls += 1
            return Result(user_id if self.calls == 1 else [tenant_id])

    async def decode(_token: str):
        return {
            "sub": "provider-subject-123",
            "iss": "https://idp.example",
            "tenant_id": str(tenant_id),
        }

    monkeypatch.setattr(auth, "_IS_DEV", False)
    monkeypatch.setattr(auth, "_decode_oidc_token", decode)
    request = _make_request("valid-token")

    resolved_user_id = await auth.resolve_user_from_token(
        request, cast(AsyncSession, Session())
    )

    assert resolved_user_id == user_id
    assert request.state.user_id == str(user_id)
    assert request.state.tenant_id == str(tenant_id)


@pytest.mark.asyncio
async def test_oidc_tenant_must_match_user_membership(monkeypatch):
    user_id = uuid4()
    tenant_id = uuid4()
    other_tenant_id = uuid4()

    class Result:
        def __init__(self, value: Any):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, _statement):
            self.calls += 1
            return Result(user_id if self.calls == 1 else [tenant_id])

    async def decode(_token: str):
        return {
            "sub": "provider-subject-123",
            "iss": "https://idp.example",
            "tenant_id": str(other_tenant_id),
        }

    monkeypatch.setattr(auth, "_IS_DEV", False)
    monkeypatch.setattr(auth, "_decode_oidc_token", decode)
    request = _make_request("valid-token")

    resolved_user_id = await auth.resolve_user_from_token(
        request, cast(AsyncSession, Session())
    )

    assert resolved_user_id == user_id
    assert request.state.user_id == str(user_id)
    assert getattr(request.state, "tenant_id", None) is None


@pytest.mark.asyncio
async def test_production_api_rejects_header_only_identity(monkeypatch):
    async def asgi_app(_scope, _receive, _send):
        raise AssertionError("The middleware should reject before calling the app")

    async def call_next(_request):
        raise AssertionError("The middleware should reject before calling the route")

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/events",
            "headers": [
                (b"x-user-id", str(uuid4()).encode()),
                (b"x-tenant-id", str(uuid4()).encode()),
            ],
            "query_string": b"",
            "scheme": "https",
            "server": ("testserver", 443),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
        }
    )
    monkeypatch.setattr(tenant_middleware, "_IS_DEV", False)

    response = await TenantMiddleware(asgi_app).dispatch(request, call_next)

    assert response.status_code == 401

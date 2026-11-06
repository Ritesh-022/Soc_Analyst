"""JWT/OIDC authentication middleware.

Validates Bearer tokens on every API request. In development mode
(ASCENSE_ENV=development), the X-User-ID header is also accepted as a
bypass for tooling convenience — this bypass is DISABLED in production.

Token validation (production):
  1. Extract Bearer token from Authorization header
  2. Fetch JWKS from the configured issuer endpoint
  3. Validate RS256 signature using the matching JWK
  4. Validate audience, expiry, and issuer claims
  5. Extract internal user_id from the `sub` claim
  6. Attach user_id to request.state

Tenant context is accepted only when the authenticated user has a matching
membership. A tenant header may select among memberships but cannot grant access.

Use generate_dev_token() to create tokens for local testing.
"""

from __future__ import annotations

import time
from uuid import UUID

import httpx
import jwt as pyjwt
import structlog
from fastapi import Request
from fastapi.security import HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.config import get_settings
from ascense.models import Membership, User

logger = structlog.get_logger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

settings = get_settings()
_IS_DEV = settings.ENVIRONMENT == "development"

# JWKS cache (avoids fetching keys on every request)
_jwks_cache: dict[str, object] | None = None
_jwks_cache_time = 0.0
_JWKS_CACHE_TTL = 300  # 5 minutes


async def _fetch_jwks(*, force_refresh: bool = False) -> dict[str, object] | None:
    """Fetch JWKS from the configured issuer endpoint.

    Caches the result for 5 minutes to avoid repeated HTTP calls.
    """
    global _jwks_cache, _jwks_cache_time

    now = time.monotonic()
    if (
        not force_refresh
        and _jwks_cache is not None
        and (now - _jwks_cache_time) < _JWKS_CACHE_TTL
    ):
        return _jwks_cache

    jwks_url = settings.JWKS_URL
    if not jwks_url:
        logger.warning("auth.jwks_url_not_configured")
        return None
    if not _IS_DEV and not jwks_url.startswith("https://"):
        logger.error("auth.jwks_url_must_use_https")
        return None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
            jwks = response.json()
    except httpx.HTTPError as exc:
        logger.error("auth.jwks_fetch_failed", error=str(exc))
        return None
    except ValueError as exc:
        logger.error("auth.jwks_invalid_json", error=str(exc))
        return None

    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        logger.error("auth.jwks_invalid_format")
        return None

    _jwks_cache = jwks
    _jwks_cache_time = time.monotonic()
    logger.info("auth.jwks_fetched", key_count=len(jwks["keys"]))
    return jwks


def _decode_dev_token(token: str) -> dict | None:
    """In development, accept a simple shared-secret signed JWT (HS256).

    Payload: {"sub": "<user_id>", "tenant_id": "<tenant_id>"}
    """
    try:
        return pyjwt.decode(
            token,
            key=settings.DEV_AUTH_SECRET,
            algorithms=["HS256"],
            issuer="dev-ascense",
            audience="ascense-api",
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except pyjwt.PyJWTError:
        return None


async def _decode_oidc_token(token: str) -> dict | None:
    """Validate an OIDC RS256 token from the configured issuer.

    Steps:
      1. Decode the unverified header to get the kid
      2. Fetch JWKS from the issuer endpoint (cached)
      3. Find the matching JWK by kid
      4. Validate the token signature, audience, issuer, and expiry
      5. Return the decoded payload
    """
    try:
        if not settings.JWT_ISSUER or not settings.JWT_AUDIENCE:
            logger.error("auth.issuer_or_audience_not_configured")
            return None
        if not _IS_DEV and not settings.JWT_ISSUER.startswith("https://"):
            logger.error("auth.issuer_must_use_https")
            return None

        unverified_header = pyjwt.get_unverified_header(token)
        if unverified_header.get("alg") != "RS256":
            logger.warning("auth.token_unsupported_algorithm")
            return None
        kid = unverified_header.get("kid")
        if not isinstance(kid, str) or not kid:
            logger.warning("auth.token_missing_kid")
            return None

        jwks = await _fetch_jwks()
        if jwks is None:
            return None

        def find_signing_jwk(keys: list[object]) -> dict | None:
            return next(
                (
                    key
                    for key in keys
                    if isinstance(key, dict)
                    and key.get("kid") == kid
                    and key.get("kty") == "RSA"
                    and key.get("use", "sig") == "sig"
                    and key.get("alg", "RS256") == "RS256"
                ),
                None,
            )

        signing_jwk = find_signing_jwk(jwks["keys"])
        if signing_jwk is None:
            jwks = await _fetch_jwks(force_refresh=True)
            if jwks is None:
                return None
            signing_jwk = find_signing_jwk(jwks["keys"])
        if signing_jwk is None:
            logger.warning("auth.jwks_key_not_found", kid=kid)
            return None

        from jwt import PyJWK

        signing_key = PyJWK.from_dict(signing_jwk)
        return pyjwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )

    except pyjwt.ExpiredSignatureError:
        logger.warning("auth.token_expired")
        return None
    except pyjwt.InvalidAudienceError:
        logger.warning("auth.token_invalid_audience")
        return None
    except pyjwt.InvalidIssuerError:
        logger.warning("auth.token_invalid_issuer")
        return None
    except pyjwt.PyJWTError as exc:
        logger.warning("auth.token_invalid", error=str(exc))
        return None
    except (TypeError, ValueError) as exc:
        logger.error("auth.token_decode_error", error=str(exc))
        return None


async def resolve_user_from_token(
    request: Request,
    session: AsyncSession,
) -> UUID | None:
    """Extract and validate user identity from the request.

    Priority order:
      1. request.state.user_id — already resolved by earlier middleware
      2. Bearer JWT token (OIDC RS256 in prod, HS256 dev token in dev)
      3. X-User-ID header — DEV ONLY, rejected in production
      4. 401 Unauthorized (caller handles)
    """
    # Already resolved by earlier middleware
    state_user_id = getattr(request.state, "user_id", None)
    if state_user_id:
        try:
            return UUID(state_user_id)
        except ValueError:
            pass  # fall through to other auth methods

    # Production: JWT Bearer token
    auth_header = request.headers.get("Authorization", "")
    scheme, separator, token = auth_header.partition(" ")
    if separator and scheme.casefold() == "bearer" and token.strip():
        token = token.strip()

        payload = _decode_dev_token(token) if _IS_DEV else None
        is_dev_token = payload is not None
        if payload is None:
            payload = await _decode_oidc_token(token)

        if payload is not None:
            sub = payload.get("sub", "")
            if is_dev_token:
                try:
                    user_id = UUID(sub)
                except (ValueError, TypeError, AttributeError):
                    logger.warning("auth.invalid_sub_claim")
                    return None
            else:
                issuer = payload.get("iss")
                if not isinstance(sub, str) or not sub or not isinstance(issuer, str):
                    logger.warning("auth.invalid_identity_claims")
                    return None
                result = await session.execute(
                    select(User.id).where(User.issuer == issuer, User.subject == sub)
                )
                user_id = result.scalar_one_or_none()
                if user_id is None:
                    logger.warning("auth.user_not_registered", issuer=issuer)
                    return None

            request.state.user_id = str(user_id)
            await _resolve_tenant_context(request, session, user_id, payload)
            return user_id

    # Dev bypass: X-User-ID header — PRODUCTION REJECTS THIS
    if _IS_DEV:
        x_user_id = request.headers.get("X-User-ID")
        if x_user_id:
            try:
                user_id = UUID(x_user_id)
                request.state.user_id = str(user_id)
                return user_id
            except ValueError:
                logger.warning("auth.invalid_x_user_id_header", value=x_user_id[:32])

    return None


async def _resolve_tenant_context(
    request: Request,
    session: AsyncSession,
    user_id: UUID,
    payload: dict,
) -> None:
    """Set tenant context only when the authenticated user has a membership."""
    result = await session.execute(
        select(Membership.tenant_id).where(Membership.user_id == user_id)
    )
    memberships = set(result.scalars().all())

    claim = payload.get("tenant_id") or payload.get("tid")
    header = request.headers.get("X-Tenant-ID")
    if claim is not None and header is not None:
        try:
            if UUID(str(claim)) != UUID(header):
                logger.warning(
                    "auth.tenant_selector_conflicts_with_claim",
                    user_id=str(user_id),
                )
                return
        except (ValueError, TypeError, AttributeError):
            logger.warning("auth.invalid_tenant_claim", user_id=str(user_id))
            return

    selector = claim if claim is not None else header
    if selector is not None:
        try:
            selected_tenant = UUID(str(selector))
        except (ValueError, TypeError, AttributeError):
            logger.warning("auth.invalid_tenant_claim", user_id=str(user_id))
            return
        if selected_tenant not in memberships:
            logger.warning(
                "auth.user_not_member_of_tenant",
                user_id=str(user_id),
                tenant_id=str(selected_tenant),
            )
            return
        request.state.tenant_id = str(selected_tenant)
    elif len(memberships) == 1:
        request.state.tenant_id = str(next(iter(memberships)))


def generate_dev_token(user_id: UUID, tenant_id: UUID) -> str:
    """Generate a development JWT (HS256) for testing.

    Usage:
        token = generate_dev_token(user_id, tenant_id)
        headers = {"Authorization": f"Bearer {token}"}
    """
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "iss": "dev-ascense",
        "aud": "ascense-api",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return pyjwt.encode(payload, key=settings.DEV_AUTH_SECRET, algorithm="HS256")

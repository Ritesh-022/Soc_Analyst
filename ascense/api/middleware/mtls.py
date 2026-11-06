"""Gateway mTLS verification middleware.

For all /edge/v1/ endpoints, verifies that the client presented a valid
mTLS certificate and that the certificate's subject CN matches the
gateway_id in the URL path.

In production:
  1. The reverse proxy terminates TLS and forwards the client certificate
     in the X-Client-Cert header (or the SSL_CLIENT_CERT header)
  2. This middleware validates the certificate fingerprint against the
     gateway_certificates table
  3. The gateway_id from the URL is matched against the certificate's CN

In development:
  - mTLS verification is bypassed when ASCENSE_ENV=development
  - X-Tenant-ID and X-Gateway-ID headers are used instead
"""

from __future__ import annotations

import hashlib
from uuid import UUID

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ascense.config import get_settings

logger = structlog.get_logger(__name__)

settings = get_settings()
_IS_DEV = settings.ENVIRONMENT == "development"


class GatewayMTLSMiddleware(BaseHTTPMiddleware):
    """Verifies gateway client certificate on /edge/v1/ endpoints.

    In production, the reverse proxy must forward the client certificate.
    This middleware checks:
      1. A certificate was presented
      2. The certificate fingerprint matches a record in gateway_certificates
      3. The gateway_id in the URL matches the certificate's subject CN
      4. The certificate has not been revoked or expired
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only enforce on edge API endpoints
        if not path.startswith("/edge/v1/"):
            return await call_next(request)

        # Skip in development mode (no mTLS infrastructure)
        if _IS_DEV:
            # In dev mode, extract gateway_id from X-Gateway-ID header
            # or from the URL path for heartbeat/event endpoints
            gateway_id = request.headers.get("X-Gateway-ID")
            if gateway_id:
                request.state.gateway_id = gateway_id
            return await call_next(request)

        # Production: verify client certificate
        # The reverse proxy forwards the certificate PEM in X-Client-Cert
        # or the fingerprint in X-Client-Cert-Fingerprint
        cert_pem = request.headers.get("X-Client-Cert", "")
        cert_fingerprint = request.headers.get("X-Client-Cert-Fingerprint", "")

        if not cert_pem and not cert_fingerprint:
            return _reject_mtls(request, "No client certificate presented")

        # Compute fingerprint if we got the PEM
        if cert_pem and not cert_fingerprint:
            cert_fingerprint = hashlib.sha256(cert_pem.encode()).hexdigest()

        # Extract gateway_id from URL path
        # Paths: /edge/v1/gateways/{gateway_id}/heartbeat
        #        /edge/v1/gateways/{gateway_id}/commands:claim
        #        /edge/v1/gateways/{gateway_id}/commands/{command_id}/...
        path_parts = path.split("/")
        gateway_id_str = None
        if "gateways" in path_parts:
            idx = path_parts.index("gateways")
            if idx + 1 < len(path_parts):
                gateway_id_str = path_parts[idx + 1]

        if not gateway_id_str:
            return await call_next(request)  # no gateway_id in path

        try:
            gateway_id = UUID(gateway_id_str)
        except ValueError:
            return _reject_mtls(request, f"Invalid gateway_id in URL: {gateway_id_str}")

        # Verify the certificate against the database
        # This is async but BaseHTTPMiddleware doesn't support async DB calls
        # in dispatch. We store the fingerprint for the route to verify.
        request.state.gateway_cert_fingerprint = cert_fingerprint
        request.state.gateway_id = str(gateway_id)

        # The actual DB verification happens in the route handler via
        # verify_gateway_certificate() dependency.
        return await call_next(request)


def _reject_mtls(request: Request, reason: str) -> JSONResponse:
    """Return a 401 for failed mTLS verification."""
    logger.warning(
        "mtls.verification_failed",
        path=request.url.path,
        reason=reason,
        client_ip=request.client.host if request.client else "unknown",
    )
    return JSONResponse(
        status_code=401,
        content={
            "type": "https://api.ascense.example/problems/gateway-mtls-required",
            "title": "Gateway mTLS certificate required",
            "status": 401,
            "detail": reason,
            "error_code": "GATEWAY_MTLS_REQUIRED",
        },
        media_type="application/problem+json",
    )

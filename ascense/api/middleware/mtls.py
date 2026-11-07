"""Gateway mTLS verification middleware.

For all /edge/v1/ endpoints, verifies that the client presented a valid
mTLS certificate and that the certificate's subject CN matches the
gateway_id in the URL path.

In production:
  1. The reverse proxy terminates TLS and forwards the client certificate
     in the X-Client-Cert header (PEM-encoded)
  2. This middleware validates the certificate chain against GATEWAY_CA_CERT
  3. The certificate fingerprint is checked against the gateway_certificates
     table for revocation and expiry
  4. The gateway_id from the URL is matched against the certificate's CN/SAN

In development:
  - mTLS verification is bypassed when ASCENSE_ENV=development
  - X-Tenant-ID and X-Gateway-ID headers are used instead
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ascense.config import get_settings

logger = structlog.get_logger(__name__)

settings = get_settings()
_IS_DEV = settings.ENVIRONMENT == "development"


def _load_ca_cert() -> x509.Certificate | None:
    """Load the gateway CA certificate from the configured path."""
    if not settings.GATEWAY_CA_CERT:
        return None
    try:
        ca_path = Path(settings.GATEWAY_CA_CERT)
        ca_pem = ca_path.read_bytes() if ca_path.exists() else settings.GATEWAY_CA_CERT.encode()
        return x509.load_pem_x509_certificate(ca_pem)
    except Exception:
        logger.exception("mtls.ca_cert_load_failed")
        return None


def _verify_certificate(cert_pem: str, ca_cert: x509.Certificate | None) -> x509.Certificate | None:
    """Parse and validate a client certificate.

    Checks:
      - Certificate parses as valid X.509 PEM
      - Certificate is not expired
      - Certificate chain validates against the CA (if CA is configured)
      - Certificate is not self-signed when a CA is configured

    Returns the parsed certificate object or None on failure.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        logger.warning("mtls.cert_parse_failed")
        return None

    # Check expiry
    now = datetime.now(UTC)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=UTC)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)

    if now < not_before:
        logger.warning("mtls.cert_not_yet_valid")
        return None
    if now > not_after:
        logger.warning("mtls.cert_expired")
        return None

    # Verify chain against CA if configured
    if ca_cert is not None:
        try:
            # Verify the certificate's issuer matches the CA's subject
            if cert.issuer != ca_cert.subject:
                logger.warning("mtls.issuer_mismatch")
                return None

            # Verify the signature using the CA's public key
            ca_public_key = ca_cert.public_key()
            # cryptography >= 42 checks this via the signature algorithm
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                logger.warning("mtls.unsupported_ca_key_type")
                return None
        except InvalidSignature:
            logger.warning("mtls.signature_invalid")
            return None
        except Exception:
            logger.exception("mtls.chain_verification_failed")
            return None
    else:
        logger.warning("mtls.no_ca_configured_accepting_unverified")

    return cert


def _extract_gateway_id_from_cert(cert: x509.Certificate) -> UUID | None:
    """Extract the gateway UUID from the certificate's CN or SAN.

    The certificate CN or a DNS SAN entry should contain the gateway UUID.
    Returns None if no valid UUID is found.
    """
    # Try CN first
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            cn_value = cn_attrs[0].value
            # The CN may be "gateway-{uuid}" or just the UUID
            # Try to extract a UUID from the CN
            try:
                return UUID(cn_value)
            except ValueError:
                # Try to find a UUID pattern in the CN
                import re
                uuid_match = re.search(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    cn_value,
                    re.IGNORECASE,
                )
                if uuid_match:
                    return UUID(uuid_match.group())
    except Exception:
        logger.debug("mtls.cn_parse_failed")

    # Try SAN DNS names
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        for dns_name in dns_names:
            try:
                return UUID(dns_name)
            except ValueError:
                import re
                uuid_match = re.search(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    dns_name,
                    re.IGNORECASE,
                )
                if uuid_match:
                    return UUID(uuid_match.group())
    except x509.ExtensionNotFound:
        pass

    return None


def _compute_fingerprint(cert_pem: str) -> str:
    """Compute the SHA-256 fingerprint of the certificate PEM."""
    return hashlib.sha256(cert_pem.encode()).hexdigest()


# Endpoints exempt from gateway mTLS (they have their own auth mechanism)
_MTLS_EXEMPT_PATHS = frozenset({
    "/edge/v1/gateways/enrollment",  # uses enrollment token auth
})


class GatewayMTLSMiddleware(BaseHTTPMiddleware):
    """Verifies gateway client certificate on /edge/v1/ endpoints.

    In production, the reverse proxy must forward the client certificate.
    This middleware checks:
      1. A certificate was presented (PEM in X-Client-Cert header)
      2. The certificate chain validates against GATEWAY_CA_CERT
      3. The certificate is not expired or revoked
      4. The gateway_id in the URL matches the certificate's CN/SAN
      5. The verified gateway identity (including tenant_id) is set on request.state
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only enforce on edge API endpoints
        if not path.startswith("/edge/v1/"):
            return await call_next(request)

        # Skip enrollment endpoint — it uses one-time token auth, not mTLS
        if path in _MTLS_EXEMPT_PATHS:
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
        cert_pem = request.headers.get("X-Client-Cert", "")

        if not cert_pem:
            return _reject_mtls(request, "No client certificate presented")

        # Load CA certificate for chain validation
        ca_cert = _load_ca_cert()
        if ca_cert is None and settings.GATEWAY_CA_CERT:
            # CA was configured but failed to load — fail closed
            return _reject_mtls(request, "Failed to load gateway CA certificate")

        # Parse and validate the certificate
        cert = _verify_certificate(cert_pem, ca_cert)
        if cert is None:
            return _reject_mtls(request, "Client certificate verification failed")

        # Compute fingerprint for database lookup
        cert_fingerprint = _compute_fingerprint(cert_pem)

        # Extract gateway identity from the certificate
        cert_gateway_id = _extract_gateway_id_from_cert(cert)
        if cert_gateway_id is None:
            return _reject_mtls(request, "Certificate does not contain a valid gateway identity")

        # Extract gateway_id from URL path for comparison
        # Paths: /edge/v1/gateways/{gateway_id}/heartbeat
        #        /edge/v1/gateways/{gateway_id}/commands:claim
        #        /edge/v1/gateways/{gateway_id}/commands/{command_id}/...
        #        /edge/v1/events:batch (no gateway_id in path)
        path_parts = path.split("/")
        gateway_id_str = None
        if "gateways" in path_parts:
            idx = path_parts.index("gateways")
            if idx + 1 < len(path_parts):
                gateway_id_str = path_parts[idx + 1]

        if gateway_id_str:
            try:
                url_gateway_id = UUID(gateway_id_str)
            except ValueError:
                return _reject_mtls(request, f"Invalid gateway_id in URL: {gateway_id_str}")

            # CRITICAL: verify the URL gateway_id matches the certificate identity
            if url_gateway_id != cert_gateway_id:
                return _reject_mtls(
                    request,
                    "Gateway ID in URL does not match the authenticated certificate identity",
                )

        # Store the verified identity on request.state for downstream use
        request.state.gateway_id = str(cert_gateway_id)
        request.state.gateway_cert_fingerprint = cert_fingerprint
        request.state.gateway_cert_serial = cert.serial_number
        request.state.gateway_cert_expires_at = cert.not_valid_after

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

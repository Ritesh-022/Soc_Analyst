"""Gateway mTLS verification middleware.

For all /edge/v1/ endpoints, verifies that the client presented a valid
mTLS certificate and that the certificate's subject CN matches the
gateway_id in the URL path.

In production:
  1. The reverse proxy terminates TLS and forwards the client certificate
     in the X-Client-Cert header (Base64-encoded DER)
  2. This middleware validates the certificate chain against GATEWAY_CA_CERT
  3. The gateway dependency checks the fingerprint against the
     gateway_certificates table for authorization and revocation
  4. The gateway_id from the URL is matched against the certificate's CN/SAN

In development:
  - mTLS verification is bypassed when ASCENSE_ENV=development
  - X-Tenant-ID and X-Gateway-ID headers are used instead
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
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


MAX_FORWARDED_CERT_BYTES = 16 * 1024


def _verify_certificate(
    cert_der: bytes,
    ca_cert: x509.Certificate | None,
) -> x509.Certificate | None:
    """Parse and validate a client certificate.

    Checks:
      - Certificate parses as one DER-encoded X.509 certificate
      - Certificate is not expired
      - Certificate chain validates against the CA (if CA is configured)
      - Certificate is not self-signed when a CA is configured

    Returns the parsed certificate object or None on failure.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
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

    if not _has_approved_gateway_profile(cert):
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
            signature_hash_algorithm = cert.signature_hash_algorithm
            if signature_hash_algorithm is None:
                logger.warning("mtls.signature_algorithm_missing")
                return None
            # cryptography >= 42 checks this via the signature algorithm
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    signature_hash_algorithm,
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(signature_hash_algorithm),
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


def _has_approved_gateway_profile(cert: x509.Certificate) -> bool:
    """Validate the initial gateway leaf-certificate profile."""
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            logger.warning("mtls.rsa_key_too_small")
            return False
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1", "secp521r1"}:
            logger.warning("mtls.ec_curve_not_approved")
            return False
    else:
        logger.warning("mtls.public_key_type_not_approved")
        return False

    try:
        signature_hash = cert.signature_hash_algorithm
    except (UnsupportedAlgorithm, ValueError):
        logger.warning("mtls.signature_algorithm_not_approved")
        return False
    if signature_hash is None or signature_hash.name not in {"sha256", "sha384", "sha512"}:
        logger.warning("mtls.signature_algorithm_not_approved")
        return False

    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_key_usage = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (x509.ExtensionNotFound, ValueError):
        logger.warning("mtls.required_certificate_extension_missing")
        return False

    if basic_constraints.ca:
        logger.warning("mtls.gateway_certificate_is_ca")
        return False
    if not key_usage.digital_signature or key_usage.key_cert_sign:
        logger.warning("mtls.invalid_gateway_key_usage")
        return False
    if ExtendedKeyUsageOID.CLIENT_AUTH not in extended_key_usage:
        logger.warning("mtls.client_auth_eku_missing")
        return False
    if not san:
        logger.warning("mtls.gateway_san_missing")
        return False
    return True


def _extract_gateway_id_from_cert(cert: x509.Certificate) -> UUID | None:
    """Extract one consistent gateway UUID from CN and DNS SAN identities."""
    import re

    pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        re.IGNORECASE,
    )
    values: list[str] = []
    try:
        values.extend(
            str(attribute.value)
            for attribute in cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )
        )
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        values.extend(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    identities: set[UUID] = set()
    for value in values:
        match = pattern.search(value)
        if match:
            identities.add(UUID(match.group()))

    if len(identities) != 1:
        if len(identities) > 1:
            logger.warning("mtls.certificate_identity_conflict")
        return None
    return next(iter(identities))


def _compute_fingerprint(cert_der: bytes) -> str:
    """Compute the SHA-256 fingerprint of canonical DER certificate bytes."""
    return hashlib.sha256(cert_der).hexdigest()


# Endpoints exempt from gateway mTLS (they have their own auth mechanism)
_MTLS_EXEMPT_PATHS = frozenset({
    "/edge/v1/gateways/enrollment",  # uses enrollment token auth
})


class GatewayMTLSMiddleware(BaseHTTPMiddleware):
    """Verifies gateway client certificate on /edge/v1/ endpoints.

    In production, the reverse proxy must forward the client certificate.
    This middleware checks:
      1. A certificate was presented (Base64-encoded DER in X-Client-Cert)
      2. The certificate chain validates against GATEWAY_CA_CERT
      3. The certificate is not expired
      4. The gateway_id in the URL matches the certificate's CN/SAN
      5. The transport identity is made available for database authorization
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

        # Production: verify the single-line Base64-encoded DER certificate
        # forwarded by the authenticated reverse proxy.
        cert_headers = request.headers.getlist("X-Client-Cert")
        if len(cert_headers) != 1 or not cert_headers[0]:
            return _reject_mtls(request, "No client certificate presented")

        try:
            cert_der = base64.b64decode(cert_headers[0], validate=True)
        except (binascii.Error, ValueError):
            return _reject_mtls(request, "Malformed forwarded client certificate")

        if not cert_der or len(cert_der) > MAX_FORWARDED_CERT_BYTES:
            return _reject_mtls(request, "Invalid forwarded client certificate size")

        # Load CA certificate for chain validation
        ca_cert = _load_ca_cert()
        if ca_cert is None:
            return _reject_mtls(request, "Failed to load gateway CA certificate")

        # Parse and validate the certificate
        cert = _verify_certificate(cert_der, ca_cert)
        if cert is None:
            return _reject_mtls(request, "Client certificate verification failed")

        # Compute fingerprint for database lookup
        cert_fingerprint = _compute_fingerprint(cert_der)

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
        request.state.gateway_certificate_der = cert_der
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

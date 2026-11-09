from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ascense.api.middleware.mtls import (
    _compute_fingerprint,
    _extract_gateway_id_from_cert,
    _has_approved_gateway_profile,
    _verify_certificate,
)


def _certificate(
    *,
    include_client_auth: bool = True,
    san_gateway_id: str | None = None,
) -> tuple[x509.Certificate, x509.Certificate]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ascense Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gateway_id = str(uuid4())
    eku = [ExtendedKeyUsageOID.CLIENT_AUTH] if include_client_auth else []
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, gateway_id)]))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(eku), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(san_gateway_id or gateway_id)]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca, leaf


def test_gateway_certificate_requires_client_auth_profile():
    ca, valid_leaf = _certificate()
    _, invalid_leaf = _certificate(include_client_auth=False)

    assert _has_approved_gateway_profile(valid_leaf)
    assert not _has_approved_gateway_profile(invalid_leaf)
    assert _verify_certificate(
        valid_leaf.public_bytes(serialization.Encoding.DER),
        ca,
    ) == valid_leaf


def test_fingerprint_is_canonical_der_bytes():
    _, leaf = _certificate()
    der = leaf.public_bytes(serialization.Encoding.DER)
    pem = leaf.public_bytes(serialization.Encoding.PEM)

    assert _compute_fingerprint(der) == _compute_fingerprint(bytes(der))
    assert _compute_fingerprint(der) != _compute_fingerprint(pem)


def test_pem_is_not_accepted_as_forwarded_der():
    ca, leaf = _certificate()

    assert _verify_certificate(
        leaf.public_bytes(serialization.Encoding.PEM),
        ca,
    ) is None


def test_conflicting_certificate_identities_are_rejected():
    ca, leaf = _certificate(san_gateway_id=str(uuid4()))

    assert _extract_gateway_id_from_cert(leaf) is None
    assert _verify_certificate(
        leaf.public_bytes(serialization.Encoding.DER),
        ca,
    ) == leaf

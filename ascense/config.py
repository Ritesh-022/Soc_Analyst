"""Platform configuration loaded from environment variables.

Security defaults: the application defaults to "production" mode unless the
runtime explicitly sets ASCENSE_ENV=development. In production, this means:
  - X-User-ID and X-Tenant-ID headers are REJECTED
  - mTLS is enforced on /edge/v1/ endpoints
  - Debug is off, logging is INFO level
  - Placeholder secrets (dev-secret-change-me, etc.) cause startup failure

For local development, set ASCENSE_ENV=development explicitly.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

# Placeholder secrets that must be replaced in production
_PLACEHOLDER_SECRETS = {
    "dev-secret-change-me",
    "dev-command-signing-key-change-in-production",
}


class Settings:
    """Application settings. Override via environment variables."""

    # Core — production is the secure default; development must be
    # explicitly requested by setting ASCENSE_ENV=development.
    APP_NAME: str = "Ascense"
    ENVIRONMENT: str = os.getenv("ASCENSE_ENV", "production")
    DEBUG: bool = os.getenv("ASCENSE_DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def is_dev(self) -> bool:
        return self.ENVIRONMENT == "development"

    def validate_production(self) -> list[str]:
        """Check for insecure defaults in production mode.

        Returns a list of error messages. Empty list = safe to start.
        """
        errors: list[str] = []
        if self.is_dev:
            return errors  # dev mode allows placeholder secrets

        if self.DEV_AUTH_SECRET in _PLACEHOLDER_SECRETS:
            errors.append(
                "DEV_AUTH_SECRET must be set to a strong random value "
                "in production (current value is a placeholder)"
            )
        if self.COMMAND_SIGNING_KEY in _PLACEHOLDER_SECRETS:
            errors.append(
                "COMMAND_SIGNING_KEY must be set to a 256-bit random key "
                "in production (current value is a placeholder)"
            )
        if not self.JWKS_URL:
            errors.append(
                "JWKS_URL must be configured in production "
                "(OIDC token validation requires a JWKS endpoint)"
            )
        if self.DEBUG:
            errors.append(
                "DEBUG=true is not allowed in production"
            )
        return errors

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://ascense:ascense_dev_password@localhost:5432/ascense",
    )

    # RabbitMQ
    RABBITMQ_URL: str = os.getenv(
        "RABBITMQ_URL", "amqp://ascense:ascense_dev_password@localhost:5672/"
    )

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Object storage (MinIO/S3)
    S3_ENDPOINT: str = os.getenv("S3_ENDPOINT", "http://localhost:9000")
    S3_ACCESS_KEY: str = os.getenv("S3_ACCESS_KEY", "ascense")
    S3_SECRET_KEY: str = os.getenv("S3_SECRET_KEY", "ascense_dev_password")
    S3_BUCKET_EVIDENCE: str = os.getenv("S3_BUCKET_EVIDENCE", "ascense-evidence")

    # OpenTelemetry
    OTEL_EXPORTER_OTLP_ENDPOINT: str = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"
    )
    OTEL_SERVICE_NAME: str = os.getenv("OTEL_SERVICE_NAME", "ascense-platform")

    # Auth
    JWT_ISSUER: str = os.getenv("JWT_ISSUER", "https://auth.ascense.example")
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "ascense-api")
    # JWKS endpoint for OIDC RS256 token validation
    # Set to your IdP's discovery endpoint (e.g. https://auth.ascense.example/.well-known/jwks.json)
    JWKS_URL: str = os.getenv("JWKS_URL", "")
    # In development, we allow a simple shared secret for testing
    DEV_AUTH_SECRET: str = os.getenv("DEV_AUTH_SECRET", "dev-secret-change-me")

    # Command signing — HMAC-SHA256 key used to sign commands sent to gateways
    # In production, use a 256-bit random key (e.g. openssl rand -hex 32)
    COMMAND_SIGNING_KEY: str = os.getenv(
        "COMMAND_SIGNING_KEY", "dev-command-signing-key-change-in-production"
    )

    # Internal service-to-service access: a workload identity token or shared
    # secret used only by trusted internal workers.
    INTERNAL_SERVICE_TOKEN: str = os.getenv(
        "INTERNAL_SERVICE_TOKEN", "dev-internal-service-token"
    )

    # Gateway mTLS
    # Path to the CA certificate PEM file used to verify gateway client certificates
    GATEWAY_CA_CERT: str = os.getenv("GATEWAY_CA_CERT", "")

    # Contracts directory
    CONTRACTS_DIR: Path = Path(__file__).resolve().parent.parent / "contracts"


@lru_cache
def get_settings() -> Settings:
    return Settings()

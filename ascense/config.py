"""Platform configuration loaded from environment variables."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


class Settings:
    """Application settings. Override via environment variables."""

    # Core
    APP_NAME: str = "Ascense"
    ENVIRONMENT: str = os.getenv("ASCENSE_ENV", "development")
    DEBUG: bool = os.getenv("ASCENSE_DEBUG", "true").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

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
    # In development, we allow a simple shared secret for testing
    DEV_AUTH_SECRET: str = os.getenv("DEV_AUTH_SECRET", "dev-secret-change-me")

    # Gateway mTLS
    GATEWAY_CA_CERT: str = os.getenv("GATEWAY_CA_CERT", "")

    # Contracts directory
    CONTRACTS_DIR: Path = Path(__file__).resolve().parent.parent / "contracts"


@lru_cache
def get_settings() -> Settings:
    return Settings()

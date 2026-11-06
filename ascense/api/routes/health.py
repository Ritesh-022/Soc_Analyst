"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Liveness probe. Returns 200 when the API process is running."""
    return {"status": "ok", "service": "ascense-platform-api"}

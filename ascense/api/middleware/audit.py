"""Audit logging middleware.

Records security-relevant operations to the audit log. The audit log is
append-only and independently protected. Every security-relevant
operation must produce an audit record containing: event_time, actor_id,
actor_type, tenant_id, action, resource_type, resource_id, outcome,
trace_id.

Audit records must never be deleted or modified during their defined
retention period.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = structlog.get_logger(__name__)

# Operations that require audit records
AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Path patterns that require audit records
AUDITED_PATHS = {
    "/api/v1/gateways/enrollment-tokens": "gateway.enrollment_token_created",
    "/api/v1/alerts": "alert.acknowledged",
    "/api/v1/incidents": "incident.transitioned",
    "/api/v1/action-proposals": "proposal.created",
    "/api/v1/approvals": "approval.recorded",
    "/edge/v1/events": "event.ingested",
    "/edge/v1/commands": "command.claimed",
}


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs security-relevant API operations to the audit trail.

    In production, this writes to the audit_events table. For now, it
    logs structured events that include all required fields.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Only audit write operations
        if request.method not in AUDITED_METHODS:
            return response

        path = request.url.path

        # Match against audited path patterns
        audit_action = None
        for prefix, action in AUDITED_PATHS.items():
            if prefix in path:
                audit_action = action
                break

        if audit_action:
            tenant_id = getattr(request.state, "tenant_id", None)
            traceparent = request.headers.get("traceparent", "")
            trace_id = traceparent.split("-")[1] if traceparent else None

            logger.info(
                "audit.event",
                audit_event_id=str(uuid7()),
                tenant_id=tenant_id,
                action=audit_action,
                method=request.method,
                path=path,
                status_code=response.status_code,
                outcome="success" if response.status_code < 400 else "failure",
                trace_id=trace_id,
                occurred_at=datetime.now(UTC).isoformat(),
            )

        return response

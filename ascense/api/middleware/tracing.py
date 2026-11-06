"""W3C Trace Context and request ID propagation middleware.

Every inbound request creates or continues a W3C traceparent trace.
Every outbound broker message carries the trace context. The gateway
includes trace context in event batches.

Conventions:
  - trace_id: W3C 32-char lowercase hex (NOT a UUIDv7)
  - request_id: UUIDv7, distinct from trace_id
  - Both are included in structured logs and error responses
"""

from __future__ import annotations

import re
from uuid import uuid7

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)

# W3C traceparent format: version-trace_id-parent_id-trace_flags
TRACEPARENT_PATTERN = re.compile(
    r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
)


class TracingMiddleware(BaseHTTPMiddleware):
    """Propagates W3C traceparent and generates request_id for every request.

    - If the incoming request has a traceparent header, continue that trace.
    - If not, generate a new trace_id.
    - Always generate a request_id (UUIDv7) for this specific request.
    - Attach both to request.state for use by routes and logging.
    - Include trace_id and request_id in the response headers.
    """

    async def dispatch(self, request: Request, call_next):
        # Parse or generate trace_id
        incoming_traceparent = request.headers.get("traceparent", "")
        if incoming_traceparent and TRACEPARENT_PATTERN.match(incoming_traceparent):
            parts = incoming_traceparent.split("-")
            trace_id = parts[1]
        else:
            # Generate a new W3C trace_id (32-char hex)
            import secrets
            trace_id = secrets.token_hex(16)

        # Generate request_id (UUIDv7, distinct from trace_id)
        request_id = str(uuid7())

        # Attach to request state for downstream use
        request.state.trace_id = trace_id
        request.state.request_id = request_id

        # Bind to structlog context for structured logging
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            trace_id=trace_id,
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        response: Response = await call_next(request)

        # Include in response headers
        response.headers["X-Request-ID"] = request_id
        # Build a minimal traceparent for the response
        response.headers["traceparent"] = f"00-{trace_id}-{'0' * 16}-01"

        return response

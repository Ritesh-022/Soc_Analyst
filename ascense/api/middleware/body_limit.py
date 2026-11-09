"""Bound request bodies before FastAPI parses event batches."""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_EVENT_BODY_BYTES = 10 * 1024 * 1024
EVENT_BATCH_PATH = "/edge/v1/events:batch"


class EventBodyLimitMiddleware:
    """Enforce the event body limit while receiving, not after parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != EVENT_BATCH_PATH:
            await self.app(scope, receive, send)
            return

        content_length = _content_length(scope)
        if content_length is None and _has_content_length(scope):
            await _send_error(send, 400, "Malformed Content-Length header.")
            return
        if content_length is not None and content_length > MAX_EVENT_BODY_BYTES:
            await _send_error(send, 413, "Event request body exceeds the maximum size.")
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_EVENT_BODY_BYTES:
                await _send_error(send, 413, "Event request body exceeds the maximum size.")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_body() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)


def _has_content_length(scope: Scope) -> bool:
    return any(name.lower() == b"content-length" for name, _ in scope.get("headers", []))


def _content_length(scope: Scope) -> int | None:
    values = [
        value
        for name, value in scope.get("headers", [])
        if name.lower() == b"content-length"
    ]
    if not values:
        return None
    if len(values) != 1:
        return None
    try:
        decoded = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not decoded.isdecimal():
        return None
    return int(decoded)


async def _send_error(send: Send, status_code: int, detail: str) -> None:
    payload = json.dumps(
        {
            "type": "https://api.ascense.example/problems/request-body-too-large",
            "title": "Invalid event request body",
            "status": status_code,
            "detail": detail,
            "error_code": "EVENT_BODY_LIMIT",
        }
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/problem+json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})

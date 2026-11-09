import pytest

from ascense.api.middleware.body_limit import (
    EVENT_BATCH_PATH,
    MAX_EVENT_BODY_BYTES,
    EventBodyLimitMiddleware,
)


def _scope(headers: list[tuple[bytes, bytes]]) -> dict:
    return {"type": "http", "path": EVENT_BATCH_PATH, "headers": headers}


async def _run(body_chunks: list[bytes], headers: list[tuple[bytes, bytes]]):
    received = iter(
        [
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(body_chunks) - 1,
            }
            for index, chunk in enumerate(body_chunks)
        ]
    )
    sent = []
    app_body = bytearray()
    app_called = False

    async def receive():
        return next(received)

    async def send(message):
        sent.append(message)

    async def app(scope, app_receive, app_send):
        nonlocal app_called
        app_called = True
        while True:
            message = await app_receive()
            app_body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break

    await EventBodyLimitMiddleware(app)(_scope(headers), receive, send)
    return sent, bytes(app_body), app_called


@pytest.mark.asyncio
async def test_body_below_limit_is_replayed_to_fastapi():
    body = b'{"events":[]}'
    sent, replayed, app_called = await _run(
        [body],
        [(b"content-length", str(len(body)).encode())],
    )

    assert app_called
    assert replayed == body
    assert sent == []


@pytest.mark.asyncio
async def test_body_exactly_at_limit_is_accepted():
    body = b"x" * MAX_EVENT_BODY_BYTES
    sent, replayed, app_called = await _run(
        [body],
        [(b"content-length", str(len(body)).encode())],
    )

    assert app_called
    assert len(replayed) == MAX_EVENT_BODY_BYTES
    assert sent == []


@pytest.mark.asyncio
async def test_streamed_body_over_limit_is_rejected_before_application():
    sent, replayed, app_called = await _run(
        [b"x" * MAX_EVENT_BODY_BYTES, b"x"],
        [],
    )

    assert not app_called
    assert replayed == b""
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_malformed_content_length_is_rejected():
    sent, _, app_called = await _run(
        [b"{}"],
        [(b"content-length", b"not-a-number")],
    )

    assert not app_called
    assert sent[0]["status"] == 400

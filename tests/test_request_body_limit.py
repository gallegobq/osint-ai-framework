from __future__ import annotations

import pytest
from starlette.types import Message, Scope

from app.middleware.request_body_limit import RequestBodyLimitMiddleware


def _scope(headers: list[tuple[bytes, bytes]] | None = None) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
    }


async def _run(
    messages: list[Message],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[bool, list[Message]]:
    called = False
    sent: list[Message] = []
    queue = iter(messages)

    async def receive() -> Message:
        return next(queue)

    async def send(message: Message) -> None:
        sent.append(message)

    async def downstream(scope, receive, send) -> None:
        nonlocal called
        called = True
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=8)
    await middleware(_scope(headers), receive, send)
    return called, sent


@pytest.mark.asyncio
async def test_rejects_declared_oversized_body() -> None:
    called, sent = await _run(
        [{"type": "http.request", "body": b"", "more_body": False}],
        headers=[(b"content-length", b"9")],
    )

    assert called is False
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_rejects_oversized_chunked_body() -> None:
    called, sent = await _run(
        [
            {"type": "http.request", "body": b"12345", "more_body": True},
            {"type": "http.request", "body": b"6789", "more_body": False},
        ]
    )

    assert called is False
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_replays_body_within_limit() -> None:
    called, sent = await _run(
        [{"type": "http.request", "body": b"12345678", "more_body": False}]
    )

    assert called is True
    assert sent[0]["status"] == 204

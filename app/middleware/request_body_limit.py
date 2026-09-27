from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.settings import settings


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies before JSON or form parsing."""

    def __init__(
        self,
        app: ASGIApp,
        max_body_bytes: int | None = None,
    ) -> None:
        self.app = app
        self.max_body_bytes = (
            max_body_bytes
            if max_body_bytes is not None
            else settings.max_request_body_bytes
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if (
            content_length is not None
            and content_length > self.max_body_bytes
        ):
            await self._reject(scope, receive, send)
            return

        messages: list[Message] = []
        received_bytes = 0
        more_body = True
        while more_body:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received_bytes += len(message.get("body", b""))
            if received_bytes > self.max_body_bytes:
                await self._reject(scope, receive, send)
                return
            more_body = bool(message.get("more_body", False))

        replay = self._replay(messages)
        await self.app(scope, replay, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope.get("headers", []):
            if name.lower() != b"content-length":
                continue
            try:
                parsed = int(value)
            except ValueError:
                return None
            return parsed if parsed >= 0 else None
        return None

    @staticmethod
    def _replay(messages: list[Message]) -> Receive:
        index = 0

        async def receive() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        return receive

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "success": False,
                "error": {
                    "code": "REQUEST_TOO_LARGE",
                    "message": "Request body exceeds the configured limit.",
                },
            },
        )
        await response(scope, receive, send)

"""Bearer-token gate for the MCP transport.

The MCP server exposes a powerful tool surface; when it is published
beyond the docker-compose internal network or beyond localhost, every
HTTP request must authenticate. The gate is intentionally minimal: a
single shared secret, constant-time comparison, no key rotation, no
JWT, no OAuth. Production deployments that need stronger auth should
sit the server behind an OAuth2 proxy or mTLS-terminating gateway.
"""

import secrets
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

log = structlog.get_logger()

# ASGI types are loose; pin them locally to keep the contract clear.
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class BearerAuthASGI:
    """Plain ASGI middleware enforcing `Authorization: Bearer <token>`.

    Only `lifespan` scopes pass through ungated: they carry no client
    request. Every `http` scope goes through the bearer check. Any other
    scope type (`websocket`, or one a future server adds) is refused
    without reaching the app: the SSE transport serves no websocket route,
    so a scope the gate does not know is a scope it cannot vouch for.

    Comparison uses `secrets.compare_digest` to avoid timing oracles on
    the token value.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise ValueError("BearerAuthASGI requires a non-empty token")
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope_type != "http":
            await self._refuse_non_http(scope, send)
            return

        header_value = b""
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                header_value = value
                break

        if not secrets.compare_digest(header_value, self._expected):
            log.warning(
                "mcp_auth_rejected",
                path=scope.get("path"),
                method=scope.get("method"),
                client=scope.get("client"),
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="mcp"'),
                    ],
                },
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"error":"unauthorized"}',
                },
            )
            return

        await self._app(scope, receive, send)

    @staticmethod
    async def _refuse_non_http(scope: Scope, send: Send) -> None:
        scope_type = scope.get("type")
        log.warning(
            "mcp_auth_scope_refused",
            scope_type=str(scope_type)[:32],
            path=scope.get("path"),
            client=scope.get("client"),
        )
        if scope_type == "websocket":
            # Closing before accept makes the server answer the handshake
            # with HTTP 403 (ASGI websocket spec). 1008 = policy violation.
            await send({"type": "websocket.close", "code": 1008})
        # Any other scope type has no response message we could send; not
        # calling the app is the refusal.

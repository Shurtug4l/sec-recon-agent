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

    Lifespan and non-HTTP scopes (websocket, dispatched internally by
    FastMCP) are passed through. Only http requests are checked.

    Comparison uses `secrets.compare_digest` to avoid timing oracles on
    the token value.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise ValueError("BearerAuthASGI requires a non-empty token")
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
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

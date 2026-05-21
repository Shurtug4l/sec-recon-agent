"""Contract tests for the MCP bearer-auth ASGI middleware."""

from typing import Any

import pytest

from sec_recon_agent.mcp_server.auth import BearerAuthASGI


class _Recorder:
    """Capture every ASGI message a middleware emits via `send`."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.app_called = False

    async def send(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    async def passthrough_app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.app_called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _empty_receive() -> dict[str, Any]:
    return {"type": "http.disconnect"}


def _http_scope(headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    return {
        "type": "http",
        "method": "POST",
        "path": "/sse",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
    }


@pytest.mark.asyncio
async def test_rejects_missing_authorization() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    await mw(_http_scope([]), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_rejects_wrong_token() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Bearer nope")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_rejects_wrong_scheme() -> None:
    """Basic auth must not bypass the bearer gate."""
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Basic czNjcmV0")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert not rec.app_called
    assert rec.messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_accepts_correct_token() -> None:
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    headers = [(b"authorization", b"Bearer s3cret")]
    await mw(_http_scope(headers), _empty_receive, rec.send)

    assert rec.app_called
    assert rec.messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_passes_through_non_http_scope() -> None:
    """Lifespan / websocket scopes must not be challenged."""
    rec = _Recorder()
    mw = BearerAuthASGI(rec.passthrough_app, token="s3cret")

    await mw({"type": "lifespan"}, _empty_receive, rec.send)

    assert rec.app_called


def test_constructor_rejects_empty_token() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        BearerAuthASGI(lambda *_: None, token="")  # type: ignore[arg-type]


def test_build_app_without_token_returns_raw_sse_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MCP_AUTH_TOKEN is unset, build_app returns the SSE app unwrapped."""
    from sec_recon_agent.mcp_server import server as srv

    monkeypatch.setattr(srv.settings, "mcp_auth_token", None)
    app = srv.build_app()
    assert not isinstance(app, BearerAuthASGI)


def test_build_app_with_token_wraps_in_bearer_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """When MCP_AUTH_TOKEN is set, build_app wraps the SSE app in BearerAuthASGI."""
    from pydantic import SecretStr

    from sec_recon_agent.mcp_server import server as srv

    monkeypatch.setattr(srv.settings, "mcp_auth_token", SecretStr("s3cret"))
    app = srv.build_app()
    assert isinstance(app, BearerAuthASGI)

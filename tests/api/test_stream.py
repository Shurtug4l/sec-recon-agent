"""Tests for the FastAPI surface.

The triage endpoint is exercised with a fake agent (no LLM, no MCP server)
to verify SSE wiring at the HTTP level. End-to-end agent behavior is
covered manually with curl against a running stack.
"""

import json
from contextlib import asynccontextmanager
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from sec_recon_agent.agent.schema import (
    Confidence,
    Severity,
    TriageReport,
)
from sec_recon_agent.api import stream as stream_module
from sec_recon_agent.api.stream import app


@pytest.fixture
def fake_report() -> TriageReport:
    return TriageReport(
        summary="Fake summary for tests.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="Patch.",
        cves=[],
        reasoning_chain=["fake_tool() -> ok"],
    )


@pytest.fixture
def fake_agent_factory(fake_report: TriageReport) -> Any:
    """Return a build_agent replacement that yields scripted SSE events."""

    class _FakeNode:
        pass

    class _FakeResult:
        def __init__(self, output: TriageReport) -> None:
            self.output = output

    class _FakeRun:
        def __init__(self, output: TriageReport) -> None:
            self._output = output
            self.result = _FakeResult(output)

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield _FakeNode()
                yield _FakeNode()

            return gen()

    class _FakeAgent:
        def __init__(self, output: TriageReport) -> None:
            self._output = output

        @asynccontextmanager
        async def iter(self, query: str) -> Any:
            yield _FakeRun(self._output)

    def _factory(model_override: str | None = None) -> _FakeAgent:
        # Test factory ignores model override — the fake agent does not
        # actually call an LLM, so any model string is equally fine.
        del model_override
        return _FakeAgent(fake_report)

    return _factory


def test_health_returns_ok() -> None:
    client = TestClient(app)
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_meta_returns_system_prompt_and_tool_inventory() -> None:
    """The transparency endpoint must surface the literal system prompt
    plus a stable tool inventory. The frontend's dashboard depends on
    both being present and well-shaped."""
    client = TestClient(app)
    response = client.get("/v1/meta")
    assert response.status_code == 200
    body = response.json()
    assert "system_prompt" in body
    assert "model" in body
    assert "tools" in body
    # System prompt must include the untrusted-content boundary mention;
    # if it drifts, the transparency view loses its key value.
    assert "untrusted" in body["system_prompt"].lower()
    # Tool inventory: nine tools, names match the MCP tool surface.
    names = {t["name"] for t in body["tools"]}
    assert names == {
        "cve_lookup",
        "cve_semantic_search",
        "exploit_check",
        "kev_check",
        "epss_score",
        "patch_lookup",
        "sbom_ingest",
        "nmap_parse_xml",
        "attack_mapping",
    }
    for tool in body["tools"]:
        assert tool["description"]  # non-empty


def test_triage_validates_missing_query() -> None:
    client = TestClient(app)
    response = client.post("/v1/triage", json={})
    assert response.status_code == 422


def test_triage_validates_empty_query() -> None:
    client = TestClient(app)
    response = client.post("/v1/triage", json={"query": ""})
    assert response.status_code == 422


def test_triage_streams_started_and_final_events(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
    fake_report: TriageReport,
) -> None:
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "CVE-2021-41773"}) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        body = "".join(response.iter_text())

    # SSE format: blank-line-separated frames, each `event: ...\ndata: ...`
    assert "event: started" in body
    assert "event: node" in body
    assert "event: final" in body

    # Final frame must carry the TriageReport JSON
    final_data_line = next(
        line for line in body.splitlines() if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_data_line[len("data: ") :])
    assert payload["summary"] == fake_report.summary
    assert payload["severity"] == "high"


def test_triage_rejects_unknown_model_override(monkeypatch: MonkeyPatch) -> None:
    """A body that sets an unknown `model` must surface as an error
    event with the allowlist-violation message preserved.

    `resolve_model` raises ValueError before any LLM / MCP work happens,
    so this test routes through the real build_agent code path; the
    factory monkeypatch in other tests is unnecessary here.
    """

    def _build_agent_calling_real_resolve(model_override: str | None = None) -> Any:
        from sec_recon_agent.agent.triage import resolve_model

        resolve_model(model_override)  # may raise ValueError
        raise AssertionError("test expects resolve_model to raise before this point")

    monkeypatch.setattr(stream_module, "build_agent", _build_agent_calling_real_resolve)

    client = TestClient(app)
    with client.stream(
        "POST",
        "/v1/triage",
        json={"query": "test", "model": "gpt-4-secret"},
    ) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: error" in body
    assert "allowlist" in body
    assert "gpt-4-secret" in body


def test_triage_appends_one_audit_event_on_success(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
    tmp_path: Any,
) -> None:
    """The triage handler must append exactly one audit event per call,
    even though the audit pipeline is best-effort."""
    from sec_recon_agent.audit.store import AuditStore
    from sec_recon_agent.config import settings

    audit_path = tmp_path / "audit.db"
    monkeypatch.setattr(settings, "audit_db_path", audit_path)
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    monkeypatch.setattr(settings, "audit_include_query", False)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    stream_module._reset_audit_store()

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "CVE-2021-41773"}) as response:
        assert response.status_code == 200
        for _ in response.iter_text():
            pass

    store = AuditStore(audit_path)
    try:
        assert store.count() == 1
        assert store.verify() == 1
        events = store.tail(limit=1)
        ev = events[0]
        assert ev.outcome == "success"
        assert ev.severity == "high"
        # Privacy: query_plain stays None when AUDIT_INCLUDE_QUERY is off.
        assert ev.query_plain is None
        # But the digest is always there.
        assert len(ev.query_sha256) == 64
        assert ev.query_length == len("CVE-2021-41773")
    finally:
        store.close()
        stream_module._reset_audit_store()


def test_triage_appends_audit_event_on_error(monkeypatch: MonkeyPatch, tmp_path: Any) -> None:
    """An agent failure still produces one audit event with outcome=error."""
    from sec_recon_agent.audit.store import AuditStore
    from sec_recon_agent.config import settings

    audit_path = tmp_path / "audit.db"
    monkeypatch.setattr(settings, "audit_db_path", audit_path)
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    stream_module._reset_audit_store()

    class _BrokenAgent:
        @asynccontextmanager
        async def iter(self, query: str) -> Any:
            raise RuntimeError("boom")
            yield  # pragma: no cover

    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _BrokenAgent(),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        for _ in response.iter_text():
            pass

    store = AuditStore(audit_path)
    try:
        assert store.count() == 1
        ev = store.tail(1)[0]
        assert ev.outcome == "error"
        assert ev.error_class == "RuntimeError"
    finally:
        store.close()
        stream_module._reset_audit_store()


def test_meta_open_when_no_api_keys_configured() -> None:
    client = TestClient(app)
    resp = client.get("/v1/meta")
    assert resp.status_code == 200


def test_meta_requires_api_key_when_configured(monkeypatch: MonkeyPatch) -> None:
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("super-secret-123")])
    client = TestClient(app)

    # No header -> 401
    resp = client.get("/v1/meta")
    assert resp.status_code == 401
    assert "missing or invalid" in resp.json()["detail"]

    # Wrong key -> 401
    resp = client.get("/v1/meta", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401

    # Right key via Bearer -> 200
    resp = client.get(
        "/v1/meta",
        headers={"Authorization": "Bearer super-secret-123"},
    )
    assert resp.status_code == 200

    # Right key via X-API-Key -> 200
    resp = client.get("/v1/meta", headers={"X-API-Key": "super-secret-123"})
    assert resp.status_code == 200


def test_triage_requires_api_key_when_configured(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("good-key")])
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    client = TestClient(app)

    # No header -> 401 from the dependency, no agent invocation happens
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 401

    # Good key -> 200 SSE stream
    with client.stream(
        "POST",
        "/v1/triage",
        json={"query": "test"},
        headers={"Authorization": "Bearer good-key"},
    ) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())
        assert "event: final" in body


def test_health_remains_open_even_with_api_keys_configured(
    monkeypatch: MonkeyPatch,
) -> None:
    """/v1/health is a liveness probe — must stay open for container
    orchestrators (Docker, Kubernetes) regardless of auth posture."""
    from pydantic import SecretStr

    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "api_keys", [SecretStr("good-key")])
    client = TestClient(app)

    resp = client.get("/v1/health")
    assert resp.status_code == 200


def test_triage_rate_limit_returns_429_when_exceeded(
    monkeypatch: MonkeyPatch,
    fake_agent_factory: Any,
) -> None:
    """With rate_limit_per_minute=2 the third request inside the window
    must come back as 429 with a generic detail (the configured limit
    must not be echoed)."""
    from sec_recon_agent.api.stream import limiter
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "rate_limit_per_minute", 2)
    monkeypatch.setattr(stream_module, "build_agent", fake_agent_factory)
    # slowapi caches the resolved limit per route; reset so the patched
    # value takes effect.
    limiter.reset()

    client = TestClient(app)
    # First two pass...
    for _ in range(2):
        with client.stream("POST", "/v1/triage", json={"query": "test"}) as r:
            assert r.status_code == 200
            for _ in r.iter_text():
                pass
    # ...third is throttled.
    resp = client.post("/v1/triage", json={"query": "test"})
    assert resp.status_code == 429
    body = resp.json()
    assert body == {"detail": "rate limit exceeded"}
    # The configured limit value must NOT appear in the response.
    assert "2" not in body["detail"]


def test_api_keys_parses_csv_from_env(monkeypatch: MonkeyPatch) -> None:
    """Settings field validator must split a comma-separated env value
    into a list of SecretStr — that is the carrier format users actually
    set in .env / docker-compose."""
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("API_KEYS", "key-one, key-two,key-three")
    fresh = Settings()
    assert [k.get_secret_value() for k in fresh.api_keys] == [
        "key-one",
        "key-two",
        "key-three",
    ]


def test_rate_limit_empty_env_string_disables_limiter(monkeypatch: MonkeyPatch) -> None:
    """docker-compose interpolates an unset host var to "" via
    ${RATE_LIMIT_PER_MINUTE:-}; that empty string must not crash Settings
    and must mean "limiter disabled" (None), matching the documented
    default."""
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "")
    fresh = Settings()
    assert fresh.rate_limit_per_minute is None


def test_rate_limit_numeric_env_string_parsed(monkeypatch: MonkeyPatch) -> None:
    from sec_recon_agent.config import Settings

    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "30")
    fresh = Settings()
    assert fresh.rate_limit_per_minute == 30


def test_triage_emits_error_event_when_agent_raises(monkeypatch: MonkeyPatch) -> None:
    class _BrokenAgent:
        @asynccontextmanager
        async def iter(self, query: str) -> Any:
            raise RuntimeError("agent boom with internal context: /var/lib/secret")
            yield  # pragma: no cover

    monkeypatch.setattr(
        stream_module,
        "build_agent",
        lambda model_override=None: _BrokenAgent(),
    )

    client = TestClient(app)
    with client.stream("POST", "/v1/triage", json={"query": "test"}) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert "event: error" in body
    # Exception class name is fine to echo
    assert "RuntimeError" in body
    # Original message must NOT leak (filesystem path, internal context)
    assert "agent boom" not in body
    assert "/var/lib/secret" not in body
    assert "Internal error" in body

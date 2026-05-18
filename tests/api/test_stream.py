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
        async def iter(self, query: str) -> Any:  # noqa: A003
            yield _FakeRun(self._output)

    def _factory() -> _FakeAgent:
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
    # Tool inventory: five tools, names match the MCP tool surface.
    names = {t["name"] for t in body["tools"]}
    assert names == {
        "cve_lookup",
        "cve_semantic_search",
        "exploit_check",
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
        line for line in body.splitlines()
        if line.startswith("data: ") and "Fake summary" in line
    )
    payload = json.loads(final_data_line[len("data: "):])
    assert payload["summary"] == fake_report.summary
    assert payload["severity"] == "high"


def test_triage_emits_error_event_when_agent_raises(monkeypatch: MonkeyPatch) -> None:
    class _BrokenAgent:
        @asynccontextmanager
        async def iter(self, query: str) -> Any:  # noqa: A003
            raise RuntimeError("agent boom with internal context: /var/lib/secret")
            yield  # pragma: no cover

    monkeypatch.setattr(stream_module, "build_agent", lambda: _BrokenAgent())

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

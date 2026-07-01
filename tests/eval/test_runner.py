"""Unit tests for the eval runner. Mocks the live API via respx."""

import json

import pytest
import respx
from httpx import Response

from sec_recon_agent.agent.schema import (
    Confidence,
    Severity,
    TriageReport,
)
from sec_recon_agent.eval.golden_set import GoldenCase
from sec_recon_agent.eval.runner import DEFAULT_API_URL, run_case


def _make_final_payload() -> str:
    """Build a final-event payload identical to the one /v1/triage emits."""
    report = TriageReport(
        summary="ok",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        recommended_action="patch",
    )
    return report.model_dump_json()


def _sse_frames(events: list[tuple[str, str]], separator: str = "\r\n") -> bytes:
    """Build an SSE byte stream with the given separator. sse-starlette
    uses CRLF in production; the parser must also tolerate LF-only."""
    out = []
    for ev_name, data in events:
        out.append(f"event: {ev_name}{separator}data: {data}{separator}{separator}")
    return "".join(out).encode()


@pytest.fixture
def case() -> GoldenCase:
    return GoldenCase(id="dummy", query="test", expected_severity=Severity.HIGH)


@respx.mock
def test_runner_parses_final_event_with_crlf(case: GoldenCase) -> None:
    payload = _make_final_payload()
    stream = _sse_frames(
        [("started", "{}"), ("node", '{"node":"x"}'), ("final", payload)],
        separator="\r\n",
    )
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.error is None, result.error
    assert result.report is not None
    assert result.report.severity == Severity.CRITICAL


@respx.mock
def test_runner_parses_final_event_with_lf_only(case: GoldenCase) -> None:
    payload = _make_final_payload()
    stream = _sse_frames(
        [("final", payload)],
        separator="\n",
    )
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.error is None
    assert result.report is not None


@respx.mock
def test_runner_surfaces_agent_error_event(case: GoldenCase) -> None:
    stream = _sse_frames(
        [("error", json.dumps({"type": "Boom", "message": "internal"}))],
        separator="\r\n",
    )
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.report is None
    assert result.error is not None
    assert "Boom" in result.error


@respx.mock
def test_runner_handles_missing_final_event(case: GoldenCase) -> None:
    stream = _sse_frames([("started", "{}"), ("node", '{"node":"x"}')])
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.report is None
    assert "no final event" in (result.error or "")


@respx.mock
def test_runner_handles_http_500(case: GoldenCase) -> None:
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(return_value=Response(500))

    result = run_case(case)

    assert result.report is None
    assert "HTTP 500" in (result.error or "")


@respx.mock
def test_runner_captures_usage_event(case: GoldenCase) -> None:
    payload = _make_final_payload()
    usage = json.dumps({"input_tokens": 1200, "output_tokens": 340, "requests": 3})
    stream = _sse_frames(
        [("final", payload), ("usage", usage)],
        separator="\r\n",
    )
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.report is not None
    assert result.input_tokens == 1200
    assert result.output_tokens == 340
    assert result.requests == 3


@respx.mock
def test_runner_tokens_none_when_no_usage_event(case: GoldenCase) -> None:
    stream = _sse_frames([("final", _make_final_payload())], separator="\n")
    respx.post(DEFAULT_API_URL + "/v1/triage").mock(
        return_value=Response(200, content=stream, headers={"content-type": "text/event-stream"}),
    )

    result = run_case(case)

    assert result.report is not None
    assert result.input_tokens is None
    assert result.output_tokens is None

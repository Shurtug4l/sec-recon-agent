"""Tests for the message-history -> ToolInvocation extraction."""

from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

from sec_recon_agent.agent.trajectory import extract_tool_invocations


def _call(tool: str, call_id: str, args: object) -> ModelResponse:
    return ModelResponse(parts=[ToolCallPart(tool_name=tool, args=args, tool_call_id=call_id)])


def _return(tool: str, call_id: str, content: object) -> ModelRequest:
    return ModelRequest(
        parts=[ToolReturnPart(tool_name=tool, content=content, tool_call_id=call_id)],
    )


def test_pairs_call_and_return_on_tool_call_id() -> None:
    messages = [
        _call("kev_check", "c1", {"cve_id": "CVE-2021-44228"}),
        _return("kev_check", "c1", {"in_catalog": True}),
    ]
    invocations = extract_tool_invocations(messages)
    assert len(invocations) == 1
    inv = invocations[0]
    assert inv.tool_name == "kev_check"
    assert inv.args == {"cve_id": "CVE-2021-44228"}
    assert inv.content == {"in_catalog": True}
    assert inv.outcome == "success"


def test_json_string_args_normalize_to_dict() -> None:
    messages = [
        _call("epss_score", "c1", '{"cve_id": "CVE-2014-0160"}'),
        _return("epss_score", "c1", {"probability": 0.9}),
    ]
    invocations = extract_tool_invocations(messages)
    assert invocations[0].args == {"cve_id": "CVE-2014-0160"}


def test_malformed_args_still_yield_a_dict() -> None:
    """pydantic-ai wraps unparseable args rather than raising; either way the
    extraction must always hand the verifier a dict and never fail."""
    messages = [
        _call("epss_score", "c1", "{not json"),
        _return("epss_score", "c1", {"probability": 0.9}),
    ]
    invocations = extract_tool_invocations(messages)
    assert isinstance(invocations[0].args, dict)
    assert invocations[0].outcome == "success"


def test_unpaired_call_is_no_return() -> None:
    invocations = extract_tool_invocations([_call("cve_lookup", "c1", {})])
    assert invocations[0].outcome == "no_return"
    assert invocations[0].content is None


def test_retry_prompt_marks_call_failed() -> None:
    messages = [
        _call("cve_lookup", "c1", {"cve_id": "CVE-2024-3094"}),
        ModelRequest(
            parts=[RetryPromptPart(content="validation failed", tool_call_id="c1")],
        ),
    ]
    invocations = extract_tool_invocations(messages)
    assert invocations[0].outcome == "failed"
    assert invocations[0].content is None


def test_plain_string_content_passes_through() -> None:
    messages = [
        _call("cve_lookup", "c1", {}),
        _return("cve_lookup", "c1", "no data available"),
    ]
    assert extract_tool_invocations(messages)[0].content == "no data available"


def test_non_tool_parts_and_alien_messages_are_skipped() -> None:
    messages: list[object] = [
        ModelRequest(parts=[UserPromptPart(content="triage CVE-2021-44228")]),
        ModelResponse(parts=[TextPart(content="thinking...")]),
        object(),  # no .parts at all
        _call("kev_check", "c1", {}),
        _return("kev_check", "c1", {"in_catalog": False}),
    ]
    invocations = extract_tool_invocations(messages)
    assert [inv.tool_name for inv in invocations] == ["kev_check"]


def test_empty_history_yields_no_invocations() -> None:
    assert extract_tool_invocations([]) == []


def test_preserves_call_order() -> None:
    messages = [
        _call("cve_lookup", "c1", {}),
        _call("kev_check", "c2", {}),
        _return("kev_check", "c2", {"in_catalog": True}),
        _return("cve_lookup", "c1", {"cvss_v3_score": 9.8}),
    ]
    assert [inv.tool_name for inv in extract_tool_invocations(messages)] == [
        "cve_lookup",
        "kev_check",
    ]

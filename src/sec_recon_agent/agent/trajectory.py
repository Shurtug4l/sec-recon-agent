"""Extract typed tool invocations from a pydantic-ai message history.

This is the only surface coupled to pydantic-ai's message classes: it turns
whatever `run.result.all_messages()` returns into plain `ToolInvocation`
records that the grounding verifier (and, later, a record-replay harness)
can consume without importing pydantic-ai.

Pairing model: tool CALLS appear as ToolCallPart inside ModelResponse.parts;
tool RETURNS come back as ToolReturnPart inside ModelRequest.parts, matched
on `tool_call_id`. A call whose arguments failed output validation gets a
RetryPromptPart instead of a return; a call with neither is left dangling
(e.g. the run errored mid-round). Both are kept, marked by `outcome`, so the
verifier can tell "tool answered" from "tool never answered".
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart

ToolOutcome = Literal["success", "failed", "denied", "no_return"]


@dataclass(frozen=True)
class ToolInvocation:
    """One tool call and (when present) its return, decoupled from pydantic-ai.

    `content` is the raw ToolReturnPart.content: for this project's MCP tools
    that is normally an already-parsed dict/list (the MCP layer parses JSON
    text), but it can be a plain string or None when the call never returned.
    """

    tool_name: str
    tool_call_id: str
    args: dict[str, Any]
    content: object | None
    outcome: ToolOutcome


def extract_tool_invocations(messages: Sequence[object]) -> list[ToolInvocation]:
    """Walk a message history and pair tool calls with their returns.

    Defensive by design: unknown message or part kinds are skipped (fakes,
    future pydantic-ai parts), malformed args degrade to {}, and the result
    is deterministic in call order.
    """
    calls: dict[str, tuple[str, dict[str, Any]]] = {}
    returns: dict[str, tuple[object | None, ToolOutcome]] = {}

    for message in messages:
        parts = getattr(message, "parts", None)
        if not isinstance(parts, Sequence):
            continue
        for part in parts:
            if isinstance(part, ToolCallPart):
                try:
                    args = part.args_as_dict()
                except Exception:
                    args = {}
                calls[part.tool_call_id] = (part.tool_name, dict(args))
            elif isinstance(part, ToolReturnPart):
                outcome: ToolOutcome = (
                    part.outcome if part.outcome in ("success", "failed", "denied") else "failed"
                )
                returns[part.tool_call_id] = (part.content, outcome)
            elif isinstance(part, RetryPromptPart):
                tool_call_id = getattr(part, "tool_call_id", None)
                if isinstance(tool_call_id, str) and tool_call_id not in returns:
                    returns[tool_call_id] = (None, "failed")

    invocations: list[ToolInvocation] = []
    for tool_call_id, (tool_name, args) in calls.items():
        content, outcome = returns.get(tool_call_id, (None, "no_return"))
        invocations.append(
            ToolInvocation(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                args=args,
                content=content,
                outcome=outcome,
            ),
        )
    return invocations

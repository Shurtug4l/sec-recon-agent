"""Trajectory cassettes for the record-replay gate.

A cassette freezes one real golden-set run: the full pydantic-ai message
history (serialized with `ModelMessagesTypeAdapter`, the framework's own
persistence contract), the raw LLM TriageReport (ssvc/grounding left null,
per the leave-null contract), and the deterministic outcomes computed at
record time. Replay (tests/replay/) re-runs the CURRENT deterministic
pipeline (trajectory extraction, grounding, SSVC, golden scorer) over the
frozen behavior and asserts it reproduces the recorded outcomes, at zero
LLM cost and immune to live-feed drift.

The staleness hash pins the LLM-visible behavior surface: the system
prompt, every MCP tool schema (name, description, input schema), and the
TriageReport JSON schema (the model sees it as the output tool). Any edit
to that surface invalidates the recorded trajectories by construction, so
the replay gate hard-fails until cassettes are re-recorded against the new
surface (`make record-cassettes`). This operationalizes the
behavior-bearing-text rule in CONTRIBUTING.md.
"""

import asyncio
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sec_recon_agent.agent.schema import TriageReport

CASSETTE_SCHEMA_VERSION = 1

# Repo-relative by convention; the replay tests and the scorecard resolve
# their own absolute paths. Committed to git: cassettes ARE the gate's
# fixtures, CI replays them on every PR.
DEFAULT_CASSETTES_DIR = Path("tests/cassettes")


class RecordedOutcomes(BaseModel):
    """Deterministic-layer outputs computed at record time.

    `ssvc` and `grounding` are full model dumps (mode="json") of the
    assessments, compared bit-exact at replay: the functions are pure, so
    any divergence is a real behavior change in the deterministic code and
    must be either fixed or consciously re-recorded.
    """

    ssvc: dict[str, Any]
    grounding: dict[str, Any]
    golden_passed: bool


class Cassette(BaseModel):
    """One frozen golden-set run."""

    schema_version: int = CASSETTE_SCHEMA_VERSION
    case_id: str
    model: str
    recorded_at: str = Field(description="ISO 8601 UTC timestamp of the recording.")
    staleness_hash: str = Field(min_length=64, max_length=64)
    elapsed_seconds: float
    usage: dict[str, int | None] = Field(
        default_factory=dict,
        description="input_tokens / output_tokens / requests, when available.",
    )
    messages: list[Any] = Field(
        description="Full message history via ModelMessagesTypeAdapter (mode='json').",
    )
    report: dict[str, Any] = Field(
        description="Raw LLM TriageReport dump; ssvc and grounding are null.",
    )
    outcomes: RecordedOutcomes


def normalize_description(text: str | None) -> str:
    """Canonicalize a docstring-derived tool description for hashing.

    CPython 3.13 dedents docstrings at compile time, so the same source
    yields `__doc__` with per-line leading whitespace on 3.12 and without
    it on 3.13+. FastMCP forwards `__doc__` as the tool description, so an
    unnormalized hash diverges across the CI interpreter matrix while the
    semantic surface is identical. `inspect.cleandoc` is idempotent and
    maps both forms to the same text (which is also what a 3.13+ runtime
    actually serves to the model).
    """
    return inspect.cleandoc(text) if text else ""


def llm_surface() -> dict[str, Any]:
    """The complete LLM-visible behavior surface, as a canonicalizable dict.

    Tool schemas come from the FastMCP instance introspected in-process
    (same source the MCP transport serves to pydantic-ai), so no live
    server is needed. Imported lazily: eval consumers that never hash
    (e.g. the scorer) should not pull the MCP server module.
    """
    from sec_recon_agent.mcp_server.server import _register_tools, mcp

    _register_tools()
    tools = asyncio.run(mcp.list_tools())
    from sec_recon_agent.agent.prompts import SYSTEM_PROMPT

    return {
        "system_prompt": SYSTEM_PROMPT,
        "tools": sorted(
            (
                {
                    "name": tool.name,
                    "description": normalize_description(tool.description),
                    "input_schema": tool.inputSchema,
                }
                for tool in tools
            ),
            key=lambda t: str(t["name"]),
        ),
        "output_schema": TriageReport.model_json_schema(),
    }


def staleness_hash(surface: dict[str, Any] | None = None) -> str:
    """SHA-256 over the canonical JSON form of the LLM-visible surface.

    Reproducible within this repo (recorded on a dev machine, recomputed in
    CI): key-sorted compact JSON is enough; no cross-language verifier
    consumes this hash, unlike the audit chain.
    """
    canonical = json.dumps(
        surface if surface is not None else llm_surface(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cassette_path(directory: Path, case_id: str) -> Path:
    return directory / f"{case_id}.json"


def save_cassette(cassette: Cassette, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = cassette_path(directory, cassette.case_id)
    path.write_text(cassette.model_dump_json(indent=1) + "\n", encoding="utf-8")
    return path


def load_cassette(path: Path) -> Cassette:
    return Cassette.model_validate_json(path.read_text(encoding="utf-8"))


def load_all_cassettes(directory: Path) -> list[Cassette]:
    return [load_cassette(path) for path in sorted(directory.glob("*.json"))]

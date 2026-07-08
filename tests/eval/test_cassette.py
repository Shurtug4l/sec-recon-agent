"""Unit tests for the cassette model and the staleness hash."""

import copy
from pathlib import Path

from sec_recon_agent.eval.cassette import (
    CASSETTE_SCHEMA_VERSION,
    Cassette,
    RecordedOutcomes,
    llm_surface,
    load_all_cassettes,
    load_cassette,
    save_cassette,
    staleness_hash,
)


def _synthetic_cassette(case_id: str = "synthetic-case") -> Cassette:
    return Cassette(
        case_id=case_id,
        model="claude-sonnet-4-6",
        recorded_at="2026-07-08T00:00:00+00:00",
        staleness_hash="a" * 64,
        elapsed_seconds=1.5,
        usage={"input_tokens": 100, "output_tokens": 50, "requests": 3},
        messages=[{"kind": "request", "parts": []}],
        report={"severity": "high"},
        outcomes=RecordedOutcomes(
            ssvc={"decision": "act", "rule": "kev"},
            grounding={"status": "grounded", "claims_checked": 2},
            golden_passed=True,
        ),
    )


def test_surface_and_hash_are_deterministic() -> None:
    surface = llm_surface()
    assert staleness_hash(surface) == staleness_hash(llm_surface())
    assert staleness_hash(surface) == staleness_hash(surface)


def test_surface_carries_the_full_llm_visible_set() -> None:
    surface = llm_surface()
    names = [t["name"] for t in surface["tools"]]
    assert len(names) == len(set(names))
    assert "cve_lookup" in names
    assert names == sorted(names), "tool order must be canonical, not registration order"
    assert surface["system_prompt"]
    assert surface["output_schema"]["title"] == "TriageReport"


def test_hash_is_sensitive_to_every_surface_component() -> None:
    surface = llm_surface()
    baseline = staleness_hash(surface)

    prompt_edit = copy.deepcopy(surface)
    prompt_edit["system_prompt"] += " "
    tool_edit = copy.deepcopy(surface)
    tool_edit["tools"][0]["description"] += "!"
    schema_edit = copy.deepcopy(surface)
    schema_edit["output_schema"]["title"] = "Other"

    hashes = {baseline, *(staleness_hash(s) for s in (prompt_edit, tool_edit, schema_edit))}
    assert len(hashes) == 4


def test_cassette_round_trip(tmp_path: Path) -> None:
    original = _synthetic_cassette()
    path = save_cassette(original, tmp_path)
    assert path.name == "synthetic-case.json"
    assert load_cassette(path) == original
    assert original.schema_version == CASSETTE_SCHEMA_VERSION


def test_load_all_cassettes_sorted(tmp_path: Path) -> None:
    save_cassette(_synthetic_cassette("zeta"), tmp_path)
    save_cassette(_synthetic_cassette("alpha"), tmp_path)
    loaded = load_all_cassettes(tmp_path)
    assert [c.case_id for c in loaded] == ["alpha", "zeta"]

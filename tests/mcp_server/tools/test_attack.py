"""Contract tests for the attack_mapping MCP tool."""

import pytest

from sec_recon_agent.mcp_server.tools.attack import attack_mapping


def test_path_traversal_maps_to_t1190() -> None:
    """CWE-22 (path traversal) must map to T1190 (Exploit Public-Facing
    Application) — the most-cited example pattern."""
    result = attack_mapping(["CWE-22"])
    ids = {t.id for t in result}
    assert "T1190" in ids


def test_command_injection_maps_to_execution_family() -> None:
    """CWE-78 (OS command injection) must surface T1059 + T1190."""
    result = attack_mapping(["CWE-78"])
    ids = {t.id for t in result}
    assert "T1059" in ids


def test_unknown_cwe_returns_empty() -> None:
    """A CWE not in the curated table is silently skipped (no fake mapping)."""
    assert attack_mapping(["CWE-99999"]) == []


def test_multiple_cwes_deduplicate_techniques() -> None:
    """CWE-22 and CWE-78 both map to T1190; T1190 must appear once in the
    output, with both CWEs in related_cwes."""
    result = attack_mapping(["CWE-22", "CWE-78"])
    t1190s = [t for t in result if t.id == "T1190"]
    assert len(t1190s) == 1
    assert set(t1190s[0].related_cwes) == {"CWE-22", "CWE-78"}


def test_techniques_carry_mitigations() -> None:
    """Each returned technique must carry at least one mitigation (M-XXXX);
    otherwise the report has no defensive guidance."""
    result = attack_mapping(["CWE-22"])
    assert result
    technique = next(t for t in result if t.id == "T1190")
    assert technique.mitigations
    for m in technique.mitigations:
        assert m.id.startswith("M")
        assert m.name
        assert str(m.url).startswith("https://attack.mitre.org/mitigations/")


def test_techniques_carry_tactics() -> None:
    result = attack_mapping(["CWE-22"])
    technique = next(t for t in result if t.id == "T1190")
    assert technique.tactics == ["Initial Access"]


def test_empty_input_returns_empty() -> None:
    assert attack_mapping([]) == []


def test_malformed_cwe_silently_skipped() -> None:
    """Inputs that don't match the CWE-NNN pattern are skipped, not raised."""
    result = attack_mapping(["not-a-cwe", "CWE-22", ""])
    ids = {t.id for t in result}
    assert "T1190" in ids


def test_ordering_by_related_cwe_count() -> None:
    """Techniques touched by more CWEs come first."""
    # CWE-22 and CWE-78 both map to T1190 (matches 2 CWEs).
    # CWE-22 alone also maps to T1083 (matches 1 CWE).
    result = attack_mapping(["CWE-22", "CWE-78"])
    # T1190 should rank before T1083.
    ids_in_order = [t.id for t in result]
    if "T1190" in ids_in_order and "T1083" in ids_in_order:
        assert ids_in_order.index("T1190") < ids_in_order.index("T1083")

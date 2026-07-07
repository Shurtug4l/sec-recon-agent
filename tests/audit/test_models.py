"""Tests for the audit hash-chain primitives (pure logic, no I/O)."""

from sec_recon_agent.audit.models import (
    GENESIS_HASH,
    TriageEvent,
    compute_event_hash,
    seal_event,
    sha256_hex,
    summarize_for_audit,
    utcnow_iso,
    verify_link,
)


def _make_event(prev_hash: str = GENESIS_HASH) -> TriageEvent:
    return TriageEvent(
        event_id="abcd1234",
        ts=utcnow_iso(),
        query_sha256=sha256_hex("hello"),
        query_length=5,
        report_sha256=sha256_hex("{}"),
        severity="high",
        confidence="high",
        cves_count=1,
        attack_techniques_count=0,
        kev_hits=0,
        ransomware_hits=0,
        high_epss_hits=0,
        model="anthropic:claude-haiku-4-5",
        duration_ms=1000,
        outcome="success",
        prev_event_hash=prev_hash,
    )


def test_seal_event_populates_hash_deterministically() -> None:
    e = _make_event()
    sealed = seal_event(e)
    assert sealed.this_event_hash == compute_event_hash(e)
    # Sealing twice yields the same hash.
    assert seal_event(e).this_event_hash == sealed.this_event_hash


def test_hash_changes_when_any_field_changes() -> None:
    a = seal_event(_make_event())
    b = seal_event(_make_event().model_copy(update={"duration_ms": 1001}))
    assert a.this_event_hash != b.this_event_hash


def test_verify_link_accepts_genesis() -> None:
    a = seal_event(_make_event())
    ok, reason = verify_link(None, a)
    assert ok, reason


def test_verify_link_rejects_bad_prev_hash() -> None:
    a = seal_event(_make_event())
    b = seal_event(_make_event(prev_hash="f" * 64))
    ok, reason = verify_link(a, b)
    assert ok is False
    assert reason is not None
    assert "prev_event_hash mismatch" in reason


def test_verify_link_rejects_tampered_event() -> None:
    a = seal_event(_make_event())
    # Build a valid chained event, then mutate a non-hash field after sealing.
    b_raw = _make_event(prev_hash=a.this_event_hash)
    b = seal_event(b_raw)
    # Tamper: change a field, do NOT recompute the hash.
    tampered = b.model_copy(update={"cves_count": 99})
    ok, reason = verify_link(a, tampered)
    assert ok is False
    assert reason is not None
    assert "this_event_hash mismatch" in reason


def test_summarize_handles_missing_fields() -> None:
    out = summarize_for_audit({})
    assert out["cves_count"] == 0
    assert out["kev_hits"] == 0
    assert out["severity"] is None


def test_summarize_counts_kev_and_ransomware() -> None:
    report = {
        "severity": "critical",
        "confidence": "high",
        "cves": [
            {"in_kev_catalog": True, "known_ransomware_use": True, "epss_probability": 0.9},
            {"in_kev_catalog": True, "known_ransomware_use": False, "epss_probability": 0.1},
            {"in_kev_catalog": False, "known_ransomware_use": None, "epss_probability": None},
        ],
        "attack_techniques": [{"id": "T1001"}, {"id": "T1002"}],
    }
    out = summarize_for_audit(report)
    assert out["cves_count"] == 3
    assert out["attack_techniques_count"] == 2
    assert out["kev_hits"] == 2
    assert out["ransomware_hits"] == 1
    assert out["high_epss_hits"] == 1
    assert out["severity"] == "critical"


def test_default_schema_version_is_3() -> None:
    assert _make_event().schema_version == 3


def test_summarize_extracts_ssvc_decision() -> None:
    report = {"ssvc": {"decision": "Act", "rule": "kev-active-exploitation"}}
    assert summarize_for_audit(report)["ssvc_decision"] == "Act"


def test_summarize_ssvc_decision_absent_is_none() -> None:
    assert summarize_for_audit({})["ssvc_decision"] is None
    # Malformed ssvc block must not raise.
    assert summarize_for_audit({"ssvc": "not-a-dict"})["ssvc_decision"] is None


def test_v2_event_hash_covers_ssvc_decision() -> None:
    base = _make_event()  # schema_version=2, ssvc_decision=None
    with_ssvc = base.model_copy(update={"ssvc_decision": "Act"})
    assert compute_event_hash(base) != compute_event_hash(with_ssvc)


def test_v1_event_hash_ignores_ssvc_decision() -> None:
    """Backward-compat: a schema_version=1 row is hashed without the v2
    ssvc_decision field, so an old chain stays valid after the code learns the
    new field."""
    v1 = _make_event().model_copy(update={"schema_version": 1})
    v1_with_ssvc = v1.model_copy(update={"ssvc_decision": "Act"})
    assert compute_event_hash(v1) == compute_event_hash(v1_with_ssvc)


def test_summarize_extracts_grounding_status() -> None:
    report = {"grounding": {"status": "suspect", "unbacked": 2}}
    assert summarize_for_audit(report)["grounding_status"] == "suspect"


def test_summarize_grounding_status_absent_or_malformed_is_none() -> None:
    assert summarize_for_audit({})["grounding_status"] is None
    assert summarize_for_audit({"grounding": "not-a-dict"})["grounding_status"] is None
    assert summarize_for_audit({"grounding": {"status": 42}})["grounding_status"] is None


def test_v3_event_hash_covers_grounding_status() -> None:
    base = _make_event()  # schema_version=3, grounding_status=None
    with_grounding = base.model_copy(update={"grounding_status": "grounded"})
    assert compute_event_hash(base) != compute_event_hash(with_grounding)


def test_v2_event_hash_ignores_grounding_status() -> None:
    """Backward-compat: a schema_version=2 row is hashed without the v3
    grounding_status field, so a chain written before this release stays
    valid after the code learns the new field."""
    v2 = _make_event().model_copy(update={"schema_version": 2})
    v2_with_grounding = v2.model_copy(update={"grounding_status": "grounded"})
    assert compute_event_hash(v2) == compute_event_hash(v2_with_grounding)
    # And a v2 row still covers ITS OWN newest field.
    v2_with_ssvc = v2.model_copy(update={"ssvc_decision": "Act"})
    assert compute_event_hash(v2) != compute_event_hash(v2_with_ssvc)

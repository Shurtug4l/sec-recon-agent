"""Contract tests for GET /v1/audit.

The endpoint is the HTTP face of the tamper-evident audit trail: it returns the
most recent rows (digest-only) plus a live hash-chain verification. These tests
pin the load-bearing guarantees: it is off when logging is off, it never leaks
the opt-in plaintext, and it reports a broken chain as data rather than a 500.
"""

from pathlib import Path

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from sec_recon_agent.api import stream as stream_module
from sec_recon_agent.api.stream import app
from sec_recon_agent.audit.models import (
    GENESIS_HASH,
    TriageEvent,
    sha256_hex,
    utcnow_iso,
)
from sec_recon_agent.config import settings


def _event(
    event_id: str, *, query_plain: str | None = None, summary: str | None = None
) -> TriageEvent:
    return TriageEvent(
        event_id=event_id,
        ts=utcnow_iso(),
        query_sha256=sha256_hex(event_id),
        query_length=len(event_id),
        query_plain=query_plain,
        report_sha256=sha256_hex("{}"),
        severity="high",
        confidence="high",
        cves_count=1,
        ssvc_decision="Act",
        grounding_status="grounded",
        kev_hits=1,
        report_summary_plain=summary,
        model="anthropic:claude-haiku-4-5",
        duration_ms=1234,
        outcome="success",
        prev_event_hash=GENESIS_HASH,  # store overwrites under its lock
    )


@pytest.fixture
def enabled_audit(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    # The api conftest disables audit by default; re-enable on a tmp db.
    monkeypatch.setattr(settings, "audit_log_enabled", True)
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "audit.db")
    stream_module._reset_audit_store()


def test_audit_disabled_returns_empty_but_ok() -> None:
    # conftest leaves audit_log_enabled False.
    client = TestClient(app)
    body = client.get("/v1/audit").json()
    assert body["enabled"] is False
    assert body["count"] == 0
    assert body["events"] == []
    assert body["verification"]["ok"] is True


def test_audit_returns_rows_and_verifies(enabled_audit: None) -> None:
    store = stream_module._get_audit_store()
    store.append(_event("evt-0001"))
    store.append(_event("evt-0002"))

    body = TestClient(app).get("/v1/audit").json()
    assert body["enabled"] is True
    assert body["count"] == 2
    assert body["verification"] == {"ok": True, "verified_count": 2, "broken_event_id": None}
    # tail is most-recent-first.
    assert [e["event_id"] for e in body["events"]] == ["evt-0002", "evt-0001"]
    newest, oldest = body["events"]
    assert newest["ssvc_decision"] == "Act"
    assert newest["grounding_status"] == "grounded"
    assert len(newest["this_event_hash"]) == 64
    # Chain integrity is visible in the projection: the oldest row links to
    # genesis, and the newest row's prev is the oldest row's this-hash.
    assert oldest["prev_event_hash"] == GENESIS_HASH
    assert newest["prev_event_hash"] == oldest["this_event_hash"]


def test_audit_never_leaks_plaintext_even_when_retained(enabled_audit: None) -> None:
    secret_q = "SECRET-QUERY-CANARY-9f3a"
    secret_s = "SECRET-SUMMARY-CANARY-1b7c"
    store = stream_module._get_audit_store()
    store.append(_event("evt-0001", query_plain=secret_q, summary=secret_s))

    response = TestClient(app).get("/v1/audit")
    raw = response.text
    assert secret_q not in raw
    assert secret_s not in raw
    row = response.json()["events"][0]
    assert "query_plain" not in row
    assert "report_summary_plain" not in row
    # The digest is still present so uniqueness/length questions stay answerable.
    assert row["query_sha256"] == sha256_hex("evt-0001")


def test_audit_reports_tamper_as_data_not_500(
    enabled_audit: None, monkeypatch: MonkeyPatch
) -> None:
    from sec_recon_agent.audit.store import TamperDetectedError

    store = stream_module._get_audit_store()
    store.append(_event("evt-0001"))

    def _raise() -> int:
        raise TamperDetectedError(row_id=1, event_id="evt-0001", reason="hash mismatch")

    monkeypatch.setattr(store, "verify", _raise)
    body = TestClient(app).get("/v1/audit").json()
    assert body["verification"]["ok"] is False
    assert body["verification"]["broken_event_id"] == "evt-0001"
    # Rows still return so the operator can see what is there.
    assert body["count"] == 1


def test_audit_limit_is_capped(enabled_audit: None) -> None:
    body = TestClient(app).get("/v1/audit?limit=99999").json()
    # No rows, but the request must not error on an over-large limit.
    assert body["enabled"] is True
    assert body["events"] == []

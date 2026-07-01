"""Tests for the SQLite AuditStore including tamper detection."""

import sqlite3
from pathlib import Path

import pytest

from sec_recon_agent.audit.models import (
    GENESIS_HASH,
    TriageEvent,
    sha256_hex,
    utcnow_iso,
)
from sec_recon_agent.audit.store import (
    AuditStore,
    TamperDetectedError,
)


def _event(event_id: str = "abcd1234") -> TriageEvent:
    return TriageEvent(
        event_id=event_id,
        ts=utcnow_iso(),
        query_sha256=sha256_hex(event_id),
        query_length=len(event_id),
        report_sha256=sha256_hex("{}"),
        severity="high",
        confidence="high",
        cves_count=1,
        attack_techniques_count=0,
        kev_hits=0,
        ransomware_hits=0,
        high_epss_hits=0,
        model="anthropic:claude-haiku-4-5",
        duration_ms=1234,
        outcome="success",
        prev_event_hash=GENESIS_HASH,  # store overwrites under lock
    )


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    s = AuditStore(tmp_path / "audit.db")
    yield s
    s.close()


def test_first_event_chains_off_genesis(store: AuditStore) -> None:
    sealed = store.append(_event("ev-0001"))
    assert sealed.prev_event_hash == GENESIS_HASH
    assert sealed.this_event_hash != ""
    assert store.count() == 1


def test_subsequent_events_chain_off_predecessor(store: AuditStore) -> None:
    a = store.append(_event("ev-0001"))
    b = store.append(_event("ev-0002"))
    assert b.prev_event_hash == a.this_event_hash
    assert b.this_event_hash != a.this_event_hash


def test_verify_passes_on_clean_chain(store: AuditStore) -> None:
    for i in range(5):
        store.append(_event(f"ev-{i:04d}"))
    verified = store.verify()
    assert verified == 5


def test_verify_detects_field_tamper(store: AuditStore, tmp_path: Path) -> None:
    """Mutate a row directly through SQLite at the bytes layer.

    The append-only triggers reject UPDATE/DELETE inside SQL, so we
    have to drop them first to simulate an attacker that has database
    access. The hash chain catches it anyway.
    """
    store.append(_event("ev-0001"))
    store.append(_event("ev-0002"))
    store.append(_event("ev-0003"))

    # Bypass the triggers and mutate row 2.
    raw_db = sqlite3.connect(tmp_path / "audit.db")
    raw_db.executescript(
        "DROP TRIGGER IF EXISTS triage_events_no_update; "
        "DROP TRIGGER IF EXISTS triage_events_no_delete;",
    )
    raw_db.execute(
        "UPDATE triage_events SET cves_count = 999 WHERE event_id = ?",
        ("ev-0002",),
    )
    raw_db.commit()
    raw_db.close()

    with pytest.raises(TamperDetectedError) as exc_info:
        store.verify()
    err = exc_info.value
    assert err.event_id == "ev-0002"
    assert "this_event_hash mismatch" in err.reason


def test_verify_detects_inserted_row_with_wrong_prev_hash(
    store: AuditStore,
    tmp_path: Path,
) -> None:
    """Insert a forged row that does not chain off the live head."""
    store.append(_event("ev-0001"))
    store.append(_event("ev-0002"))

    # Forge a row whose prev_event_hash points nowhere.
    forged = _event("ev-FORGED").model_copy(
        update={
            "prev_event_hash": "f" * 64,
            "this_event_hash": "0" * 64,  # also bogus
        },
    )
    raw_db = sqlite3.connect(tmp_path / "audit.db")
    raw_db.execute(
        """
        INSERT INTO triage_events (
            event_id, ts, query_sha256, query_length, query_plain,
            report_sha256, severity, confidence,
            cves_count, attack_techniques_count,
            kev_hits, ransomware_hits, high_epss_hits,
            report_summary_plain, model, duration_ms, outcome,
            error_class, prev_event_hash, this_event_hash, schema_version
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            forged.event_id,
            forged.ts,
            forged.query_sha256,
            forged.query_length,
            forged.query_plain,
            forged.report_sha256,
            forged.severity,
            forged.confidence,
            forged.cves_count,
            forged.attack_techniques_count,
            forged.kev_hits,
            forged.ransomware_hits,
            forged.high_epss_hits,
            forged.report_summary_plain,
            forged.model,
            forged.duration_ms,
            forged.outcome,
            forged.error_class,
            forged.prev_event_hash,
            forged.this_event_hash,
            forged.schema_version,
        ),
    )
    raw_db.commit()
    raw_db.close()

    with pytest.raises(TamperDetectedError) as exc_info:
        store.verify()
    assert exc_info.value.event_id == "ev-FORGED"


_PRE_V2_SCHEMA = """
CREATE TABLE triage_events (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    query_sha256 TEXT NOT NULL,
    query_length INTEGER NOT NULL,
    query_plain TEXT,
    report_sha256 TEXT NOT NULL,
    severity TEXT,
    confidence TEXT,
    cves_count INTEGER NOT NULL DEFAULT 0,
    attack_techniques_count INTEGER NOT NULL DEFAULT 0,
    kev_hits INTEGER NOT NULL DEFAULT 0,
    ransomware_hits INTEGER NOT NULL DEFAULT 0,
    high_epss_hits INTEGER NOT NULL DEFAULT 0,
    report_summary_plain TEXT,
    model TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    error_class TEXT,
    prev_event_hash TEXT NOT NULL,
    this_event_hash TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1
);
"""


def test_additive_migration_adds_ssvc_column_to_pre_v2_db(tmp_path: Path) -> None:
    """A database created before the ssvc_decision column must gain it on open,
    so appends keep working after an in-place upgrade of an existing deployment."""
    db_path = tmp_path / "audit.db"
    raw = sqlite3.connect(db_path)
    raw.executescript(_PRE_V2_SCHEMA)
    raw.commit()
    raw.close()

    cols_before = _columns(db_path)
    assert "ssvc_decision" not in cols_before

    store = AuditStore(db_path)
    try:
        # Opening + appending must not raise "no such column: ssvc_decision".
        store.append(_event("ev-migrated").model_copy(update={"ssvc_decision": "Act"}))
        assert store.count() == 1
        assert store.verify() == 1
        assert store.tail(1)[0].ssvc_decision == "Act"
    finally:
        store.close()

    assert "ssvc_decision" in _columns(db_path)


def _columns(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {row[1] for row in conn.execute("PRAGMA table_info(triage_events)")}
    finally:
        conn.close()


def test_triggers_block_in_sql_update(store: AuditStore, tmp_path: Path) -> None:
    """The append-only triggers refuse UPDATE through the normal SQL path."""
    store.append(_event("ev-0001"))
    raw_db = sqlite3.connect(tmp_path / "audit.db")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw_db.execute(
            "UPDATE triage_events SET cves_count = 999 WHERE event_id = ?",
            ("ev-0001",),
        )
    raw_db.close()


def test_tail_returns_recent_first(store: AuditStore) -> None:
    for i in range(5):
        store.append(_event(f"ev-{i:04d}"))
    rows = store.tail(limit=3)
    assert len(rows) == 3
    # tail() returns reverse chronological (rowid DESC).
    assert rows[0].event_id == "ev-0004"
    assert rows[2].event_id == "ev-0002"

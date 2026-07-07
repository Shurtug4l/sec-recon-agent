"""SQLite-backed append-only audit store.

Threading model: a single SQLite connection per process, guarded by a
`threading.Lock`. SQLite is configured with WAL journal so concurrent
readers (the verify CLI) do not block the writer (the API).

The store enforces append-only at the application layer: there is no
`update` or `delete` method. SQLite triggers reject DML on the table
beyond INSERT, so even direct file manipulation by another process
that goes through the SQL parser fails (a sufficiently determined
attacker can edit the file at the bytes layer — the hash chain is the
real tamper-evidence; the SQL trigger is a guardrail against
accidental tampering by a future commit).
"""

import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import structlog

from sec_recon_agent.audit.models import (
    GENESIS_HASH,
    TriageEvent,
    seal_event,
    verify_link,
)

log = structlog.get_logger()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_events (
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
    ssvc_decision TEXT,
    grounding_status TEXT,
    report_summary_plain TEXT,
    model TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    error_class TEXT,
    prev_event_hash TEXT NOT NULL,
    this_event_hash TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ts ON triage_events(ts);
"""

# Additive migrations applied after the base schema, for databases created by
# an earlier version. Each entry is (column_name, DDL). `CREATE TABLE IF NOT
# EXISTS` never alters an existing table, so a pre-v2 db lacks these columns;
# ADD COLUMN backfills them as NULL. Old rows keep verifying because
# `_canonical_payload` is version-aware (it excludes v2 fields when hashing a
# v1 row).
_ADDITIVE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("ssvc_decision", "ALTER TABLE triage_events ADD COLUMN ssvc_decision TEXT"),
    ("grounding_status", "ALTER TABLE triage_events ADD COLUMN grounding_status TEXT"),
)

# Trigger that rejects any UPDATE / DELETE on the audit table. Belt and
# braces — the API never issues those, and a future contributor poking
# around is expected to hit this fence before they realize the hash chain
# would have caught them anyway.
_APPEND_ONLY_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS triage_events_no_update
BEFORE UPDATE ON triage_events
BEGIN
    SELECT RAISE(FAIL, 'triage_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS triage_events_no_delete
BEFORE DELETE ON triage_events
BEGIN
    SELECT RAISE(FAIL, 'triage_events is append-only');
END;
"""


class AuditStoreError(Exception):
    """Raised on a store-level failure that the caller should surface."""


class TamperDetectedError(AuditStoreError):
    """Raised by `verify()` when the chain is broken.

    `row_id` is the first event where the chain breaks. `reason` is a
    short human explanation.
    """

    def __init__(self, row_id: int, event_id: str, reason: str) -> None:
        super().__init__(f"tamper at row {row_id} (event_id={event_id}): {reason}")
        self.row_id = row_id
        self.event_id = event_id
        self.reason = reason


class AuditStore:
    """SQLite-backed append-only audit store with hash-chain integrity."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # --- lifecycle --------------------------------------------------------

    def _ensure_open(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; we BEGIN explicitly
        )
        conn.row_factory = sqlite3.Row
        # WAL keeps readers off the writer's lock.
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.executescript(_SCHEMA)
        self._apply_additive_migrations(conn)
        conn.executescript(_APPEND_ONLY_TRIGGERS)
        self._conn = conn
        return conn

    @staticmethod
    def _apply_additive_migrations(conn: sqlite3.Connection) -> None:
        """Add columns introduced after a db was first created. Idempotent."""
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(triage_events)")}
        for column, ddl in _ADDITIVE_COLUMNS:
            if column not in existing:
                conn.execute(ddl)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # --- write ------------------------------------------------------------

    def append(self, event_without_hash: TriageEvent) -> TriageEvent:
        """Seal the event with the live chain head, persist it, return the sealed copy.

        Caller passes an event whose `prev_event_hash` is a placeholder
        (typically GENESIS_HASH); we overwrite it with the live head under
        the lock and then seal.
        """
        with self._lock:
            conn = self._ensure_open()
            head_hash = self._head_hash_unsynchronized(conn)
            ready = event_without_hash.model_copy(
                update={"prev_event_hash": head_hash},
            )
            sealed = seal_event(ready)
            conn.execute(
                """
                INSERT INTO triage_events (
                    event_id, ts, query_sha256, query_length, query_plain,
                    report_sha256, severity, confidence,
                    cves_count, attack_techniques_count,
                    kev_hits, ransomware_hits, high_epss_hits, ssvc_decision,
                    grounding_status,
                    report_summary_plain, model, duration_ms, outcome,
                    error_class, prev_event_hash, this_event_hash,
                    schema_version
                ) VALUES (
                    :event_id, :ts, :query_sha256, :query_length, :query_plain,
                    :report_sha256, :severity, :confidence,
                    :cves_count, :attack_techniques_count,
                    :kev_hits, :ransomware_hits, :high_epss_hits, :ssvc_decision,
                    :grounding_status,
                    :report_summary_plain, :model, :duration_ms, :outcome,
                    :error_class, :prev_event_hash, :this_event_hash,
                    :schema_version
                )
                """,
                sealed.model_dump(),
            )
            return sealed

    def _head_hash_unsynchronized(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT this_event_hash FROM triage_events ORDER BY rowid DESC LIMIT 1",
        ).fetchone()
        if row is None:
            return GENESIS_HASH
        return str(row["this_event_hash"])

    # --- read -------------------------------------------------------------

    def count(self) -> int:
        with self._lock:
            conn = self._ensure_open()
            row = conn.execute("SELECT COUNT(*) AS n FROM triage_events").fetchone()
            return int(row["n"])

    def tail(self, limit: int = 20) -> list[TriageEvent]:
        with self._lock:
            conn = self._ensure_open()
            rows = conn.execute(
                "SELECT * FROM triage_events ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_event(r) for r in rows]

    def _iter_rows(self) -> Iterator[sqlite3.Row]:
        conn = self._ensure_open()
        cur = conn.execute("SELECT * FROM triage_events ORDER BY rowid ASC")
        try:
            yield from cur
        finally:
            cur.close()

    def verify(self) -> int:
        """Walk every row in order, recomputing the hash chain.

        Returns the number of rows verified. Raises TamperDetectedError on
        the first broken link.
        """
        with self._lock:
            self._ensure_open()
            prev_event: TriageEvent | None = None
            verified = 0
            for row in self._iter_rows():
                event = _row_to_event(row)
                ok, reason = verify_link(prev_event, event)
                if not ok:
                    raise TamperDetectedError(
                        row_id=int(row["rowid"]),
                        event_id=str(row["event_id"]),
                        reason=reason or "unknown",
                    )
                verified += 1
                prev_event = event
            return verified


def _row_to_event(row: sqlite3.Row) -> TriageEvent:
    """sqlite3.Row -> TriageEvent. Pydantic enforces field validation."""
    payload: dict[str, Any] = dict(row)
    payload.pop("rowid", None)
    return TriageEvent.model_validate(payload)

"""Shared fixtures for tests/api/.

Audit logging is enabled by default at the application layer. In tests
that exercise the FastAPI surface we want it off by default to avoid
side effects on the real `./data/audit.db`; individual tests that want
to assert audit behavior opt in by re-enabling the flag and pointing
`audit_db_path` at tmp_path.
"""

from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=True)
def _isolate_audit_log(monkeypatch: MonkeyPatch, tmp_path: Path) -> Any:
    from sec_recon_agent.api import stream as stream_module
    from sec_recon_agent.config import settings

    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "audit.db")
    monkeypatch.setattr(settings, "audit_log_enabled", False)
    stream_module._reset_audit_store()
    yield
    stream_module._reset_audit_store()

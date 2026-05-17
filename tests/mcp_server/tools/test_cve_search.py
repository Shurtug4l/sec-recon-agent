"""Tests for cve_semantic_search and the seed pipeline.

A session-scoped fixture pre-warms ChromaDB's default ONNX embedder so
respx-mocked tests don't need network. First session run downloads
~15MB of ONNX model; subsequent runs use the local cache.
"""

from pathlib import Path
from typing import Any

import pytest
import respx
from _pytest.monkeypatch import MonkeyPatch
from httpx import Response

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.nvd_client import NVD_BASE_URL
from sec_recon_agent.mcp_server.tools import cve_search
from sec_recon_agent.mcp_server.tools.cve_search import (
    _seed_index_async,
    cve_semantic_search,
)


@pytest.fixture(scope="session", autouse=True)
def warm_up_default_embedder() -> None:
    """Pre-cache the ONNX MiniLM model once per pytest session, outside respx scope."""
    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

    embedder = DefaultEmbeddingFunction()
    _ = embedder(["warmup"])


@pytest.fixture(autouse=True)
def isolated_chroma(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings, "chroma_persist_dir", tmp_path / "chroma")
    cve_search._reset_collection_cache()


def _make_vuln(cve_id: str, description: str, score: float = 9.5) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": score,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            },
            "published": "2026-03-01",
        }
    }


@pytest.mark.slow
@respx.mock
async def test_seed_then_search_returns_relevant_cve() -> None:
    critical_payload = {
        "totalResults": 3,
        "vulnerabilities": [
            _make_vuln(
                "CVE-2026-1001",
                "Apache HTTP Server path traversal vulnerability allowing remote code execution",
            ),
            _make_vuln(
                "CVE-2026-1002",
                "SQL injection in PostgreSQL administration tools",
            ),
            _make_vuln(
                "CVE-2026-1003",
                "Buffer overflow in OpenSSH server pre-authentication",
            ),
        ],
    }
    high_payload = {"totalResults": 0, "vulnerabilities": []}

    respx.get(url__startswith=NVD_BASE_URL).mock(
        side_effect=[
            Response(200, json=critical_payload),
            Response(200, json=high_payload),
        ],
    )

    indexed = await _seed_index_async(lookback_days=30)
    assert indexed == 3

    results = await cve_semantic_search("Apache web server path traversal")
    assert results
    assert results[0].cve_id == "CVE-2026-1001"
    assert 0.0 <= results[0].similarity <= 1.0


async def test_empty_query_returns_empty_list() -> None:
    assert await cve_semantic_search("") == []
    assert await cve_semantic_search("   ") == []


@pytest.mark.slow
@respx.mock
async def test_top_k_is_capped() -> None:
    payload = {
        "totalResults": 1,
        "vulnerabilities": [
            _make_vuln("CVE-2026-2001", "Test vulnerability description"),
        ],
    }
    empty = {"totalResults": 0, "vulnerabilities": []}
    respx.get(url__startswith=NVD_BASE_URL).mock(
        side_effect=[Response(200, json=payload), Response(200, json=empty)],
    )

    await _seed_index_async(lookback_days=30)
    results = await cve_semantic_search("test", top_k=1000)
    assert len(results) <= 25

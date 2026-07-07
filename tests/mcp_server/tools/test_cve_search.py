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


@pytest.mark.slow
@respx.mock
async def test_bm25_arm_rescues_identifier_only_query() -> None:
    """A query that is a bare product identifier must surface the right CVE
    through the lexical arm even when the prose around it gives the dense
    embedding little to work with."""
    payload = {
        "totalResults": 2,
        "vulnerabilities": [
            _make_vuln(
                "CVE-2026-3001",
                "Deserialization flaw in libfoozle 3.2.1 daemon allows crafted "
                "payloads to run code",
            ),
            _make_vuln(
                "CVE-2026-3002",
                "Improper certificate validation in barzap client permits "
                "man-in-the-middle interception",
            ),
        ],
    }
    empty = {"totalResults": 0, "vulnerabilities": []}
    respx.get(url__startswith=NVD_BASE_URL).mock(
        side_effect=[Response(200, json=payload), Response(200, json=empty)],
    )

    await _seed_index_async(lookback_days=30)
    results = await cve_semantic_search("libfoozle 3.2.1")
    assert results
    assert results[0].cve_id == "CVE-2026-3001"
    assert all(0.0 <= r.similarity <= 1.0 for r in results)


# ----------------------------------------------------------------------------
# Hybrid plumbing, fast (mocked collection + embedder, no ONNX, no chroma).
# ----------------------------------------------------------------------------


def _fake_hybrid_setup(
    monkeypatch: MonkeyPatch,
    dense_ids: list[str],
    corpus: dict[str, str],
    embeddings: dict[str, list[float]],
    query_vector: list[float],
) -> Any:
    """Wire module-level fakes: dense ranking, corpus for BM25, stored embeddings."""
    from unittest.mock import MagicMock

    fake_collection = MagicMock()
    fake_collection.query.return_value = {
        "ids": [dense_ids],
        "documents": [[corpus[i] for i in dense_ids]],
        "distances": [[0.1 * (rank + 1) for rank in range(len(dense_ids))]],
    }

    def _fake_get(**kwargs: Any) -> dict[str, Any]:
        ids = kwargs.get("ids")
        if ids is None:  # BM25 build path
            return {"ids": list(corpus.keys()), "documents": list(corpus.values())}
        return {
            "ids": ids,
            "documents": [corpus[i] for i in ids],
            "embeddings": [embeddings[i] for i in ids],
        }

    fake_collection.get.side_effect = _fake_get
    monkeypatch.setattr(cve_search, "_collection", fake_collection)
    monkeypatch.setattr(cve_search, "_embedding_fn", lambda texts: [query_vector])
    return fake_collection


async def test_hybrid_bm25_only_candidate_carries_true_cosine(
    monkeypatch: MonkeyPatch,
) -> None:
    """A document surfaced only by BM25 must enter the fused results with its
    real cosine similarity against the stored embedding, not a placeholder."""
    corpus = {
        "CVE-2026-4001": "generic memory corruption in a network service",
        "CVE-2026-4002": "flaw in libfoozle daemon",
    }
    # Query vector aligned with CVE-LEX's stored embedding at ~cos 0.6.
    embeddings = {"CVE-2026-4001": [1.0, 0.0], "CVE-2026-4002": [0.6, 0.8]}
    _fake_hybrid_setup(
        monkeypatch,
        dense_ids=["CVE-2026-4001"],
        corpus=corpus,
        embeddings=embeddings,
        query_vector=[1.0, 0.0],
    )
    monkeypatch.setattr(settings, "retrieval_hybrid_enabled", True)

    results = await cve_search.cve_semantic_search("libfoozle daemon", top_k=5)

    by_id = {r.cve_id: r for r in results}
    assert "CVE-2026-4002" in by_id, "BM25-only candidate missing from fused results"
    assert by_id["CVE-2026-4002"].similarity == pytest.approx(0.6)
    # The dense hit keeps its HNSW-derived similarity (1 - 0.1 distance).
    assert by_id["CVE-2026-4001"].similarity == pytest.approx(0.9)
    # Summaries stay fenced like any untrusted feed text.
    assert "libfoozle" in by_id["CVE-2026-4002"].summary


async def test_hybrid_disabled_uses_dense_path_only(monkeypatch: MonkeyPatch) -> None:
    """RETRIEVAL_HYBRID_ENABLED=false must restore the pre-hybrid call shape:
    one text query at top_k depth, no BM25 build."""
    from unittest.mock import MagicMock

    fake_collection = MagicMock()
    fake_collection.query.return_value = {
        "ids": [["CVE-2026-4003"]],
        "documents": [["some description"]],
        "distances": [[0.2]],
    }
    monkeypatch.setattr(cve_search, "_collection", fake_collection)
    monkeypatch.setattr(cve_search, "_bm25", None)
    monkeypatch.setattr(settings, "retrieval_hybrid_enabled", False)

    results = await cve_search.cve_semantic_search("anything", top_k=3)

    assert [r.cve_id for r in results] == ["CVE-2026-4003"]
    assert results[0].similarity == pytest.approx(0.8)
    fake_collection.query.assert_called_once_with(query_texts=["anything"], n_results=3)
    fake_collection.get.assert_not_called()
    assert cve_search._bm25 is None


async def test_hybrid_empty_corpus_returns_empty(monkeypatch: MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    fake_collection = MagicMock()
    fake_collection.get.return_value = {"ids": [], "documents": []}
    monkeypatch.setattr(cve_search, "_collection", fake_collection)
    monkeypatch.setattr(cve_search, "_embedding_fn", lambda texts: [[0.0]])
    monkeypatch.setattr(settings, "retrieval_hybrid_enabled", True)

    assert await cve_search.cve_semantic_search("anything") == []
    fake_collection.query.assert_not_called()

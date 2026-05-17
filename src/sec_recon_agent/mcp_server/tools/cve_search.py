"""Semantic search over recent high-severity CVEs.

Two surfaces:
- `seed_index()`: one-shot script (`uv run sec-recon-seed`) that pulls recent
  CRITICAL+HIGH CVEs from NVD and indexes their descriptions in ChromaDB.
- `cve_semantic_search(query, top_k)`: MCP tool that returns the closest
  matches as a list of CVECandidate.

Embedding: ChromaDB's DefaultEmbeddingFunction (ONNX MiniLM-L6, 384-d).
Self-contained, no torch / transformers dependency, ~10x faster cold start.
Distance: cosine (HNSW), exposed as similarity = 1 - distance, clamped to [0, 1].
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.models import CVECandidate
from sec_recon_agent.mcp_server.nvd_client import HTTP_TIMEOUT_SECONDS, nvd_get
from sec_recon_agent.mcp_server.server import mcp

log = structlog.get_logger()

COLLECTION_NAME = "cve_descriptions"
NVD_LOOKBACK_DAYS = 90
NVD_PAGE_SIZE = 2000
UPSERT_BATCH = 500
MAX_TOP_K = 25

_collection: Any = None


def _get_collection() -> Any:
    global _collection
    if _collection is not None:
        return _collection

    import chromadb
    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

    settings.chroma_persist_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(settings.chroma_persist_dir))
    _collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=DefaultEmbeddingFunction(),
        metadata={"hnsw:space": "cosine"},
    )
    return _collection


def _reset_collection_cache() -> None:
    """Reset the module-level collection cache. Intended for tests only."""
    global _collection
    _collection = None


def _vuln_to_record(vuln: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
    cve = vuln.get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str):
        return None

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = str(desc.get("value", ""))
            break
    if not description:
        return None

    metadata: dict[str, Any] = {"published": str(cve.get("published", ""))}
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if score is not None:
                metadata["cvss_v3_score"] = float(score)
            if severity is not None:
                metadata["severity"] = str(severity)
            break

    return cve_id, description, metadata


async def _fetch_severity_window(
    client: httpx.AsyncClient,
    severity: str,
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    collected: list[dict[str, Any]] = []
    index = 0
    while True:
        payload = await nvd_get(
            client,
            params={
                "cvssV3Severity": severity,
                "lastModStartDate": start.strftime(fmt),
                "lastModEndDate": end.strftime(fmt),
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": index,
            },
        )
        batch = payload.get("vulnerabilities") or []
        collected.extend(batch)
        total = int(payload.get("totalResults", 0))
        index += len(batch)
        log.info(
            "seed_fetch_progress",
            severity=severity,
            fetched=index,
            total=total,
        )
        if not batch or index >= total:
            break
    return collected


async def _seed_index_async(lookback_days: int = NVD_LOOKBACK_DAYS) -> int:
    collection = _get_collection()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    log.info("seed_starting", lookback_days=lookback_days)

    vulns: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        for severity in ("CRITICAL", "HIGH"):
            vulns.extend(await _fetch_severity_window(client, severity, start, end))

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen: set[str] = set()
    for vuln in vulns:
        record = _vuln_to_record(vuln)
        if record is None:
            continue
        cve_id, description, metadata = record
        if cve_id in seen:
            continue
        seen.add(cve_id)
        ids.append(cve_id)
        documents.append(description)
        metadatas.append(metadata)

    if not ids:
        log.warning("seed_no_records")
        return 0

    log.info("seed_upserting", count=len(ids))
    for i in range(0, len(ids), UPSERT_BATCH):
        collection.upsert(
            ids=ids[i : i + UPSERT_BATCH],
            documents=documents[i : i + UPSERT_BATCH],
            metadatas=metadatas[i : i + UPSERT_BATCH],
        )
    log.info("seed_done", indexed=len(ids))
    return len(ids)


def seed_index() -> None:
    """Entry point for `uv run sec-recon-seed`."""
    indexed = asyncio.run(_seed_index_async())
    log.info("seed_script_exit", indexed=indexed)


@mcp.tool()
async def cve_semantic_search(query: str, top_k: int = 5) -> list[CVECandidate]:
    """Find recent high-severity CVEs whose descriptions match the query semantically.

    Returns up to top_k CVECandidate results ranked by cosine similarity over
    sentence-transformer embeddings of the CVE description text.
    """
    if not query.strip():
        return []
    top_k = max(1, min(top_k, MAX_TOP_K))

    def _query_sync() -> dict[str, Any]:
        collection = _get_collection()
        return collection.query(query_texts=[query], n_results=top_k)

    result = await asyncio.to_thread(_query_sync)

    ids_batches = result.get("ids") or [[]]
    doc_batches = result.get("documents") or [[]]
    dist_batches = result.get("distances") or [[]]
    ids = ids_batches[0] if ids_batches else []
    docs = doc_batches[0] if doc_batches else []
    distances = dist_batches[0] if dist_batches else []

    candidates: list[CVECandidate] = []
    for cve_id, doc, dist in zip(ids, docs, distances, strict=False):
        similarity = max(0.0, min(1.0, 1.0 - float(dist)))
        candidates.append(
            CVECandidate(
                cve_id=str(cve_id),
                summary=(str(doc)[:500]) if doc else "",
                similarity=similarity,
            ),
        )
    log.info("cve_semantic_search_done", query_len=len(query), hits=len(candidates))
    return candidates

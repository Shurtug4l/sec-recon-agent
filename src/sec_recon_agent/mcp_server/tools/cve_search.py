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
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.models import CVECandidate
from sec_recon_agent.mcp_server.nvd_client import HTTP_TIMEOUT_SECONDS, nvd_get
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.mcp_server.server import mcp
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

COLLECTION_NAME = "cve_descriptions"
# 30-day default: yields ~5-8k recent high-severity CVEs which is enough
# for a meaningful semantic-search corpus without saturating the NVD
# public rate budget (~3-4 pages per severity = 6-8 requests total).
# Larger windows are fine with NVD_API_KEY set (50 req/30s vs 5 req/30s).
NVD_LOOKBACK_DAYS = 30
NVD_PAGE_SIZE = 2000
NVD_MAX_PAGES_PER_SEVERITY = 25
UPSERT_BATCH = 500
MAX_TOP_K = 25
MAX_QUERY_CHARS = 2000  # MiniLM-L6 truncates at ~512 tokens; cap early to bound embedding latency

_collection: Any = None
_collection_lock = threading.Lock()


def _get_collection() -> Any:
    # Double-checked locking. The fast path skips the lock once the collection
    # is built. Without the lock, two concurrent first-callers can both open
    # a PersistentClient on the same SQLite path, which corrupts the index
    # or fails with a lock error from chroma.
    global _collection
    if _collection is not None:
        return _collection

    with _collection_lock:
        if _collection is not None:
            return _collection

        import chromadb
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        settings.chroma_persist_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(settings.chroma_persist_dir))
        # ChromaDB's stubs declare a tighter EmbeddingFunction generic than
        # DefaultEmbeddingFunction satisfies; the implementations are
        # equivalent at runtime.
        _collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=DefaultEmbeddingFunction(),  # type: ignore[arg-type]
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
    # Hard page cap so a malformed totalResults from NVD cannot push us into
    # an effectively unbounded fetch loop that exhausts the rate budget.
    for _ in range(NVD_MAX_PAGES_PER_SEVERITY):
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
    else:
        log.warning("seed_page_cap_reached", severity=severity, cap=NVD_MAX_PAGES_PER_SEVERITY)
    return collected


async def _seed_index_async(lookback_days: int = NVD_LOOKBACK_DAYS) -> int:
    collection = _get_collection()

    end = datetime.now(UTC)
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
    embeddings of the CVE description text.
    """
    with _tracer.start_as_current_span("tool.cve_semantic_search") as span:
        # query.length is a useful operational signal; query text itself
        # is NOT recorded (it may contain user PII or instruction-like
        # content from a hostile prompt).
        span.set_attribute("tool.name", "cve_semantic_search")
        span.set_attribute("query.length", len(query))
        span.set_attribute("query.top_k", top_k)
        if not query.strip():
            span.set_attribute("tool.success", True)
            span.set_attribute("results.count", 0)
            return []
        # Cap defensively at the tool boundary: the FastAPI layer caps user
        # input at 4000 chars, but the agent can synthesize longer queries.
        query = query[:MAX_QUERY_CHARS]
        top_k = max(1, min(top_k, MAX_TOP_K))

        def _query_sync() -> dict[str, Any]:
            collection = _get_collection()
            result_dict: dict[str, Any] = collection.query(
                query_texts=[query],
                n_results=top_k,
            )
            return result_dict

        try:
            result = await asyncio.to_thread(_query_sync)
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        ids_batches = result.get("ids") or [[]]
        doc_batches = result.get("documents") or [[]]
        dist_batches = result.get("distances") or [[]]
        ids = ids_batches[0] if ids_batches else []
        docs = doc_batches[0] if doc_batches else []
        distances = dist_batches[0] if dist_batches else []

        candidates: list[CVECandidate] = []
        for cve_id, doc, dist in zip(ids, docs, distances, strict=False):
            similarity = max(0.0, min(1.0, 1.0 - float(dist)))
            raw_summary = str(doc)[:500] if doc else ""
            candidates.append(
                CVECandidate(
                    cve_id=str(cve_id),
                    summary=fence_untrusted(raw_summary) or "",
                    similarity=similarity,
                ),
            )
        span.set_attribute("tool.success", True)
        span.set_attribute("results.count", len(candidates))
        log.info("cve_semantic_search_done", query_len=len(query), hits=len(candidates))
        return candidates

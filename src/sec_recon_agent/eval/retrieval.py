"""Retrieval-quality evaluation for cve_semantic_search.

The semantic-search tool is the RAG component of the pipeline, and until now its
quality was unmeasured (stock MiniLM-L6 embeddings, no reranker, no hit-rate).
This module measures it directly with hit-rate@k and mean reciprocal rank.

Corpus-agnostic by design. The ChromaDB index holds whatever `sec-recon-seed`
last pulled (recent high-severity CVEs, a moving 30-day window by default), so a
fixed golden set of specific CVE IDs would mostly miss the corpus and measure
nothing. Instead this samples the live collection, turns a truncated prefix of
each CVE's own description into a query, and checks whether the retriever ranks
that CVE back. It answers "given a partial symptom description, does the tool
surface the right CVE?" -- the realistic RAG task -- without needing a
hand-labeled set tied to specific IDs.

Live-only: requires a seeded ChromaDB index, so it runs in-process against the
local collection rather than over HTTP. Excluded from CI (see pyproject omit);
the pure ranking math it depends on lives in eval/metrics.py and is unit-tested.
"""

import asyncio
from dataclasses import dataclass

from sec_recon_agent.eval.metrics import (
    hit_rate_at_k,
    mean_reciprocal_rank,
    percentile,
)

# A truncated prefix of the description is used as the query, so retrieval is
# non-trivial (identical text would rank 1 by construction). ~160 chars is
# roughly the first sentence or two of an NVD description.
DEFAULT_QUERY_CHARS = 160
DEFAULT_SAMPLE_SIZE = 100
DEFAULT_TOP_K = 10


@dataclass(frozen=True)
class RetrievalReport:
    """Aggregate retrieval quality over the sampled queries."""

    sampled: int
    top_k: int
    query_chars: int
    mrr: float | None
    hit_rate_at_1: float | None
    hit_rate_at_3: float | None
    hit_rate_at_5: float | None
    p95_similarity_top1: float | None


def _sample_corpus(sample_size: int) -> list[tuple[str, str]]:
    """Return up to `sample_size` (cve_id, description) pairs from the index."""
    from sec_recon_agent.mcp_server.tools.cve_search import _get_collection

    collection = _get_collection()
    got = collection.get(limit=sample_size, include=["documents"])
    ids = got.get("ids") or []
    docs = got.get("documents") or []
    return [
        (str(cve_id), str(doc))
        for cve_id, doc in zip(ids, docs, strict=False)
        if isinstance(doc, str) and doc.strip()
    ]


async def _rank_one(query: str, top_k: int) -> tuple[list[str], float | None]:
    """Run the tool for one query; return (ranked cve ids, top-1 similarity)."""
    from sec_recon_agent.mcp_server.tools.cve_search import cve_semantic_search

    candidates = await cve_semantic_search(query, top_k=top_k)
    ranked = [c.cve_id for c in candidates]
    top1_sim = candidates[0].similarity if candidates else None
    return ranked, top1_sim


async def _run_async(
    sample_size: int,
    top_k: int,
    query_chars: int,
) -> RetrievalReport:
    corpus = _sample_corpus(sample_size)
    results: list[tuple[list[str], list[str]]] = []
    top1_sims: list[float] = []
    for cve_id, description in corpus:
        query = description[:query_chars]
        ranked, top1 = await _rank_one(query, top_k)
        results.append((ranked, [cve_id]))
        if top1 is not None:
            top1_sims.append(top1)

    return RetrievalReport(
        sampled=len(results),
        top_k=top_k,
        query_chars=query_chars,
        mrr=mean_reciprocal_rank(results),
        hit_rate_at_1=hit_rate_at_k(results, 1),
        hit_rate_at_3=hit_rate_at_k(results, 3),
        hit_rate_at_5=hit_rate_at_k(results, 5),
        p95_similarity_top1=percentile(top1_sims, 95),
    )


def run_retrieval(
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    top_k: int = DEFAULT_TOP_K,
    query_chars: int = DEFAULT_QUERY_CHARS,
) -> RetrievalReport:
    """Evaluate cve_semantic_search against the local ChromaDB index.

    Requires a seeded index (`sec-recon-seed`). Returns aggregate hit-rate@k and
    MRR; an empty index yields a report with `sampled=0` and None metrics.
    """
    return asyncio.run(_run_async(sample_size, top_k, query_chars))

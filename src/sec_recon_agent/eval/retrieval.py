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

Two query modes:
- default: a ~160-char prefix of the description (first sentence or two).
  Self-retrieval on near-verbatim text; easy, and saturated near MRR 1.0.
- hard: a ~80-char keyword-style query distilled from the description
  (stopwords and CVE boilerplate dropped, first occurrence order kept). This
  approximates how an analyst actually queries -- short, identifier-heavy --
  and is where dense-vs-lexical retrieval differences become visible.

Live-only: requires a seeded ChromaDB index, so it runs in-process against the
local collection rather than over HTTP. Excluded from CI (see pyproject omit);
the pure ranking math it depends on lives in eval/metrics.py and is unit-tested;
the pure query derivation below is unit-tested in tests/eval/test_retrieval.py.
"""

import asyncio
import re
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
HARD_QUERY_CHARS = 80
DEFAULT_SAMPLE_SIZE = 100
DEFAULT_TOP_K = 10

# Generic English stopwords plus CVE-prose boilerplate. The boilerplate terms
# ("vulnerability", "attacker", "versions", ...) appear in nearly every NVD
# description, so they carry no discriminating signal; an analyst's query
# keeps the product / component / flaw-type tokens instead.
_STOPWORDS = frozenset(
    """
    a against also an and any are as at be been but by can could do does for
    from has have if in into is it its may might no not of on or other such
    than that the their then there these they this those through to use used
    using via was were when where which while who whose will with
    affected allow allows allowed attacker attackers before cause caused
    crafted due earlier exploit exploited exploitation issue issues lead leads
    possible potentially prior product products remote specially user users
    version versions vulnerability vulnerabilities
    """.split(),
)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")


def _keyword_query(description: str, char_budget: int) -> str:
    """Distill a description into a short keyword-style query.

    Lowercases, keeps identifier-like tokens whole (log4j, 2.14.1,
    cve-2021-44228), drops stopwords/boilerplate, dedups preserving first
    occurrence, and stops at `char_budget`. Falls back to the plain truncated
    prefix if nothing survives (a description made only of stopwords).
    """
    picked: list[str] = []
    seen: set[str] = set()
    for token in _TOKEN_RE.findall(description.lower()):
        if token in _STOPWORDS or token in seen:
            continue
        if picked and len(" ".join([*picked, token])) > char_budget:
            break
        picked.append(token)
        seen.add(token)
    if not picked:
        return description[:char_budget]
    return " ".join(picked)


@dataclass(frozen=True)
class RetrievalReport:
    """Aggregate retrieval quality over the sampled queries."""

    sampled: int
    top_k: int
    query_chars: int
    mode: str
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
    hard: bool,
) -> RetrievalReport:
    corpus = _sample_corpus(sample_size)
    results: list[tuple[list[str], list[str]]] = []
    top1_sims: list[float] = []
    for cve_id, description in corpus:
        query = _keyword_query(description, query_chars) if hard else description[:query_chars]
        ranked, top1 = await _rank_one(query, top_k)
        results.append((ranked, [cve_id]))
        if top1 is not None:
            top1_sims.append(top1)

    return RetrievalReport(
        sampled=len(results),
        top_k=top_k,
        query_chars=query_chars,
        mode="hard" if hard else "default",
        mrr=mean_reciprocal_rank(results),
        hit_rate_at_1=hit_rate_at_k(results, 1),
        hit_rate_at_3=hit_rate_at_k(results, 3),
        hit_rate_at_5=hit_rate_at_k(results, 5),
        p95_similarity_top1=percentile(top1_sims, 95),
    )


def run_retrieval(
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    top_k: int = DEFAULT_TOP_K,
    query_chars: int | None = None,
    hard: bool = False,
) -> RetrievalReport:
    """Evaluate cve_semantic_search against the local ChromaDB index.

    Requires a seeded index (`sec-recon-seed`). Returns aggregate hit-rate@k and
    MRR; an empty index yields a report with `sampled=0` and None metrics.
    `hard=True` switches to short keyword-style queries (see module docstring);
    `query_chars` defaults per mode (160 default, 80 hard) unless given.
    """
    if query_chars is None:
        query_chars = HARD_QUERY_CHARS if hard else DEFAULT_QUERY_CHARS
    return asyncio.run(_run_async(sample_size, top_k, query_chars, hard))

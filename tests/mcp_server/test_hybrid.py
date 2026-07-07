"""Unit + property tests for the pure hybrid-retrieval primitives.

BM25 and RRF are the ranking layer under cve_semantic_search; they are pure
and deterministic, so the contract is pinned here exhaustively with no
chroma, no network, no embedder.
"""

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sec_recon_agent.mcp_server.hybrid import (
    Bm25Index,
    cosine_similarity,
    rrf_fuse,
    tokenize,
)

CORPUS = {
    "CVE-A": "Apache Log4j2 JNDI remote code execution via crafted log messages",
    "CVE-B": "OpenSSL heartbeat buffer over-read leaks process memory Heartbleed",
    "CVE-C": "SQL injection in PostgreSQL administration tool allows data exfiltration",
    "CVE-D": "Apache HTTP Server path traversal enables remote file disclosure",
}


def _index() -> Bm25Index:
    return Bm25Index(list(CORPUS.keys()), list(CORPUS.values()))


# ----------------------------------------------------------------------------
# tokenize
# ----------------------------------------------------------------------------


def test_tokenize_keeps_identifiers_whole() -> None:
    assert tokenize("Log4j2 2.14.1 CVE-2021-44228") == ["log4j2", "2.14.1", "cve-2021-44228"]


def test_tokenize_lowercases_and_splits_punctuation() -> None:
    assert tokenize("OpenSSL, heartbeat!") == ["openssl", "heartbeat"]


def test_tokenize_empty() -> None:
    assert tokenize("") == []
    assert tokenize("!!! ???") == []


# ----------------------------------------------------------------------------
# Bm25Index
# ----------------------------------------------------------------------------


def test_bm25_rare_term_ranks_its_document_first() -> None:
    ranked = _index().search("heartbleed openssl", top_n=4)
    assert ranked[0] == "CVE-B"


def test_bm25_shared_term_scores_both_documents() -> None:
    ranked = _index().search("apache", top_n=4)
    assert set(ranked) == {"CVE-A", "CVE-D"}


def test_bm25_unknown_terms_return_empty() -> None:
    assert _index().search("zephyr quantum blockchain", top_n=4) == []


def test_bm25_empty_query_returns_empty() -> None:
    assert _index().search("", top_n=4) == []


def test_bm25_empty_corpus_returns_empty() -> None:
    assert Bm25Index([], []).search("apache", top_n=4) == []
    assert len(Bm25Index([], [])) == 0


def test_bm25_top_n_caps_results() -> None:
    assert len(_index().search("apache remote", top_n=1)) == 1


def test_bm25_deterministic() -> None:
    a = _index().search("apache remote code", top_n=4)
    b = _index().search("apache remote code", top_n=4)
    assert a == b


# ----------------------------------------------------------------------------
# rrf_fuse
# ----------------------------------------------------------------------------


def test_rrf_doc_in_both_rankings_beats_doc_in_one() -> None:
    # "x" is rank 2 in both lists; "a" and "b" are rank 1 in one list each.
    # 2/(k+2) > 1/(k+1) for k=60, so consensus wins over a single first place.
    fused = rrf_fuse([["a", "x"], ["b", "x"]])
    assert fused[0] == "x"


def test_rrf_hand_computed_scores() -> None:
    fused = rrf_fuse([["a", "b"], ["b", "a"]], k=60)
    # Both docs score 1/61 + 1/62; tie breaks on best rank (equal: 1), then id.
    assert fused == ["a", "b"]


def test_rrf_single_ranking_preserves_order() -> None:
    assert rrf_fuse([["a", "b", "c"]]) == ["a", "b", "c"]


def test_rrf_empty() -> None:
    assert rrf_fuse([]) == []
    assert rrf_fuse([[], []]) == []


def test_rrf_symmetric_in_ranking_order() -> None:
    dense = ["a", "b", "c"]
    lexical = ["c", "d"]
    assert rrf_fuse([dense, lexical]) == rrf_fuse([lexical, dense])


# ----------------------------------------------------------------------------
# cosine_similarity
# ----------------------------------------------------------------------------


def test_cosine_identical_vectors() -> None:
    assert cosine_similarity([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)


def test_cosine_orthogonal_vectors() -> None:
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == 0.0


def test_cosine_zero_norm_is_zero() -> None:
    assert cosine_similarity([0.0, 0.0], [1.0, 2.0]) == 0.0


# ----------------------------------------------------------------------------
# Properties
# ----------------------------------------------------------------------------

_doc_texts = st.lists(
    st.text(alphabet="abcdefghij0123456789 .", min_size=1, max_size=60),
    min_size=1,
    max_size=15,
)


@given(docs=_doc_texts, query=st.text(alphabet="abcdefghij0123456789 .", max_size=40))
@settings(max_examples=100)
def test_bm25_results_are_subset_of_corpus_and_unique(docs: list[str], query: str) -> None:
    ids = [f"D{i}" for i in range(len(docs))]
    ranked = Bm25Index(ids, docs).search(query, top_n=10)
    assert len(ranked) == len(set(ranked))
    assert set(ranked) <= set(ids)
    assert len(ranked) <= 10


@given(docs=_doc_texts, query=st.text(alphabet="abcdefghij0123456789 .", max_size=40))
@settings(max_examples=100)
def test_bm25_scores_only_documents_sharing_a_query_term(docs: list[str], query: str) -> None:
    ids = [f"D{i}" for i in range(len(docs))]
    index = Bm25Index(ids, docs)
    query_tokens = set(tokenize(query))
    for doc_id in index.search(query, top_n=len(docs)):
        doc_tokens = set(tokenize(docs[ids.index(doc_id)]))
        assert doc_tokens & query_tokens


_rankings = st.lists(
    st.lists(st.sampled_from([f"D{i}" for i in range(8)]), max_size=8, unique=True),
    max_size=4,
)


@given(rankings=_rankings)
@settings(max_examples=100)
def test_rrf_fused_set_is_union_of_inputs(rankings: list[list[str]]) -> None:
    fused = rrf_fuse(rankings)
    expected = set().union(*rankings) if rankings else set()
    assert set(fused) == expected
    assert len(fused) == len(set(fused))


@given(rankings=_rankings)
@settings(max_examples=100)
def test_rrf_is_permutation_invariant_across_rankings(rankings: list[list[str]]) -> None:
    assert rrf_fuse(rankings) == rrf_fuse(list(reversed(rankings)))


@given(
    a=st.lists(st.floats(-10, 10), min_size=2, max_size=8),
)
@settings(max_examples=100)
def test_cosine_bounded(a: list[float]) -> None:
    b = list(reversed(a))
    value = cosine_similarity(a, b)
    assert -1.0 - 1e-9 <= value <= 1.0 + 1e-9
    assert not math.isnan(value)

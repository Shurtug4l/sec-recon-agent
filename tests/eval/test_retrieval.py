"""Unit tests for the pure query-derivation logic in eval/retrieval.py.

The live retrieval loop needs a seeded ChromaDB index and is excluded from
CI (pyproject omit); the hard-mode keyword derivation is pure and tested here.
"""

from sec_recon_agent.eval.retrieval import (
    DEFAULT_QUERY_CHARS,
    HARD_QUERY_CHARS,
    _keyword_query,
)

LOG4SHELL = (
    "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
    "2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log "
    "messages, and parameters do not protect against attacker controlled "
    "LDAP and other JNDI related endpoints. An attacker who can control log "
    "messages or log message parameters can execute arbitrary code loaded "
    "from LDAP servers when message lookup substitution is enabled."
)


def test_keeps_identifier_tokens_whole() -> None:
    query = _keyword_query(LOG4SHELL, HARD_QUERY_CHARS)
    assert "log4j2" in query.split()
    assert "2.15.0" in query.split()


def test_drops_stopwords_and_boilerplate() -> None:
    query = _keyword_query(LOG4SHELL, 500)
    tokens = query.split()
    for noise in ("and", "the", "in", "an", "attacker", "against"):
        assert noise not in tokens


def test_respects_char_budget() -> None:
    query = _keyword_query(LOG4SHELL, HARD_QUERY_CHARS)
    assert 0 < len(query) <= HARD_QUERY_CHARS


def test_dedups_preserving_first_occurrence() -> None:
    query = _keyword_query("nginx nginx buffer overflow nginx buffer", 200)
    assert query == "nginx buffer overflow"


def test_lowercases() -> None:
    query = _keyword_query("OpenSSL Heartbleed TLS heartbeat", 200)
    assert query == "openssl heartbleed tls heartbeat"


def test_deterministic() -> None:
    assert _keyword_query(LOG4SHELL, HARD_QUERY_CHARS) == _keyword_query(
        LOG4SHELL,
        HARD_QUERY_CHARS,
    )


def test_all_stopword_description_falls_back_to_prefix() -> None:
    text = "the and of to a in is that it with"
    assert _keyword_query(text, HARD_QUERY_CHARS) == text[:HARD_QUERY_CHARS]


def test_empty_description_falls_back_to_empty() -> None:
    assert _keyword_query("", HARD_QUERY_CHARS) == ""


def test_single_oversized_token_is_kept() -> None:
    token = "a" * 120
    assert _keyword_query(token, HARD_QUERY_CHARS) == token


def test_defaults_are_sane() -> None:
    assert HARD_QUERY_CHARS < DEFAULT_QUERY_CHARS

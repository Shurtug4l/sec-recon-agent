"""Unit tests for the eval cost model (pure, no I/O)."""

import pytest

from sec_recon_agent.agent.triage import ALLOWED_MODELS, MODEL_ALIASES
from sec_recon_agent.eval.cost import (
    MODEL_PRICING,
    estimate_cost_usd,
    price_for,
)


def test_pricing_covers_every_allowlisted_model() -> None:
    """A model the backend will run must have a price, or cost silently drops
    to n/a for real runs. Pin the two sets together."""
    assert set(MODEL_PRICING) == set(ALLOWED_MODELS)


def test_aliases_resolve_to_priced_models() -> None:
    for alias in ("haiku", "sonnet", "opus"):
        assert price_for(alias) is not None
    # The CLI's alias targets must match the agent's alias targets.
    for alias, full in MODEL_ALIASES.items():
        assert price_for(alias) == price_for(full)


def test_estimate_cost_haiku() -> None:
    # 1M input @ $1 + 1M output @ $5 = $6.00 exactly.
    cost = estimate_cost_usd("claude-haiku-4-5-20251001", 1_000_000, 1_000_000)
    assert cost == pytest.approx(6.0)


def test_estimate_cost_resolves_alias_and_provider_prefix() -> None:
    a = estimate_cost_usd("haiku", 1_000_000, 0)
    b = estimate_cost_usd("anthropic:claude-haiku-4-5-20251001", 1_000_000, 0)
    assert a == pytest.approx(1.0)
    assert a == pytest.approx(b)


def test_estimate_cost_unknown_model_is_none() -> None:
    assert estimate_cost_usd("gpt-4-turbo", 1000, 1000) is None


def test_estimate_cost_missing_tokens_is_none() -> None:
    assert estimate_cost_usd("haiku", None, None) is None


def test_estimate_cost_treats_one_missing_token_count_as_zero() -> None:
    # Only output tokens known: input contributes 0, not None.
    cost = estimate_cost_usd("haiku", None, 1_000_000)
    assert cost == pytest.approx(5.0)

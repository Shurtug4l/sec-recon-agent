"""Per-model token pricing for the eval scorecard.

Cost is estimated locally from token counts (the API does not return a price),
so the scorecard can report $/triage without a billing call. Prices are USD per
million tokens, keyed by the exact model identifiers on the backend allowlist
(agent/triage.py::ALLOWED_MODELS) plus the short aliases the eval CLI accepts.

Source: Anthropic published API pricing per tier as of 2026-06-24
(Haiku 4.5 $1.00 / $5.00, Sonnet tier $3.00 / $15.00, Opus tier $5.00 / $25.00
per MTok input / output). Update the table and the stamped date if pricing
moves. Unknown models return None rather than a fabricated cost -- an honest
"n/a" beats a wrong number on a portfolio scorecard.
"""

from dataclasses import dataclass

PRICING_SOURCE_DATE = "2026-06-24"


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens, input and output."""

    input_usd_per_mtok: float
    output_usd_per_mtok: float


# Keyed by the full model identifiers the backend allows, so a cost lookup can
# not silently attribute a price to a model the deployment never runs.
MODEL_PRICING: dict[str, ModelPrice] = {
    "claude-haiku-4-5-20251001": ModelPrice(1.0, 5.0),
    "claude-sonnet-4-6": ModelPrice(3.0, 15.0),
    "claude-opus-4-7": ModelPrice(5.0, 25.0),
}

# Short aliases the eval CLI passes in place of the full identifier, mirroring
# agent/triage.py::MODEL_ALIASES so the two never drift silently.
_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-7",
    "default": "claude-haiku-4-5-20251001",
}


def _normalize_model(model: str) -> str:
    """Resolve aliases and strip a provider prefix (`anthropic:claude-...`)."""
    candidate = model.strip()
    if ":" in candidate:
        candidate = candidate.split(":", 1)[1]
    return _ALIASES.get(candidate, candidate)


def price_for(model: str) -> ModelPrice | None:
    """Look up the price for a model id / alias, or None if unpriced."""
    return MODEL_PRICING.get(_normalize_model(model))


def estimate_cost_usd(
    model: str,
    input_tokens: int | None,
    output_tokens: int | None,
) -> float | None:
    """Estimate USD cost for one triage from its token counts.

    Returns None when the model is unpriced or both token counts are missing,
    so the caller renders "n/a" rather than a misleading $0.00.
    """
    price = price_for(model)
    if price is None:
        return None
    if input_tokens is None and output_tokens is None:
        return None
    inp = input_tokens or 0
    out = output_tokens or 0
    return (inp / 1_000_000) * price.input_usd_per_mtok + (
        out / 1_000_000
    ) * price.output_usd_per_mtok

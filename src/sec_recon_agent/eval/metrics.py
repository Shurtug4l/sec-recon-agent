"""Pure metric primitives for the eval harness.

These are deliberately dependency-free and side-effect-free so they can be
unit-tested exhaustively without a live stack. The live runner and CLI feed
them observed values (latencies, token counts, retrieval rankings, confidence
vs correctness) and get back the scalars the scorecard reports.

Metric families:
- latency:      percentile (p50 / p95 / ...) over per-case wall-clock times
- retrieval:    hit-rate@k and mean reciprocal rank over cve_semantic_search
- calibration:  confidence -> nominal probability, and expected calibration
                error vs observed correctness
- conformance:  is a returned report structurally well-formed (not degenerate)
"""

import math
from collections.abc import Sequence

from sec_recon_agent.agent.schema import Confidence, TriageReport

# --- latency --------------------------------------------------------------


def percentile(values: Sequence[float], p: float) -> float | None:
    """Linear-interpolated percentile, matching numpy's default method.

    `p` is in [0, 100]. Returns None for an empty sequence so the caller can
    render "n/a" rather than crash on a run with zero successful cases.
    """
    if not values:
        return None
    if not 0.0 <= p <= 100.0:
        raise ValueError(f"percentile p must be in [0, 100], got {p}")
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    rank = (len(xs) - 1) * (p / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(xs[int(rank)])
    return float(xs[low] + (xs[high] - xs[low]) * (rank - low))


# --- retrieval ------------------------------------------------------------


def reciprocal_rank(ranked_ids: Sequence[str], relevant_ids: Sequence[str]) -> float:
    """1 / (rank of the first relevant id), or 0.0 if none appear.

    Rank is 1-indexed: a relevant id in first position scores 1.0.
    """
    relevant = set(relevant_ids)
    for index, candidate in enumerate(ranked_ids, start=1):
        if candidate in relevant:
            return 1.0 / index
    return 0.0


def mean_reciprocal_rank(
    results: Sequence[tuple[Sequence[str], Sequence[str]]],
) -> float | None:
    """MRR over (ranked_ids, relevant_ids) pairs. None for an empty set."""
    if not results:
        return None
    return sum(reciprocal_rank(ranked, relevant) for ranked, relevant in results) / len(results)


def hit_at_k(ranked_ids: Sequence[str], relevant_ids: Sequence[str], k: int) -> bool:
    """True iff any relevant id appears in the top-k of the ranking."""
    if k <= 0:
        return False
    relevant = set(relevant_ids)
    return any(candidate in relevant for candidate in ranked_ids[:k])


def hit_rate_at_k(
    results: Sequence[tuple[Sequence[str], Sequence[str]]],
    k: int,
) -> float | None:
    """Fraction of queries with at least one relevant id in the top-k."""
    if not results:
        return None
    return sum(1 for ranked, relevant in results if hit_at_k(ranked, relevant, k)) / len(results)


# --- calibration ----------------------------------------------------------

# Nominal probability the agent implies by each confidence level. The agent's
# `confidence` is a coarse 3-level enum, not a probability, so we map it to a
# representative probability to compute calibration error against observed
# correctness. Documented and stable so the scorecard is reproducible.
_CONFIDENCE_PROBABILITY: dict[Confidence, float] = {
    Confidence.HIGH: 0.9,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}


def confidence_to_probability(confidence: Confidence | str) -> float:
    """Map a Confidence level (or its string value) to a nominal probability."""
    level = Confidence(confidence) if isinstance(confidence, str) else confidence
    return _CONFIDENCE_PROBABILITY[level]


def expected_calibration_error(
    samples: Sequence[tuple[float, bool]],
    n_bins: int = 10,
) -> float | None:
    """Expected calibration error over (predicted_probability, correct) pairs.

    Bins predictions into `n_bins` equal-width buckets over [0, 1]; for each
    non-empty bucket accumulates |mean_confidence - accuracy| weighted by the
    bucket's share of samples. 0.0 is perfectly calibrated. Returns None for an
    empty sample set.

    With the 3-level confidence enum each nominal probability lands in its own
    bucket, so the default 10 bins is more than enough; the parameter is kept
    for reuse with finer-grained probabilities.
    """
    if not samples:
        return None
    if n_bins < 1:
        raise ValueError(f"n_bins must be >= 1, got {n_bins}")
    total = len(samples)
    ece = 0.0
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        # Last bucket is closed on the right so predicted_prob == 1.0 lands in it.
        if b == n_bins - 1:
            bucket = [(p, c) for p, c in samples if lo <= p <= hi]
        else:
            bucket = [(p, c) for p, c in samples if lo <= p < hi]
        if not bucket:
            continue
        mean_conf = sum(p for p, _ in bucket) / len(bucket)
        accuracy = sum(1 for _, c in bucket if c) / len(bucket)
        ece += (len(bucket) / total) * abs(mean_conf - accuracy)
    return ece


# --- conformance ----------------------------------------------------------


def is_conformant(report: TriageReport | None) -> bool:
    """True iff the report is structurally well-formed, not merely schema-valid.

    Schema validity is a precondition (a non-None report already parsed against
    TriageReport). Conformance additionally rejects degenerate output the schema
    permits: an empty summary or recommended_action, or a missing SSVC verdict
    (the server always stamps one, so its absence signals a broken pipeline).
    """
    if report is None:
        return False
    if not report.summary.strip():
        return False
    if not report.recommended_action.strip():
        return False
    return report.ssvc is not None

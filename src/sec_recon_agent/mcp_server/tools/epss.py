"""FIRST EPSS (Exploit Prediction Scoring System) lookup.

EPSS is a daily-refreshed model that estimates the probability a CVE will
be exploited in the wild in the next 30 days. It complements CISA KEV:
- KEV answers "is this CVE known to be exploited right now?".
- EPSS answers "how likely is this CVE to be exploited soon?".

Together they let the agent recommend prioritization beyond raw CVSS,
which famously over-weights theoretical impact relative to real-world
exploitation likelihood.

The API is unauthenticated, low-rate. Queries are single-shot per CVE
(no bulk pre-fetch). A 4 MB response cap defends against a hostile
upstream; current per-CVE payload is < 1 KB.
"""

from typing import Any

import httpx
import structlog

from sec_recon_agent.mcp_server.errors import (
    EpssRequestError,
    MalformedEpssPayloadError,
)
from sec_recon_agent.mcp_server.models import CveIdStr, EpssScore
from sec_recon_agent.mcp_server.server import mcp
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TRUSTED_HOST = "api.first.org"
EPSS_TIMEOUT_SECONDS = 15.0
EPSS_MAX_BYTES = 4 * 1024 * 1024


def _coerce_score(value: Any) -> float | None:
    """EPSS payload encodes numbers as strings (e.g. '0.94521'). Be liberal."""
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0.0 or parsed > 1.0:
        return None
    return parsed


@mcp.tool()
async def epss_score(cve_id: CveIdStr) -> EpssScore:
    """Fetch the EPSS exploit-prediction probability and percentile for a CVE.

    EPSS returns `probability` in [0, 1] (chance of exploitation in the
    next 30 days) and `percentile` in [0, 1] (rank relative to all scored
    CVEs). Returns all fields None when the CVE is not in the EPSS
    dataset (very fresh CVEs, rejected CVEs, etc.).
    """
    with _tracer.start_as_current_span("tool.epss_score") as span:
        span.set_attribute("tool.name", "epss_score")
        span.set_attribute("cve.id", cve_id)
        log.info("epss_score_start", cve_id=cve_id)

        try:
            async with httpx.AsyncClient(timeout=EPSS_TIMEOUT_SECONDS) as client:
                resp = await client.get(
                    EPSS_API_URL,
                    params={"cve": cve_id},
                )
        except httpx.TransportError as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise EpssRequestError(f"Transport error querying EPSS: {exc}") from exc

        final_host = resp.url.host or ""
        if final_host != EPSS_TRUSTED_HOST:
            span.set_attribute("tool.success", False)
            raise EpssRequestError(
                f"EPSS request landed on unexpected host: {final_host}",
            )

        if resp.status_code != 200:
            span.set_attribute("tool.success", False)
            raise EpssRequestError(
                f"EPSS API returned HTTP {resp.status_code}",
            )

        # Defensive cap: api.first.org responses are tiny in practice, but
        # we still guard against a hostile upstream.
        if resp.content is not None and len(resp.content) > EPSS_MAX_BYTES:
            span.set_attribute("tool.success", False)
            raise EpssRequestError(
                f"EPSS response exceeded {EPSS_MAX_BYTES} byte limit",
            )

        try:
            payload: dict[str, Any] = resp.json()
        except ValueError as exc:
            span.set_attribute("tool.success", False)
            raise MalformedEpssPayloadError(f"EPSS response was not JSON: {exc}") from exc

        data = payload.get("data")
        if not isinstance(data, list):
            raise MalformedEpssPayloadError(
                "EPSS payload missing top-level 'data' list",
            )

        if not data:
            result = EpssScore(cve_id=cve_id)
            span.set_attribute("tool.success", True)
            span.set_attribute("epss.in_dataset", False)
            log.info("epss_score_done", cve_id=cve_id, in_dataset=False)
            return result

        entry = data[0]
        if not isinstance(entry, dict):
            raise MalformedEpssPayloadError(
                "EPSS data entry was not an object",
            )

        # Defensive: if the API ever returns a different CVE ID, treat as
        # a miss rather than silently attributing the score to the wrong
        # CVE.
        returned_cve = entry.get("cve")
        if isinstance(returned_cve, str) and returned_cve != cve_id:
            log.warning(
                "epss_cve_mismatch",
                requested=cve_id,
                returned=returned_cve,
            )
            return EpssScore(cve_id=cve_id)

        probability = _coerce_score(entry.get("epss"))
        percentile = _coerce_score(entry.get("percentile"))
        score_date = entry.get("date") if isinstance(entry.get("date"), str) else None

        result = EpssScore(
            cve_id=cve_id,
            probability=probability,
            percentile=percentile,
            score_date=score_date,
        )
        span.set_attribute("tool.success", True)
        span.set_attribute("epss.in_dataset", probability is not None)
        if probability is not None:
            span.set_attribute("epss.probability", probability)
        log.info(
            "epss_score_done",
            cve_id=cve_id,
            probability=probability,
            percentile=percentile,
        )
        return result

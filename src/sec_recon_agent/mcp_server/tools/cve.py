"""NVD CVE lookup tool.

Exposes `cve_lookup(cve_id)` as an MCP tool. Talks to the NVD CVE 2.0 API,
rate-limits with a sliding window to respect public limits (5 req/30s without
API key, 50 with), and retries transient failures via tenacity.
"""

import asyncio
from collections import deque
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.errors import (
    CveNotFoundError,
    MalformedNvdPayloadError,
    NvdConnectionError,
    NvdRateLimitError,
    NvdServerError,
)
from sec_recon_agent.mcp_server.models import CVEDetail, CveIdStr
from sec_recon_agent.mcp_server.server import mcp

log = structlog.get_logger()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "sec-recon-agent/0.1"
HTTP_TIMEOUT_SECONDS = 15.0


class _NvdRateLimiter:
    """Sliding-window rate limiter.

    NVD enforces a per-30s budget. We track timestamps of recent calls and
    sleep until the oldest is outside the window when the budget is full.
    """

    def __init__(self, max_requests: int, window_seconds: float = 30.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            self._drop_expired(now)
            if len(self._timestamps) >= self._max:
                sleep_for = self._window - (now - self._timestamps[0]) + 0.1
                log.debug("nvd_rate_limit_wait", sleep_seconds=round(sleep_for, 2))
                await asyncio.sleep(sleep_for)
                now = loop.time()
                self._drop_expired(now)
            self._timestamps.append(now)

    def _drop_expired(self, now: float) -> None:
        while self._timestamps and now - self._timestamps[0] > self._window:
            self._timestamps.popleft()


_limiter = _NvdRateLimiter(max_requests=settings.nvd_rate_limit_per_30s)


def _build_headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if settings.nvd_api_key is not None:
        headers["apiKey"] = settings.nvd_api_key.get_secret_value()
    return headers


@retry(
    retry=retry_if_exception_type((NvdServerError, NvdConnectionError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
async def _fetch_cve_raw(cve_id: str, client: httpx.AsyncClient) -> dict[str, Any]:
    await _limiter.acquire()
    try:
        resp = await client.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=_build_headers(),
        )
    except httpx.TransportError as exc:
        raise NvdConnectionError(f"NVD transport error for {cve_id}: {exc}") from exc

    if resp.status_code == 404:
        raise CveNotFoundError(cve_id)
    if resp.status_code == 429:
        raise NvdRateLimitError(f"NVD rate limit hit for {cve_id}")
    if resp.status_code >= 500:
        raise NvdServerError(f"NVD returned {resp.status_code} for {cve_id}")
    resp.raise_for_status()
    payload: dict[str, Any] = resp.json()
    return payload


def _extract_english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            value = desc.get("value", "")
            return str(value)
    return ""


def _extract_cvss_v3(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            return (
                float(score) if score is not None else None,
                str(severity) if severity is not None else None,
            )
    return None, None


def _extract_cwe_ids(cve: dict[str, Any]) -> list[str]:
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if isinstance(value, str) and value.startswith("CWE-") and value not in cwe_ids:
                    cwe_ids.append(value)
    return cwe_ids[:20]


def _extract_cpes(cve: dict[str, Any]) -> list[str]:
    cpes: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria")
                if isinstance(cpe, str) and cpe not in cpes:
                    cpes.append(cpe)
    return cpes[:50]


def _extract_references(cve: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if isinstance(url, str) and url not in refs:
            refs.append(url)
    return refs[:20]


def _parse_cve_payload(cve_id: str, payload: dict[str, Any]) -> CVEDetail:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        raise CveNotFoundError(cve_id)
    cve = vulns[0].get("cve")
    if not isinstance(cve, dict):
        raise MalformedNvdPayloadError(f"NVD payload missing 'cve' object for {cve_id}")

    score, severity = _extract_cvss_v3(cve)
    return CVEDetail(
        cve_id=cve.get("id", cve_id),
        description=_extract_english_description(cve),
        cvss_v3_score=score,
        cvss_v3_severity=severity,
        published=str(cve.get("published", "")),
        last_modified=str(cve.get("lastModified", "")),
        cwe_ids=_extract_cwe_ids(cve),
        affected_cpes=_extract_cpes(cve),
        references=_extract_references(cve),  # type: ignore[arg-type]
    )


@mcp.tool()
async def cve_lookup(cve_id: CveIdStr) -> CVEDetail:
    """Fetch the full CVE record from NVD.

    Returns a typed CVEDetail with CVSS v3, CWE IDs, affected CPEs, and references.
    Raises CveNotFoundError for unknown IDs.
    """
    log.info("cve_lookup_start", cve_id=cve_id)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        payload = await _fetch_cve_raw(cve_id, client)
    detail = _parse_cve_payload(cve_id, payload)
    log.info(
        "cve_lookup_done",
        cve_id=detail.cve_id,
        cvss=detail.cvss_v3_score,
        severity=detail.cvss_v3_severity,
        cpes=len(detail.affected_cpes),
    )
    return detail

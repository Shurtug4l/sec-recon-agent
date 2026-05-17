"""Shared NVD HTTP utilities. Used by both cve_lookup and cve_semantic_search."""

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
    NvdConnectionError,
    NvdRateLimitError,
    NvdServerError,
)

log = structlog.get_logger()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "sec-recon-agent/0.1"
HTTP_TIMEOUT_SECONDS = 15.0


class NvdRateLimiter:
    """Sliding-window limiter. NVD enforces a per-30s budget."""

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


nvd_limiter = NvdRateLimiter(max_requests=settings.nvd_rate_limit_per_30s)


def build_headers() -> dict[str, str]:
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
async def nvd_get(
    client: httpx.AsyncClient,
    params: dict[str, Any],
) -> dict[str, Any]:
    """GET against the NVD CVE 2.0 endpoint with rate limiting and retry on transients.

    Raises NvdRateLimitError on 429, NvdServerError on persistent 4xx/5xx,
    NvdConnectionError on persistent network errors.
    """
    await nvd_limiter.acquire()
    try:
        resp = await client.get(NVD_BASE_URL, params=params, headers=build_headers())
    except httpx.TransportError as exc:
        raise NvdConnectionError(f"NVD transport error: {exc}") from exc

    if resp.status_code == 429:
        raise NvdRateLimitError(f"NVD rate limit hit (params={params})")
    if resp.status_code >= 500:
        raise NvdServerError(f"NVD returned {resp.status_code}")
    if resp.status_code >= 400:
        raise NvdServerError(f"NVD returned client error {resp.status_code}")
    payload: dict[str, Any] = resp.json()
    return payload

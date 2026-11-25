"""NVD CVE lookup tool. Returns a typed CVEDetail for a given CVE ID."""

import re
from typing import Any

import httpx
import structlog

from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import (
    CveNotFoundError,
    MalformedNvdPayloadError,
)
from sec_recon_agent.mcp_server.models import (
    CPE_MAX_CHARS,
    CVE_CPES_MAX,
    CVE_CWE_IDS_MAX,
    CVE_DESCRIPTION_CHARS,
    CWE_ID_PATTERN,
    CVEDetail,
    CveIdStr,
)
from sec_recon_agent.mcp_server.nvd_client import (
    HTTP_TIMEOUT_SECONDS,
    NVD_BASE_URL,
    nvd_get,
)
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

# Re-exported for tests that previously imported NVD_BASE_URL from this module.
__all__ = ["NVD_BASE_URL", "cve_lookup"]

_CWE_ID_RE = re.compile(CWE_ID_PATTERN)
# CPE 2.3 formatted string: `cpe:2.3:` + part (a/o/h, or a wildcard) + ten
# more colon-separated components of printable ASCII. Inside a component a
# character is either anything but `:` and `\`, or a `\`-escape; the two
# alternatives never overlap, so a failing match stays linear (an earlier
# `[^\s:]*` version let `\:` split two ways and backtracked exponentially).
_CPE_RE = re.compile(r"cpe:2\.3:[aoh*\-](?::(?:[!-9;-\[\]-~]|\\[!-~])*){10}")
_CVSS_V3_SEVERITIES = frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


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
            # A CVSS v3 severity token or nothing: the field reaches the
            # model unfenced, so an unexpected upstream string is dropped.
            return (
                float(score) if score is not None else None,
                severity if isinstance(severity, str) and severity in _CVSS_V3_SEVERITIES else None,
            )
    return None, None


def _extract_cwe_ids(cve: dict[str, Any]) -> list[str]:
    # Whole-string CWE-N only: NVD's own placeholders (NVD-CWE-Other,
    # NVD-CWE-noinfo) and anything with trailing text are dropped, so the
    # field cannot carry prose to the model.
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if isinstance(value, str) and _CWE_ID_RE.fullmatch(value) and value not in cwe_ids:
                    cwe_ids.append(value)
    return cwe_ids[:CVE_CWE_IDS_MAX]


def _extract_cpes(cve: dict[str, Any]) -> list[str]:
    # Only a whole CPE 2.3 formatted string within the length cap is kept:
    # anything else is dropped, never truncated into a different name.
    cpes: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria")
                if (
                    isinstance(cpe, str)
                    and len(cpe) <= CPE_MAX_CHARS
                    and _CPE_RE.fullmatch(cpe)
                    and cpe not in cpes
                ):
                    cpes.append(cpe)
    return cpes[:CVE_CPES_MAX]


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
    description = _extract_english_description(cve)
    return CVEDetail(
        cve_id=cve.get("id", cve_id),
        description=fence_untrusted(description, max_chars=CVE_DESCRIPTION_CHARS) or "",
        cvss_v3_score=score,
        cvss_v3_severity=severity,
        published=str(cve.get("published", "")),
        last_modified=str(cve.get("lastModified", "")),
        cwe_ids=_extract_cwe_ids(cve),
        affected_cpes=_extract_cpes(cve),
        references=_extract_references(cve),
    )


@declared_tool()
async def cve_lookup(cve_id: CveIdStr) -> CVEDetail:
    """Fetch the full CVE record from NVD.

    Returns a typed CVEDetail with CVSS v3, CWE IDs, affected CPEs, and references.
    Raises CveNotFoundError if NVD returns no record for the given ID.

    The `references` field of the result contains UNTRUSTED vendor URLs:
    do not auto-fetch them server-side. They are an analyst audit trail.
    """
    with _tracer.start_as_current_span("tool.cve_lookup") as span:
        # cve.id is a structured identifier and safe to record. The full
        # description is NOT recorded (it contains untrusted vendor text).
        span.set_attribute("tool.name", "cve_lookup")
        span.set_attribute("cve.id", cve_id)
        log.info("cve_lookup_start", cve_id=cve_id)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                payload = await nvd_get(client, params={"cveId": cve_id})
            detail = _parse_cve_payload(cve_id, payload)
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise
        span.set_attribute("tool.success", True)
        span.set_attribute("cve.cvss_v3_score", detail.cvss_v3_score or 0.0)
        span.set_attribute("cve.cpes_count", len(detail.affected_cpes))
        log.info(
            "cve_lookup_done",
            cve_id=detail.cve_id,
            cvss=detail.cvss_v3_score,
            severity=detail.cvss_v3_severity,
            cpes=len(detail.affected_cpes),
        )
        return detail

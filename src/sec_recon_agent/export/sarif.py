"""TriageReport -> SARIF 2.1.0 renderer for GitHub code scanning.

Pure function of (report, artifact_uri, tool_version): same inputs, same
document, byte for byte. The report stays the single source of truth - the
renderer never re-derives a verdict:

- `result.level` is a display mapping of each CVE's own severity
  (critical/high -> error, medium -> warning, low/info -> note), not a
  second prioritization. The authoritative SSVC verdict passes through
  verbatim in the run property bag, and its rationale is echoed on the
  driving CVE's result message.
- `rule.properties["security-severity"]` carries the CVSS v3 score as a
  string, the exact form GitHub maps onto critical/high/medium/low bands
  (>9.0 / 7.0-8.9 / 4.0-6.9 / 0.1-3.9); omitted when the score is absent
  or 0.0, which GitHub treats as "no security severity".
- `partialFingerprints.primaryLocationLineHash` is synthetic but stable
  (sha256 over rule id + artifact uri), so re-uploading the same triage
  updates alerts instead of duplicating them.

GitHub-required fields honored per result: message.text, one location with
artifactLocation.uri + region.startLine, partialFingerprints; per rule:
shortDescription, fullDescription, help. Findings here have no source
line, so startLine is pinned to 1 (the same convention Trivy uses for
container-image findings).
"""

import hashlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from sec_recon_agent.agent.schema import CVEReference, Severity, TriageReport

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_TOOL_NAME = "sec-recon-agent"
_INFORMATION_URI = "https://github.com/Shurtug4l/sec-recon-agent"

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _resolve_tool_version() -> str:
    try:
        return version(_TOOL_NAME)
    except PackageNotFoundError:
        return "0.0.0"


def _fingerprint(rule_id: str, artifact_uri: str) -> str:
    digest = hashlib.sha256(f"{rule_id}|{artifact_uri}".encode()).hexdigest()[:16]
    return f"{digest}:1"


def _rule(report: TriageReport, cve: CVEReference) -> dict[str, Any]:
    properties: dict[str, Any] = {"tags": ["security", "vulnerability"]}
    if cve.cvss_v3_score is not None and cve.cvss_v3_score > 0.0:
        properties["security-severity"] = f"{cve.cvss_v3_score:.1f}"
    return {
        "id": cve.cve_id,
        "shortDescription": {"text": f"{cve.cve_id}: {cve.severity} severity"},
        "fullDescription": {"text": cve.summary},
        "help": {"text": f"{report.recommended_action}\n\nNVD reference: {cve.nvd_url}"},
        "helpUri": str(cve.nvd_url),
        "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[cve.severity]},
        "properties": properties,
    }


def _result_message(report: TriageReport, cve: CVEReference) -> str:
    parts = [cve.summary]
    signals: list[str] = []
    if cve.in_kev_catalog:
        due = f" (federal remediation due {cve.kev_due_date})" if cve.kev_due_date else ""
        signals.append(f"listed in CISA KEV{due}")
    if cve.known_ransomware_use:
        signals.append("associated with known ransomware campaigns")
    if cve.exploits_public:
        signals.append("public exploit available")
    if cve.epss_probability is not None:
        signals.append(f"EPSS {cve.epss_probability:.3f}")
    if signals:
        parts.append("Signals: " + "; ".join(signals) + ".")
    if report.ssvc is not None and report.ssvc.driving_cve == cve.cve_id:
        parts.append(f"SSVC {report.ssvc.decision}: {report.ssvc.rationale}")
    return " ".join(parts)


def _result(
    report: TriageReport,
    cve: CVEReference,
    rule_index: int,
    artifact_uri: str,
) -> dict[str, Any]:
    return {
        "ruleId": cve.cve_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEVERITY[cve.severity],
        "message": {"text": _result_message(report, cve)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                },
            },
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _fingerprint(cve.cve_id, artifact_uri),
        },
        "properties": {
            "in_kev_catalog": cve.in_kev_catalog,
            "known_ransomware_use": cve.known_ransomware_use,
            "exploits_public": cve.exploits_public,
            "epss_probability": cve.epss_probability,
            "epss_percentile": cve.epss_percentile,
        },
    }


def to_sarif(
    report: TriageReport,
    *,
    artifact_uri: str,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Render the report as a SARIF 2.1.0 log with a single run.

    `artifact_uri` is the location GitHub attaches every alert to: use a
    path relative to the consumer repository root (e.g. the SBOM or report
    file that produced the triage). One rule per distinct CVE id; duplicate
    CVE entries share the rule and emit their own results.
    """
    if not artifact_uri.strip():
        raise ValueError("artifact_uri must be a non-empty relative path or identifier")

    rule_indices: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for cve in report.cves:
        if cve.cve_id not in rule_indices:
            rule_indices[cve.cve_id] = len(rules)
            rules.append(_rule(report, cve))
    results = [_result(report, cve, rule_indices[cve.cve_id], artifact_uri) for cve in report.cves]

    run_properties: dict[str, Any] = {
        "summary": report.summary,
        "confidence": report.confidence,
        "grounding_status": report.grounding.status if report.grounding is not None else None,
    }
    if report.ssvc is not None:
        run_properties["ssvc"] = report.ssvc.model_dump(mode="json")

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _INFORMATION_URI,
                        "semanticVersion": tool_version or _resolve_tool_version(),
                        "rules": rules,
                    },
                },
                "results": results,
                "properties": run_properties,
            },
        ],
    }

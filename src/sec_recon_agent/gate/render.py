"""GateReport -> neutral VulnRecord adapters for the export renderers.

The spec mechanics (SARIF fields, OpenVEX @id, fingerprints) live in
export/; this module only maps gate findings onto VulnRecord rows. Two
gate-specific behaviors:

- SARIF fingerprints carry the component as a discriminator, so two
  components sharing a CVE stay two distinct GitHub alerts.
- OpenVEX statements bind each finding to its own component purl. Product
  identity is never guessed: a purl is synthesized only for PyPI (the
  requirements.txt path, where the mapping name+version -> purl is
  mechanical and lossless per PEP 503); findings whose component has no
  purl are excluded from the VEX document and reported, never silently
  dropped.
"""

import re
from datetime import datetime
from typing import Any

from sec_recon_agent.agent.ssvc import rule_rationale
from sec_recon_agent.export.openvex import DEFAULT_AUTHOR, ProductIdentityError, render_openvex
from sec_recon_agent.export.records import VulnRecord
from sec_recon_agent.export.sarif import render_sarif
from sec_recon_agent.gate.models import GateFinding, GateReport

_PYPI_NORMALIZE = re.compile(r"[-_.]+")


def _vex_purl(finding: GateFinding) -> str | None:
    if finding.component_purl is not None:
        return finding.component_purl
    if finding.component_ecosystem == "PyPI":
        name = _PYPI_NORMALIZE.sub("-", finding.component_name).lower()
        return f"pkg:pypi/{name}@{finding.component_version}"
    return None


def _action(finding: GateFinding) -> str:
    if finding.fixed_version:
        return f"Upgrade {finding.component_name} to {finding.fixed_version} or later."
    return (
        f"No fixed version listed upstream for {finding.osv_id}; review the "
        "advisory and mitigate or replace the dependency."
    )


def _summary(finding: GateFinding) -> str:
    if finding.summary:
        return finding.summary
    return f"{finding.osv_id} affects {finding.component_name} {finding.component_version}."


def _record(finding: GateFinding, *, products: tuple[str, ...] = ()) -> VulnRecord:
    return VulnRecord(
        rule_id=finding.cve_id or finding.osv_id,
        summary=_summary(finding),
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        url=finding.reference_url,
        action=_action(finding),
        in_kev=finding.in_kev,
        kev_due_date=finding.kev_due_date,
        known_ransomware=finding.known_ransomware_use,
        exploit_public=finding.exploits_public,
        epss_probability=finding.epss_probability,
        epss_percentile=finding.epss_percentile,
        ssvc_note=f"SSVC {finding.decision}: {rule_rationale(finding.rule)}.",
        reference_label="NVD reference" if finding.cve_id else "OSV reference",
        products=products,
        fingerprint_extra=finding.component_purl
        or f"{finding.component_name}@{finding.component_version}",
        extra_properties={
            "component": finding.component_name,
            "component_version": finding.component_version,
            "component_purl": finding.component_purl,
            "osv_id": finding.osv_id,
            "fixed_version": finding.fixed_version,
            "coverage": finding.coverage.model_dump(mode="json"),
        },
    )


def gate_to_sarif(
    report: GateReport,
    *,
    artifact_uri: str,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Render the gate report as SARIF 2.1.0 (one result per finding)."""
    records = [_record(f) for f in report.findings]
    run_properties: dict[str, Any] = {
        "source": "sec-recon-gate",
        "sbom_format": report.sbom_format,
        "components_total": report.components_total,
        "components_scanned": report.components_scanned,
        "components_skipped": len(report.skipped),
        "sbom_truncated": report.sbom_truncated,
        "ssvc": report.ssvc.model_dump(mode="json"),
        "policy": report.policy.model_dump(mode="json"),
    }
    return render_sarif(
        records,
        artifact_uri=artifact_uri,
        run_properties=run_properties,
        tool_version=tool_version or report.tool_version,
    )


def openvex_excluded(report: GateReport) -> list[str]:
    """Advisory ids that cannot appear in the VEX for lack of product identity."""
    return [f.osv_id for f in report.findings if _vex_purl(f) is None]


def gate_to_openvex(
    report: GateReport,
    *,
    timestamp: datetime,
    author: str = DEFAULT_AUTHOR,
    doc_version: int = 1,
) -> dict[str, Any]:
    """Render the gate report as OpenVEX v0.2.0, one statement per finding.

    Raises ProductIdentityError when no finding carries a product purl (an
    OpenVEX document requires at least one statement, and a statement
    requires a product).
    """
    records = [
        _record(f, products=(purl,)) for f in report.findings if (purl := _vex_purl(f)) is not None
    ]
    if not records:
        raise ProductIdentityError("no findings with a product purl: nothing to attest in OpenVEX")
    return render_openvex(records, timestamp=timestamp, author=author, doc_version=doc_version)

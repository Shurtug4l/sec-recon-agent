"""Neutral per-vulnerability record consumed by the SARIF / OpenVEX cores.

Two producers exist: the LLM triage path (TriageReport -> records, adapters in
sarif.py / openvex.py keep their public signatures) and the deterministic SBOM
gate (GateReport -> records, adapter in gate/render.py). The renderers only
ever see this shape, so neither producer's report model leaks into the spec
logic and the gate is not constrained by TriageReport's 10-CVE cap or its
LLM-authored fields.

Phrasing responsibilities stay with the adapters (ssvc_note text, reference
label); the cores own the spec mechanics (fingerprints, level mapping,
security-severity, document @id).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sec_recon_agent.agent.references import nvd_url
from sec_recon_agent.agent.schema import Severity, TriageReport


@dataclass(frozen=True)
class VulnRecord:
    """One vulnerability occurrence to render.

    `rule_id` is the advisory identifier (CVE-* or an OSV-native id such as
    GHSA-*). `severity` is None when no source provided one (the gate, or a
    driving CVE the report left out); the SARIF core then falls back to
    level=warning
    and omits security-severity. `products` and `fingerprint_extra` only vary
    on the gate path: per-occurrence product purls for OpenVEX statements and
    the component discriminator that keeps two components sharing a CVE from
    collapsing into one GitHub alert.
    """

    rule_id: str
    summary: str
    severity: Severity | None
    cvss_score: float | None
    url: str
    action: str
    in_kev: bool
    kev_due_date: str | None
    known_ransomware: bool | None
    exploit_public: bool
    epss_probability: float | None
    epss_percentile: float | None
    ssvc_note: str | None = None
    reference_label: str = "NVD reference"
    products: tuple[str, ...] = ()
    fingerprint_extra: str = ""
    extra_properties: Mapping[str, Any] = field(default_factory=dict)
    vex_status: str = "affected"


def omitted_driver_record(
    report: TriageReport, products: tuple[str, ...] = ()
) -> VulnRecord | None:
    """A record for the CVE driving the verdict when the report does not list it.

    Without one the verdict stays in a property bag: consumers read results and
    statements, and those would say nothing, or only speak of quieter CVEs.
    What the stamp knows is the id and the rationale, so the signal fields stay
    None instead of reading as negatives, and OpenVEX says under_investigation:
    `affected` is an assertion this run never made about this product.
    """
    ssvc = report.ssvc
    if ssvc is None or ssvc.driving_cve is None:
        return None
    if any(cve.cve_id == ssvc.driving_cve for cve in report.cves):
        return None
    return VulnRecord(
        rule_id=ssvc.driving_cve,
        summary="Flagged by the tools during triage, missing from the report.",
        severity=None,
        cvss_score=None,
        url=nvd_url(ssvc.driving_cve),
        action="Triage this CVE: the report did not assess it.",
        in_kev=False,
        kev_due_date=None,
        known_ransomware=None,
        exploit_public=False,
        epss_probability=None,
        epss_percentile=None,
        ssvc_note=f"SSVC {ssvc.decision}: {ssvc.rationale}",
        products=products,
        extra_properties={"in_kev_catalog": None, "exploits_public": None, "in_report": False},
        vex_status="under_investigation",
    )

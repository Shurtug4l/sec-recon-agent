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

from sec_recon_agent.agent.schema import Severity


@dataclass(frozen=True)
class VulnRecord:
    """One vulnerability occurrence to render.

    `rule_id` is the advisory identifier (CVE-* or an OSV-native id such as
    GHSA-*). `severity` is None when no source provided one (possible for the
    gate, never for triage); the SARIF core then falls back to level=warning
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

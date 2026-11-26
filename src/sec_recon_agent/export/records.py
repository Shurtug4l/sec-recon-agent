"""Neutral per-vulnerability record consumed by the SARIF / OpenVEX cores.

Two producers exist: the LLM triage path (TriageReport -> records, adapters in
sarif.py / openvex.py keep their public signatures) and the deterministic SBOM
gate (GateReport -> records, adapter in gate/render.py). The renderers only
ever see this shape, so neither producer's report model leaks into the spec
logic and the gate is not constrained by TriageReport's 10-CVE cap or its
LLM-authored fields.

Phrasing shared by both triage adapters (the omitted-driver record, the
grounding note) lives here; the rest stays with the adapters (ssvc_note text,
reference label). The cores own the spec mechanics (fingerprints, level
mapping, security-severity, document @id).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from sec_recon_agent.agent.references import nvd_url
from sec_recon_agent.agent.schema import (
    GROUNDING_SUBJECT_MAX,
    GroundingClaimStatus,
    GroundingStatus,
    Severity,
    TriageReport,
)

GroundingLabel = Literal["verified", "flagged", "unverified"]

# Claim outcomes that say the report contradicts or outruns the tools.
# UNVERIFIABLE is not one: the evidence exists, it just could not be parsed.
_FLAGGING = frozenset({GroundingClaimStatus.UNBACKED, GroundingClaimStatus.MISMATCH})
# Fields named in one note; the counts in the report stay complete.
_NOTE_FIELDS = 5


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
    vex_status: Literal["affected", "under_investigation"] = "affected"
    grounding_note: str | None = None


@dataclass(frozen=True)
class CveGrounding:
    """How far the grounding stamp backs one CVE of the report.

    `label` is `verified` when the stamp ran and flagged none of the CVE's
    claims, `flagged` when it found one unbacked or contradicted by a tool
    return, `unverified` when nothing checked it: no stamp, a stamp that
    could not run, an id that surfaced only in unparseable tool output, or a
    suspect stamp whose findings hit their cap, where this CVE's finding may
    be the one cut off. `note` is None only for
    `verified`.

    `asserted` is what OpenVEX may say: `affected` needs the CVE's identity
    backed. A flag on a signal field (KEV, EPSS, CVSS, exploit, ransomware)
    leaves it asserted with the note attached, because the statement carries
    none of those fields, and stripping it would let injected tool text that
    provokes one wrong field weaken a real CVE's statement.
    """

    label: GroundingLabel
    note: str | None
    asserted: bool


def cve_grounding(report: TriageReport, cve_id: str) -> CveGrounding:
    """Read the report's grounding stamp for one CVE (see CveGrounding)."""
    grounding = report.grounding
    if grounding is None:
        return CveGrounding(
            "unverified", "Not verified: the report carries no grounding assessment.", False
        )
    if grounding.status is GroundingStatus.NOT_EVALUATED:
        return CveGrounding(
            "unverified", "Not verified: grounding could not run on this report.", False
        )
    # The verifier cuts subjects to the cap; compare on the same prefix.
    wanted = cve_id.upper()[:GROUNDING_SUBJECT_MAX]
    flags = [
        claim
        for claim in grounding.findings
        if claim.status in _FLAGGING and claim.subject.upper() == wanted
    ]
    if flags:
        # A report that repeats a CVE repeats its findings; name each once.
        named = list(dict.fromkeys(f"{claim.field} {claim.status.value}" for claim in flags))
        shown = ", ".join(named[:_NOTE_FIELDS])
        more = f" (+{len(named) - _NOTE_FIELDS} more)" if len(named) > _NOTE_FIELDS else ""
        identity_flagged = any(claim.field == "cve_id" for claim in flags)
        return CveGrounding(
            "flagged", f"Grounding flagged this CVE: {shown}{more}.", not identity_flagged
        )
    # The id surfaced only in a tool return that would not parse: nothing
    # backs it, and that content is not evidence (fenced or upstream prose).
    if any(
        claim.field == "cve_id"
        and claim.status is GroundingClaimStatus.UNVERIFIABLE
        and claim.subject.upper() == wanted
        for claim in grounding.findings
    ):
        return CveGrounding(
            "unverified",
            "Not verified: grounding could not read the tool output naming this CVE.",
            False,
        )
    if grounding.status is GroundingStatus.SUSPECT and grounding.truncated:
        return CveGrounding(
            "unverified", "Not verified: the grounding findings were truncated.", False
        )
    return CveGrounding("verified", None, True)


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
    # Never `verified`: the report did not assess this CVE. Grounding records
    # the omission as a `cves` mismatch on its id, so it usually reads flagged.
    flagged = cve_grounding(report, ssvc.driving_cve).label == "flagged"
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
        extra_properties={
            "in_kev_catalog": None,
            "exploits_public": None,
            "in_report": False,
            "grounding": "flagged" if flagged else "unverified",
        },
        vex_status="under_investigation",
    )

"""Deterministic post-run verification of the report's tool-derived claims.

`verify_grounding` compares every checkable factual claim in a TriageReport
(CVSS score, KEV membership, EPSS values, exploit flags, ATT&CK technique
ids) against the tool returns captured from the run's message history, and
produces a GroundingAssessment the API stamps onto the report (same
server-side authority pattern as agent/ssvc.py).

Claim policy, designed to never accuse falsely:
- Only positive / non-default claims can be UNBACKED. A CVE left at
  `in_kev_catalog=False` with no kev_check call is the honest default, not a
  fabrication; `in_kev_catalog=True` with no supporting kev_check return is.
- MISMATCH fires in both directions once evidence exists: downplaying a
  tool-confirmed signal contradicts the trajectory just as much as inflating.
- Only STRUCTURED tool fields count as evidence. Fenced free text is
  untrusted upstream prose, never proof. When a successful return could not
  be parsed back into its typed model, affected claims degrade to
  UNVERIFIABLE instead of UNBACKED.

This module is pure and imports nothing from pydantic-ai: it consumes the
ToolInvocation records produced by agent/trajectory.py.
"""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from pydantic import TypeAdapter, ValidationError

from sec_recon_agent.agent.schema import (
    CVEReference,
    GroundingAssessment,
    GroundingClaim,
    GroundingClaimStatus,
    GroundingStatus,
    TriageReport,
)
from sec_recon_agent.agent.trajectory import ToolInvocation
from sec_recon_agent.mcp_server.models import (
    AttackTechnique,
    CVECandidate,
    CVEDetail,
    EpssScore,
    EpssStatus,
    ExploitCheck,
    KevCheck,
    OsvScanResult,
    PatchAvailability,
)

# CVSS scores are reported to one decimal; EPSS models round to a few. Small
# absolute tolerances absorb representation noise without hiding real drift.
CVSS_SCORE_TOLERANCE = 0.05
EPSS_TOLERANCE = 0.01
MAX_FINDINGS = 40

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_LIST_ATTACK = TypeAdapter(list[AttackTechnique])
_LIST_CANDIDATES = TypeAdapter(list[CVECandidate])


@dataclass
class _Evidence:
    """Index of parsed tool returns, built once per verification."""

    cve_details: dict[str, list[CVEDetail]] = field(default_factory=dict)
    kev: dict[str, list[KevCheck]] = field(default_factory=dict)
    epss: dict[str, list[EpssScore]] = field(default_factory=dict)
    exploits: dict[str, list[ExploitCheck]] = field(default_factory=dict)
    attack_ids: set[str] = field(default_factory=set)
    mentioned_cve_ids: set[str] = field(default_factory=set)
    unparsed: dict[str, list[ToolInvocation]] = field(default_factory=dict)


def _scan_cve_ids(value: object) -> set[str]:
    """CVE ids appearing anywhere in a JSON-dumpable structure, normalized."""
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return {match.upper() for match in _CVE_ID_RE.findall(text)}


def _mentions_cve(invocation: ToolInvocation, cve_id: str) -> bool:
    return cve_id in _scan_cve_ids(invocation.args) or cve_id in _scan_cve_ids(
        invocation.content,
    )


def _build_evidence(invocations: Sequence[ToolInvocation]) -> _Evidence:
    evidence = _Evidence()
    for invocation in invocations:
        if invocation.outcome != "success":
            continue
        # Tool args are model-authored structured data: a queried CVE id
        # counts as a mention even when the tool's answer was empty.
        evidence.mentioned_cve_ids |= _scan_cve_ids(invocation.args)
        try:
            _index_content(evidence, invocation)
        except (ValidationError, TypeError, ValueError):
            evidence.unparsed.setdefault(invocation.tool_name, []).append(invocation)
    return evidence


def _index_content(evidence: _Evidence, invocation: ToolInvocation) -> None:
    """Parse one successful return into the typed index. Raises on mismatch."""
    content = invocation.content
    tool = invocation.tool_name
    if tool == "cve_lookup":
        detail = CVEDetail.model_validate(content)
        evidence.cve_details.setdefault(detail.cve_id.upper(), []).append(detail)
        evidence.mentioned_cve_ids.add(detail.cve_id.upper())
    elif tool == "kev_check":
        kev = KevCheck.model_validate(content)
        evidence.kev.setdefault(kev.cve_id.upper(), []).append(kev)
        evidence.mentioned_cve_ids.add(kev.cve_id.upper())
    elif tool == "epss_score":
        epss = EpssScore.model_validate(content)
        evidence.epss.setdefault(epss.cve_id.upper(), []).append(epss)
        evidence.mentioned_cve_ids.add(epss.cve_id.upper())
    elif tool == "exploit_check":
        exploit = ExploitCheck.model_validate(content)
        evidence.exploits.setdefault(exploit.cve_id.upper(), []).append(exploit)
        evidence.mentioned_cve_ids.add(exploit.cve_id.upper())
    elif tool == "patch_lookup":
        patch = PatchAvailability.model_validate(content)
        evidence.mentioned_cve_ids.add(patch.cve_id.upper())
    elif tool == "osv_lookup":
        osv = OsvScanResult.model_validate(content)
        for vuln in osv.vulnerabilities:
            evidence.mentioned_cve_ids |= _scan_cve_ids(vuln.id)
            evidence.mentioned_cve_ids |= _scan_cve_ids(vuln.aliases)
    elif tool == "attack_mapping":
        techniques = _LIST_ATTACK.validate_python(content)
        evidence.attack_ids |= {technique.id for technique in techniques}
    elif tool == "cve_semantic_search":
        candidates = _LIST_CANDIDATES.validate_python(content)
        evidence.mentioned_cve_ids |= {c.cve_id.upper() for c in candidates}
    # nmap_parse_xml / sbom_ingest carry no report-claim evidence: skip.


class _Collector:
    """Accumulates claim outcomes in deterministic order."""

    def __init__(self) -> None:
        self.checked = 0
        self.counts: dict[GroundingClaimStatus, int] = dict.fromkeys(GroundingClaimStatus, 0)
        self.findings: list[GroundingClaim] = []

    def record(
        self,
        subject: str,
        claim_field: str,
        status: GroundingClaimStatus,
        detail: str | None = None,
    ) -> None:
        self.checked += 1
        self.counts[status] += 1
        if status is not GroundingClaimStatus.SUPPORTED:
            self.findings.append(
                GroundingClaim(
                    subject=subject[:40],
                    field=claim_field[:40],
                    status=status,
                    detail=detail[:200] if detail else None,
                ),
            )

    def assessment(self) -> GroundingAssessment:
        suspect = (
            self.counts[GroundingClaimStatus.UNBACKED] + self.counts[GroundingClaimStatus.MISMATCH]
        )
        return GroundingAssessment(
            status=GroundingStatus.SUSPECT if suspect else GroundingStatus.GROUNDED,
            claims_checked=self.checked,
            supported=self.counts[GroundingClaimStatus.SUPPORTED],
            unbacked=self.counts[GroundingClaimStatus.UNBACKED],
            mismatched=self.counts[GroundingClaimStatus.MISMATCH],
            unverifiable=self.counts[GroundingClaimStatus.UNVERIFIABLE],
            findings=self.findings[:MAX_FINDINGS],
            truncated=len(self.findings) > MAX_FINDINGS,
        )


def _absence_status(
    evidence: _Evidence,
    tool: str,
    cve_id: str,
) -> GroundingClaimStatus:
    """UNVERIFIABLE when an unparseable success from `tool` mentions the CVE
    (evidence may exist, we just cannot read it); UNBACKED otherwise."""
    for invocation in evidence.unparsed.get(tool, []):
        if _mentions_cve(invocation, cve_id):
            return GroundingClaimStatus.UNVERIFIABLE
    return GroundingClaimStatus.UNBACKED


def verify_grounding(
    report: TriageReport,
    invocations: Sequence[ToolInvocation] | None,
) -> GroundingAssessment:
    """Verify the report's tool-derived claims against the captured trajectory.

    `invocations=None` means the message history was unavailable: the outcome
    is NOT_EVALUATED (an honest skip). An empty list is a real trajectory in
    which no tool was called, so positive claims cannot be backed.
    """
    if invocations is None:
        return GroundingAssessment(status=GroundingStatus.NOT_EVALUATED)

    evidence = _build_evidence(invocations)
    collector = _Collector()

    for cve in report.cves:
        _check_cve(collector, evidence, cve)

    for technique in report.attack_techniques:
        if technique.id in evidence.attack_ids:
            collector.record(technique.id, "attack_technique", GroundingClaimStatus.SUPPORTED)
        elif evidence.unparsed.get("attack_mapping"):
            collector.record(
                technique.id,
                "attack_technique",
                GroundingClaimStatus.UNVERIFIABLE,
                "attack_mapping returned unparseable content",
            )
        else:
            collector.record(
                technique.id,
                "attack_technique",
                GroundingClaimStatus.UNBACKED,
                "no attack_mapping return carries this technique",
            )

    return collector.assessment()


def _check_cve(collector: _Collector, evidence: _Evidence, cve: CVEReference) -> None:
    cve_id = cve.cve_id.upper()

    # Identity first: a CVE id no tool was asked about and no tool returned is
    # the strongest fabrication signal. One finding, no per-field pile-on.
    if cve_id not in evidence.mentioned_cve_ids:
        status = GroundingClaimStatus.UNBACKED
        for unparsed in evidence.unparsed.values():
            if any(_mentions_cve(inv, cve_id) for inv in unparsed):
                status = GroundingClaimStatus.UNVERIFIABLE
                break
        collector.record(
            cve_id,
            "cve_id",
            status,
            "not present in any tool call or structured tool return",
        )
        return
    collector.record(cve_id, "cve_id", GroundingClaimStatus.SUPPORTED)

    _check_cvss(collector, evidence, cve_id, cve.cvss_v3_score)
    _check_bool_signal(
        collector,
        cve_id,
        "exploits_public",
        cve.exploits_public,
        [e.has_public_exploit for e in evidence.exploits.get(cve_id, [])],
        evidence,
        tool="exploit_check",
    )
    _check_bool_signal(
        collector,
        cve_id,
        "in_kev_catalog",
        cve.in_kev_catalog,
        [k.in_catalog for k in evidence.kev.get(cve_id, [])],
        evidence,
        tool="kev_check",
    )
    _check_kev_due_date(collector, evidence, cve_id, cve.kev_due_date)
    _check_ransomware(collector, evidence, cve_id, cve.known_ransomware_use)
    _check_epss(collector, evidence, cve_id, "epss_probability", cve.epss_probability)
    _check_epss(collector, evidence, cve_id, "epss_percentile", cve.epss_percentile)


def _check_cvss(
    collector: _Collector,
    evidence: _Evidence,
    cve_id: str,
    claimed: float | None,
) -> None:
    if claimed is None:
        return
    scores = [
        d.cvss_v3_score for d in evidence.cve_details.get(cve_id, []) if d.cvss_v3_score is not None
    ]
    if any(abs(score - claimed) <= CVSS_SCORE_TOLERANCE for score in scores):
        collector.record(cve_id, "cvss_v3_score", GroundingClaimStatus.SUPPORTED)
    elif scores:
        collector.record(
            cve_id,
            "cvss_v3_score",
            GroundingClaimStatus.MISMATCH,
            f"cve_lookup returned {scores[-1]}, report claims {claimed}",
        )
    else:
        collector.record(
            cve_id,
            "cvss_v3_score",
            _absence_status(evidence, "cve_lookup", cve_id),
            "no cve_lookup return carries a CVSS score for this CVE",
        )


def _check_bool_signal(
    collector: _Collector,
    cve_id: str,
    claim_field: str,
    claimed: bool,
    observed: list[bool],
    evidence: _Evidence,
    *,
    tool: str,
) -> None:
    """Shared policy for exploits_public / in_kev_catalog.

    A True claim always needs backing; a False claim is only judged when
    evidence exists (False is the schema default, not an assertion).
    """
    if observed:
        if claimed in observed:
            collector.record(cve_id, claim_field, GroundingClaimStatus.SUPPORTED)
        else:
            collector.record(
                cve_id,
                claim_field,
                GroundingClaimStatus.MISMATCH,
                f"{tool} returned {observed[-1]}, report claims {claimed}",
            )
    elif claimed:
        collector.record(
            cve_id,
            claim_field,
            _absence_status(evidence, tool, cve_id),
            f"no {tool} return backs this claim",
        )


def _check_kev_due_date(
    collector: _Collector,
    evidence: _Evidence,
    cve_id: str,
    claimed: str | None,
) -> None:
    if claimed is None:
        return
    in_catalog_entries = [k for k in evidence.kev.get(cve_id, []) if k.in_catalog]
    observed = [k.due_date.strip() for k in in_catalog_entries if k.due_date]
    if claimed.strip() in observed:
        collector.record(cve_id, "kev_due_date", GroundingClaimStatus.SUPPORTED)
    elif in_catalog_entries:
        collector.record(
            cve_id,
            "kev_due_date",
            GroundingClaimStatus.MISMATCH,
            f"kev_check due_date is {observed[-1] if observed else None}, report claims {claimed}",
        )
    else:
        collector.record(
            cve_id,
            "kev_due_date",
            _absence_status(evidence, "kev_check", cve_id),
            "no kev_check return places this CVE in the catalog",
        )


def _check_ransomware(
    collector: _Collector,
    evidence: _Evidence,
    cve_id: str,
    claimed: bool | None,
) -> None:
    if claimed is None:
        return
    observed = [
        k.known_ransomware_use
        for k in evidence.kev.get(cve_id, [])
        if k.known_ransomware_use is not None
    ]
    if observed:
        if claimed in observed:
            collector.record(cve_id, "known_ransomware_use", GroundingClaimStatus.SUPPORTED)
        else:
            collector.record(
                cve_id,
                "known_ransomware_use",
                GroundingClaimStatus.MISMATCH,
                f"kev_check returned {observed[-1]}, report claims {claimed}",
            )
    elif claimed:
        # KEV not providing the flag is absence of backing, not contradiction.
        collector.record(
            cve_id,
            "known_ransomware_use",
            _absence_status(evidence, "kev_check", cve_id),
            "no kev_check return carries a ransomware flag for this CVE",
        )


def _check_epss(
    collector: _Collector,
    evidence: _Evidence,
    cve_id: str,
    claim_field: str,
    claimed: float | None,
) -> None:
    if claimed is None:
        return
    attr = "probability" if claim_field == "epss_probability" else "percentile"
    observed = [
        value
        for e in evidence.epss.get(cve_id, [])
        if e.status is EpssStatus.FOUND and (value := getattr(e, attr)) is not None
    ]
    if any(abs(value - claimed) <= EPSS_TOLERANCE for value in observed):
        collector.record(cve_id, claim_field, GroundingClaimStatus.SUPPORTED)
    elif observed:
        collector.record(
            cve_id,
            claim_field,
            GroundingClaimStatus.MISMATCH,
            f"epss_score returned {observed[-1]}, report claims {claimed}",
        )
    else:
        collector.record(
            cve_id,
            claim_field,
            _absence_status(evidence, "epss_score", cve_id),
            "no found-status epss_score return backs this value",
        )

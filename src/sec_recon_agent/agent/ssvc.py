"""Deterministic SSVC prioritization over the signals the agent collects.

SSVC (Stakeholder-Specific Vulnerability Categorization) is CISA's methodology
for turning vulnerability signals into a remediation-urgency decision, replacing
"triage by CVSS score" with a decision tree over exploitation status, impact,
and mission context. Its four coordinator outcomes are Act / Attend / Track* /
Track (see agent/schema.py::SsvcDecision).

Why this lives here and not in the LLM:
    The prioritization verdict is a compliance-relevant, safety-relevant signal.
    An LLM is probabilistic; the same CVE could get a different verdict on two
    runs. A deterministic function over the collected signals is reproducible,
    auditable, and testable. The LLM's job is to gather the grounded signals and
    to *echo* the resulting decision in prose; this function is the authority.

Faithfulness to CISA SSVC (honest scope):
    CISA's decision tree has four points: Exploitation (none / PoC / active),
    Automatable (no / yes), Technical Impact (partial / total), and Mission &
    Well-being (low / medium / high). This project has clean signals for
    Exploitation (KEV = active, public-exploit = PoC) and a defensible proxy for
    the likelihood axis (EPSS). It does NOT have deployment-specific Mission &
    Well-being context (a stateless triage tool cannot know the operator's
    asset criticality), and it uses ransomware association + CVSS severity as
    coarse impact escalators rather than the full Technical-Impact point. The
    mapping below is therefore SSVC-*informed*, not a certified SSVC
    implementation. That distinction is stated in the docs and the report
    rationale rather than hidden.

Thresholds are module constants so the decision boundaries are inspectable and
unit-testable, and they align with the prioritization heuristic already stated
in the agent system prompt (EPSS >= 0.5 or percentile >= 0.95 = high real-world
risk; the audit trail's high_epss_hits uses the same 0.5 cut).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from sec_recon_agent.agent.schema import (
    CVEReference,
    Severity,
    SsvcAssessment,
    SsvcDecision,
)

# EPSS probability at or above which forward-looking exploitation risk is treated
# as high (matches the system-prompt heuristic and the audit high_epss cut).
EPSS_HIGH_PROBABILITY = 0.5
# EPSS percentile at or above which the CVE ranks in the most-exploitable tail.
EPSS_HIGH_PERCENTILE = 0.95
# EPSS probability at or above which risk is elevated but sub-"high": enough to
# warrant closer monitoring (Track*), not yet sustained attention (Attend).
EPSS_WATCH_PROBABILITY = 0.10

# Mirrors the CveIdStr constraint on SsvcAssessment.driving_cve.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Urgency ordering used to reduce per-CVE decisions to a single report verdict.
_DECISION_RANK: dict[SsvcDecision, int] = {
    SsvcDecision.TRACK: 0,
    SsvcDecision.TRACK_STAR: 1,
    SsvcDecision.ATTEND: 2,
    SsvcDecision.ACT: 3,
}

_ELEVATED_SEVERITIES: frozenset[Severity] = frozenset(
    {Severity.CRITICAL, Severity.HIGH},
)


@dataclass(frozen=True)
class SsvcSignals:
    """The exploitation / likelihood / impact signals SSVC reduces to a decision.

    Mirrors the fields carried per CVE in the report so the decision function is
    a pure mapping from these five inputs, independent of the report shape.
    """

    in_kev: bool
    known_ransomware: bool | None
    exploit_public: bool
    epss_probability: float | None
    epss_percentile: float | None
    severity: Severity | None


def _epss_high(sig: SsvcSignals) -> bool:
    prob_high = sig.epss_probability is not None and sig.epss_probability >= EPSS_HIGH_PROBABILITY
    pct_high = sig.epss_percentile is not None and sig.epss_percentile >= EPSS_HIGH_PERCENTILE
    return prob_high or pct_high


def _epss_elevated(sig: SsvcSignals) -> bool:
    return sig.epss_probability is not None and sig.epss_probability >= EPSS_WATCH_PROBABILITY


def decide_for_signals(sig: SsvcSignals) -> tuple[SsvcDecision, str]:
    """Map one CVE's signals to an (SSVC decision, rule id).

    Rules are evaluated most-urgent first; the first match wins. Each rule has a
    stable string id so the audit trail and regression tests can pin *why* a
    decision was reached, not just the outcome.
    """
    # --- Act: active exploitation or imminent, out-of-cycle remediation ---
    if sig.known_ransomware is True:
        # Ransomware association is CISA's own top escalator on KEV entries.
        return SsvcDecision.ACT, "ransomware"
    if sig.in_kev:
        # KEV membership == exploitation "active" in the wild.
        return SsvcDecision.ACT, "kev-active-exploitation"
    if sig.exploit_public and _epss_high(sig):
        # PoC exists AND high predicted exploitation: effectively imminent.
        return SsvcDecision.ACT, "public-exploit+high-epss"

    # --- Attend: remediate sooner than standard, needs attention ---
    if sig.exploit_public:
        # Exploitation "PoC": a public exploit exists but no active/high signal.
        return SsvcDecision.ATTEND, "public-exploit"
    if _epss_high(sig):
        # High forward-looking risk even without a known public exploit.
        return SsvcDecision.ATTEND, "high-epss"

    # --- Track*: standard timeline, but monitor closely for escalation ---
    if _epss_elevated(sig):
        return SsvcDecision.TRACK_STAR, "elevated-epss"
    if sig.severity in _ELEVATED_SEVERITIES:
        # High/Critical impact with no exploitation signal yet: watch it.
        return SsvcDecision.TRACK_STAR, "high-severity-no-exploitation"

    # --- Track: no action beyond standard update timelines ---
    return SsvcDecision.TRACK, "baseline"


def _signals_from_cve(cve: CVEReference) -> SsvcSignals:
    return SsvcSignals(
        in_kev=cve.in_kev_catalog,
        known_ransomware=cve.known_ransomware_use,
        exploit_public=cve.exploits_public,
        epss_probability=cve.epss_probability,
        epss_percentile=cve.epss_percentile,
        severity=cve.severity,
    )


_RULE_RATIONALE: dict[str, str] = {
    "ransomware": "on the CISA KEV catalog and associated with known ransomware campaigns",
    "kev-active-exploitation": "on the CISA KEV catalog: actively exploited in the wild",
    "public-exploit+high-epss": (
        "a public exploit is available and EPSS predicts high near-term exploitation"
    ),
    "public-exploit": "a public exploit or proof-of-concept is available",
    "high-epss": "EPSS predicts high near-term exploitation likelihood",
    "elevated-epss": "EPSS is elevated but below the high-risk threshold",
    "high-severity-no-exploitation": (
        "high CVSS severity with no observed exploitation signal yet"
    ),
    "baseline": "no active-exploitation, public-exploit, or high-EPSS signal observed",
}


def decision_rank(decision: SsvcDecision) -> int:
    """Urgency rank of a decision (higher = more urgent).

    Public so policy layers (the SBOM gate's fail-on threshold) can compare
    decisions without duplicating the ordering.
    """
    return _DECISION_RANK[decision]


def rule_rationale(rule: str) -> str:
    """Human-readable fragment for a rule id; falls back to the id itself."""
    return _RULE_RATIONALE.get(rule, rule)


def assess_from_signals(items: Iterable[tuple[str, SsvcSignals]]) -> SsvcAssessment:
    """Reduce (vulnerability id, signals) pairs to a single, most-urgent verdict.

    Shape-independent core shared by the LLM triage path (assess_ssvc over the
    report's CVEReference entries) and the deterministic SBOM gate (findings
    carry SsvcSignals directly, no report object involved). The most urgent
    per-item decision wins; the driving id and rule are recorded so the verdict
    is explainable and auditable. With no items the decision is TRACK.
    """
    # Sentinel below Track's rank (0) so the FIRST CVE always registers, even
    # when the whole report is Track. Initializing at Track's rank would make
    # an all-Track report keep the "no-cves" sentinel rule and a null driver,
    # producing a "no CVEs were grounded" rationale that is simply false when
    # CVEs were present and merely scored Track.
    best_decision = SsvcDecision.TRACK
    best_rank = -1
    best_rule = "no-cves"
    driving_cve: str | None = None

    for vuln_id, signals in items:
        decision, rule = decide_for_signals(signals)
        rank = _DECISION_RANK[decision]
        if rank > best_rank:
            best_rank = rank
            best_decision = decision
            best_rule = rule
            driving_cve = vuln_id

    # driving_cve is None only when the loop never ran (no CVEs at all); any
    # CVE, including a Track one, sets it via the sentinel above.
    if driving_cve is None:
        rationale = (
            f"SSVC decision {best_decision.value}: no CVEs were grounded in this "
            "triage, so no active remediation signal is present."
        )
    else:
        reason = _RULE_RATIONALE.get(best_rule, best_rule)
        rationale = f"SSVC decision {best_decision.value}: {driving_cve} {reason}."
        if not _CVE_ID_RE.match(driving_cve):
            # The model's driving_cve field is CVE-shaped by contract. On the
            # SBOM-gate path the driver can be a non-CVE advisory id (GHSA-*,
            # PYSEC-*): it stays named in the rationale, the typed field goes
            # null. Unreachable on the triage path, where every id is a
            # CVEReference.cve_id.
            driving_cve = None

    return SsvcAssessment(
        decision=best_decision,
        rule=best_rule,
        rationale=rationale[:500],
        driving_cve=driving_cve,
    )


def assess_ssvc(cves: Iterable[CVEReference]) -> SsvcAssessment:
    """Reduce the report's CVEs to a single, most-urgent SSVC verdict.

    Thin adapter over assess_from_signals for the report shape; behavior is
    pinned bit-exact by the cassette replay gate.
    """
    return assess_from_signals((cve.cve_id, _signals_from_cve(cve)) for cve in cves)

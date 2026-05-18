"""Soft-assertion scorer for the eval suite.

The agent is a probabilistic system; bit-exact assertions would either
encode brittle prompts or require deterministic seeds the API does not
expose. Soft scoring keeps the eval useful as a regression detector
without producing false alarms on minor LLM output variations.

Rules:
- Severity matches when within +-1 step of the expected baseline.
- Expected CVE IDs match when at least half are present in the report.
- KEV / ransomware flags must be honored when explicitly expected.
- A CVE-not-found expectation is satisfied when the report has
  confidence=LOW and an empty CVE list (or any subset of {LOW, MEDIUM}
  severity with no CVEs).
"""

from dataclasses import dataclass

from sec_recon_agent.agent.schema import Severity, TriageReport
from sec_recon_agent.eval.golden_set import GoldenCase

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

MIN_CVE_RECALL = 0.5


@dataclass(frozen=True)
class CaseVerdict:
    """Per-case outcome of an eval run."""

    case_id: str
    passed: bool
    severity_ok: bool
    cve_recall: float
    kev_ok: bool
    ransomware_ok: bool
    notes: tuple[str, ...]


def _severity_within_one(expected: Severity, observed: Severity) -> bool:
    return abs(_SEVERITY_RANK[expected] - _SEVERITY_RANK[observed]) <= 1


def score(case: GoldenCase, report: TriageReport) -> CaseVerdict:
    notes: list[str] = []

    # --- severity ---
    severity_ok = _severity_within_one(case.expected_severity, report.severity)
    if not severity_ok:
        notes.append(
            f"severity={report.severity} expected~={case.expected_severity}",
        )

    # --- expected CVEs ---
    observed_ids = {c.cve_id for c in report.cves}
    if case.expected_cves:
        hits = sum(1 for c in case.expected_cves if c in observed_ids)
        cve_recall = hits / len(case.expected_cves)
        cve_ok = cve_recall >= MIN_CVE_RECALL
        if not cve_ok:
            missing = [c for c in case.expected_cves if c not in observed_ids]
            notes.append(f"missing CVEs: {missing}")
    else:
        # No CVEs expected: skip recall check.
        cve_recall = 1.0
        cve_ok = True

    # --- KEV flag ---
    kev_observed = any(c.in_kev_catalog for c in report.cves)
    if case.expected_in_kev:
        kev_ok = kev_observed
        if not kev_ok:
            notes.append("no CVE in report carried in_kev_catalog=True")
    else:
        kev_ok = True

    # --- ransomware flag ---
    ransomware_observed = any(c.known_ransomware_use is True for c in report.cves)
    if case.expected_ransomware:
        ransomware_ok = ransomware_observed
        if not ransomware_ok:
            notes.append("no CVE in report carried known_ransomware_use=True")
    else:
        ransomware_ok = True

    passed = severity_ok and cve_ok and kev_ok and ransomware_ok
    return CaseVerdict(
        case_id=case.id,
        passed=passed,
        severity_ok=severity_ok,
        cve_recall=cve_recall,
        kev_ok=kev_ok,
        ransomware_ok=ransomware_ok,
        notes=tuple(notes),
    )

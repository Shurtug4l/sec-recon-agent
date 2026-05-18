"""Unit tests for the eval scorer (pure logic, no LLM, no network)."""

from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    Severity,
    TriageReport,
)
from sec_recon_agent.eval.golden_set import GoldenCase
from sec_recon_agent.eval.scorer import score


def _cve(
    cve_id: str = "CVE-2021-41773",
    severity: Severity = Severity.CRITICAL,
    in_kev: bool = False,
    ransomware: bool | None = None,
) -> CVEReference:
    return CVEReference(
        cve_id=cve_id,
        summary="s",
        cvss_v3_score=9.0,
        severity=severity,
        exploits_public=False,
        affected_products=[],
        nvd_url="https://nvd.nist.gov/vuln/detail/" + cve_id,
        in_kev_catalog=in_kev,
        kev_due_date=None,
        known_ransomware_use=ransomware,
        epss_probability=None,
        epss_percentile=None,
    )


def _report(
    severity: Severity = Severity.CRITICAL,
    cves: list[CVEReference] | None = None,
) -> TriageReport:
    return TriageReport(
        summary="s",
        severity=severity,
        confidence=Confidence.HIGH,
        recommended_action="patch",
        cves=cves or [],
    )


def test_passes_when_severity_exact_match_and_cve_present() -> None:
    case = GoldenCase(
        id="t1",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2021-41773",),
    )
    report = _report(Severity.CRITICAL, [_cve("CVE-2021-41773")])
    verdict = score(case, report)
    assert verdict.passed is True
    assert verdict.cve_recall == 1.0


def test_passes_when_severity_within_one_step() -> None:
    case = GoldenCase(
        id="t2",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_cves=(),
    )
    report = _report(Severity.HIGH, [])
    verdict = score(case, report)
    assert verdict.passed is True
    assert verdict.severity_ok is True


def test_fails_when_severity_two_steps_off() -> None:
    case = GoldenCase(
        id="t3",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_cves=(),
    )
    report = _report(Severity.MEDIUM, [])
    verdict = score(case, report)
    assert verdict.passed is False
    assert verdict.severity_ok is False


def test_passes_with_half_cve_recall() -> None:
    case = GoldenCase(
        id="t4",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_cves=(
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
            "CVE-2024-0004",
        ),
    )
    report = _report(
        Severity.CRITICAL,
        [_cve("CVE-2024-0001"), _cve("CVE-2024-0003")],  # 50% recall, threshold
    )
    verdict = score(case, report)
    assert verdict.passed is True
    assert verdict.cve_recall == 0.5


def test_fails_below_half_cve_recall() -> None:
    case = GoldenCase(
        id="t5",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_cves=("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"),
    )
    report = _report(Severity.CRITICAL, [_cve("CVE-2024-0001")])  # 33%, below
    verdict = score(case, report)
    assert verdict.passed is False
    assert verdict.cve_recall < 0.5


def test_kev_flag_required_and_missing_fails() -> None:
    case = GoldenCase(
        id="t6",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_in_kev=True,
    )
    report = _report(Severity.CRITICAL, [_cve(in_kev=False)])
    verdict = score(case, report)
    assert verdict.passed is False
    assert verdict.kev_ok is False


def test_kev_flag_required_and_present_passes() -> None:
    case = GoldenCase(
        id="t7",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_in_kev=True,
    )
    report = _report(Severity.CRITICAL, [_cve(in_kev=True)])
    verdict = score(case, report)
    assert verdict.passed is True
    assert verdict.kev_ok is True


def test_ransomware_flag_required_and_missing_fails() -> None:
    case = GoldenCase(
        id="t8",
        query="q",
        expected_severity=Severity.CRITICAL,
        expected_ransomware=True,
    )
    report = _report(Severity.CRITICAL, [_cve(ransomware=False)])
    verdict = score(case, report)
    assert verdict.passed is False
    assert verdict.ransomware_ok is False


def test_no_expected_cves_does_not_require_any() -> None:
    case = GoldenCase(
        id="t9",
        query="q",
        expected_severity=Severity.INFO,
        expected_cves=(),
    )
    report = _report(Severity.LOW, [])
    verdict = score(case, report)
    assert verdict.passed is True
    assert verdict.cve_recall == 1.0

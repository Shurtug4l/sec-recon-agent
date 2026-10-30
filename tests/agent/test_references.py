"""Reference URLs are a pure function of the validated id."""

import pytest
from pydantic import HttpUrl

from sec_recon_agent.agent.references import (
    canonicalize_references,
    mitigation_url,
    nvd_url,
    technique_url,
)
from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    Severity,
    TriageReport,
)
from sec_recon_agent.mcp_server.models import AttackMitigation, AttackTechnique
from sec_recon_agent.mcp_server.tools.attack import _load_attack_data

_EVIL = HttpUrl("https://evil.example/phish")


def _report() -> TriageReport:
    return TriageReport(
        summary="s",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommended_action="a",
        cves=[
            CVEReference(
                cve_id="CVE-2021-41773",
                summary="s",
                severity=Severity.HIGH,
                exploits_public=False,
                nvd_url=_EVIL,
            )
        ],
        attack_techniques=[
            AttackTechnique(
                id="T1059.001",
                name="PowerShell",
                url=_EVIL,
                mitigations=[AttackMitigation(id="M1038", name="Execution Prevention", url=_EVIL)],
            )
        ],
    )


def test_every_reference_is_replaced() -> None:
    report = canonicalize_references(_report())
    assert str(report.cves[0].nvd_url) == "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    technique = report.attack_techniques[0]
    assert str(technique.url) == "https://attack.mitre.org/techniques/T1059/001/"
    assert str(technique.mitigations[0].url) == "https://attack.mitre.org/mitigations/M1038/"
    assert "evil.example" not in report.model_dump_json()


def test_the_report_stays_a_valid_report() -> None:
    report = canonicalize_references(_report())
    assert TriageReport.model_validate_json(report.model_dump_json()) == report


def test_canonical_forms_match_the_bundled_attack_data() -> None:
    """The derived URLs are the ones the tool itself returns, so a report that
    was already right comes through unchanged."""
    data = _load_attack_data()
    assert data["techniques"]
    for technique_id, technique in data["techniques"].items():
        assert technique["url"] == technique_url(technique_id)
    assert data["mitigations"]
    for mitigation_id, mitigation in data["mitigations"].items():
        assert mitigation["url"] == mitigation_url(mitigation_id)


@pytest.mark.parametrize(
    ("written", "kept"),
    [
        ("2021-12-24", "2021-12-24"),
        ("2021-12-24 ", "2021-12-24"),
        ("", None),
        (None, None),
        ("2021-12-24T00:00:00Z", None),
        ("![](https://evil.example/?d=secret)", None),
    ],
)
def test_only_a_date_survives_as_a_kev_due_date(written: str | None, kept: str | None) -> None:
    report = _report()
    report.cves[0].kev_due_date = written
    assert canonicalize_references(report).cves[0].kev_due_date == kept


def test_nvd_url_shape() -> None:
    assert nvd_url("CVE-2024-3094") == "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"

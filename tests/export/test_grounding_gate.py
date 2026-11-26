"""The exporters assert only what the grounding stamp backs.

A CVE becomes an OpenVEX "affected" statement only when grounding ran and
backed its identity; a flag on a signal field rides along in status_notes.
Otherwise it is "under_investigation" with the reason in status_notes. SARIF
keeps the severity level and labels every result.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from sec_recon_agent.agent.grounding import verify_grounding
from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    GroundingAssessment,
    GroundingClaim,
    GroundingClaimStatus,
    GroundingStatus,
    Severity,
    SsvcAssessment,
    SsvcBasis,
    SsvcDecision,
    TriageReport,
)
from sec_recon_agent.export.openvex import to_openvex
from sec_recon_agent.export.records import cve_grounding
from sec_recon_agent.export.sarif import to_sarif

_TS = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)
_PURL = "pkg:pypi/example@1.0.0"
_A = "CVE-2021-44228"
_B = "CVE-2021-45046"


def _cve(cve_id: str) -> CVEReference:
    return CVEReference(
        cve_id=cve_id,
        summary="Log4j2 JNDI lookup flaw.",
        cvss_v3_score=9.0,
        severity=Severity.CRITICAL,
        exploits_public=True,
        nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        in_kev_catalog=True,
    )


def _claim(subject: str, field: str, status: GroundingClaimStatus) -> GroundingClaim:
    return GroundingClaim(subject=subject, field=field, status=status)


def _report(
    grounding: GroundingAssessment | None, cves: tuple[str, ...] = (_A, _B)
) -> TriageReport:
    return TriageReport(
        summary="Log4j exposure.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        recommended_action="Upgrade log4j-core to 2.17.1.",
        cves=[_cve(c) for c in cves],
        grounding=grounding,
    )


def _suspect(*findings: GroundingClaim, truncated: bool = False) -> GroundingAssessment:
    return GroundingAssessment(
        status=GroundingStatus.SUSPECT,
        claims_checked=10,
        supported=10 - len(findings),
        mismatched=len(findings),
        findings=list(findings),
        truncated=truncated,
    )


def _statements(report: TriageReport) -> dict[str, dict[str, Any]]:
    doc = to_openvex(report, products=[_PURL], timestamp=_TS)
    return {s["vulnerability"]["name"]: s for s in doc["statements"]}


def _results(report: TriageReport) -> dict[str, dict[str, Any]]:
    doc = to_sarif(report, artifact_uri="report.json")
    return {r["ruleId"]: r for r in doc["runs"][0]["results"]}


def test_a_grounded_report_is_affected_and_labeled_verified() -> None:
    report = _report(GroundingAssessment(status=GroundingStatus.GROUNDED, claims_checked=4))
    for statement in _statements(report).values():
        assert statement["status"] == "affected"
        assert statement["action_statement"] == "Upgrade log4j-core to 2.17.1."
        assert "status_notes" not in statement
    for result in _results(report).values():
        assert result["properties"]["grounding"] == "verified"
        assert result["message"]["text"].startswith("Log4j2 JNDI lookup flaw.")


def test_an_unstamped_report_asserts_nothing() -> None:
    report = _report(None)
    for statement in _statements(report).values():
        assert statement["status"] == "under_investigation"
        assert "action_statement" not in statement
        assert statement["status_notes"].startswith("Not verified: the report carries no")
    for result in _results(report).values():
        assert result["properties"]["grounding"] == "unverified"
        assert result["message"]["text"].startswith("Not verified:")


def test_a_skipped_grounding_asserts_nothing() -> None:
    report = _report(GroundingAssessment(status=GroundingStatus.NOT_EVALUATED))
    statuses = {s["status"] for s in _statements(report).values()}
    assert statuses == {"under_investigation"}
    assert all(r["properties"]["grounding"] == "unverified" for r in _results(report).values())


def test_an_unbacked_identity_loses_its_assertion() -> None:
    report = _report(_suspect(_claim(_A, "cve_id", GroundingClaimStatus.UNBACKED)))
    statements = _statements(report)
    assert statements[_A]["status"] == "under_investigation"
    assert "action_statement" not in statements[_A]
    assert statements[_A]["status_notes"] == "Grounding flagged this CVE: cve_id unbacked."
    assert statements[_B]["status"] == "affected"
    results = _results(report)
    assert results[_A]["properties"]["grounding"] == "flagged"
    assert results[_B]["properties"]["grounding"] == "verified"


def test_a_signal_flag_keeps_the_assertion_and_carries_the_note() -> None:
    # The statement carries no KEV/EPSS/CVSS field; stripping it on a signal
    # flag would let injected tool text weaken a real CVE's statement.
    report = _report(_suspect(_claim(_A, "in_kev_catalog", GroundingClaimStatus.MISMATCH)))
    statement = _statements(report)[_A]
    assert statement["status"] == "affected"
    assert statement["action_statement"] == "Upgrade log4j-core to 2.17.1."
    assert statement["status_notes"] == "Grounding flagged this CVE: in_kev_catalog mismatch."
    assert _results(report)[_A]["properties"]["grounding"] == "flagged"


def test_a_flag_labels_the_sarif_result_without_lowering_its_level() -> None:
    flagged = _report(_suspect(_claim(_A, "cve_id", GroundingClaimStatus.UNBACKED)), cves=(_A,))
    result = _results(flagged)[_A]
    assert result["level"] == "error"
    assert result["message"]["text"].startswith("Grounding flagged this CVE: cve_id unbacked.")


@pytest.mark.parametrize("cve_id", ["CVE-2099-0001", "CVE-2099-" + "1" * 40])
def test_a_fabricated_id_the_verifier_flags_is_never_affected(cve_id: str) -> None:
    # The contract end to end: verifier output, not a hand-built finding.
    # The long id outruns the verifier's subject cap and must still match.
    report = _report(None, cves=(cve_id,))
    report = report.model_copy(update={"grounding": verify_grounding(report, [])})
    assert report.grounding is not None
    assert report.grounding.status is GroundingStatus.SUSPECT
    assert _statements(report)[cve_id]["status"] == "under_investigation"
    assert _results(report)[cve_id]["properties"]["grounding"] == "flagged"


def test_an_unverifiable_claim_does_not_flag_the_cve() -> None:
    # Evidence existed but could not be parsed: the verifier does not accuse.
    report = _report(
        GroundingAssessment(
            status=GroundingStatus.GROUNDED,
            claims_checked=4,
            supported=3,
            unverifiable=1,
            findings=[_claim(_A, "epss_probability", GroundingClaimStatus.UNVERIFIABLE)],
        )
    )
    assert _statements(report)[_A]["status"] == "affected"


def test_a_flag_on_another_subject_leaves_the_cves_asserted() -> None:
    report = _report(_suspect(_claim("T1190", "attack_technique", GroundingClaimStatus.UNBACKED)))
    assert {s["status"] for s in _statements(report).values()} == {"affected"}


def test_truncated_findings_leave_an_unlisted_cve_unverified() -> None:
    # Past the findings cap the CVE's own flag may be the one cut off.
    report = _report(
        _suspect(_claim(_A, "cvss_v3_score", GroundingClaimStatus.MISMATCH), truncated=True)
    )
    assert cve_grounding(report, _A).label == "flagged"
    unlisted = cve_grounding(report, _B)
    assert unlisted.label == "unverified"
    assert not unlisted.asserted
    assert unlisted.note == "Not verified: the grounding findings were truncated."


def test_the_note_names_a_bounded_number_of_fields() -> None:
    fields = [
        "cvss_v3_score",
        "in_kev_catalog",
        "kev_due_date",
        "epss_probability",
        "epss_percentile",
        "known_ransomware_use",
        "exploits_public",
    ]
    report = _report(
        _suspect(*(_claim(_A, f, GroundingClaimStatus.MISMATCH) for f in fields)), cves=(_A,)
    )
    note = cve_grounding(report, _A).note
    assert note is not None
    assert note.endswith("epss_percentile mismatch (+2 more).")
    assert "known_ransomware_use" not in note


def test_grounding_and_ssvc_notes_share_status_notes() -> None:
    ssvc = SsvcAssessment(
        decision=SsvcDecision.ACT,
        rule="kev-active-exploitation",
        rationale="on the CISA KEV catalog",
        driving_cve=_A,
        basis=SsvcBasis.EVIDENCE,
    )
    report = _report(None, cves=(_A,)).model_copy(update={"ssvc": ssvc})
    notes = _statements(report)[_A]["status_notes"]
    assert notes.startswith("Not verified:")
    assert notes.endswith("SSVC Act: on the CISA KEV catalog")


def test_an_id_seen_only_in_unparseable_output_is_not_asserted() -> None:
    report = _report(_suspect(_claim(_A, "cve_id", GroundingClaimStatus.UNVERIFIABLE)), cves=(_A,))
    statement = _statements(report)[_A]
    assert statement["status"] == "under_investigation"
    assert statement["status_notes"].startswith("Not verified: grounding could not read")
    assert _results(report)[_A]["properties"]["grounding"] == "unverified"


def test_a_repeated_cve_names_each_flag_once() -> None:
    flag = _claim(_A, "in_kev_catalog", GroundingClaimStatus.MISMATCH)
    report = _report(_suspect(flag, flag), cves=(_A, _A))
    assert cve_grounding(report, _A).note == (
        "Grounding flagged this CVE: in_kev_catalog mismatch."
    )

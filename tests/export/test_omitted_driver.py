"""A verdict resting on an omitted CVE reaches the documents, not just the JSON.

Stamp to consumer: code scanning builds alerts from SARIF results and a VEX
consumer reads statements, so a verdict left in a property bag says nothing.
"""

from datetime import UTC, datetime

from sec_recon_agent.agent.schema import Confidence, CVEReference, Severity, TriageReport
from sec_recon_agent.agent.ssvc import assess_ssvc
from sec_recon_agent.agent.trajectory import ToolInvocation
from sec_recon_agent.export.openvex import to_openvex
from sec_recon_agent.export.records import omitted_driver_record
from sec_recon_agent.export.sarif import to_sarif

_DROPPED = "CVE-2021-44228"
_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
_TS = datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)


def _stamped() -> TriageReport:
    """The attack: a report with no CVEs over a run where KEV listed one."""
    report = TriageReport(
        summary="Nothing to do.",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        recommended_action="No action needed.",
    )
    kev = ToolInvocation(
        tool_name="kev_check",
        tool_call_id="c1",
        args={"cve_id": _DROPPED},
        content={"cve_id": _DROPPED, "in_catalog": True},
        outcome="success",
    )
    return report.model_copy(update={"ssvc": assess_ssvc(report.cves, [kev])})


def test_sarif_gives_the_omitted_driver_a_result() -> None:
    run = to_sarif(_stamped(), artifact_uri="sbom.json")["runs"][0]
    assert [result["ruleId"] for result in run["results"]] == [_DROPPED]
    result = run["results"][0]
    assert "SSVC Act" in result["message"]["text"]
    assert result["properties"]["in_report"] is False
    # Unknown, not negative: the stamp does not carry the feed fields.
    assert result["properties"]["in_kev_catalog"] is None
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == f"https://nvd.nist.gov/vuln/detail/{_DROPPED}"


def test_openvex_says_under_investigation_not_affected() -> None:
    doc = to_openvex(_stamped(), products=[_PURL], timestamp=_TS)
    statement = doc["statements"][0]
    assert statement["vulnerability"]["name"] == _DROPPED
    assert statement["status"] == "under_investigation"
    assert "action_statement" not in statement
    assert "SSVC Act" in statement["status_notes"]


def _listed_driver() -> TriageReport:
    """A report that lists the CVE its stamped verdict rests on."""
    report = TriageReport(
        summary="Patch log4j.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        recommended_action="Upgrade log4j-core.",
        cves=[
            CVEReference(
                cve_id=_DROPPED,
                summary="Log4Shell RCE.",
                severity=Severity.CRITICAL,
                in_kev_catalog=True,
                exploits_public=False,
                nvd_url=f"https://nvd.nist.gov/vuln/detail/{_DROPPED}",
            ),
        ],
    )
    kev = ToolInvocation(
        tool_name="kev_check",
        tool_call_id="c1",
        args={"cve_id": _DROPPED},
        content={"cve_id": _DROPPED, "in_catalog": True},
        outcome="success",
    )
    stamped = report.model_copy(update={"ssvc": assess_ssvc(report.cves, [kev])})
    assert stamped.ssvc is not None
    assert stamped.ssvc.driving_cve == _DROPPED
    return stamped


def test_a_listed_driver_adds_nothing() -> None:
    report = _listed_driver()
    assert omitted_driver_record(report) is None
    results = to_sarif(report, artifact_uri="sbom.json")["runs"][0]["results"]
    assert [result["ruleId"] for result in results] == [_DROPPED]
    assert "in_report" not in results[0]["properties"]
    statements = to_openvex(report, products=[_PURL], timestamp=_TS)["statements"]
    assert [s["vulnerability"]["name"] for s in statements] == [_DROPPED]
    assert statements[0]["status"] == "affected"

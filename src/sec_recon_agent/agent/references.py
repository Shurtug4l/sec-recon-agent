"""Canonical reference URLs, derived from validated ids.

`nvd_url`, `AttackTechnique.url` and `AttackMitigation.url` are model-written
and only shaped as `HttpUrl`: grounding does not check them, so a prompt
injection could point a report's reference anywhere and every sink would carry
it (SARIF `helpUri`, the OpenVEX vulnerability `@id`, the Markdown export). The
ids are pattern-validated by the schema, so the URLs carry no information of
their own: derive them. Same authority pattern as `ssvc` and `grounding`, the
model's value never survives.

`kev_due_date` is the same exposure with no id to derive from: a bare `str`
that consumers print as a date. Anything that is not one is dropped. Grounding
runs on the report as the model wrote it, so the claim is still judged.

No schema or prompt change, so the record-replay staleness hash is untouched.
"""

import re

from pydantic import HttpUrl

from sec_recon_agent.agent.schema import CVEReference, TriageReport
from sec_recon_agent.mcp_server.models import AttackMitigation, AttackTechnique

NVD_DETAIL = "https://nvd.nist.gov/vuln/detail"
ATTACK_TECHNIQUES = "https://attack.mitre.org/techniques"
ATTACK_MITIGATIONS = "https://attack.mitre.org/mitigations"

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def nvd_url(cve_id: str) -> str:
    return f"{NVD_DETAIL}/{cve_id}"


def technique_url(technique_id: str) -> str:
    # A sub-technique T1059.001 lives at /techniques/T1059/001/.
    return f"{ATTACK_TECHNIQUES}/{technique_id.replace('.', '/')}/"


def mitigation_url(mitigation_id: str) -> str:
    return f"{ATTACK_MITIGATIONS}/{mitigation_id}/"


def _canonical_due_date(value: str | None) -> str | None:
    due = value.strip() if value else None
    return due if due and _ISO_DATE.fullmatch(due) else None


def _canonical_cve(cve: CVEReference) -> CVEReference:
    return cve.model_copy(
        update={
            "nvd_url": HttpUrl(nvd_url(cve.cve_id)),
            "kev_due_date": _canonical_due_date(cve.kev_due_date),
        }
    )


def _canonical_mitigation(mitigation: AttackMitigation) -> AttackMitigation:
    return mitigation.model_copy(update={"url": HttpUrl(mitigation_url(mitigation.id))})


def _canonical_technique(technique: AttackTechnique) -> AttackTechnique:
    return technique.model_copy(
        update={
            "url": HttpUrl(technique_url(technique.id)),
            "mitigations": [_canonical_mitigation(m) for m in technique.mitigations],
        }
    )


def canonicalize_references(report: TriageReport) -> TriageReport:
    """The report with every reference URL replaced by its derived form."""
    return report.model_copy(
        update={
            "cves": [_canonical_cve(c) for c in report.cves],
            "attack_techniques": [_canonical_technique(t) for t in report.attack_techniques],
        }
    )

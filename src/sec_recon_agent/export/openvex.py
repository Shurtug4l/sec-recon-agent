"""OpenVEX v0.2.0 renderer.

Core (`render_openvex`) is a pure function over neutral VulnRecord rows;
`to_openvex` is the TriageReport adapter and keeps the public signature and
byte-for-byte output it had before the SBOM gate landed. The document `@id`
follows the reference-tooling convention
(`https://openvex.dev/docs/public/vex-<sha256>` over the canonicalized
content), so identical inputs produce an identical document, `@id` included.

Product identity is never fabricated. A standalone OpenVEX statement
without products is invalid, and the triage report does not carry the
queried package's identity - so the triage caller must supply the purl(s)
of the triaged product. The SBOM gate derives them mechanically from the
SBOM and binds each statement to the affected component's own purl. A
bare-CVE triage has no trustworthy product identity: the export refuses
with a typed error instead of guessing one.

Status posture: every vulnerability kept by a producer was confirmed
relevant to its product by the feeds, so statements are emitted as
"affected" with the producer's remediation text as the action_statement
(the spec prose makes it mandatory for that status). The status never
derives from the LLM's confidence field: affectedness is not an LLM
verdict in this codebase, and "not_affected" reachability analysis is out
of scope.
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.export.records import VulnRecord

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
DEFAULT_AUTHOR = "https://github.com/Shurtug4l/sec-recon-agent"

_ID_NAMESPACE = "https://openvex.dev/docs/public/vex-"


class ProductIdentityError(ValueError):
    """OpenVEX export needs at least one purl identifying the affected product."""


def _validated_purls(products: Sequence[str]) -> list[str]:
    purls = [p.strip() for p in products]
    if not purls or any(not p for p in purls):
        raise ProductIdentityError(
            "OpenVEX statements require at least one product purl; a bare-CVE "
            "triage has no trustworthy product identity to attest about"
        )
    malformed = [p for p in purls if not p.startswith("pkg:")]
    if malformed:
        raise ProductIdentityError(
            f"product identifiers must be purls (pkg:<type>/...): {malformed}"
        )
    return purls


def render_openvex(
    records: Sequence[VulnRecord],
    *,
    timestamp: datetime,
    author: str = DEFAULT_AUTHOR,
    doc_version: int = 1,
) -> dict[str, Any]:
    """Render neutral records as a standalone OpenVEX v0.2.0 document.

    One "affected" statement per record, bound to that record's product
    purl(s); producers own deduplication. `timestamp` must be timezone-aware
    and is the only non-content input that varies the document `@id`.
    """
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")

    statements: list[dict[str, Any]] = []
    for record in records:
        purls = _validated_purls(record.products)
        statement: dict[str, Any] = {
            "vulnerability": {
                "@id": record.url,
                "name": record.rule_id,
                "description": record.summary,
            },
            "products": [{"@id": p, "identifiers": {"purl": p}} for p in purls],
            "status": "affected",
            "action_statement": record.action,
        }
        if record.ssvc_note is not None:
            statement["status_notes"] = record.ssvc_note
        statements.append(statement)

    body: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "author": author,
        "timestamp": timestamp.isoformat(),
        "version": doc_version,
        "statements": statements,
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"@id": f"{_ID_NAMESPACE}{digest}", **body}


def to_openvex(
    report: TriageReport,
    *,
    products: Sequence[str],
    timestamp: datetime,
    author: str = DEFAULT_AUTHOR,
    doc_version: int = 1,
) -> dict[str, Any]:
    """Render the report as a standalone OpenVEX v0.2.0 document.

    TriageReport adapter over render_openvex: one "affected" statement per
    distinct CVE, all bound to the supplied product purl(s).
    """
    purls = tuple(_validated_purls(products))
    ssvc_note: str | None = None
    if report.ssvc is not None:
        ssvc_note = f"SSVC {report.ssvc.decision}: {report.ssvc.rationale}"

    records: list[VulnRecord] = []
    seen: set[str] = set()
    for cve in report.cves:
        if cve.cve_id in seen:
            continue
        seen.add(cve.cve_id)
        records.append(
            VulnRecord(
                rule_id=cve.cve_id,
                summary=cve.summary,
                severity=cve.severity,
                cvss_score=cve.cvss_v3_score,
                url=str(cve.nvd_url),
                action=report.recommended_action,
                in_kev=cve.in_kev_catalog,
                kev_due_date=cve.kev_due_date,
                known_ransomware=cve.known_ransomware_use,
                exploit_public=cve.exploits_public,
                epss_probability=cve.epss_probability,
                epss_percentile=cve.epss_percentile,
                ssvc_note=ssvc_note,
                products=purls,
            )
        )
    return render_openvex(records, timestamp=timestamp, author=author, doc_version=doc_version)

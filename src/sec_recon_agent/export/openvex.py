"""TriageReport -> OpenVEX v0.2.0 renderer.

Pure function of (report, products, timestamp, author, doc_version). The
document `@id` follows the reference-tooling convention
(`https://openvex.dev/docs/public/vex-<sha256>` over the canonicalized
content), so identical inputs produce an identical document, `@id`
included.

Product identity is never fabricated. A standalone OpenVEX statement
without products is invalid, and the report does not carry the queried
package's identity - so the caller must supply the purl(s) of the triaged
product (whoever ran a package/SBOM-sourced triage has them; the SBOM gate
derives them mechanically from the SBOM). A bare-CVE triage has no
trustworthy product identity: the export refuses with a typed error
instead of guessing one.

Status posture: every CVE kept in the report was confirmed relevant to
the queried product by the feeds, so statements are emitted as "affected"
with the report's recommended_action as the action_statement (the spec
prose makes it mandatory for that status). The status never derives from
the LLM's confidence field: affectedness is not an LLM verdict in this
codebase, and "not_affected" reachability analysis is out of scope for a
stateless triage tool.
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sec_recon_agent.agent.schema import TriageReport

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
DEFAULT_AUTHOR = "https://github.com/Shurtug4l/sec-recon-agent"

_ID_NAMESPACE = "https://openvex.dev/docs/public/vex-"


class ProductIdentityError(ValueError):
    """OpenVEX export needs at least one purl identifying the triaged product."""


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


def to_openvex(
    report: TriageReport,
    *,
    products: Sequence[str],
    timestamp: datetime,
    author: str = DEFAULT_AUTHOR,
    doc_version: int = 1,
) -> dict[str, Any]:
    """Render the report as a standalone OpenVEX v0.2.0 document.

    One "affected" statement per distinct CVE, all bound to the supplied
    product purl(s). `timestamp` must be timezone-aware and is the only
    non-content input that varies the document `@id`.
    """
    purls = _validated_purls(products)
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")

    product_entries = [{"@id": p, "identifiers": {"purl": p}} for p in purls]

    statements: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cve in report.cves:
        if cve.cve_id in seen:
            continue
        seen.add(cve.cve_id)
        statement: dict[str, Any] = {
            "vulnerability": {
                "@id": str(cve.nvd_url),
                "name": cve.cve_id,
                "description": cve.summary,
            },
            "products": product_entries,
            "status": "affected",
            "action_statement": report.recommended_action,
        }
        if report.ssvc is not None:
            statement["status_notes"] = f"SSVC {report.ssvc.decision}: {report.ssvc.rationale}"
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

"""MITRE ATT&CK technique mapping from CWE IDs.

Static mapping loaded from `data/mitre_attack.json` once at import time.
The data is a curated subset of the MITRE ATT&CK CWE-to-technique
mapping covering the patterns most commonly seen in CRITICAL+HIGH CVEs.

Not exhaustive: a CWE without a mapping returns no technique rather
than a wrong one. The transparency tab surfaces this contract.
"""

import json
import threading
from importlib import resources
from typing import Any

import structlog

from sec_recon_agent.mcp_server.models import AttackMitigation, AttackTechnique
from sec_recon_agent.mcp_server.server import mcp
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

MAX_TECHNIQUES_RETURNED = 20

_attack_data: dict[str, Any] | None = None
_attack_data_lock = threading.Lock()


def _load_attack_data() -> dict[str, Any]:
    """Load the bundled ATT&CK mapping. Double-checked locking so two
    concurrent first-callers cannot race on the JSON parse."""
    global _attack_data
    if _attack_data is not None:
        return _attack_data
    with _attack_data_lock:
        if _attack_data is not None:
            return _attack_data
        raw = resources.files("sec_recon_agent.mcp_server.data").joinpath(
            "mitre_attack.json",
        ).read_text(encoding="utf-8")
        _attack_data = json.loads(raw)
        log.info(
            "mitre_attack_loaded",
            techniques=len(_attack_data["techniques"]),
            mitigations=len(_attack_data["mitigations"]),
            cwe_mappings=len(_attack_data["cwe_to_technique"]),
        )
        return _attack_data


def _build_technique(
    technique_id: str,
    data: dict[str, Any],
    related_cwes: list[str],
) -> AttackTechnique | None:
    technique = data["techniques"].get(technique_id)
    if technique is None:
        return None
    mitigations: list[AttackMitigation] = []
    for mitigation_id in technique.get("mitigations", []):
        m = data["mitigations"].get(mitigation_id)
        if m is not None:
            mitigations.append(
                AttackMitigation(id=mitigation_id, name=m["name"], url=m["url"]),
            )
    return AttackTechnique(
        id=technique_id,
        name=technique["name"],
        tactics=technique.get("tactics", []),
        url=technique["url"],
        mitigations=mitigations,
        related_cwes=related_cwes,
    )


@mcp.tool()
def attack_mapping(cwe_ids: list[str]) -> list[AttackTechnique]:
    """Map a set of CWE IDs to MITRE ATT&CK techniques and their mitigations.

    Each input CWE (e.g. "CWE-22") is looked up in a curated CWE-to-technique
    table. The returned list contains each matching technique once, annotated
    with which of the input CWEs led to the match and the associated MITRE
    mitigations (M-IDs with names and URLs).

    CWEs without a known mapping are silently skipped; a triage that returns
    an empty technique list means none of the CVE's CWEs are in the curated
    mapping table (transparent: the data file is shipped with the repo and
    versioned).
    """
    with _tracer.start_as_current_span("tool.attack_mapping") as span:
        span.set_attribute("tool.name", "attack_mapping")
        span.set_attribute("cwe.count", len(cwe_ids))
        # CWE IDs are short, ASCII, regex-bounded by Pydantic upstream;
        # safe to record as an attribute for operational visibility.
        span.set_attribute("cwe.ids", ",".join(cwe_ids[:10]))

        try:
            data = _load_attack_data()
            cwe_to_technique: dict[str, list[str]] = data["cwe_to_technique"]

            # technique_id -> set of CWE IDs that led to it
            buckets: dict[str, list[str]] = {}
            for raw in cwe_ids:
                cwe = raw.strip()
                if not cwe.startswith("CWE-"):
                    continue
                for technique_id in cwe_to_technique.get(cwe, []):
                    buckets.setdefault(technique_id, [])
                    if cwe not in buckets[technique_id]:
                        buckets[technique_id].append(cwe)

            techniques: list[AttackTechnique] = []
            for technique_id, related in buckets.items():
                built = _build_technique(technique_id, data, related)
                if built is not None:
                    techniques.append(built)
            # Stable order: most-related-CWEs first, then by technique ID
            techniques.sort(key=lambda t: (-len(t.related_cwes), t.id))
            techniques = techniques[:MAX_TECHNIQUES_RETURNED]
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        span.set_attribute("tool.success", True)
        span.set_attribute("attack.techniques_count", len(techniques))
        log.info(
            "attack_mapping_done",
            input_cwes=len(cwe_ids),
            techniques=len(techniques),
        )
        return techniques

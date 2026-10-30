"""frontend/src/lib/shared-report.ts mirrors the report schema by hand.

It rejects what it does not recognize, so a value added here and not there is a
silent share outage: every report carrying it stops minting and stops reading.
The frontend's own tests cannot see that, since no capture holds the new value.
"""

import re
from enum import StrEnum
from pathlib import Path

import pytest
from annotated_types import MaxLen
from pydantic import BaseModel

from sec_recon_agent.agent.schema import (
    Confidence,
    CVEReference,
    FeedStatus,
    GroundingAssessment,
    GroundingClaim,
    GroundingClaimStatus,
    GroundingStatus,
    Severity,
    SignalStatus,
    SsvcAssessment,
    SsvcBasis,
    SsvcDecision,
    TriageReport,
)
from sec_recon_agent.mcp_server.models import AttackTechnique

SOURCE = (Path(__file__).parents[1] / "frontend/src/lib/shared-report.ts").read_text()


def _max_length(model: type[BaseModel], field: str) -> int:
    lengths = [m.max_length for m in model.model_fields[field].metadata if isinstance(m, MaxLen)]
    assert lengths, f"{model.__name__}.{field} has no max_length"
    return lengths[0]


def _builder(name: str) -> str:
    match = re.search(rf"^(?:export )?function {name}\(.*?^}}$", SOURCE, re.S | re.M)
    assert match, f"no builder {name} in shared-report.ts"
    return match.group(0)


@pytest.mark.parametrize(
    ("constant", "enum"),
    [
        ("SEVERITIES", Severity),
        ("CONFIDENCES", Confidence),
        ("SSVC_DECISIONS", SsvcDecision),
        ("SSVC_BASES", SsvcBasis),
        ("SIGNAL_STATUSES", SignalStatus),
        ("GROUNDING_STATUSES", GroundingStatus),
        ("CLAIM_STATUSES", GroundingClaimStatus),
    ],
)
def test_enums_match_the_schema(constant: str, enum: type[StrEnum]) -> None:
    match = re.search(rf"const {constant} = \[(.*?)\] as const", SOURCE)
    assert match, f"no {constant} in shared-report.ts"
    assert set(re.findall(r'"([^"]+)"', match.group(1))) == {member.value for member in enum}


@pytest.mark.parametrize(
    ("builder", "model", "field"),
    [
        ("parseReport", TriageReport, "summary"),
        ("parseReport", TriageReport, "recommended_action"),
        ("parseReport", TriageReport, "cves"),
        ("parseReport", TriageReport, "attack_techniques"),
        ("parseReport", TriageReport, "signal_coverage"),
        ("cveReference", CVEReference, "summary"),
        ("cveReference", CVEReference, "affected_products"),
        ("attackTechnique", AttackTechnique, "tactics"),
        ("attackTechnique", AttackTechnique, "mitigations"),
        ("attackTechnique", AttackTechnique, "related_cwes"),
        ("ssvcAssessment", SsvcAssessment, "rule"),
        ("ssvcAssessment", SsvcAssessment, "rationale"),
        ("ssvcAssessment", SsvcAssessment, "unverified_signals"),
        ("feedStatus", FeedStatus, "feed"),
        ("feedStatus", FeedStatus, "detail"),
        ("groundingClaim", GroundingClaim, "subject"),
        ("groundingClaim", GroundingClaim, "field"),
        ("groundingClaim", GroundingClaim, "detail"),
        ("groundingAssessment", GroundingAssessment, "findings"),
    ],
)
def test_caps_match_the_schema(builder: str, model: type[BaseModel], field: str) -> None:
    match = re.search(rf"\(v\.{field}, ([\d_]+)", _builder(builder))
    assert match, f"{builder} does not cap {field}"
    assert int(match.group(1)) == _max_length(model, field)

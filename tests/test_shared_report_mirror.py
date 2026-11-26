"""frontend/src/lib/shared-report.ts mirrors the report schema by hand.

It rejects what it does not recognize, so a value added here and not there is a
silent share outage: every report carrying it stops minting and stops reading.
The frontend's own tests cannot see that, since no capture holds the new value.
"""

import re
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import pytest
from annotated_types import MaxLen
from pydantic import BaseModel, TypeAdapter, ValidationError

from sec_recon_agent.agent.references import _ISO_DATE, _canonical_due_date
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
from sec_recon_agent.mcp_server.models import AttackMitigation, AttackTechnique

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


# Patterns shared-report.ts re-implements. A value the server keeps and the
# decoder rejects fails the whole report, so the two must agree on what they
# accept, digit class included: JS \d is [0-9] by spec, Python's \d (re and
# pydantic-core alike) matches every Unicode decimal digit.
_ID_FIELDS = [
    ("CVE_ID", CVEReference, "cve_id", "CVE-2021-41773"),
    ("CVE_ID", SsvcAssessment, "driving_cve", "CVE-2021-41773"),
    ("TECHNIQUE_ID", AttackTechnique, "id", "T1059.001"),
    ("MITIGATION_ID", AttackMitigation, "id", "M1038"),
]
_DIGIT_ZEROS = [0x0660, 0x0966, 0xFF10]  # Arabic-Indic, Devanagari, fullwidth


def _ts_pattern(constant: str) -> str:
    # No flags after the closing slash: an `i` or `u` would change what it matches.
    match = re.search(rf"^const {constant} = /(.*)/;$", SOURCE, re.M)
    assert match, f"no {constant} in shared-report.ts"
    return match.group(1)


def _schema_pattern(model: type[BaseModel], field: str) -> str:
    info = model.model_fields[field]
    schema = TypeAdapter(Annotated[info.annotation, info]).json_schema()
    branches = schema.get("anyOf", [schema])
    patterns = [b["pattern"] for b in branches if "pattern" in b]
    assert len(patterns) == 1, f"{model.__name__}.{field} has no single pattern"
    return str(patterns[0])


def _shape(pattern: str) -> str:
    """The pattern with anchors dropped and both digit spellings unified.

    The digit class is not equal across the two spellings: the digit tests below
    check what each side accepts.
    """
    return pattern.removeprefix("^").removesuffix("$").replace("[0-9]", r"\d")


def _decoder_keeps(constant: str) -> Callable[[str], bool]:
    source = _ts_pattern(constant)
    assert source.startswith("^") and source.endswith("$"), f"{constant} is not anchored"
    # JS semantics: \d is ASCII and an unflagged $ is the end of the input only.
    compiled = re.compile(source.removesuffix("$") + r"\Z", re.ASCII)
    return lambda value: compiled.match(value) is not None


def _schema_keeps(model: type[BaseModel], field: str) -> Callable[[str], bool]:
    info = model.model_fields[field]
    adapter: TypeAdapter[Any] = TypeAdapter(Annotated[info.annotation, info])

    def keeps(value: str) -> bool:
        try:
            adapter.validate_python(value)
        except ValidationError:
            return False
        return True

    return keeps


def _probes(valid: str) -> list[str]:
    return [valid] + [
        valid.translate({ord("0") + n: zero + n for n in range(10)}) for zero in _DIGIT_ZEROS
    ]


@pytest.mark.parametrize(
    ("constant", "model", "field"),
    [(constant, model, field) for constant, model, field, _ in _ID_FIELDS],
)
def test_id_patterns_match_the_schema(constant: str, model: type[BaseModel], field: str) -> None:
    assert _shape(_ts_pattern(constant)) == _shape(_schema_pattern(model, field))


def test_date_pattern_matches_the_server() -> None:
    assert _shape(_ts_pattern("ISO_DATE")) == _shape(_ISO_DATE.pattern)


@pytest.mark.parametrize(
    ("constant", "model", "field", "valid"),
    _ID_FIELDS,
)
def test_id_digits_match_the_schema(
    constant: str, model: type[BaseModel], field: str, valid: str
) -> None:
    decoder, server = _decoder_keeps(constant), _schema_keeps(model, field)
    assert decoder(valid) and server(valid)
    assert {p: server(p) for p in _probes(valid)} == {p: decoder(p) for p in _probes(valid)}


def test_date_digits_match_the_server() -> None:
    decoder = _decoder_keeps("ISO_DATE")
    valid = "2021-12-24"
    assert decoder(valid) and _canonical_due_date(valid) == valid
    assert {p: _canonical_due_date(p) == p for p in _probes(valid)} == {
        p: decoder(p) for p in _probes(valid)
    }

"""Typed models for the deterministic SBOM gate.

GateReport is a sibling of TriageReport, not a variant of it: no LLM-authored
fields (summary, confidence), no 10-CVE cap, and per-(component, advisory)
granularity. It lives outside agent/schema.py on purpose - the record-replay
staleness hash covers the LLM-visible TriageReport schema, and the gate must
be able to evolve without forcing a cassette re-record.

Honesty posture mirrors the triage report's signal_coverage: every finding
carries per-feed coverage so a missing signal is visibly missing, never a
silent False.
"""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from sec_recon_agent.agent.schema import (
    CveIdStr,
    Severity,
    SsvcAssessment,
    SsvcDecision,
)


class SkipReason(StrEnum):
    """Why a component never reached OSV."""

    NO_VERSION = "no_version"
    NO_ECOSYSTEM = "no_ecosystem"
    UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"
    OSV_ERROR = "osv_error"


class SkippedComponent(BaseModel):
    """A component the gate could not scan, and why. Never dropped silently."""

    name: str = Field(max_length=200)
    version: str | None = Field(default=None, max_length=100)
    ecosystem: str | None = Field(default=None, max_length=40)
    reason: SkipReason
    detail: str | None = Field(default=None, max_length=500)


class FeedCoverage(StrEnum):
    """Per-feed enrichment outcome for one finding.

    OK: the feed answered authoritatively for this advisory.
    NOT_FOUND: the feed answered and has no entry (a real answer, EPSS only).
    NOT_APPLICABLE: the advisory has no CVE id, so a CVE-keyed feed cannot
        apply to it by construction.
    SKIPPED: deliberately not queried because the decision was already fixed
        at Act by KEV membership (the exploit signal cannot escalate further);
        saves the rate-limited GitHub search arm on large SBOMs.
    DEGRADED: partial answer (exploit check ran without GITHUB_TOKEN: only
        the ExploitDB arm was consulted).
    ERROR: the feed was reached but unusable, or the lookup raised.
    """

    OK = "ok"
    NOT_FOUND = "not_found"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    ERROR = "error"


class FindingCoverage(BaseModel):
    """Which enrichment feeds actually backed this finding's signals."""

    kev: FeedCoverage
    epss: FeedCoverage
    exploits: FeedCoverage


class GateFinding(BaseModel):
    """One (component, advisory) pair with its signals and SSVC decision.

    `osv_id` is the OSV-native advisory id (GHSA-*, PYSEC-*, or a CVE-*);
    `cve_id` is the CVE alias used for KEV/EPSS/exploit enrichment, None when
    the advisory has no CVE cross-reference (those findings can still gate on
    severity). `summary` is upstream-authored text and arrives fenced from
    the tool boundary; it is passed through verbatim.
    """

    component_name: str = Field(max_length=200)
    component_version: str = Field(max_length=100)
    component_ecosystem: str = Field(max_length=40)
    component_purl: str | None = Field(default=None, max_length=500)
    osv_id: str = Field(max_length=100)
    cve_id: CveIdStr | None = None
    aliases: list[str] = Field(default_factory=list, max_length=20)
    summary: str | None = Field(default=None, max_length=1050)
    severity: Severity | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    fixed_version: str | None = Field(default=None, max_length=100)
    reference_url: str = Field(max_length=300)
    in_kev: bool = False
    kev_due_date: str | None = None
    known_ransomware_use: bool | None = None
    exploits_public: bool = False
    epss_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    decision: SsvcDecision
    rule: str = Field(max_length=100)
    coverage: FindingCoverage


FailOn = Literal["act", "attend", "track_star", "never"]


class GatePolicy(BaseModel):
    """The policy evaluation: what was asked, what triggered, the verdict.

    `triggered` lists the advisory ids whose SSVC decision met or exceeded
    the `fail_on` threshold. `coverage_gaps` counts findings with an ERROR
    feed plus components skipped on OSV errors; under `strict` any gap fails
    the gate even with zero triggered findings (a gate that cannot see is
    not a passing gate).
    """

    fail_on: FailOn
    strict: bool = False
    triggered: list[str] = Field(default_factory=list)
    coverage_gaps: int = Field(default=0, ge=0)
    passed: bool


class GateReport(BaseModel):
    """Full deterministic output of one SBOM gate run."""

    schema_version: int = 1
    sbom_format: str = Field(max_length=40)
    components_total: int = Field(ge=0)
    components_scanned: int = Field(ge=0)
    sbom_truncated: bool = False
    skipped: list[SkippedComponent] = Field(default_factory=list)
    findings: list[GateFinding] = Field(default_factory=list)
    ssvc: SsvcAssessment
    policy: GatePolicy
    tool_version: str = Field(max_length=40)

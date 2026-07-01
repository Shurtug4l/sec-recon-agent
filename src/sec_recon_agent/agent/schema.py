"""Agent output contracts. The public surface returned to API clients."""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field, HttpUrl

from sec_recon_agent.mcp_server.models import AttackTechnique

CveIdStr = Annotated[
    str,
    Field(pattern=r"^CVE-\d{4}-\d{4,}$", examples=["CVE-2021-41773"]),
]


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SsvcDecision(StrEnum):
    """CISA SSVC outcome vocabulary (Stakeholder-Specific Vulnerability
    Categorization), ordered most- to least-urgent.

    ACT: remediate out-of-cycle, as fast as possible.
    ATTEND: remediate sooner than standard timelines; needs supervisor attention.
    TRACK_STAR: remediate within standard timelines, but monitor closely for
        signal changes that would escalate the decision.
    TRACK: no action beyond standard update timelines.

    This project derives the decision deterministically from the signals the
    agent actually collects (KEV / EPSS / public-exploit / ransomware / CVSS).
    It is SSVC-informed, not the full CISA tree: the CISA "Automatable" and
    "Mission & Well-being" decision points are approximated (EPSS stands in for
    exploitation likelihood / automatability; deployment-specific mission
    context is out of scope for a stateless triage tool). See agent/ssvc.py.
    """

    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"


class SsvcAssessment(BaseModel):
    """Deterministic prioritization verdict stamped onto the report server-side.

    NOT produced by the LLM: computed by agent/ssvc.py from the report's CVE
    signals so the verdict is reproducible from the same inputs. The LLM echoes
    the resulting decision in `recommended_action` prose; this structured field
    is the authoritative machine-readable form and the one downstream consumers
    (scorecard, audit) trust.
    """

    decision: SsvcDecision
    rule: str = Field(
        max_length=64,
        description="Stable identifier of the decision rule that fired (for audit / regression).",
    )
    rationale: str = Field(
        max_length=500,
        description="One-sentence human explanation of why this decision was reached.",
    )
    driving_cve: CveIdStr | None = Field(
        default=None,
        description="The CVE whose signals drove the report-level decision, when applicable.",
    )


class SignalStatus(StrEnum):
    """Per-feed coverage status, so the report is honest about what it checked.

    FOUND: the feed was queried and returned data for the CVE.
    NOT_FOUND: the feed was queried successfully but has no entry for the CVE
        (a real answer, not a failure: e.g. a CVE absent from the EPSS dataset).
    ERROR: the feed could not be consulted (timeout, 5xx, malformed response).
    NOT_QUERIED: the feed was not consulted for this triage.
    """

    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    NOT_QUERIED = "not_queried"


class FeedStatus(BaseModel):
    """Coverage of one external signal feed for this triage."""

    feed: str = Field(
        max_length=40,
        description="Feed identifier: nvd | kev | epss | exploit | osv | attack | semantic_search.",
    )
    status: SignalStatus
    detail: str | None = Field(
        default=None,
        max_length=200,
        description="Optional short note (e.g. which CVE was not_found, or the error class).",
    )


class CVEReference(BaseModel):
    """A single CVE included in the triage report."""

    cve_id: CveIdStr
    summary: str = Field(max_length=1000)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Severity
    exploits_public: bool
    affected_products: list[str] = Field(default_factory=list, max_length=20)
    nvd_url: HttpUrl
    in_kev_catalog: bool = Field(
        default=False,
        description=(
            "True when CISA KEV reports the CVE as actively exploited "
            "in the wild. Highest-priority remediation signal."
        ),
    )
    kev_due_date: str | None = Field(
        default=None,
        description=(
            "ISO date by which CISA requires federal agencies to remediate. "
            "Set only when in_kev_catalog is True."
        ),
    )
    known_ransomware_use: bool | None = Field(
        default=None,
        description=(
            "CISA-reported association with known ransomware campaigns. "
            "None when KEV did not provide the flag."
        ),
    )
    epss_probability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "EPSS probability of exploitation in the next 30 days. "
            "None when the CVE is not in the EPSS dataset."
        ),
    )
    epss_percentile: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="EPSS rank relative to all scored CVEs.",
    )


class TriageReport(BaseModel):
    """Structured agent output. Single source of truth returned over SSE."""

    summary: str = Field(max_length=500)
    severity: Severity
    confidence: Confidence
    recommended_action: str = Field(max_length=500)
    cves: list[CVEReference] = Field(default_factory=list, max_length=10)
    attack_techniques: list[AttackTechnique] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "MITRE ATT&CK techniques mapped from the CVEs' CWE IDs via the "
            "attack_mapping tool. Empty when no CWEs matched the curated table."
        ),
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
        description="Ordered audit log of tool calls and intermediate decisions",
    )
    ssvc: SsvcAssessment | None = Field(
        default=None,
        description=(
            "Deterministic SSVC prioritization verdict (Act / Attend / Track* / "
            "Track). Computed server-side from the CVE signals AFTER the model "
            "returns; leave this null. The recommended_action prose should echo "
            "the decision."
        ),
    )
    signal_coverage: list[FeedStatus] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Per-feed coverage honesty: for each external feed consulted, whether "
            "it returned data (found), was queried but had no entry (not_found), "
            "or could not be reached (error). Never imply a signal was checked "
            "clean when the feed errored or was not queried."
        ),
    )

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

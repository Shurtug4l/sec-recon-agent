"""I/O contracts for MCP tools. Every tool returns a typed Pydantic model."""

from typing import Annotated

from pydantic import BaseModel, Field, HttpUrl

CveIdStr = Annotated[
    str,
    Field(pattern=r"^CVE-\d{4}-\d{4,}$", examples=["CVE-2021-41773"]),
]


class CVECandidate(BaseModel):
    """Lightweight CVE hit returned by semantic search."""

    cve_id: CveIdStr
    summary: str = Field(max_length=500)
    similarity: float = Field(ge=0.0, le=1.0)


class CVEDetail(BaseModel):
    """Full CVE record returned by cve_lookup. Maps NVD CVE 2.0 schema."""

    cve_id: CveIdStr
    description: str
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_severity: str | None = None
    published: str
    last_modified: str
    cwe_ids: list[str] = Field(default_factory=list)
    affected_cpes: list[str] = Field(default_factory=list, max_length=50)
    references: list[HttpUrl] = Field(default_factory=list, max_length=20)


class ExploitCheck(BaseModel):
    """Result of exploit-availability lookup."""

    cve_id: CveIdStr
    has_public_exploit: bool
    exploit_db_ids: list[str] = Field(default_factory=list)
    github_poc_urls: list[HttpUrl] = Field(default_factory=list, max_length=10)


class NmapPort(BaseModel):
    portid: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class NmapHost(BaseModel):
    ip: str
    hostnames: list[str] = Field(default_factory=list, max_length=50)
    ports: list[NmapPort] = Field(default_factory=list, max_length=200)


class NmapScanResult(BaseModel):
    scan_start: str | None = None
    hosts: list[NmapHost] = Field(default_factory=list)


# --- MITRE ATT&CK ---------------------------------------------------------


class AttackMitigation(BaseModel):
    """A defensive control associated with one or more ATT&CK techniques."""

    id: str = Field(pattern=r"^M\d{4}$")
    name: str
    url: HttpUrl


class AttackTechnique(BaseModel):
    """A MITRE ATT&CK technique mapped from one or more CWE IDs.

    The same technique is returned only once per attack_mapping call even
    if multiple CWEs point to it; the `related_cwes` field records which
    of the input CWEs triggered the match.
    """

    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactics: list[str] = Field(default_factory=list, max_length=12)
    url: HttpUrl
    mitigations: list[AttackMitigation] = Field(default_factory=list, max_length=15)
    related_cwes: list[str] = Field(default_factory=list, max_length=20)

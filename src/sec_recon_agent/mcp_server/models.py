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


class KevCheck(BaseModel):
    """Result of a CISA KEV catalog lookup.

    `in_catalog` is the operational signal the agent cares about: True means
    the CVE is on CISA's Known Exploited Vulnerabilities list and federal
    agencies are required to patch it by `due_date`. The remaining fields
    are CISA-provided metadata for human review.

    Free-text fields (`vulnerability_name`, `required_action`, `notes`)
    arrive wrapped in UNTRUSTED_CONTENT markers from the tool boundary —
    `max_length` includes ~41 chars of marker overhead on top of the
    intended payload length.
    """

    cve_id: CveIdStr
    in_catalog: bool
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = Field(default=None, max_length=550)
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = Field(default=None, max_length=1050)
    known_ransomware_use: bool | None = None
    notes: str | None = Field(default=None, max_length=2050)


class PatchEntry(BaseModel):
    """One product / version pair where the CVE is reported as patched."""

    product_cpe: str = Field(max_length=400)
    fixed_in_version: str = Field(max_length=100)
    # `versionStartIncluding` / `versionStartExcluding` from the same NVD
    # CPE match. Kept for downstream consumers that need the full
    # affected-range descriptor (e.g. "fixed in X but only for builds
    # from version Y onwards").
    version_range_start: str | None = Field(default=None, max_length=100)


class PatchAvailability(BaseModel):
    """Result of a patch-availability lookup.

    `has_fix` is the headline signal. `fixed_entries` enumerates every
    distinct product / fixed-version pair the NVD CPE configuration
    declares; `references` echoes the NVD advisory URLs from the same
    record so the consumer can audit the source.
    """

    cve_id: CveIdStr
    has_fix: bool
    fixed_entries: list[PatchEntry] = Field(default_factory=list, max_length=50)
    references: list[HttpUrl] = Field(default_factory=list, max_length=20)


class SbomComponent(BaseModel):
    """A single software component normalized out of an SBOM.

    `purl` (Package URL, https://github.com/package-url/purl-spec) is the
    canonical cross-ecosystem identifier when present in the source SBOM
    (CycloneDX always carries it; SPDX often does; requirements.txt never).
    `ecosystem` is the soft hint used to route ecosystem-specific lookups
    later (pypi, npm, maven, etc.).
    """

    name: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=100)
    ecosystem: str | None = Field(default=None, max_length=40)
    purl: str | None = Field(default=None, max_length=500)


class SbomComponentList(BaseModel):
    """Result of sbom_ingest: a deduplicated list of components plus
    metadata about the source SBOM."""

    format: str  # 'cyclonedx', 'spdx', 'requirements'
    component_count: int = Field(ge=0)
    components: list[SbomComponent] = Field(default_factory=list, max_length=500)
    truncated: bool = Field(
        default=False,
        description="True when the source had more components than the cap.",
    )


class EpssScore(BaseModel):
    """Result of a FIRST.org EPSS lookup.

    EPSS estimates the probability a CVE will be exploited in the wild in
    the next 30 days. Returns None when the CVE is not in the EPSS dataset
    (typically pre-publication or non-public CVEs).
    """

    cve_id: CveIdStr
    probability: float | None = Field(default=None, ge=0.0, le=1.0)
    percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    score_date: str | None = None


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

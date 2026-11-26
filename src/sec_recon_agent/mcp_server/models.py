"""I/O contracts for MCP tools. Every tool returns a typed Pydantic model."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, HttpUrl

from sec_recon_agent.mcp_server.security import FENCE_OVERHEAD


def ascii_only(value: str) -> str:
    """Reject non-ASCII ids that the `\\d` in a pattern would otherwise accept.

    Python's `\\d` matches every Unicode decimal digit, so a CVE id spelled in
    fullwidth digits passed the pattern and broke the ASCII-only /r decoder. A
    validator, not a `[0-9]` pattern, because the pattern is part of the JSON
    schema the model sees and the record-replay staleness hash pins it.
    """
    if not value.isascii():
        raise ValueError("id must be ASCII")
    return value


CveIdStr = Annotated[
    str,
    Field(pattern=r"^CVE-\d{4}-\d{4,}$", examples=["CVE-2021-41773"]),
    AfterValidator(ascii_only),
]

# OSV.dev supports many ecosystems; we expose the seven that cover the vast
# majority of triage traffic. A value outside this set is rejected at the MCP
# boundary rather than silently coerced — OSV would return an empty result for
# an unknown ecosystem string, which reads as "not vulnerable" and is worse
# than an explicit validation error.
OsvEcosystem = Literal[
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "crates.io",
    "NuGet",
    "RubyGems",
]

# Package name and version are user-supplied identifiers, not free prose. They
# are bounded in length but not fenced: they never reach the LLM as authored
# text, only as the query subject echoed back in the structured result.
PackageNameStr = Annotated[str, Field(min_length=1, max_length=200, examples=["numpy"])]
PackageVersionStr = Annotated[str, Field(min_length=1, max_length=100, examples=["1.22.0"])]


# Payload budgets for the fenced free-text fields. Each model cap below is
# budget + FENCE_OVERHEAD, and the tool that fills the field passes the same
# budget to fence_untrusted(max_chars=...), which truncates AFTER neutralizing
# marker-shaped tokens. One place to change, and the cap holds for any input.
CVE_DESCRIPTION_CHARS = 4000
CVE_CANDIDATE_SUMMARY_CHARS = 500
KEV_VULNERABILITY_NAME_CHARS = 500
KEV_REQUIRED_ACTION_CHARS = 1000
KEV_NOTES_CHARS = 2000
OSV_SUMMARY_CHARS = 1000
NMAP_BANNER_CHARS = 200
# Short identifiers that are bounded but not fenced.
NMAP_NAME_CHARS = 64
NMAP_HOSTNAME_CHARS = 253
NMAP_HOSTNAMES_MAX = 50
# Identifier patterns below spell digits as [0-9], not \d: both Python's `re`
# and pydantic's regex engine read \d as any Unicode digit.
# Payload caps for one parsed scan: hosts per scan, ports per host, and ports
# across the whole scan. The total cap is what bounds the result; the per-host
# cap alone allows 1000 * 200 port entries.
NMAP_HOSTS_MAX = 1000
NMAP_PORTS_PER_HOST_MAX = 200
NMAP_PORTS_TOTAL_MAX = 2000
# Hostnames across the whole scan: the per-host cap alone allows 1000 * 50.
NMAP_HOSTNAMES_TOTAL_MAX = 2000
# Hostname charset: RFC 1123 (letters, digits, dot, hyphen) plus underscore,
# which AD and NetBIOS PTR records carry; alphanumeric or underscore first
# character, at most 253 characters. A name outside it is dropped, so a
# hostname attribute cannot carry spaced prose to the model. Hyphen-joined
# words still pass: a residual recorded in docs/mcp_self_audit.md.
NMAP_HOSTNAME_PATTERN = r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]{0,252})$"
# Nmap writes `start` as a Unix epoch in seconds.
NMAP_SCAN_START_PATTERN = r"^[0-9]{1,12}$"
# Port state tokens (`open`, `closed`, `filtered`, `open|filtered`, ...); an
# unknown token becomes "unknown".
NMAP_STATE_PATTERN = r"^[a-z|-]{1,32}$"
# Service names from nmap-services (`http`, `microsoft-ds`, `ssl/http`); an
# unknown token becomes None.
NMAP_SERVICE_PATTERN = r"^[A-Za-z0-9._+/-]{1,64}$"
NmapProtocol = Literal["tcp", "udp", "sctp", "ip"]
# A canonical IPv4/IPv6 address: hex digits, dots and colons only (scoped
# IPv6 addresses are dropped by the parser, so no `%zone`).
NMAP_IP_PATTERN = r"^[0-9A-Fa-f:.]{2,45}$"

# CVE side fields from NVD that are identifiers, not prose.
CWE_ID_PATTERN = r"^CWE-[0-9]{1,6}$"
CPE_MAX_CHARS = 400
CVE_CWE_IDS_MAX = 20
CVE_CPES_MAX = 50

# SBOM component identifiers. Name and version are package identifiers: no
# whitespace, no control characters. The version charset adds `!` for PEP 440
# epochs (`1!2.0`). A purl must have the Package URL shape (scheme, a type
# short enough to be the ecosystem hint, then a path with no whitespace).
SBOM_NAME_CHARS = 200
SBOM_VERSION_CHARS = 100
SBOM_PURL_CHARS = 500
SBOM_ECOSYSTEM_CHARS = 40
SBOM_NAME_PATTERN = r"^[A-Za-z0-9@/._+:~-]+$"
SBOM_VERSION_PATTERN = r"^[A-Za-z0-9@/._+:~!-]+$"
# No `?`, `=`, `&` or `#`: the parser keeps only type/namespace/name@version
# and drops qualifiers and subpath, which are free-form text.
SBOM_PURL_PATTERN = r"^pkg:[a-z][a-z0-9.+-]{0,39}/[A-Za-z0-9._~%@/:+!-]+$"


class CVECandidate(BaseModel):
    """Lightweight CVE hit returned by semantic search.

    `summary` is the CVE description, truncated to CVE_CANDIDATE_SUMMARY_CHARS
    in cve_search.py and wrapped in UNTRUSTED_CONTENT markers. `max_length` is
    that budget plus FENCE_OVERHEAD, so a fenced full-length payload validates
    (same convention as every fenced free-text field).
    """

    cve_id: CveIdStr
    summary: str = Field(max_length=CVE_CANDIDATE_SUMMARY_CHARS + FENCE_OVERHEAD)
    similarity: float = Field(ge=0.0, le=1.0)


class CVEDetail(BaseModel):
    """Full CVE record returned by cve_lookup. Maps NVD CVE 2.0 schema.

    `references` carries the URLs the upstream NVD record lists for the
    CVE. Origins are vendor advisories, third-party blog posts, GitHub
    issues, exploit write-ups. These URLs are UNTRUSTED: do not auto-fetch
    them, do not present them as authoritative, do not follow redirects
    server-side. They are an audit trail for a human analyst to review.
    """

    cve_id: CveIdStr
    # Fenced; capped so a multi-kilobyte NVD description (or one stuffed with
    # forged markers) cannot flood the model context through this field.
    description: str = Field(max_length=CVE_DESCRIPTION_CHARS + FENCE_OVERHEAD)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_severity: str | None = None
    published: str
    last_modified: str
    cwe_ids: list[Annotated[str, Field(pattern=CWE_ID_PATTERN)]] = Field(
        default_factory=list, max_length=CVE_CWE_IDS_MAX
    )
    affected_cpes: list[Annotated[str, Field(max_length=CPE_MAX_CHARS)]] = Field(
        default_factory=list, max_length=CVE_CPES_MAX
    )
    references: list[HttpUrl] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Vendor-published advisory URLs from NVD. UNTRUSTED: do not "
            "auto-fetch or follow server-side. For analyst review only."
        ),
    )


class ExploitArmStatus(StrEnum):
    """Coverage status of one exploit_check source, so a False signal is never
    ambiguous between "looked, nothing there" and "could not look".

    FOUND: the source has at least one accepted hit for the CVE.
    NOT_FOUND: the source was consulted successfully and has nothing accepted.
    ERROR: the source could not be consulted or could not be concluded on
        (download failure, rate limit, unusable response, repository
        metadata unavailable for every candidate).
    SKIPPED: the source was not consulted by configuration (GitHub without
        GITHUB_TOKEN). A conclusive "did not look", not a failure.
    """

    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    SKIPPED = "skipped"


class ExploitCheck(BaseModel):
    """Result of exploit-availability lookup, with per-source status.

    `has_public_exploit` is True when either source has an accepted hit. The
    per-arm statuses say what that False rests on: a False with an arm in
    ERROR is "unknown", not "no exploit", and downstream consumers (the SSVC
    verdict, the grounding verifier, the gate's coverage) treat it as such.

    `github_poc_urls` are REPOSITORY URLs (https://github.com/owner/repo),
    never file URLs: a file path is attacker-chosen free text and would reach
    the model unfenced inside a validated URL. A GitHub hit is accepted only
    when the repository is established (a minimum star count or age), so a
    throwaway repository named after the CVE cannot flip the signal;
    candidates that failed that bar are counted in `github_unverified_hits`.
    """

    cve_id: CveIdStr
    has_public_exploit: bool
    exploit_db: ExploitArmStatus
    github: ExploitArmStatus
    exploit_db_ids: list[str] = Field(default_factory=list, max_length=20)
    github_poc_urls: list[HttpUrl] = Field(default_factory=list, max_length=10)
    github_unverified_hits: int = Field(default=0, ge=0)

    def arms_conclusive(self) -> bool:
        """True when no source is in ERROR: a False signal is then evidence."""
        return ExploitArmStatus.ERROR not in (self.exploit_db, self.github)


class KevCheck(BaseModel):
    """Result of a CISA KEV catalog lookup.

    `in_catalog` is the operational signal the agent cares about: True means
    the CVE is on CISA's Known Exploited Vulnerabilities list and federal
    agencies are required to patch it by `due_date`. The remaining fields
    are CISA-provided metadata for human review.

    Free-text fields (`vulnerability_name`, `required_action`, `notes`)
    arrive wrapped in UNTRUSTED_CONTENT markers from the tool boundary —
    `max_length` is the payload budget plus FENCE_OVERHEAD on top of the
    intended payload length.
    """

    cve_id: CveIdStr
    in_catalog: bool
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = Field(
        default=None, max_length=KEV_VULNERABILITY_NAME_CHARS + FENCE_OVERHEAD
    )
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = Field(
        default=None, max_length=KEV_REQUIRED_ACTION_CHARS + FENCE_OVERHEAD
    )
    known_ransomware_use: bool | None = None
    notes: str | None = Field(default=None, max_length=KEV_NOTES_CHARS + FENCE_OVERHEAD)


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

    `references` are UNTRUSTED (same provenance as CVEDetail.references):
    vendor-published, do not auto-fetch or follow server-side.
    """

    cve_id: CveIdStr
    has_fix: bool
    fixed_entries: list[PatchEntry] = Field(default_factory=list, max_length=50)
    references: list[HttpUrl] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Vendor-published advisory URLs from NVD. UNTRUSTED: do not "
            "auto-fetch or follow server-side. For analyst review only."
        ),
    )


class SbomComponent(BaseModel):
    """A single software component normalized out of an SBOM.

    `purl` (Package URL, https://github.com/package-url/purl-spec) is the
    canonical cross-ecosystem identifier when present in the source SBOM
    (CycloneDX always carries it; SPDX often does; requirements.txt never).
    `ecosystem` is the soft hint used to route ecosystem-specific lookups
    later (pypi, npm, maven, etc.).

    Every field comes from the caller's SBOM, so every field is a validated
    identifier rather than free text: `name` and `version` match a package
    identifier charset (no whitespace or control characters), `purl` matches
    the Package URL shape, and `ecosystem` is derived from the purl type.
    """

    name: str = Field(min_length=1, max_length=SBOM_NAME_CHARS, pattern=SBOM_NAME_PATTERN)
    version: str | None = Field(
        default=None, max_length=SBOM_VERSION_CHARS, pattern=SBOM_VERSION_PATTERN
    )
    ecosystem: str | None = Field(default=None, max_length=SBOM_ECOSYSTEM_CHARS)
    purl: str | None = Field(default=None, max_length=SBOM_PURL_CHARS, pattern=SBOM_PURL_PATTERN)


class SbomComponentList(BaseModel):
    """Result of sbom_ingest: a deduplicated list of components plus
    metadata about the source SBOM.

    `rejected_count` counts source entries whose name failed identifier
    validation and were dropped, so a hostile or malformed SBOM reads as
    partially covered instead of silently shorter.
    """

    format: str  # 'cyclonedx', 'spdx', 'requirements'
    component_count: int = Field(ge=0)
    components: list[SbomComponent] = Field(default_factory=list, max_length=500)
    truncated: bool = Field(
        default=False,
        description="True when the source had more components than the cap.",
    )
    rejected_count: int = Field(
        default=0,
        ge=0,
        description="Source entries dropped because the name was not a valid identifier.",
    )


class EpssStatus(StrEnum):
    """Coverage status of an EPSS lookup, so a null probability is never
    ambiguous.

    FOUND: the CVE is in the EPSS dataset and a usable probability was returned.
    NOT_FOUND: EPSS answered successfully but has no entry for this CVE
        (typically pre-publication, rejected, or non-public CVEs). A real
        "no score" answer, not a failure.
    UPSTREAM_ERROR: EPSS returned a response we reached but could not use for
        this CVE (the datum was for a different CVE, or the score was
        unparseable / out of range). Distinct from a hard request failure,
        which raises a typed exception instead of returning a result.
    """

    FOUND = "found"
    NOT_FOUND = "not_found"
    UPSTREAM_ERROR = "upstream_error"


class EpssScore(BaseModel):
    """Result of a FIRST.org EPSS lookup.

    EPSS estimates the probability a CVE will be exploited in the wild in
    the next 30 days. `status` disambiguates a null probability: NOT_FOUND
    (queried, no entry) vs UPSTREAM_ERROR (reached the feed, datum unusable).
    A hard request failure (transport, HTTP 5xx, non-JSON, missing data list)
    raises a typed EpssError instead of returning a result.
    """

    cve_id: CveIdStr
    status: EpssStatus
    probability: float | None = Field(default=None, ge=0.0, le=1.0)
    percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    score_date: str | None = None


class OsvVuln(BaseModel):
    """A single vulnerability record returned by OSV.dev for a package+version.

    This is the inverse of the NVD-driven tools: instead of "given a CVE, what
    do we know", it answers "given a package at a version, which advisories
    apply". `id` is the OSV-native identifier (GHSA-*, PYSEC-*, or a CVE-* when
    OSV mirrors one); `aliases` carries the cross-references (CVE <-> GHSA <->
    ecosystem-specific IDs) so the agent can pivot to cve_lookup.

    `summary` is upstream-authored free text and arrives wrapped in
    UNTRUSTED_CONTENT markers (max_length is the payload budget plus
    FENCE_OVERHEAD). `introduced` / `fixed` are the version-range boundaries for the
    queried package, mirroring patch_lookup's fixed-version semantics.
    """

    id: str = Field(max_length=100)
    summary: str | None = Field(default=None, max_length=OSV_SUMMARY_CHARS + FENCE_OVERHEAD)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    severity: str | None = Field(
        default=None,
        max_length=120,
        description="Raw upstream severity token (CVSS vector or score string).",
    )
    introduced: str | None = Field(default=None, max_length=100)
    fixed: str | None = Field(default=None, max_length=100)
    references: list[HttpUrl] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Upstream advisory URLs from OSV. UNTRUSTED: do not auto-fetch or "
            "follow server-side. For analyst review only."
        ),
    )


class OsvScanResult(BaseModel):
    """Result of an osv_lookup: every advisory OSV.dev has for the queried
    package at the queried version.

    `is_vulnerable` is the headline signal (True when OSV returned at least one
    matching advisory). `vulnerabilities` is capped; `truncated` flags when the
    upstream list exceeded the cap.
    """

    package: str = Field(max_length=200)
    ecosystem: str = Field(max_length=40)
    version: str = Field(max_length=100)
    is_vulnerable: bool
    vulnerabilities: list[OsvVuln] = Field(default_factory=list, max_length=100)
    truncated: bool = Field(
        default=False,
        description="True when OSV returned more advisories than the cap.",
    )


class NmapPort(BaseModel):
    """One port of a parsed Nmap scan. Every string is attacker-controlled
    (the scan XML is caller-supplied): `protocol` is an enum, `state` and
    `service` are token-validated, and `product` and `version` are free-text
    banners and are fenced.
    """

    portid: int = Field(ge=1, le=65535)
    protocol: NmapProtocol
    state: str = Field(max_length=NMAP_NAME_CHARS, pattern=NMAP_STATE_PATTERN)
    service: str | None = Field(
        default=None, max_length=NMAP_NAME_CHARS, pattern=NMAP_SERVICE_PATTERN
    )
    product: str | None = Field(default=None, max_length=NMAP_BANNER_CHARS + FENCE_OVERHEAD)
    version: str | None = Field(default=None, max_length=NMAP_BANNER_CHARS + FENCE_OVERHEAD)


class NmapHost(BaseModel):
    """One host of a parsed Nmap scan. `ip` is a parsed IPv4 or IPv6 address
    in canonical form; `hostnames` entries match the hostname charset. The
    parser drops a host whose address does not parse and a name outside the
    charset."""

    ip: str = Field(max_length=NMAP_NAME_CHARS, pattern=NMAP_IP_PATTERN)
    hostnames: list[
        Annotated[str, Field(max_length=NMAP_HOSTNAME_CHARS, pattern=NMAP_HOSTNAME_PATTERN)]
    ] = Field(default_factory=list, max_length=NMAP_HOSTNAMES_MAX)
    ports: list[NmapPort] = Field(default_factory=list, max_length=NMAP_PORTS_PER_HOST_MAX)


class NmapScanResult(BaseModel):
    """Result of nmap_parse_xml. `scan_start` is the scan's Unix epoch (digits
    only, else None). `truncated` is True when hosts or ports were cut by a
    cap (hosts per scan, ports per host, ports per scan)."""

    scan_start: str | None = Field(default=None, pattern=NMAP_SCAN_START_PATTERN)
    hosts: list[NmapHost] = Field(default_factory=list, max_length=NMAP_HOSTS_MAX)
    truncated: bool = Field(
        default=False,
        description="True when hosts, ports or hostnames were cut by a cap.",
    )


# --- MITRE ATT&CK ---------------------------------------------------------


class AttackMitigation(BaseModel):
    """A defensive control associated with one or more ATT&CK techniques."""

    id: Annotated[str, AfterValidator(ascii_only)] = Field(pattern=r"^M\d{4}$")
    name: str
    url: HttpUrl


class AttackTechnique(BaseModel):
    """A MITRE ATT&CK technique mapped from one or more CWE IDs.

    The same technique is returned only once per attack_mapping call even
    if multiple CWEs point to it; the `related_cwes` field records which
    of the input CWEs triggered the match.
    """

    id: Annotated[str, AfterValidator(ascii_only)] = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactics: list[str] = Field(default_factory=list, max_length=12)
    url: HttpUrl
    mitigations: list[AttackMitigation] = Field(default_factory=list, max_length=15)
    related_cwes: list[str] = Field(default_factory=list, max_length=20)

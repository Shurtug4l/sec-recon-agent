"""Typed exceptions for the MCP server. Every tool failure surfaces one of these."""


class SecReconError(Exception):
    """Base for all project-defined exceptions."""


class NvdError(SecReconError):
    """Base for NVD-related failures."""


class CveNotFoundError(NvdError):
    def __init__(self, cve_id: str) -> None:
        super().__init__(f"CVE not found: {cve_id}")
        self.cve_id = cve_id


class NvdRateLimitError(NvdError):
    """NVD returned 429 or local rate limiter could not satisfy in time."""


class NvdServerError(NvdError):
    """NVD returned 5xx after retries."""


class NvdConnectionError(NvdError):
    """Network failure reaching NVD after retries."""


class MalformedNvdPayloadError(NvdError):
    """NVD response did not match the expected schema."""


class NmapError(SecReconError):
    """Base for Nmap parsing failures."""


class MalformedNmapXmlError(NmapError):
    """Nmap XML payload could not be parsed or had unexpected structure (incl. blocked XXE)."""


class ExploitsError(SecReconError):
    """Base for exploit-check failures."""


class ExploitDbDownloadError(ExploitsError):
    """Failed to fetch the ExploitDB CSV manifest."""


class KevError(SecReconError):
    """Base for CISA KEV catalog failures."""


class KevDownloadError(KevError):
    """Failed to fetch the CISA KEV catalog."""


class MalformedKevPayloadError(KevError):
    """CISA KEV JSON did not match the expected schema."""


class SbomError(SecReconError):
    """Base for SBOM ingestion failures."""


class UnsupportedSbomFormatError(SbomError):
    """The provided content did not match any of the supported SBOM formats."""


class MalformedSbomPayloadError(SbomError):
    """The provided SBOM matched a format but failed schema validation."""


class EpssError(SecReconError):
    """Base for FIRST EPSS API failures."""


class EpssRequestError(EpssError):
    """Network or HTTP failure querying the EPSS API."""


class MalformedEpssPayloadError(EpssError):
    """EPSS API response did not match the expected schema."""


class AttackError(SecReconError):
    """Base for MITRE ATT&CK mapping failures."""


class InvalidCweInputError(AttackError):
    """attack_mapping received a cwe_ids list that breaches the input caps."""

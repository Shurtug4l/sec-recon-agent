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

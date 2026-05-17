"""Contract tests for the cve_lookup MCP tool. NVD API is mocked via respx."""

from typing import Any

import pytest
import respx
from httpx import Response

from sec_recon_agent.mcp_server.errors import (
    CveNotFoundError,
    MalformedNvdPayloadError,
    NvdServerError,
)
from sec_recon_agent.mcp_server.security import UNTRUSTED_END, UNTRUSTED_START
from sec_recon_agent.mcp_server.tools.cve import NVD_BASE_URL, cve_lookup


@pytest.fixture
def apache_payload() -> dict[str, Any]:
    """Realistic NVD CVE 2.0 payload for CVE-2021-41773 (Apache path traversal)."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "published": "2021-10-05T00:00:00",
                    "lastModified": "2024-01-01T00:00:00",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A flaw in Apache HTTP Server 2.4.49 path traversal.",
                        },
                        {"lang": "es", "value": "Traduccion."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-22"},
                                {"lang": "en", "value": "CWE-22"},
                            ]
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": (
                                                "cpe:2.3:a:apache:http_server:"
                                                "2.4.49:*:*:*:*:*:*:*"
                                            )
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
                    ],
                }
            }
        ]
    }


@respx.mock
async def test_cve_lookup_returns_typed_detail(apache_payload: dict[str, Any]) -> None:
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2021-41773"}).mock(
        return_value=Response(200, json=apache_payload),
    )

    result = await cve_lookup("CVE-2021-41773")

    assert result.cve_id == "CVE-2021-41773"
    assert result.cvss_v3_score == 7.5
    assert result.cvss_v3_severity == "HIGH"
    assert result.cwe_ids == ["CWE-22"]
    assert len(result.affected_cpes) == 1
    assert "apache" in result.affected_cpes[0]
    assert len(result.references) == 2
    # Description is NVD-authored free text. It must reach the agent
    # wrapped with untrusted-content markers so the LLM treats it as data.
    assert result.description.startswith(UNTRUSTED_START)
    assert result.description.endswith(UNTRUSTED_END)
    assert "Apache" in result.description


@respx.mock
async def test_cve_lookup_raises_when_unknown() -> None:
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-9999-99999"}).mock(
        return_value=Response(200, json={"vulnerabilities": []}),
    )

    with pytest.raises(CveNotFoundError) as excinfo:
        await cve_lookup("CVE-9999-99999")

    assert excinfo.value.cve_id == "CVE-9999-99999"


@respx.mock
async def test_cve_lookup_raises_on_malformed_payload() -> None:
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2021-41773"}).mock(
        return_value=Response(200, json={"vulnerabilities": [{"not_cve": {}}]}),
    )

    with pytest.raises(MalformedNvdPayloadError):
        await cve_lookup("CVE-2021-41773")


@respx.mock
async def test_cve_lookup_retries_on_5xx_then_raises() -> None:
    route = respx.get(NVD_BASE_URL, params={"cveId": "CVE-2021-41773"}).mock(
        return_value=Response(503),
    )

    with pytest.raises(NvdServerError):
        await cve_lookup("CVE-2021-41773")

    assert route.call_count == 3

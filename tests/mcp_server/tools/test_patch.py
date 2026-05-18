"""Contract tests for patch_lookup. Mocks NVD via respx."""

import pytest
import respx
from httpx import Response

from sec_recon_agent.mcp_server.errors import CveNotFoundError
from sec_recon_agent.mcp_server.nvd_client import NVD_BASE_URL
from sec_recon_agent.mcp_server.tools.patch import patch_lookup


def _nvd_payload_with_cpe_matches(cve_id: str, matches: list[dict]) -> dict:
    """Build a minimal NVD 2.0 payload with custom cpeMatch entries."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [{"nodes": [{"cpeMatch": matches}]}],
                    "references": [
                        {"url": "https://example.com/advisory"},
                        {"url": "https://example.com/patch"},
                    ],
                    "published": "2024-01-01",
                    "lastModified": "2024-01-02",
                },
            },
        ],
    }


@respx.mock
async def test_returns_fixed_versions_from_cpe_matches() -> None:
    payload = _nvd_payload_with_cpe_matches(
        "CVE-2021-41773",
        [
            {
                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                "vulnerable": True,
                "versionEndExcluding": "2.4.50",
            },
            {
                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                "vulnerable": True,
                "versionStartIncluding": "2.4.49",
                "versionEndExcluding": "2.4.51",
            },
        ],
    )
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2021-41773"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2021-41773")

    assert result.cve_id == "CVE-2021-41773"
    assert result.has_fix is True
    assert len(result.fixed_entries) == 2
    fixed_versions = {e.fixed_in_version for e in result.fixed_entries}
    assert fixed_versions == {"2.4.50", "2.4.51"}
    # One entry has a range start; the other does not.
    ranges = [e.version_range_start for e in result.fixed_entries]
    assert "2.4.49" in ranges
    assert None in ranges


@respx.mock
async def test_dedupes_identical_cpe_version_pairs() -> None:
    """Two NVD nodes can list the same fix; the result must dedupe."""
    payload = _nvd_payload_with_cpe_matches(
        "CVE-2024-0001",
        [
            {
                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.0.1",
            },
            {
                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.0.1",
            },
        ],
    )
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2024-0001"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2024-0001")

    assert result.has_fix is True
    assert len(result.fixed_entries) == 1


@respx.mock
async def test_skips_matches_without_version_end_excluding() -> None:
    """A CPE entry with no `versionEndExcluding` does not declare a fix."""
    payload = _nvd_payload_with_cpe_matches(
        "CVE-2024-0002",
        [
            {
                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                # No versionEndExcluding -> entry skipped.
            },
            {
                "criteria": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0.5",
            },
        ],
    )
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2024-0002"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2024-0002")

    assert result.has_fix is True
    assert len(result.fixed_entries) == 1
    assert result.fixed_entries[0].fixed_in_version == "2.0.5"


@respx.mock
async def test_returns_no_fix_when_no_cpe_matches() -> None:
    payload = _nvd_payload_with_cpe_matches("CVE-2024-0003", [])
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2024-0003"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2024-0003")

    assert result.has_fix is False
    assert result.fixed_entries == []
    # References still surface even without a fix.
    assert len(result.references) == 2


@respx.mock
async def test_raises_cve_not_found_when_nvd_returns_empty() -> None:
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-9999-99999"}).mock(
        return_value=Response(200, json={"vulnerabilities": []}),
    )

    with pytest.raises(CveNotFoundError):
        await patch_lookup("CVE-9999-99999")


@respx.mock
async def test_uses_version_start_excluding_when_no_including() -> None:
    """The range-start field can be either ...StartIncluding or ...StartExcluding;
    we surface whichever NVD provides."""
    payload = _nvd_payload_with_cpe_matches(
        "CVE-2024-0004",
        [
            {
                "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                "versionStartExcluding": "0.9",
                "versionEndExcluding": "1.0",
            },
        ],
    )
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2024-0004"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2024-0004")

    assert result.fixed_entries[0].version_range_start == "0.9"


@respx.mock
async def test_caps_at_max_entries() -> None:
    """The cap protects against a CVE that lists hundreds of CPE matches."""
    matches = [
        {
            "criteria": f"cpe:2.3:a:v:p:{i}:*:*:*:*:*:*:*",
            "versionEndExcluding": f"{i}.1",
        }
        for i in range(70)
    ]
    payload = _nvd_payload_with_cpe_matches("CVE-2024-0005", matches)
    respx.get(NVD_BASE_URL, params={"cveId": "CVE-2024-0005"}).mock(
        return_value=Response(200, json=payload),
    )

    result = await patch_lookup("CVE-2024-0005")
    assert len(result.fixed_entries) == 50

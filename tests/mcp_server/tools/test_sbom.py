"""Contract tests for sbom_ingest. Pure deterministic parsing, no network."""

import json

import pytest

from sec_recon_agent.mcp_server.errors import (
    MalformedSbomPayloadError,
    UnsupportedSbomFormatError,
)
from sec_recon_agent.mcp_server.tools.sbom import sbom_ingest


def test_parses_cyclonedx_json() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            },
            {
                "type": "library",
                "name": "jackson-databind",
                "version": "2.13.0",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
            },
        ],
    }
    result = sbom_ingest(json.dumps(payload))

    assert result.format == "cyclonedx"
    assert result.component_count == 2
    assert result.truncated is False
    names = [c.name for c in result.components]
    assert "log4j-core" in names
    assert all(c.ecosystem == "maven" for c in result.components)


def test_parses_spdx_json() -> None:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "express",
                "versionInfo": "4.17.1",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/express@4.17.1",
                    },
                ],
            },
            {
                "name": "lodash",
                "versionInfo": "4.17.20",
            },
        ],
    }
    result = sbom_ingest(json.dumps(payload))

    assert result.format == "spdx"
    assert result.component_count == 2
    express = next(c for c in result.components if c.name == "express")
    assert express.ecosystem == "npm"
    assert express.purl is not None and "express@4.17.1" in express.purl
    lodash = next(c for c in result.components if c.name == "lodash")
    assert lodash.ecosystem is None  # no purl in source


def test_parses_requirements_txt() -> None:
    content = """
    # Comment line, should be ignored
    requests==2.28.0
    Django>=4.2
    numpy
    cryptography==41.0.7  ; python_version >= '3.7'
    not a real line just prose mixed in
    """
    result = sbom_ingest(content)

    assert result.format == "requirements"
    names = {c.name for c in result.components}
    assert names == {"requests", "Django", "numpy", "cryptography"}
    requests = next(c for c in result.components if c.name == "requests")
    assert requests.version == "2.28.0"
    assert requests.ecosystem == "pypi"
    numpy = next(c for c in result.components if c.name == "numpy")
    assert numpy.version is None


def test_dedupes_repeated_components() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "foo", "version": "1.0"},
            {"name": "foo", "version": "1.0"},  # exact dup
            {"name": "FOO", "version": "1.0"},  # case-insensitive dup
            {"name": "foo", "version": "1.1"},  # different version: keep
        ],
    }
    result = sbom_ingest(json.dumps(payload))
    assert result.component_count == 2


def test_truncates_above_limit() -> None:
    components = [{"name": f"pkg-{i}", "version": "1.0"} for i in range(600)]
    payload = {"bomFormat": "CycloneDX", "components": components}
    result = sbom_ingest(json.dumps(payload))

    assert result.truncated is True
    assert result.component_count == 500


def test_skips_entries_with_missing_name() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "components": [
            {"version": "1.0"},  # missing name
            {"name": "", "version": "1"},  # empty name
            {"name": "good", "version": "2.0"},
            "not even an object",
        ],
    }
    result = sbom_ingest(json.dumps(payload))
    assert result.component_count == 1
    assert result.components[0].name == "good"


def test_unsupported_json_shape() -> None:
    payload = {"foo": "bar"}  # no bomFormat, no components, no spdxVersion, no packages
    with pytest.raises(UnsupportedSbomFormatError):
        sbom_ingest(json.dumps(payload))


def test_unsupported_text_shape() -> None:
    # Multi-word lines never match the requirements regex (which requires
    # one package per line, optionally with version/extras/marker).
    content = (
        "this is just regular prose with multiple words per line.\n"
        "no equals signs, no semicolons, nothing parseable here at all!\n"
    )
    with pytest.raises(UnsupportedSbomFormatError):
        sbom_ingest(content)


def test_malformed_json_raises_typed_error() -> None:
    with pytest.raises(MalformedSbomPayloadError):
        sbom_ingest("{not valid json")


def test_cyclonedx_components_not_a_list() -> None:
    payload = {"bomFormat": "CycloneDX", "components": "oops"}
    with pytest.raises(MalformedSbomPayloadError):
        sbom_ingest(json.dumps(payload))


def test_spdx_packages_not_a_list() -> None:
    payload = {"spdxVersion": "SPDX-2.3", "packages": "oops"}
    with pytest.raises(MalformedSbomPayloadError):
        sbom_ingest(json.dumps(payload))


def test_requirements_with_extras_and_markers() -> None:
    content = """
    requests[security]==2.28.0
    boto3 ; sys_platform == 'linux'
    """
    result = sbom_ingest(content)
    names = {c.name for c in result.components}
    assert "requests" in names
    assert "boto3" in names


def test_empty_payload_rejected() -> None:
    with pytest.raises(UnsupportedSbomFormatError):
        sbom_ingest("\n  \n  \n")

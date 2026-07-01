"""Contract tests for epss_score. Network is mocked via respx."""

import pytest
import respx
from httpx import Response

from sec_recon_agent.mcp_server.errors import (
    EpssRequestError,
    MalformedEpssPayloadError,
)
from sec_recon_agent.mcp_server.models import EpssStatus
from sec_recon_agent.mcp_server.tools.epss import EPSS_API_URL, epss_score


def _epss_payload(cve_id: str, prob: str, pct: str, date: str = "2026-05-18") -> dict:
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "data": [
            {
                "cve": cve_id,
                "epss": prob,
                "percentile": pct,
                "date": date,
            },
        ],
    }


@respx.mock
async def test_returns_score_for_known_cve() -> None:
    respx.get(EPSS_API_URL).mock(
        return_value=Response(200, json=_epss_payload("CVE-2021-41773", "0.94521", "0.99876")),
    )

    result = await epss_score("CVE-2021-41773")

    assert result.cve_id == "CVE-2021-41773"
    assert result.status is EpssStatus.FOUND
    assert result.probability == pytest.approx(0.94521)
    assert result.percentile == pytest.approx(0.99876)
    assert result.score_date == "2026-05-18"


@respx.mock
async def test_returns_none_for_cve_not_in_dataset() -> None:
    respx.get(EPSS_API_URL).mock(
        return_value=Response(
            200,
            json={"status": "OK", "status-code": 200, "version": "1.0", "data": []},
        ),
    )

    result = await epss_score("CVE-9999-99999")

    assert result.cve_id == "CVE-9999-99999"
    assert result.status is EpssStatus.NOT_FOUND
    assert result.probability is None
    assert result.percentile is None
    assert result.score_date is None


@respx.mock
async def test_non_200_raises_typed_error() -> None:
    respx.get(EPSS_API_URL).mock(return_value=Response(503, content=b"upstream down"))

    with pytest.raises(EpssRequestError, match="HTTP 503"):
        await epss_score("CVE-2021-41773")


@respx.mock
async def test_non_json_response_raises() -> None:
    respx.get(EPSS_API_URL).mock(return_value=Response(200, content=b"<html>error</html>"))

    with pytest.raises(MalformedEpssPayloadError):
        await epss_score("CVE-2021-41773")


@respx.mock
async def test_missing_data_field_raises() -> None:
    respx.get(EPSS_API_URL).mock(
        return_value=Response(200, json={"status": "OK", "version": "1.0"}),
    )

    with pytest.raises(MalformedEpssPayloadError, match="data"):
        await epss_score("CVE-2021-41773")


@respx.mock
async def test_data_entry_wrong_type_raises() -> None:
    respx.get(EPSS_API_URL).mock(
        return_value=Response(200, json={"data": ["not an object"]}),
    )

    with pytest.raises(MalformedEpssPayloadError):
        await epss_score("CVE-2021-41773")


@respx.mock
async def test_cve_mismatch_is_upstream_error_not_not_found() -> None:
    """Defensive: never attribute a score to the wrong CVE. A mismatch means we
    reached the feed but the datum is unusable -> upstream_error, distinct from
    'CVE genuinely absent from EPSS' (not_found)."""
    respx.get(EPSS_API_URL).mock(
        return_value=Response(
            200,
            json=_epss_payload("CVE-2099-9999", "0.5", "0.5"),
        ),
    )

    result = await epss_score("CVE-2021-41773")

    assert result.status is EpssStatus.UPSTREAM_ERROR
    assert result.probability is None
    assert result.percentile is None


@respx.mock
async def test_out_of_range_score_is_upstream_error() -> None:
    """The dataset has an entry for the exact CVE but the score is unusable:
    the feed misbehaved for a CVE it knows -> upstream_error, not not_found."""
    respx.get(EPSS_API_URL).mock(
        return_value=Response(
            200,
            json=_epss_payload("CVE-2021-41773", "1.5", "-0.1"),
        ),
    )

    result = await epss_score("CVE-2021-41773")

    assert result.status is EpssStatus.UPSTREAM_ERROR
    assert result.probability is None
    assert result.percentile is None


@respx.mock
async def test_non_numeric_score_is_upstream_error() -> None:
    respx.get(EPSS_API_URL).mock(
        return_value=Response(
            200,
            json=_epss_payload("CVE-2021-41773", "not-a-number", "still-not"),
        ),
    )

    result = await epss_score("CVE-2021-41773")

    assert result.status is EpssStatus.UPSTREAM_ERROR
    assert result.probability is None
    assert result.percentile is None

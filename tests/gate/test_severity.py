"""Severity derivation from OSV severity tokens."""

import pytest

from sec_recon_agent.agent.schema import Severity
from sec_recon_agent.gate.severity import band_for_score, severity_from_token


class TestVectors:
    def test_cvss31_critical(self) -> None:
        severity, score = severity_from_token("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert severity is Severity.CRITICAL
        assert score == 9.8

    def test_cvss31_medium(self) -> None:
        # The classic reflected-XSS vector.
        severity, score = severity_from_token("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert severity is Severity.MEDIUM
        assert score == 6.1

    def test_cvss2_bare_vector(self) -> None:
        severity, score = severity_from_token("AV:N/AC:L/Au:N/C:P/I:P/A:P")
        assert severity is Severity.HIGH
        assert score == 7.5

    def test_cvss2_parenthesized(self) -> None:
        # NVD's historical serialization wraps v2 vectors in parentheses.
        severity, score = severity_from_token("(AV:N/AC:L/Au:N/C:P/I:P/A:P)")
        assert severity is Severity.HIGH
        assert score == 7.5

    def test_cvss4_critical(self) -> None:
        severity, score = severity_from_token(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
        assert severity is Severity.CRITICAL
        assert score is not None and score >= 9.0

    def test_malformed_vector_is_none(self) -> None:
        assert severity_from_token("CVSS:3.1/AV:X/nonsense") == (None, None)


class TestNumericTokens:
    @pytest.mark.parametrize(
        ("token", "severity", "score"),
        [
            ("9.8", Severity.CRITICAL, 9.8),
            ("7.0", Severity.HIGH, 7.0),
            ("4.0", Severity.MEDIUM, 4.0),
            ("2.5", Severity.LOW, 2.5),
            ("0", Severity.INFO, 0.0),
        ],
    )
    def test_bands(self, token: str, severity: Severity, score: float) -> None:
        assert severity_from_token(token) == (severity, score)

    @pytest.mark.parametrize("token", ["11", "-1", "10.1"])
    def test_out_of_range_is_none(self, token: str) -> None:
        assert severity_from_token(token) == (None, None)


class TestDegenerateTokens:
    @pytest.mark.parametrize("token", [None, "", "   ", "important", "n/a"])
    def test_unusable_tokens(self, token: str | None) -> None:
        assert severity_from_token(token) == (None, None)


class TestBandEdges:
    @pytest.mark.parametrize(
        ("score", "severity"),
        [
            (10.0, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.9, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.9, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.9, Severity.LOW),
            (0.1, Severity.LOW),
            (0.09, Severity.INFO),
            (0.0, Severity.INFO),
        ],
    )
    def test_cuts(self, score: float, severity: Severity) -> None:
        assert band_for_score(score) is severity

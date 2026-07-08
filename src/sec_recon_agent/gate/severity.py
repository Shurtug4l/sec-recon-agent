"""Severity derivation from OSV's raw severity token.

OSV surfaces severity as the upstream-authored score string verbatim: almost
always a CVSS vector (v2 vectors are bare "AV:N/...", v3/v4 carry a
"CVSS:3.x/" / "CVSS:4.0/" prefix), occasionally a plain numeric score. The
base score is computed deterministically from the vector via the `cvss`
library (RedHatProductSecurity), then banded with the NVD qualitative cuts.
Anything unparseable yields (None, None) - the SSVC decision still works
(Act/Attend are KEV/EPSS/exploit-driven; only the severity-based Track* rung
loses signal) and the SARIF just omits security-severity for that rule.
"""

from decimal import Decimal

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from sec_recon_agent.agent.schema import Severity

# NVD qualitative bands (CVSS v3/v4 spec): 9.0+ critical, 7.0-8.9 high,
# 4.0-6.9 medium, 0.1-3.9 low. A computed 0.0 maps to INFO: evaluated, no
# impact - distinct from None, which means "no usable severity data at all".
_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def band_for_score(score: float) -> Severity:
    for cut, severity in _BANDS:
        if score >= cut:
            return severity
    return Severity.INFO


def _base_score(token: str) -> float | None:
    if token.startswith("CVSS:4"):
        raw = CVSS4(token).base_score
    elif token.startswith("CVSS:3"):
        raw = CVSS3(token).base_score
    elif token.startswith(("AV:", "(AV:")):
        # CVSS v2 vectors carry no version prefix; the parenthesized form is
        # NVD's historical serialization.
        raw = CVSS2(token.strip("()")).base_score
    else:
        try:
            raw = Decimal(token)
        except ArithmeticError:
            return None
    score = float(raw)
    if not 0.0 <= score <= 10.0:
        return None
    return score


def severity_from_token(token: str | None) -> tuple[Severity | None, float | None]:
    """Return (qualitative severity, numeric base score) for an OSV token.

    (None, None) when the token is absent, malformed, or out of range; the
    caller records the gap instead of guessing a band.
    """
    if token is None or not token.strip():
        return (None, None)
    try:
        score = _base_score(token.strip())
    except CVSSError:
        return (None, None)
    if score is None:
        return (None, None)
    return (band_for_score(score), score)

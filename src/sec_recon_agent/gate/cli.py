"""`sec-recon-gate` CLI: deterministic SBOM gate for CI.

Thin shell over gate/runner.py - the only impure inputs (clock for the
OpenVEX timestamp, file/stdin I/O, event loop) live here.

Exit codes:
    0  gate passed (no finding met the fail-on threshold, coverage OK)
    1  gate failed on policy (findings at/above threshold, or coverage
       gaps under --strict)
    2  infrastructure/usage failure (unreadable input, unusable SBOM, KEV
       catalog unavailable) - deliberately distinct from 1 so a CI job can
       tell "the dependency tree is bad" from "the gate could not run".
"""

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sec_recon_agent.export.openvex import DEFAULT_AUTHOR, ProductIdentityError
from sec_recon_agent.gate.models import FailOn, GateReport
from sec_recon_agent.gate.render import gate_to_openvex, gate_to_sarif, openvex_excluded
from sec_recon_agent.gate.runner import run_gate
from sec_recon_agent.mcp_server.errors import KevError, SbomError

_FAIL_ON_CHOICES = ("act", "attend", "track-star", "never")


def _read_sbom(path_arg: str) -> tuple[str, str]:
    """Return (content, default artifact uri)."""
    if path_arg == "-":
        return sys.stdin.read(), "sbom"
    path = Path(path_arg)
    return path.read_text(), path.as_posix()


def _emit(doc: dict[str, object], out_arg: str | None) -> None:
    text = json.dumps(doc, indent=2)
    if out_arg:
        Path(out_arg).write_text(text + "\n")
    else:
        print(text)


def _summary_line(report: GateReport) -> str:
    verdict = "PASS" if report.policy.passed else "FAIL"
    triggered = (
        f"; triggered: {', '.join(report.policy.triggered)}" if report.policy.triggered else ""
    )
    gaps = f"; coverage gaps: {report.policy.coverage_gaps}" if report.policy.coverage_gaps else ""
    return (
        f"gate {verdict} (fail-on {report.policy.fail_on}): "
        f"{len(report.findings)} findings across "
        f"{report.components_scanned}/{report.components_total} components; "
        f"SSVC {report.ssvc.decision}{triggered}{gaps}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-gate",
        description=(
            "Deterministic, no-LLM SBOM gate: OSV advisories enriched with "
            "KEV/EPSS/exploit signals, prioritized with SSVC."
        ),
    )
    parser.add_argument("sbom", nargs="?", default="-", help="SBOM path, or - for stdin")
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="act",
        help="minimum SSVC decision that fails the gate (default: act)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail the gate on enrichment coverage gaps, not only on findings",
    )
    parser.add_argument(
        "--report", default=None, help="write the GateReport JSON here instead of stdout"
    )
    parser.add_argument("--sarif", default=None, help="also write SARIF 2.1.0 to this path")
    parser.add_argument("--openvex", default=None, help="also write OpenVEX v0.2.0 to this path")
    parser.add_argument(
        "--artifact-uri",
        default=None,
        help="repo-relative path GitHub attaches alerts to (default: the SBOM path)",
    )
    parser.add_argument("--author", default=DEFAULT_AUTHOR, help="OpenVEX document author IRI")
    args = parser.parse_args(argv)

    try:
        content, default_uri = _read_sbom(args.sbom)
    except OSError as exc:
        print(f"unreadable SBOM: {exc}", file=sys.stderr)
        return 2

    fail_on = cast(FailOn, args.fail_on.replace("-", "_"))
    try:
        report = asyncio.run(run_gate(content, fail_on=fail_on, strict=args.strict))
    except SbomError as exc:
        print(f"unusable SBOM: {exc}", file=sys.stderr)
        return 2
    except KevError as exc:
        print(f"KEV catalog unavailable, refusing to gate blind: {exc}", file=sys.stderr)
        return 2

    _emit(report.model_dump(mode="json"), args.report)

    if args.sarif:
        doc = gate_to_sarif(report, artifact_uri=args.artifact_uri or default_uri)
        _emit(doc, args.sarif)
    if args.openvex:
        try:
            vex = gate_to_openvex(report, timestamp=datetime.now(UTC), author=args.author)
        except ProductIdentityError as exc:
            print(f"openvex skipped: {exc}", file=sys.stderr)
        else:
            _emit(vex, args.openvex)
            excluded = openvex_excluded(report)
            if excluded:
                print(
                    f"openvex: {len(excluded)} finding(s) excluded for missing product "
                    f"identity: {', '.join(excluded)}",
                    file=sys.stderr,
                )

    print(_summary_line(report), file=sys.stderr)
    return 0 if report.policy.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""`sec-recon-export` CLI: render a TriageReport JSON into SARIF or OpenVEX.

Thin shell over the pure renderers - the only impure inputs (clock for the
OpenVEX timestamp, file/stdin I/O) live here. Exit codes: 0 on success,
2 on bad usage (unreadable/invalid report, missing product identity).
"""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from sec_recon_agent.agent.schema import TriageReport
from sec_recon_agent.export.openvex import DEFAULT_AUTHOR, ProductIdentityError, to_openvex
from sec_recon_agent.export.sarif import to_sarif


def _load_report(path_arg: str) -> tuple[TriageReport, str]:
    """Parse the report and return it with a default artifact uri (the input path)."""
    if path_arg == "-":
        return TriageReport.model_validate_json(sys.stdin.read()), "triage-report.json"
    path = Path(path_arg)
    return TriageReport.model_validate_json(path.read_text()), path.as_posix()


def _emit(doc: dict[str, object], out_arg: str | None) -> None:
    text = json.dumps(doc, indent=2)
    if out_arg:
        Path(out_arg).write_text(text + "\n")
    else:
        print(text)


def _cmd_sarif(args: argparse.Namespace) -> int:
    try:
        report, default_uri = _load_report(args.report)
    except (OSError, ValidationError) as exc:
        print(f"invalid report: {exc}", file=sys.stderr)
        return 2
    doc = to_sarif(report, artifact_uri=args.artifact_uri or default_uri)
    _emit(doc, args.out)
    return 0


def _cmd_openvex(args: argparse.Namespace) -> int:
    try:
        report, _ = _load_report(args.report)
    except (OSError, ValidationError) as exc:
        print(f"invalid report: {exc}", file=sys.stderr)
        return 2
    try:
        doc = to_openvex(
            report,
            products=args.product,
            timestamp=datetime.now(UTC),
            author=args.author,
        )
    except ProductIdentityError as exc:
        print(f"openvex: {exc}", file=sys.stderr)
        return 2
    _emit(doc, args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-export",
        description="Render a TriageReport JSON into SARIF 2.1.0 or OpenVEX v0.2.0.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub_sarif = sub.add_parser("sarif", help="SARIF 2.1.0 for GitHub code scanning.")
    sub_sarif.add_argument(
        "report", nargs="?", default="-", help="report JSON path, or - for stdin"
    )
    sub_sarif.add_argument(
        "--artifact-uri",
        default=None,
        help="repo-relative path GitHub attaches alerts to (default: the report path)",
    )
    sub_sarif.add_argument("--out", default=None, help="write to file instead of stdout")
    sub_sarif.set_defaults(func=_cmd_sarif)

    sub_vex = sub.add_parser("openvex", help="OpenVEX v0.2.0 statements.")
    sub_vex.add_argument("report", nargs="?", default="-", help="report JSON path, or - for stdin")
    sub_vex.add_argument(
        "--product",
        action="append",
        required=True,
        help="purl of the triaged product (repeatable); required, never guessed",
    )
    sub_vex.add_argument("--author", default=DEFAULT_AUTHOR, help="document author IRI")
    sub_vex.add_argument("--out", default=None, help="write to file instead of stdout")
    sub_vex.set_defaults(func=_cmd_openvex)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

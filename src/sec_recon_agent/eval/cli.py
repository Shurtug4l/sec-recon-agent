"""`sec-recon-eval` entry point.

Run the curated golden set against a live agent API and print a
human-readable summary plus an optional JSON dump for archival.
"""

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from sec_recon_agent.eval.golden_set import GOLDEN_SET, GoldenCase
from sec_recon_agent.eval.runner import (
    DEFAULT_API_URL,
    DEFAULT_TIMEOUT_SECONDS,
    health_check,
    run_case,
)
from sec_recon_agent.eval.scorer import CaseVerdict, score


def _filter_cases(filter_expr: str | None) -> tuple[GoldenCase, ...]:
    if not filter_expr:
        return GOLDEN_SET
    tokens = {t.strip() for t in filter_expr.split(",") if t.strip()}
    return tuple(
        c for c in GOLDEN_SET if c.id in tokens or set(c.tags) & tokens
    )


def _format_row(case: GoldenCase, verdict: CaseVerdict, elapsed: float) -> str:
    badge = "PASS" if verdict.passed else "FAIL"
    note = f" | {'; '.join(verdict.notes)}" if verdict.notes else ""
    return (
        f"  [{badge}] {case.id:<30} "
        f"sev={'ok' if verdict.severity_ok else 'no':>3}  "
        f"cve_recall={verdict.cve_recall:.2f}  "
        f"kev={'ok' if verdict.kev_ok else 'no':>3}  "
        f"rw={'ok' if verdict.ransomware_ok else 'no':>3}  "
        f"{elapsed:5.1f}s{note}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-eval",
        description=(
            "Run the curated golden set against the live agent API and "
            "produce a soft-assertion regression report."
        ),
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"agent API base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--filter",
        default=None,
        help=(
            "comma-separated list of case IDs or tags to run "
            "(e.g. 'kev,by-id,heartbleed'). Default: all cases."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-case timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS:.0f})",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="optional path to dump structured results as JSON",
    )
    args = parser.parse_args(argv)

    cases = _filter_cases(args.filter)
    if not cases:
        print(f"no cases matched filter {args.filter!r}", file=sys.stderr)
        return 2

    if not health_check(args.api_url):
        print(
            f"agent API at {args.api_url} is not responding on /v1/health. "
            f"Did you `make up`?",
            file=sys.stderr,
        )
        return 2

    print(f"running {len(cases)} case(s) against {args.api_url} ...")
    json_payload: list[dict[str, Any]] = []
    passed = 0
    for case in cases:
        result = run_case(case, api_url=args.api_url, timeout_seconds=args.timeout)
        if result.report is None:
            print(
                f"  [ERR ] {case.id:<30} {result.error}  {result.elapsed_seconds:5.1f}s",
            )
            json_payload.append(
                {
                    "case": asdict(case),
                    "error": result.error,
                    "elapsed_seconds": result.elapsed_seconds,
                },
            )
            continue
        verdict = score(case, result.report)
        passed += int(verdict.passed)
        print(_format_row(case, verdict, result.elapsed_seconds))
        json_payload.append(
            {
                "case": asdict(case),
                "verdict": asdict(verdict),
                "report": result.report.model_dump(mode="json"),
                "elapsed_seconds": result.elapsed_seconds,
            },
        )

    total = len(cases)
    rate = passed / total if total else 0.0
    print(f"\nresult: {passed}/{total} cases passed ({rate:.0%})")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, default=str)
        print(f"json report written to {args.json_output}")

    # Exit code: 0 if all passed, 1 otherwise (handy for CI gating once
    # the suite is stable enough to be a blocking signal).
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

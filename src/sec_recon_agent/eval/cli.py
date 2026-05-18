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
    return tuple(c for c in GOLDEN_SET if c.id in tokens or set(c.tags) & tokens)


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
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "override LLM model for this run (haiku / sonnet / opus or a "
            "full identifier on the backend allowlist). Default: deployment "
            "default."
        ),
    )
    parser.add_argument(
        "--models",
        default=None,
        help=(
            "comma-separated list of models to compare (e.g. 'haiku,sonnet,opus'). "
            "Runs the full golden set against each and prints a side-by-side "
            "table. Mutually exclusive with --model."
        ),
    )
    args = parser.parse_args(argv)

    if args.model and args.models:
        print("--model and --models are mutually exclusive", file=sys.stderr)
        return 2

    cases = _filter_cases(args.filter)
    if not cases:
        print(f"no cases matched filter {args.filter!r}", file=sys.stderr)
        return 2

    if not health_check(args.api_url):
        print(
            f"agent API at {args.api_url} is not responding on /v1/health. Did you `make up`?",
            file=sys.stderr,
        )
        return 2

    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        return _run_comparison(cases, args, models)
    return _run_single(cases, args, args.model)


def _run_single(
    cases: tuple[GoldenCase, ...],
    args: argparse.Namespace,
    model: str | None,
) -> int:
    label = model or "default"
    print(f"running {len(cases)} case(s) against {args.api_url} (model={label}) ...")
    json_payload: list[dict[str, Any]] = []
    passed = 0
    for case in cases:
        result = run_case(
            case,
            api_url=args.api_url,
            timeout_seconds=args.timeout,
            model=model,
        )
        if result.report is None:
            print(
                f"  [ERR ] {case.id:<30} {result.error}  {result.elapsed_seconds:5.1f}s",
            )
            json_payload.append(
                {
                    "case": asdict(case),
                    "model": label,
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
                "model": label,
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


def _run_comparison(
    cases: tuple[GoldenCase, ...],
    args: argparse.Namespace,
    models: list[str],
) -> int:
    """Run the same case set against each model and print a side-by-side table."""
    per_model: dict[str, list[dict[str, Any]]] = {}
    per_model_pass: dict[str, int] = {}

    for model in models:
        print(f"\n=== model: {model} ===")
        rows: list[dict[str, Any]] = []
        passed = 0
        for case in cases:
            result = run_case(
                case,
                api_url=args.api_url,
                timeout_seconds=args.timeout,
                model=model,
            )
            if result.report is None:
                rows.append(
                    {
                        "case_id": case.id,
                        "passed": False,
                        "cve_recall": 0.0,
                        "elapsed_seconds": result.elapsed_seconds,
                        "error": result.error,
                    },
                )
                print(f"  [ERR ] {case.id:<30} {result.error}")
                continue
            verdict = score(case, result.report)
            passed += int(verdict.passed)
            rows.append(
                {
                    "case_id": case.id,
                    "passed": verdict.passed,
                    "cve_recall": verdict.cve_recall,
                    "severity_ok": verdict.severity_ok,
                    "elapsed_seconds": result.elapsed_seconds,
                },
            )
            print(_format_row(case, verdict, result.elapsed_seconds))
        per_model[model] = rows
        per_model_pass[model] = passed
        print(
            f"  -> {passed}/{len(cases)} passed ({passed / max(len(cases), 1):.0%})",
        )

    # Side-by-side summary
    print("\n=== comparison summary ===")
    header = f"  {'case':<30} " + "  ".join(f"{m:>10}" for m in models)
    print(header)
    for i, case in enumerate(cases):
        cells = []
        for model in models:
            row = per_model[model][i]
            cells.append("PASS" if row.get("passed") else "FAIL")
        print(f"  {case.id:<30} " + "  ".join(f"{c:>10}" for c in cells))
    print()
    for model in models:
        total = len(cases)
        rate = per_model_pass[model] / total if total else 0.0
        print(f"  {model:<20} {per_model_pass[model]}/{total} ({rate:.0%})")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(
                {model: per_model[model] for model in models},
                f,
                indent=2,
                default=str,
            )
        print(f"json report written to {args.json_output}")

    all_pass = all(per_model_pass[m] == len(cases) for m in models)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

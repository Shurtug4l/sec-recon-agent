"""`sec-recon-audit` CLI: verify hash chain, tail recent records, show count."""

import argparse
import json
import sys
from pathlib import Path

from sec_recon_agent.audit.store import AuditStore, TamperDetectedError
from sec_recon_agent.config import settings


def _open_store(db_path_arg: str | None) -> AuditStore:
    db_path = Path(db_path_arg) if db_path_arg else settings.audit_db_path
    return AuditStore(db_path)


def _cmd_verify(args: argparse.Namespace) -> int:
    store = _open_store(args.db_path)
    try:
        verified = store.verify()
    except TamperDetectedError as exc:
        print(f"AUDIT TAMPER: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {verified} event(s) verified, chain intact.")
    return 0


def _cmd_tail(args: argparse.Namespace) -> int:
    store = _open_store(args.db_path)
    events = store.tail(args.limit)
    if args.json:
        print(json.dumps([e.model_dump() for e in events], indent=2, default=str))
    else:
        for e in reversed(events):
            kev = f"kev={e.kev_hits}" if e.kev_hits else "kev=0"
            rw = f"rw={e.ransomware_hits}" if e.ransomware_hits else "rw=0"
            print(
                f"{e.ts}  {e.event_id[:12]}  {e.outcome:<7}  "
                f"sev={e.severity or '-':<8}  cves={e.cves_count}  {kev}  {rw}  "
                f"{e.duration_ms}ms  query_sha={e.query_sha256[:12]}",
            )
    return 0


def _cmd_count(args: argparse.Namespace) -> int:
    store = _open_store(args.db_path)
    print(store.count())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sec-recon-audit",
        description="Inspect and verify the triage audit trail.",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="path to the audit SQLite db (default: settings.audit_db_path)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub_verify = sub.add_parser(
        "verify",
        help="recompute the full hash chain; exit 1 on tamper.",
    )
    sub_verify.set_defaults(func=_cmd_verify)

    sub_tail = sub.add_parser("tail", help="show the most recent N records.")
    sub_tail.add_argument("--limit", type=int, default=20)
    sub_tail.add_argument("--json", action="store_true", help="dump as JSON array.")
    sub_tail.set_defaults(func=_cmd_tail)

    sub_count = sub.add_parser("count", help="print the total event count.")
    sub_count.set_defaults(func=_cmd_count)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

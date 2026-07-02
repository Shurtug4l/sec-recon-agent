#!/usr/bin/env python3
"""Capture a real /v1/triage SSE stream into a replay fixture.

Records every SSE frame with its arrival offset (ms from run start) so a
demo-mode replay can reproduce the real cadence. Output is one JSON file per
capture: {meta, events:[{event, data, at_ms}]}. `data` is kept as the parsed
JSON object (final/usage) or the raw dict for started/node/error.

Usage:
    python capture_sse.py --query "..." --slug log4shell [--model sonnet]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

API = "http://localhost:8000/v1/triage"


def capture(query: str, model: str | None, slug: str, out_dir: str) -> dict:
    body = {"query": query}
    if model:
        body["model"] = model
    req = urllib.request.Request(  # noqa: S310 - fixed localhost dev endpoint
        API,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        method="POST",
    )
    events: list[dict] = []
    start = time.monotonic()
    event_type: str | None = None
    with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 - localhost only
        buf = ""
        for chunk in resp:
            buf += chunk.decode("utf-8", errors="replace")
            buf = buf.replace("\r\n", "\n")
            while "\n\n" in buf:
                frame, buf = buf.split("\n\n", 1)
                event_type = None
                data_line = None
                for line in frame.split("\n"):
                    if line.startswith("event:"):
                        event_type = line[len("event:") :].strip()
                    elif line.startswith("data:"):
                        data_line = line[len("data:") :].lstrip()
                if event_type is None or data_line is None:
                    continue
                at_ms = int((time.monotonic() - start) * 1000)
                try:
                    parsed = json.loads(data_line)
                except json.JSONDecodeError:
                    parsed = data_line
                events.append({"event": event_type, "data": parsed, "at_ms": at_ms})
                # Live progress to stderr
                tag = event_type
                if event_type == "node":
                    tag = f"node:{parsed.get('node')}"
                elif event_type == "final":
                    ssvc = parsed.get("ssvc") or {}
                    tag = (
                        f"final sev={parsed.get('severity')} "
                        f"ssvc={ssvc.get('decision')} rule={ssvc.get('rule')} "
                        f"cov={len(parsed.get('signal_coverage') or [])}"
                    )
                print(f"  [{at_ms:>6}ms] {tag}", file=sys.stderr)

    duration_ms = int((time.monotonic() - start) * 1000)
    fixture = {
        "meta": {
            "slug": slug,
            "query": query,
            "model": model or "default",
            "duration_ms": duration_ms,
        },
        "events": events,
    }
    path = f"{out_dir}/{slug}.json"
    with open(path, "w") as f:
        json.dump(fixture, f, indent=2)
    err = next((e for e in events if e["event"] == "error"), None)
    print(f"-> wrote {path} ({duration_ms}ms, {len(events)} events)", file=sys.stderr)
    if err:
        print(f"!! ERROR event: {err['data']}", file=sys.stderr)
    return fixture


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--out", default=".")
    args = ap.parse_args()
    capture(args.query, args.model, args.slug, args.out)

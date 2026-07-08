"""End-to-end evaluation suite for the triage agent.

Exercises the live HTTP API (POST /v1/triage) with a curated golden set
of queries and grades the model's output with soft assertions:
- severity must be within +-1 level of the expected baseline;
- at least half of the expected CVE IDs must appear in the report;
- KEV / EPSS / ransomware flags must be honored when explicitly expected.

The suite is deliberately not part of the unit-test fast lane: it
requires `make up` (live MCP server + agent API) and bills the LLM
provider. Run on demand before shipping prompt or model changes.

What DOES run in the fast lane is the record-replay gate: cassette.py
defines the frozen-trajectory format and the staleness hash that
tests/replay/ checks against the committed recordings on every PR.
"""

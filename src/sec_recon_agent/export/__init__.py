"""Read-side exporters that render a TriageReport into interchange formats.

Pure, deterministic transforms (no I/O, no clock reads, no LLM): SARIF
2.1.0 for GitHub code scanning and OpenVEX v0.2.0 for VEX consumers. They
only READ the existing report schema - adding report fields for export
would change the LLM-visible TriageReport JSON schema and trip the
record-replay staleness gate.
"""

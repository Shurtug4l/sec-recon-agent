"""Append-only audit trail for triage runs.

Records one row per /v1/triage call with a SHA-256 hash chain
(`prev_event_hash`, `this_event_hash`) that makes silent tampering
detectable: a `sec-recon-audit verify` recomputes the chain and
flags the first broken link.

Privacy posture (default-on safe):
- query and report summary are NEVER persisted as plain text. Only
  their SHA-256 digest and length / aggregate counts are kept.
- `AUDIT_INCLUDE_QUERY=true` and `AUDIT_INCLUDE_SUMMARY=true` opt
  in to plain-text retention for deployments where the legal /
  compliance posture allows it.

Compliance angle:
- EU AI Act art. 12 ("record-keeping") and ISO/IEC 42001 require
  auditable trails for AI-system decisions. This module provides
  the substrate; the policy of what to retain stays in settings.
"""

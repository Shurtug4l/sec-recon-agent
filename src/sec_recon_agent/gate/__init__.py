"""Deterministic, no-LLM SBOM gate.

Chains the existing tool logic in-process (sbom_ingest -> osv_lookup ->
KEV/EPSS/exploit enrichment -> SSVC) into a CI-consumable verdict. No model
call anywhere on this path: the gate is reproducible, free, and safe to run
on every pull request.
"""

from sec_recon_agent.gate.models import (
    FeedCoverage,
    FindingCoverage,
    GateFinding,
    GatePolicy,
    GateReport,
    SkippedComponent,
    SkipReason,
)
from sec_recon_agent.gate.runner import run_gate

__all__ = [
    "FeedCoverage",
    "FindingCoverage",
    "GateFinding",
    "GatePolicy",
    "GateReport",
    "SkipReason",
    "SkippedComponent",
    "run_gate",
]

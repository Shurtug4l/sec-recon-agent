"""Cross-cutting security primitives applied at MCP tool output boundaries.

The agent system prompt declares an untrusted-content boundary: tool output
text from third-party sources (NVD descriptions, vendor strings, Nmap
service banners) must be treated as DATA and not as instructions. That is
the LLM-side soft boundary. This module adds the hard, code-side counterpart:
explicit marker fences around free-text fields that an attacker could craft.

Where this is applied:
- CVEDetail.description (NVD-authored, vendor-controlled)
- CVECandidate.summary (same content, sourced from the indexed corpus)
- NmapPort.product, NmapPort.version (service banners; attacker-crafted in
  hostile scan inputs)
- KevCheck.vulnerability_name, KevCheck.required_action, KevCheck.notes
  (CISA-published but vendor- and researcher-authored upstream)

Where this is NOT applied:
- CVE IDs (regex-constrained, no free text)
- CVSS scores (numeric)
- Severities (enum)
- CWE IDs (CWE-N pattern)
- CPE strings (CPE 2.3 format, structured)
- URLs / references (Pydantic HttpUrl validated)
- Hostnames (DNS charset, length-capped)
- Port numbers (int-constrained)
- KEV vendor_project / product (short identifiers like "Apache", "HTTP Server")
- KEV date_added / due_date (ISO date strings, _coerce_str-truncated to 32 chars)
- EPSS probability / percentile / score_date (numeric or ISO date)

Pydantic validators reject malformed structured fields at the boundary,
so they cannot carry instruction-like payloads.
"""

UNTRUSTED_START = "<UNTRUSTED_CONTENT>"
UNTRUSTED_END = "</UNTRUSTED_CONTENT>"


def fence_untrusted(text: str | None) -> str | None:
    """Wrap a free-text string with the untrusted-content markers.

    Returns the input unchanged when it is None or empty: fencing empty
    strings inflates token cost without changing the LLM's interpretation.
    """
    if not text:
        return text
    return f"{UNTRUSTED_START}\n{text}\n{UNTRUSTED_END}"

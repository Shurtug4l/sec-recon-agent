"""Cross-cutting security primitives applied at MCP tool output boundaries.

The agent system prompt declares an untrusted-content boundary: tool output
text from third-party sources (NVD descriptions, vendor strings, Nmap
service banners) must be treated as DATA and not as instructions. That is
the LLM-side soft boundary. This module adds the hard, code-side counterpart:
explicit marker fences around free-text fields that an attacker could craft.

The fence is structurally unforgeable from inside the payload, two ways:

- Every marker carries a random id minted once per server process
  (`FENCE_NONCE`), and the system prompt tells the model that only a pair
  with matching ids is a boundary. The text's author cannot know the id, so
  a closing tag typed into a CVE description or a banner does not match.
- Any marker-shaped token already inside the payload has its `<` escaped to
  `&lt;` before wrapping (`neutralize_markers`), so the literal tag cannot
  appear inside a fenced region at all, whatever id it claims. The text
  stays readable; only the boundary is sanitized, never the content.

Field sizing: a fenced field's `max_length` is its payload budget plus
`FENCE_OVERHEAD` (both markers and the two newlines). Neutralization can
grow a payload by three characters per escaped marker, so `fence_untrusted`
truncates the neutralized payload to `max_chars` when the caller passes its
budget: the model cap then holds for every input, including one stuffed with
forged markers to push a field over its limit.

Where this is applied:
- CVEDetail.description (NVD-authored, vendor-controlled)
- CVECandidate.summary (same content, sourced from the indexed corpus)
- NmapPort.product, NmapPort.version (service banners; attacker-crafted in
  hostile scan inputs)
- KevCheck.vulnerability_name, KevCheck.required_action, KevCheck.notes
  (CISA-published but vendor- and researcher-authored upstream)
- OsvVuln.summary (OSV.dev advisory text, authored upstream by ecosystem
  maintainers and security researchers)

Where this is NOT applied (validated identifiers, not fenced; bounded in
length, never treated as inert):
- CVE IDs (regex-constrained, no free text)
- CVSS scores (numeric)
- CVEDetail.cvss_v3_severity (one of the five CVSS v3 tokens, else None)
- CVEDetail.cwe_ids (whole-string CWE-N pattern; anything else is dropped)
- CVEDetail.affected_cpes (whole CPE 2.3 formatted strings, whitespace-free,
  capped at 400 chars per entry; anything else is dropped)
- URLs / references (Pydantic HttpUrl validated; exploit_check returns
  repository URLs only, so no attacker-chosen path text rides inside one)
- SbomComponent.name / SbomComponent.version (package-identifier charset,
  no whitespace or control characters; a bad name drops the component and
  is counted in SbomComponentList.rejected_count, a bad version is None)
- SbomComponent.purl (type/namespace/name@version in the Package URL
  shape, qualifiers and subpath dropped, else None) and
  SbomComponent.ecosystem (derived from the validated purl type)
- NmapHost.ip (a parsed IPv4/IPv6 address in canonical form; a host
  without one is dropped)
- NmapHost.hostnames (RFC 1123 charset plus underscore, 253 chars; others
  are dropped; capped per host and per scan)
- NmapScanResult.scan_start (Unix epoch digits only, else None)
- NmapPort.protocol (tcp/udp/sctp/ip, else the port is dropped),
  NmapPort.state (state token, else "unknown"), NmapPort.service
  (service-name token, else None)
- Error messages of nmap_parse_xml echo no caller text (no DOCTYPE ids, no
  root tag); the exception detail stays on the span
- KEV vendor_project / product (short identifiers like "Apache", "HTTP Server")
- KEV date_added / due_date (ISO date strings, _coerce_str-truncated to 32 chars)
- EPSS probability / percentile / score_date (numeric or ISO date)

Pydantic validators reject malformed structured fields at the boundary, and
the length caps bound what a well-formed one can carry.

Residual, accepted: identifier charsets block spaces, not words. A
hyphen-joined hostname or package name (`ignore-previous-instructions`)
still passes, bounded by the field's length cap.
"""

import re
import secrets

# One random id per server process. Minted at import so every fence this
# process emits carries the same id and the model can match pairs; a value
# the text's author cannot know is what makes a forged closing tag inert.
FENCE_NONCE = secrets.token_hex(4)

_MARKER_NAME = "UNTRUSTED_CONTENT"
UNTRUSTED_START = f'<{_MARKER_NAME} id="{FENCE_NONCE}">'
UNTRUSTED_END = f'</{_MARKER_NAME} id="{FENCE_NONCE}">'

# Characters the fence adds around a payload: both markers plus the two
# newlines. Field caps in models.py are payload budget + this constant.
FENCE_OVERHEAD = len(UNTRUSTED_START) + len(UNTRUSTED_END) + 2

# Any token that could read as one of our markers, whatever id it claims and
# whatever case it uses: `<UNTRUSTED_CONTENT`, `</UNTRUSTED_CONTENT`, with
# optional whitespace after `<` or `</`.
_MARKER_SHAPED = re.compile(r"<(\s*/?\s*)(" + _MARKER_NAME + r")", re.IGNORECASE)


def neutralize_markers(text: str) -> str:
    """Escape the `<` of every marker-shaped token so it cannot close or open
    a fence. The rest of the token is kept, so the text stays legible."""
    return _MARKER_SHAPED.sub(lambda m: "&lt;" + m.group(1) + m.group(2), text)


def fence_untrusted(text: str | None, *, max_chars: int | None = None) -> str | None:
    """Wrap a free-text string with the untrusted-content markers.

    Marker-shaped tokens inside the text are neutralized first. When
    `max_chars` is given, the neutralized payload is truncated to it so the
    result never exceeds `max_chars + FENCE_OVERHEAD`, whatever the input.

    Returns the input unchanged when it is None or empty: fencing empty
    strings inflates token cost without changing the LLM's interpretation.
    """
    if not text:
        return text
    payload = neutralize_markers(text)
    if max_chars is not None:
        payload = payload[:max_chars]
    return f"{UNTRUSTED_START}\n{payload}\n{UNTRUSTED_END}"

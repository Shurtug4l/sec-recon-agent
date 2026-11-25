"""Nmap XML parser.

Pure sync parser, no I/O. Uses defusedxml to refuse XXE / DTD / external
entity expansion. Untrusted scan XML often comes from third parties, so
the parser is deliberately conservative.
"""

# defusedxml does not re-export the Element class on every Python version
# (3.13 lost the re-export; 3.14 may still have it). Use the stdlib type
# for type hints, it is the actual runtime class returned by
# defusedxml's fromstring(), defusedxml only swaps the parser.
import ipaddress
import re
from typing import Annotated, cast, get_args
from xml.etree.ElementTree import Element as XmlElement

import structlog
from defusedxml import ElementTree as ET  # noqa: N817  # ET is the conventional alias
from defusedxml.common import DefusedXmlException
from pydantic import Field

from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.models import (
    NMAP_BANNER_CHARS,
    NMAP_HOSTNAME_PATTERN,
    NMAP_HOSTNAMES_MAX,
    NMAP_HOSTNAMES_TOTAL_MAX,
    NMAP_HOSTS_MAX,
    NMAP_PORTS_PER_HOST_MAX,
    NMAP_PORTS_TOTAL_MAX,
    NMAP_SCAN_START_PATTERN,
    NMAP_SERVICE_PATTERN,
    NMAP_STATE_PATTERN,
    NmapHost,
    NmapPort,
    NmapProtocol,
    NmapScanResult,
)
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

# Hard cap on the raw XML payload. Real Nmap scans rarely exceed a few MB;
# 20MB leaves headroom for very large enterprise scans while preventing a
# crafted multi-GB document from being parsed in-process. Pydantic enforces
# the cap on the tool boundary before any XML touches defusedxml.
_NMAP_XML_MAX_BYTES = 20_000_000

# Cap on the number of <host> children processed per scan, on top of the
# per-host caps enforced inside `_parse_host` (hostnames 50, ports 200).
# The per-host caps alone allow 1000 * 200 port entries, so a scan-wide port
# cap (_NMAP_PORTS_TOTAL_CAP) bounds the returned payload regardless of shape.
_NMAP_HOST_CAP = NMAP_HOSTS_MAX
_NMAP_PORTS_PER_HOST_CAP = NMAP_PORTS_PER_HOST_MAX
_NMAP_PORTS_TOTAL_CAP = NMAP_PORTS_TOTAL_MAX
_NMAP_HOSTNAMES_TOTAL_CAP = NMAP_HOSTNAMES_TOTAL_MAX

_HOSTNAME_RE = re.compile(NMAP_HOSTNAME_PATTERN)
_SCAN_START_RE = re.compile(NMAP_SCAN_START_PATTERN)
_STATE_RE = re.compile(NMAP_STATE_PATTERN)
_SERVICE_RE = re.compile(NMAP_SERVICE_PATTERN)
_PROTOCOLS: frozenset[str] = frozenset(get_args(NmapProtocol))

NmapXmlStr = Annotated[str, Field(max_length=_NMAP_XML_MAX_BYTES)]


def _parse_port(port_el: XmlElement) -> NmapPort | None:
    # Every attribute is attacker-controlled: the scan XML is caller input.
    # Identifiers are validated whole, never truncated, so none of them can
    # carry prose to the model; banners are fenced free text with their own
    # budget (truncated after marker neutralization).
    portid_raw = port_el.get("portid")
    protocol = port_el.get("protocol")
    if portid_raw is None or protocol not in _PROTOCOLS:
        return None
    try:
        portid = int(portid_raw)
    except ValueError:
        return None
    if not 1 <= portid <= 65535:
        return None

    state_el = port_el.find("state")
    raw_state = state_el.get("state") if state_el is not None else None
    state = raw_state if raw_state and _STATE_RE.fullmatch(raw_state) else "unknown"

    service_el = port_el.find("service")
    raw_service = service_el.get("name") if service_el is not None else None
    service = raw_service if raw_service and _SERVICE_RE.fullmatch(raw_service) else None
    product = service_el.get("product") if service_el is not None else None
    version = service_el.get("version") if service_el is not None else None

    return NmapPort(
        portid=portid,
        protocol=cast(NmapProtocol, protocol),  # checked against _PROTOCOLS above
        state=state,
        service=service,
        product=fence_untrusted(product, max_chars=NMAP_BANNER_CHARS),
        version=fence_untrusted(version, max_chars=NMAP_BANNER_CHARS),
    )


def _parse_address(host_el: XmlElement) -> str | None:
    """The first IPv4/IPv6 <address> that parses, in canonical form.

    A scoped IPv6 address is skipped: `ipaddress` accepts any zone id after
    `%`, spaces included, so `fe80::1%<prose>` would carry text to the model.
    """
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") not in ("ipv4", "ipv6"):
            continue
        candidate = addr_el.get("addr")
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
            continue
        return str(address)
    return None


def _parse_host(
    host_el: XmlElement, port_budget: int, hostname_budget: int
) -> tuple[NmapHost | None, bool]:
    """Parse one <host>. Returns the host (None without a parseable address)
    and whether any of its ports or hostnames were cut, by a per-host cap or
    because a scan-wide budget ran out."""
    ip = _parse_address(host_el)
    if ip is None:
        return None, False

    # Hostnames reach the model unfenced, so a name is kept only when it
    # matches the hostname charset whole (the pattern also bounds it to 253
    # chars); anything else is dropped rather than truncated. Hostnames and
    # ports are capped per host and per scan so a crafted scan with thousands
    # of <hostname> or <port> children cannot inflate the returned payload.
    valid_names = [
        name
        for hn in host_el.findall(".//hostname")
        if (name := hn.get("name")) and _HOSTNAME_RE.fullmatch(name)
    ]
    keep = min(NMAP_HOSTNAMES_MAX, max(hostname_budget, 0))
    hostnames = valid_names[:keep]
    cut = len(valid_names) > keep
    port_elements = host_el.findall(".//port")
    ports: list[NmapPort] = []
    for index, port_el in enumerate(port_elements):
        if index >= _NMAP_PORTS_PER_HOST_CAP or len(ports) >= port_budget:
            cut = True
            break
        parsed = _parse_port(port_el)
        if parsed is not None:
            ports.append(parsed)

    return NmapHost(ip=ip, hostnames=hostnames, ports=ports), cut


@declared_tool()
def nmap_parse_xml(xml_content: NmapXmlStr) -> NmapScanResult:
    """Parse Nmap XML output into a typed scan result.

    XML is parsed with defusedxml: DTDs, external entities, and entity
    expansion are refused, so untrusted scan output cannot trigger XXE.
    Input is capped at 20MB and at most 1000 <host> elements are processed
    per scan to bound the returned payload.
    """
    with _tracer.start_as_current_span("tool.nmap_parse_xml") as span:
        span.set_attribute("tool.name", "nmap_parse_xml")
        span.set_attribute("xml.size_bytes", len(xml_content))
        # Belt-and-suspenders: the Annotated[Field(max_length=...)] on the
        # parameter is enforced by the MCP layer, but direct callers
        # (tests, internal helpers) bypass that path, so the cap is also
        # checked here before any XML hits defusedxml.
        if len(xml_content) > _NMAP_XML_MAX_BYTES:
            span.set_attribute("tool.success", False)
            raise MalformedNmapXmlError(
                f"Nmap XML payload too large: {len(xml_content)} bytes > "
                f"{_NMAP_XML_MAX_BYTES} byte cap",
            )
        try:
            # forbid_dtd=True is tighter than defusedxml's default (which
            # only blocks entity expansion and external fetches but allows
            # DTD declarations). Real Nmap XML output has no DTD.
            root = ET.fromstring(xml_content, forbid_dtd=True)
        # The messages below reach the client and the model, so none of them
        # echoes caller text: a DOCTYPE's system/public id or a root tag is
        # attacker-chosen. The exception detail stays on the span.
        except DefusedXmlException as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise MalformedNmapXmlError(
                "Nmap XML refused: DTDs and entity declarations are not allowed",
            ) from exc
        except ET.ParseError as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            line, column = exc.position
            raise MalformedNmapXmlError(
                f"Nmap XML parse failed at line {line}, column {column}",
            ) from exc

        if root.tag != "nmaprun":
            span.set_attribute("tool.success", False)
            raise MalformedNmapXmlError("Expected root element 'nmaprun'")

        # Nmap writes `start` as a Unix epoch; anything else is dropped.
        raw_start = root.get("start")
        scan_start = raw_start if raw_start and _SCAN_START_RE.fullmatch(raw_start) else None
        host_elements = root.findall("host")
        hosts_truncated = len(host_elements) > _NMAP_HOST_CAP
        ports_truncated = False
        hosts: list[NmapHost] = []
        port_total = 0
        hostname_total = 0
        for host_el in host_elements[:_NMAP_HOST_CAP]:
            parsed, ports_cut = _parse_host(
                host_el,
                _NMAP_PORTS_TOTAL_CAP - port_total,
                _NMAP_HOSTNAMES_TOTAL_CAP - hostname_total,
            )
            ports_truncated = ports_truncated or ports_cut
            if parsed is not None:
                hosts.append(parsed)
                port_total += len(parsed.ports)
                hostname_total += len(parsed.hostnames)

        span.set_attribute("tool.success", True)
        span.set_attribute("hosts.count", len(hosts))
        span.set_attribute("hosts.count_raw", len(host_elements))
        span.set_attribute("hosts.truncated", hosts_truncated)
        span.set_attribute("ports.count_total", port_total)
        span.set_attribute("ports.truncated", ports_truncated)
        log.info(
            "nmap_parse_done",
            hosts=len(hosts),
            hosts_raw=len(host_elements),
            truncated=hosts_truncated,
            ports_truncated=ports_truncated,
            ports=port_total,
        )
        return NmapScanResult(
            scan_start=scan_start,
            hosts=hosts,
            truncated=hosts_truncated or ports_truncated,
        )

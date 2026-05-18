"""Nmap XML parser.

Pure sync parser, no I/O. Uses defusedxml to refuse XXE / DTD / external
entity expansion. Untrusted scan XML often comes from third parties, so
the parser is deliberately conservative.
"""

# defusedxml does not re-export the Element class on every Python version
# (3.13 lost the re-export; 3.14 may still have it). Use the stdlib type
# for type hints — it is the actual runtime class returned by
# defusedxml's fromstring(), defusedxml only swaps the parser.
from xml.etree.ElementTree import Element as XmlElement

import structlog
from defusedxml import ElementTree as ET  # noqa: N817  # ET is the conventional alias
from defusedxml.common import DefusedXmlException

from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.models import (
    NmapHost,
    NmapPort,
    NmapScanResult,
)
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.mcp_server.server import mcp
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()


def _parse_port(port_el: XmlElement) -> NmapPort | None:
    portid_raw = port_el.get("portid")
    protocol = port_el.get("protocol")
    if portid_raw is None or protocol is None:
        return None
    try:
        portid = int(portid_raw)
    except ValueError:
        return None

    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"

    service_el = port_el.find("service")
    service = service_el.get("name") if service_el is not None else None
    product = service_el.get("product") if service_el is not None else None
    version = service_el.get("version") if service_el is not None else None

    return NmapPort(
        portid=portid,
        protocol=protocol,
        state=state,
        service=service,
        product=fence_untrusted(product),
        version=fence_untrusted(version),
    )


def _parse_host(host_el: XmlElement) -> NmapHost | None:
    ip: str | None = None
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            candidate = addr_el.get("addr")
            if candidate:
                ip = candidate
                break
    if not ip:
        return None

    # Cap hostnames and ports per host: a crafted Nmap XML with thousands
    # of <hostname> or <port> children should not be able to inflate the
    # returned payload arbitrarily.
    hostnames = [
        name for hn in host_el.findall(".//hostname") if (name := hn.get("name"))
    ][:50]
    ports: list[NmapPort] = []
    for port_el in host_el.findall(".//port")[:200]:
        parsed = _parse_port(port_el)
        if parsed is not None:
            ports.append(parsed)

    return NmapHost(ip=ip, hostnames=hostnames, ports=ports)


@mcp.tool()
def nmap_parse_xml(xml_content: str) -> NmapScanResult:
    """Parse Nmap XML output into a typed scan result.

    XML is parsed with defusedxml: DTDs, external entities, and entity
    expansion are refused, so untrusted scan output cannot trigger XXE.
    """
    with _tracer.start_as_current_span("tool.nmap_parse_xml") as span:
        span.set_attribute("tool.name", "nmap_parse_xml")
        span.set_attribute("xml.size_bytes", len(xml_content))
        try:
            # forbid_dtd=True is tighter than defusedxml's default (which
            # only blocks entity expansion and external fetches but allows
            # DTD declarations). Real Nmap XML output has no DTD.
            root = ET.fromstring(xml_content, forbid_dtd=True)
        except (ET.ParseError, DefusedXmlException) as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise MalformedNmapXmlError(f"Nmap XML parse failed: {exc}") from exc

        if root.tag != "nmaprun":
            span.set_attribute("tool.success", False)
            raise MalformedNmapXmlError(
                f"Expected root element 'nmaprun', got '{root.tag}'",
            )

        scan_start = root.get("start")
        hosts = [parsed for host_el in root.findall("host") if (parsed := _parse_host(host_el))]

        span.set_attribute("tool.success", True)
        span.set_attribute("hosts.count", len(hosts))
        span.set_attribute("ports.count_total", sum(len(h.ports) for h in hosts))
        log.info("nmap_parse_done", hosts=len(hosts), ports=sum(len(h.ports) for h in hosts))
        return NmapScanResult(scan_start=scan_start, hosts=hosts)

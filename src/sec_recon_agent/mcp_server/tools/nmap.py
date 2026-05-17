"""Nmap XML parser.

Pure sync parser, no I/O. Uses defusedxml to refuse XXE / DTD / external
entity expansion. Untrusted scan XML often comes from third parties, so
the parser is deliberately conservative.
"""

import structlog
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.models import (
    NmapHost,
    NmapPort,
    NmapScanResult,
)
from sec_recon_agent.mcp_server.server import mcp

log = structlog.get_logger()


def _parse_port(port_el: ET.Element) -> NmapPort | None:
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
        product=product,
        version=version,
    )


def _parse_host(host_el: ET.Element) -> NmapHost | None:
    ip: str | None = None
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            candidate = addr_el.get("addr")
            if candidate:
                ip = candidate
                break
    if not ip:
        return None

    hostnames = [
        name for hn in host_el.findall(".//hostname") if (name := hn.get("name"))
    ]
    ports: list[NmapPort] = []
    for port_el in host_el.findall(".//port"):
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
    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise MalformedNmapXmlError(f"Nmap XML parse failed: {exc}") from exc

    if root.tag != "nmaprun":
        raise MalformedNmapXmlError(
            f"Expected root element 'nmaprun', got '{root.tag}'",
        )

    scan_start = root.get("start")
    hosts = [parsed for host_el in root.findall("host") if (parsed := _parse_host(host_el))]

    log.info("nmap_parse_done", hosts=len(hosts), ports=sum(len(h.ports) for h in hosts))
    return NmapScanResult(scan_start=scan_start, hosts=hosts)

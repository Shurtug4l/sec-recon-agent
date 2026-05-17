"""Contract tests for the nmap_parse_xml MCP tool. Pure sync; no HTTP."""

import pytest

from sec_recon_agent.mcp_server.errors import MalformedNmapXmlError
from sec_recon_agent.mcp_server.tools.nmap import nmap_parse_xml


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun start="1730000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
    <hostnames>
      <hostname name="target.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_extracts_host_and_ports() -> None:
    result = nmap_parse_xml(SAMPLE_NMAP_XML)

    assert result.scan_start == "1730000000"
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.0.0.5"
    assert host.hostnames == ["target.local"]
    assert len(host.ports) == 3

    apache = next(p for p in host.ports if p.portid == 80)
    assert apache.protocol == "tcp"
    assert apache.state == "open"
    assert apache.service == "http"
    assert apache.product == "Apache httpd"
    assert apache.version == "2.4.49"

    closed = next(p for p in host.ports if p.portid == 443)
    assert closed.state == "closed"
    assert closed.service is None


def test_parse_raises_on_invalid_xml() -> None:
    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml("not valid xml")


def test_parse_raises_on_wrong_root_element() -> None:
    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml("<otherroot><host/></otherroot>")


def test_parse_blocks_xxe_external_entity() -> None:
    """XXE attempt should be refused by defusedxml, not parsed."""
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun start="0">
  <host>
    <address addr="&xxe;" addrtype="ipv4"/>
  </host>
</nmaprun>"""

    with pytest.raises(MalformedNmapXmlError):
        nmap_parse_xml(xxe_payload)


def test_parse_skips_host_without_ip() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun start="0">
  <host>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
  </host>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>"""

    result = nmap_parse_xml(xml)
    assert len(result.hosts) == 1
    assert result.hosts[0].ip == "10.0.0.1"

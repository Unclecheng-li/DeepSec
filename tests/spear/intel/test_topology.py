import json

import pytest

from deepsec.spear.intel import topology
from deepsec.spear.intel.topology import (
    auto_parse,
    format_markdown,
    parse_masscan_output,
    parse_nmap_text,
    parse_nmap_xml,
    render_ascii,
    topology_build_tool,
)

MASSCAN = """Discovered open port 80/tcp on 192.168.1.10
Discovered open port 443/tcp on 192.168.1.10
Discovered open port 22/tcp on 192.168.1.20
"""

NMAP_TEXT = """Starting Nmap 7.94
Nmap scan report for web.example.com (192.168.1.10)
Host is up (0.012s latency).
PORT     STATE SERVICE  VERSION
80/tcp   open  http     nginx 1.18.0
443/tcp  open  ssl/http nginx 1.18.0
OS details: Linux 5.4
MAC Address: AA:BB:CC:DD:EE:FF
"""

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 10.0.0.5" startstr="Mon">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="db.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0.32"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x"/></os>
  </host>
</nmaprun>
"""


def test_get_subnet():
    assert topology._get_subnet("192.168.1.10") == "192.168.1.0/24"
    assert topology._get_subnet("not-an-ip") == ""


def test_parse_masscan():
    topo = parse_masscan_output(MASSCAN)
    hosts = [n for n in topo.nodes if n.node_type == "host"]
    assert {h.ip for h in hosts} == {"192.168.1.10", "192.168.1.20"}
    h10 = next(h for h in hosts if h.ip == "192.168.1.10")
    assert len(h10.ports) == 2
    # subnet node + scanner->subnet edge exist
    assert any(n.node_type == "subnet" for n in topo.nodes)


def test_parse_nmap_text():
    topo = parse_nmap_text(NMAP_TEXT)
    hosts = [n for n in topo.nodes if n.node_type == "host"]
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "192.168.1.10"
    assert h.hostname == "web.example.com"
    assert h.os == "Linux 5.4"
    assert h.mac == "AA:BB:CC:DD:EE:FF"
    assert {p["port"] for p in h.ports} == {80, 443}


def test_parse_nmap_xml():
    topo = parse_nmap_xml(NMAP_XML)
    hosts = [n for n in topo.nodes if n.node_type == "host"]
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.0.0.5"
    assert h.hostname == "db.internal"
    assert h.os == "Linux 5.x"
    # only the open port (3306) is kept, closed 22 dropped
    assert [p["port"] for p in h.ports] == [3306]
    assert h.ports[0]["product"] == "MySQL"


def test_parse_nmap_xml_malformed_falls_back_to_text():
    # Looks like XML but is broken -> falls back to text parsing (no hosts here).
    topo = parse_nmap_xml("<?xml broken <<<")
    assert [n for n in topo.nodes if n.node_type == "host"] == []


def test_auto_parse_detects_formats():
    assert any(
        n.node_type == "host" for n in auto_parse(NMAP_XML).nodes
    )
    assert any(n.node_type == "host" for n in auto_parse(MASSCAN).nodes)
    assert any(n.node_type == "host" for n in auto_parse(NMAP_TEXT).nodes)


def test_format_markdown_and_ascii():
    topo = parse_nmap_text(NMAP_TEXT)
    md = format_markdown(topo)
    assert "## Network Topology" in md
    assert "192.168.1.10" in md
    assert "nginx" in md
    ascii_out = render_ascii(topo)
    assert "NETWORK TOPOLOGY MAP" in ascii_out
    assert "192.168.1.10" in ascii_out


def test_to_dict_stats():
    stats = parse_nmap_text(NMAP_TEXT).to_dict()["stats"]
    assert stats["total_hosts"] == 1
    assert stats["total_services"] == 2
    assert stats["subnets"] == 1


@pytest.mark.asyncio
async def test_tool_empty_input_error():
    out = await topology_build_tool(agent=None, args={"scan_output": "  "})
    assert out.startswith("[topology_build]")


@pytest.mark.asyncio
async def test_tool_markdown_default():
    out = await topology_build_tool(agent=None, args={"scan_output": MASSCAN})
    assert "## Network Topology" in out
    assert "192.168.1.10" in out


@pytest.mark.asyncio
async def test_tool_json_format_is_valid():
    out = await topology_build_tool(agent=None, args={"scan_output": NMAP_XML, "format": "json"})
    data = json.loads(out)
    assert "nodes" in data and "edges" in data and data["stats"]["total_hosts"] == 1


@pytest.mark.asyncio
async def test_tool_no_hosts_message():
    out = await topology_build_tool(agent=None, args={"scan_output": "nothing useful here"})
    assert "No hosts parsed" in out

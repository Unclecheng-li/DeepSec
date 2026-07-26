"""Network topology builder for VulnClaw.

Ported from HackBot (``hackbot/core/topology.py``). Parses nmap (text or XML) and
masscan output into a host/port/service graph, and renders it as JSON (for a
future D3 view), ASCII (CLI), or markdown. Pure/offline — it only processes scan
text the agent already holds, so the ``topology_build`` tool is read-only.
"""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_SCANNER_LABEL = "VulnClaw"

_MASSCAN_RE = re.compile(r"Discovered open port (\d+)/(\w+) on ([\d.]+)")
_NMAP_PORT_RE = re.compile(r"(\d+)/(\w+)\s+(open|closed|filtered)\s+(\S+)\s*(.*)")


# ── Data models ──────────────────────────────────────────────────────────────


@dataclass
class TopoNode:
    id: str
    label: str
    node_type: str  # "scanner", "host", "subnet", "service", "os"
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    os: str = ""
    ports: list[dict[str, Any]] = field(default_factory=list)
    status: str = "up"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os": self.os,
            "ports": self.ports,
            "status": self.status,
            "metadata": self.metadata,
        }


@dataclass
class TopoEdge:
    source: str
    target: str
    edge_type: str = "connection"  # "connection", "scan", "service"
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass
class NetworkTopology:
    nodes: list[TopoNode] = field(default_factory=list)
    edges: list[TopoEdge] = field(default_factory=list)
    scan_info: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "scan_info": self.scan_info,
            "timestamp": self.timestamp,
            "stats": {
                "total_hosts": len([n for n in self.nodes if n.node_type == "host"]),
                "total_services": sum(
                    len(n.ports) for n in self.nodes if n.node_type == "host"
                ),
                "subnets": len([n for n in self.nodes if n.node_type == "subnet"]),
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_subnet(ip: str) -> str:
    """Extract the /24 subnet from an IPv4 address."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""


def _new_scanner_topology(scanner_label: str) -> NetworkTopology:
    topo = NetworkTopology()
    topo.nodes.append(TopoNode(id="scanner", label=scanner_label, node_type="scanner"))
    return topo


def _attach_host(topo: NetworkTopology, host: TopoNode, subnet_nodes: dict[str, TopoNode]) -> None:
    """Add a host node and wire it to its subnet (or directly to the scanner)."""
    subnet_id = _get_subnet(host.ip)
    if subnet_id and subnet_id not in subnet_nodes:
        sn = TopoNode(id=f"subnet_{subnet_id}", label=subnet_id, node_type="subnet")
        subnet_nodes[subnet_id] = sn
        topo.nodes.append(sn)
        topo.edges.append(
            TopoEdge(source="scanner", target=f"subnet_{subnet_id}", edge_type="scan", label="scanned")
        )
    topo.nodes.append(host)
    if subnet_id and subnet_id in subnet_nodes:
        topo.edges.append(
            TopoEdge(source=f"subnet_{subnet_id}", target=host.id, edge_type="connection")
        )
    else:
        topo.edges.append(TopoEdge(source="scanner", target=host.id, edge_type="scan"))


def _host_id(ip: str) -> str:
    return f"host_{ip.replace('.', '_').replace(':', '_')}"


# ── Parsers ──────────────────────────────────────────────────────────────────


def parse_masscan_output(
    output: str, *, scanner_label: str = DEFAULT_SCANNER_LABEL
) -> NetworkTopology:
    """Parse masscan 'Discovered open port <port>/<proto> on <ip>' lines."""
    topo = _new_scanner_topology(scanner_label)
    hosts: dict[str, TopoNode] = {}
    subnet_nodes: dict[str, TopoNode] = {}

    for match in _MASSCAN_RE.finditer(output):
        port, proto, ip = int(match.group(1)), match.group(2), match.group(3)
        hid = _host_id(ip)
        if hid not in hosts:
            host = TopoNode(id=hid, label=ip, node_type="host", ip=ip)
            hosts[hid] = host
            _attach_host(topo, host, subnet_nodes)
        hosts[hid].ports.append({"port": port, "protocol": proto, "state": "open"})

    for host in hosts.values():
        host.label = f"{host.ip} ({len(host.ports)} ports)"
    return topo


def _parse_scan_header(output: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in output[:500].splitlines()[:5]:
        if "Nmap scan report" in line or "Starting Nmap" in line:
            info["scanner"] = "nmap"
        if "scan report" in line.lower():
            match = re.search(r"for\s+(\S+)", line)
            if match:
                info["target"] = match.group(1)
    return info


def _split_host_blocks(output: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in output.splitlines():
        if re.match(r"Nmap scan report for", line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _parse_host_block(block: str) -> Optional[TopoNode]:
    lines = block.strip().splitlines()
    if not lines:
        return None
    first = lines[0]

    ip = ""
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", first)
    if ip_match:
        ip = ip_match.group(1)
    if not ip:
        return None

    hostname = ""
    host_match = re.search(r"for\s+(\S+)", first)
    if host_match:
        name = host_match.group(1)
        if name != ip and not name.startswith("("):
            hostname = name

    status = "up"
    for line in lines:
        if "Host is up" in line:
            status = "up"
        elif "Host seems down" in line:
            status = "down"

    ports: list[dict[str, Any]] = []
    for line in lines:
        match = _NMAP_PORT_RE.match(line.strip())
        if not match:
            continue
        port_info: dict[str, Any] = {
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "state": match.group(3),
            "service": match.group(4),
        }
        banner = match.group(5).strip()
        if banner:
            parts = banner.split()
            if parts:
                port_info["product"] = parts[0]
            if len(parts) > 1:
                port_info["version"] = parts[1]
            port_info["banner"] = banner
        if port_info["state"] == "open":
            ports.append(port_info)

    os_name = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("OS details:") or stripped.startswith("Running:"):
            os_name = line.split(":", 1)[1].strip()
            break
        os_match = re.search(r"OS guess:\s*(.+)", line)
        if os_match:
            os_name = os_match.group(1)

    mac = ""
    mac_match = re.search(r"MAC Address:\s*([\w:]+)", block)
    if mac_match:
        mac = mac_match.group(1)

    label = hostname or ip
    if ports:
        label += f" ({len(ports)} ports)"

    return TopoNode(
        id=_host_id(ip),
        label=label,
        node_type="host",
        ip=ip,
        mac=mac,
        hostname=hostname,
        os=os_name,
        ports=ports,
        status=status,
    )


def parse_nmap_text(
    output: str, *, scanner_label: str = DEFAULT_SCANNER_LABEL
) -> NetworkTopology:
    """Parse standard nmap text output into a topology graph."""
    topo = _new_scanner_topology(scanner_label)
    topo.scan_info = _parse_scan_header(output)
    subnet_nodes: dict[str, TopoNode] = {}
    for block in _split_host_blocks(output):
        host = _parse_host_block(block)
        if host:
            _attach_host(topo, host, subnet_nodes)
    return topo


def parse_nmap_xml(
    xml_content: str, *, scanner_label: str = DEFAULT_SCANNER_LABEL
) -> NetworkTopology:
    """Parse nmap XML (-oX) output; falls back to text parsing on malformed XML."""
    topo = _new_scanner_topology(scanner_label)
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return parse_nmap_text(xml_content, scanner_label=scanner_label)

    topo.scan_info = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start": root.get("startstr", ""),
    }
    subnet_nodes: dict[str, TopoNode] = {}

    for host_elem in root.findall(".//host"):
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host_elem.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        if not ip:
            continue

        status_elem = host_elem.find("status")
        status = status_elem.get("state", "up") if status_elem is not None else "up"

        hostname = ""
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        mac = ""
        mac_elem = host_elem.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac = mac_elem.get("addr", "")

        os_name = ""
        os_elem = host_elem.find(".//osmatch")
        if os_elem is not None:
            os_name = os_elem.get("name", "")

        ports: list[dict[str, Any]] = []
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")
            port_info: dict[str, Any] = {
                "port": int(port_elem.get("portid", 0)),
                "protocol": port_elem.get("protocol", "tcp"),
                "state": state_elem.get("state", "unknown") if state_elem is not None else "unknown",
            }
            if service_elem is not None:
                port_info["service"] = service_elem.get("name", "")
                port_info["product"] = service_elem.get("product", "")
                port_info["version"] = service_elem.get("version", "")
                port_info["extrainfo"] = service_elem.get("extrainfo", "")
            if port_info["state"] == "open":
                ports.append(port_info)

        label = hostname or ip
        if ports:
            label += f" ({len(ports)} ports)"
        host_node = TopoNode(
            id=_host_id(ip),
            label=label,
            node_type="host",
            ip=ip,
            mac=mac,
            hostname=hostname,
            os=os_name,
            ports=ports,
            status=status,
        )
        _attach_host(topo, host_node, subnet_nodes)

    return topo


def auto_parse(output: str, *, scanner_label: str = DEFAULT_SCANNER_LABEL) -> NetworkTopology:
    """Auto-detect the scan format (XML / masscan / nmap text) and parse it."""
    stripped = output.strip()
    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        return parse_nmap_xml(output, scanner_label=scanner_label)
    if "Discovered open port" in output:
        return parse_masscan_output(output, scanner_label=scanner_label)
    return parse_nmap_text(output, scanner_label=scanner_label)


# ── Rendering ────────────────────────────────────────────────────────────────


def format_markdown(topo: NetworkTopology) -> str:
    stats = topo.to_dict()["stats"]
    lines = ["## Network Topology\n", "| Metric | Value |", "|--------|-------|"]
    lines.append(f"| Total Hosts | {stats['total_hosts']} |")
    lines.append(f"| Open Services | {stats['total_services']} |")
    lines.append(f"| Subnets | {stats['subnets']} |")
    lines.append("")

    hosts = [n for n in topo.nodes if n.node_type == "host"]
    if not hosts:
        lines.append("_No hosts discovered._")
        return "\n".join(lines)

    lines.append("### Discovered Hosts\n")
    lines.append("| IP | Hostname | OS | Open Ports | Status |")
    lines.append("|----|----------|-----|------------|--------|")
    for host in hosts:
        open_ports = [p for p in host.ports if p.get("state") == "open"]
        summary = ", ".join(
            f"{p['port']}/{p.get('protocol', 'tcp')}" for p in open_ports[:8]
        )
        if len(open_ports) > 8:
            summary += f" +{len(open_ports) - 8} more"
        lines.append(
            f"| {host.ip} | {host.hostname or '—'} | {host.os or '—'} | "
            f"{summary or '—'} | {host.status} |"
        )
    lines.append("")

    for host in hosts:
        open_ports = [p for p in host.ports if p.get("state") == "open"]
        if not open_ports:
            continue
        title = host.hostname or host.ip
        lines.append(f"#### {title} (`{host.ip}`)\n")
        if host.os:
            lines.append(f"**OS:** {host.os}\n")
        lines.append("| Port | Service | Product | Version |")
        lines.append("|------|---------|---------|---------|")
        for p in open_ports:
            lines.append(
                f"| {p['port']}/{p.get('protocol', 'tcp')} | {p.get('service', '—')} | "
                f"{p.get('product', '—')} | {p.get('version', '—')} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_ascii(topo: NetworkTopology) -> str:
    lines = ["=" * 60, "  NETWORK TOPOLOGY MAP", "=" * 60]
    hosts = [n for n in topo.nodes if n.node_type == "host"]
    stats = topo.to_dict()["stats"]
    lines.append(
        f"  Hosts: {stats['total_hosts']}  |  "
        f"Services: {stats['total_services']}  |  Subnets: {stats['subnets']}"
    )
    lines.append("-" * 60)
    if not hosts:
        lines.append("  No hosts discovered.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"  [Scanner: {topo.nodes[0].label if topo.nodes else 'unknown'}]")
    for host in hosts:
        host_label = host.ip
        if host.hostname:
            host_label += f" ({host.hostname})"
        status_icon = "●" if host.status == "up" else "○"
        os_info = f" [{host.os}]" if host.os else ""
        lines.append(f"   ├── {status_icon} {host_label}{os_info}")
        open_ports = [p for p in host.ports if p.get("state") == "open"]
        for p in open_ports[:15]:
            port_line = f"{p['port']}/{p.get('protocol', 'tcp')}"
            if p.get("service"):
                port_line += f"  {p['service']}"
            if p.get("product"):
                port_line += f" ({p['product']}"
                if p.get("version"):
                    port_line += f" {p['version']}"
                port_line += ")"
            lines.append(f"   │     └─ {port_line}")
        if len(open_ports) > 15:
            lines.append(f"   │     └─ ... and {len(open_ports) - 15} more ports")
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


# ── Tool handler ─────────────────────────────────────────────────────────────


async def topology_build_tool(agent: Any, args: dict[str, Any]) -> str:
    """Agent tool: build a network topology from nmap/masscan scan output."""
    scan_output = str(args.get("scan_output", "") or "")
    if not scan_output.strip():
        return "[topology_build] error: 'scan_output' (nmap/masscan text or XML) is required."
    fmt = str(args.get("format", "markdown") or "markdown").lower()

    topo = auto_parse(scan_output)
    if not any(n.node_type == "host" for n in topo.nodes):
        return "[topology_build] No hosts parsed from the provided scan output."

    if fmt == "json":
        return topo.to_json()
    if fmt == "ascii":
        return render_ascii(topo)
    return format_markdown(topo)

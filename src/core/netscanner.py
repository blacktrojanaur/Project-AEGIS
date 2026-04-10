"""
src/core/netscanner.py
----------------------
Project Aegis — Module D: Local Network Port Scanner (v2.0).

Responsibilities
~~~~~~~~~~~~~~~~
- **scan_ports(host, start, end, timeout)** : TCP connect-scan of ports on
  a local host (defaults to 127.0.0.1).  Returns structured ScanResult list.
- **classify_port(port)**                   : Map well-known port → service name.
- **flag_risky_ports(results)**             : Identify ports that are unexpected
  or high-risk if open (e.g. 445/SMB, 3389/RDP, 23/Telnet).
- **print_scan_report(results, host)**      : Pretty-print scan results to CLI.

Design constraints
~~~~~~~~~~~~~~~~~~
- Air-gapped: no outbound connections.  Only connects to `localhost` (127.0.0.1)
  or user-supplied private RFC-1918 addresses.  Public IP addresses are rejected.
- Fully stdlib: uses only `socket` and `concurrent.futures`.
- No root/admin required for TCP connect scans.
"""

import socket
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import click

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Private / loopback address check ────────────────────────────────────────

_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1",
)


def _is_private_or_loopback(host: str) -> bool:
    """Return True if *host* resolves to a private/loopback address."""
    try:
        resolved = socket.gethostbyname(host)
        return any(resolved.startswith(p) for p in _PRIVATE_PREFIXES)
    except socket.gaierror:
        return False


# ── Service name map ─────────────────────────────────────────────────────────

_WELL_KNOWN: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPCBind",
    119:  "NNTP",
    135:  "MS-RPC",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh/syslog",
    587:  "SMTP-MSA",
    631:  "IPP/CUPS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker (unauthenticated)",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit default",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# Ports that are suspicious / high-risk if found open locally
_HIGH_RISK_PORTS = {23, 135, 137, 138, 139, 445, 512, 513, 514, 1080,
                   2375, 3389, 4444, 5900, 9200, 27017}
_MEDIUM_RISK_PORTS = {21, 2049, 6379, 5985, 5986, 8888}


def classify_port(port: int) -> str:
    """Return service name for *port*, or 'unknown'."""
    return _WELL_KNOWN.get(port, "unknown")


def port_risk(port: int) -> str:
    """Return risk level for an open *port*."""
    if port in _HIGH_RISK_PORTS:
        return "HIGH"
    if port in _MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


# ── Data class ───────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:    int
    state:   str          # "open" | "closed" | "filtered"
    service: str = ""
    risk:    str = "LOW"
    banner:  str = ""

    def __post_init__(self) -> None:
        if not self.service:
            self.service = classify_port(self.port)
        if self.state == "open":
            self.risk = port_risk(self.port)


# ── Scanner ───────────────────────────────────────────────────────────────────

def _probe_port(host: str, port: int, timeout: float) -> PortResult:
    """Attempt a TCP connect to *host*:*port* and return state."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(port=port, state="open")
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except (socket.timeout, OSError):
        return PortResult(port=port, state="filtered")


def scan_ports(
    host: str = "127.0.0.1",
    start: int = 1,
    end: int = 1024,
    timeout: float = 0.5,
    max_workers: int = 100,
    show_closed: bool = False,
) -> List[PortResult]:
    """
    TCP connect-scan ports *start*–*end* on *host*.

    Args:
        host:        Target host (must be loopback or RFC-1918 private).
        start:       First port number (inclusive).
        end:         Last port number (inclusive).
        timeout:     Per-port connect timeout in seconds.
        max_workers: Thread pool size.
        show_closed: Include closed/filtered ports in results.

    Returns:
        Sorted list of :class:`PortResult` objects.

    Raises:
        click.ClickException: If *host* is not private/loopback.
    """
    if not _is_private_or_loopback(host):
        raise click.ClickException(
            f"Safety guard: '{host}' does not resolve to a private or loopback address.\n"
            f"  Project Aegis only scans localhost and RFC-1918 private networks."
        )

    total = end - start + 1
    log.info("Port scan started: host=%s range=%d-%d timeout=%.1fs", host, start, end, timeout)

    results: List[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_probe_port, host, port, timeout): port
            for port in range(start, end + 1)
        }
        completed = 0
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            completed += 1
            if result.state == "open" or show_closed:
                results.append(result)
            # Progress tick every 10%
            if completed % max(total // 10, 1) == 0:
                pct = int(completed / total * 100)
                click.echo(
                    click.style(f"  [{pct:3d}%] Scanned {completed}/{total} ports…", fg="cyan"),
                    nl=True,
                )

    results.sort(key=lambda r: r.port)
    open_count = sum(1 for r in results if r.state == "open")
    log.info("Port scan complete: %d open ports found.", open_count)
    return results


def flag_risky_ports(results: List[PortResult]) -> List[PortResult]:
    """Return only HIGH/MEDIUM-risk open ports from *results*."""
    return [r for r in results if r.state == "open" and r.risk in ("HIGH", "MEDIUM")]


def print_scan_report(results: List[PortResult], host: str) -> None:
    """Pretty-print port scan results to stdout."""
    open_ports = [r for r in results if r.state == "open"]
    risky      = flag_risky_ports(results)

    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║    PROJECT AEGIS — PORT SCAN REPORT   ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))
    click.echo(f"  Host          : {host}")
    click.echo(f"  Open Ports    : {len(open_ports)}")
    click.echo(click.style(
        f"  High-Risk Open: {len(risky)}",
        fg="red" if risky else "green",
        bold=bool(risky),
    ))
    click.echo("")

    if not open_ports:
        click.echo(click.style("  ✓ No open ports detected.", fg="green", bold=True))
    else:
        click.echo(click.style(
            f"  {'PORT':<8} {'SERVICE':<26} {'RISK':<10} {'STATE'}",
            fg="cyan", bold=True,
        ))
        click.echo("  " + "─" * 60)
        for r in open_ports:
            risk_col = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(r.risk, "white")
            click.echo(
                f"  {r.port:<8} {r.service:<26} " +
                click.style(f"{r.risk:<10}", fg=risk_col, bold=(r.risk != "LOW")) +
                f" {r.state}"
            )

    # Risk summary
    if risky:
        click.echo("")
        click.echo(click.style("  ⚠  Risk Advisory:", fg="red", bold=True))
        for r in risky:
            advice = _RISK_ADVICE.get(r.port, f"Port {r.port} ({r.service}) is open — review if expected.")
            click.echo(click.style(f"    • [{r.port}/{r.service}] {advice}", fg="yellow"))

    click.echo("")


_RISK_ADVICE: Dict[int, str] = {
    23:    "Telnet is unencrypted. Replace with SSH immediately.",
    135:   "MS-RPC open — common lateral-movement vector. Firewall if not needed.",
    139:   "NetBIOS open — disable if on a modern Windows network.",
    445:   "SMB open locally — ensure patched against EternalBlue (MS17-010).",
    512:   "rexec open — extremely insecure, disable immediately.",
    513:   "rlogin open — extremely insecure, disable immediately.",
    514:   "rsh open — extremely insecure, disable immediately.",
    1080:  "SOCKS proxy open — verify this is intentional.",
    2375:  "Docker daemon exposed WITHOUT TLS — critical, exposing full container control.",
    3389:  "RDP open — ensure NLA is enforced and MFA is enabled.",
    4444:  "Port 4444 open — common Metasploit reverse-shell listener. Investigate immediately.",
    5900:  "VNC open — ensure password/encryption is configured.",
    9200:  "Elasticsearch open — data may be publicly accessible. Enable auth.",
    27017: "MongoDB open — ensure auth is enabled (no anonymous access).",
}

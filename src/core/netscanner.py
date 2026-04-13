"""
src/core/netscanner.py
----------------------
Project Aegis — Module D: Local Network Port Scanner (v3.0).

v3.0 additions
~~~~~~~~~~~~~~
- Banner grabbing: reads up to 512 bytes after TCP connect.
- Scan history DB (scan_history.db): every scan run persisted.
- scan history: view past scans (filter by host).
- scan diff: compare current open ports to a saved scan.
- scan sweep: CIDR subnet discovery via TCP probes (no ICMP needed).
- scan export: save any saved scan as JSON.

v2.0 features (retained)
~~~~~~~~~~~~~~~~~~~~~~~~
- Service name mapping, risk classification, advisories,
  safety guard for non-private addresses, json-friendly PortResult.
"""

import concurrent.futures
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import click

from src.utils.db import get_connection, init_db
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Scan history DB ───────────────────────────────────────────────────────────

_SCAN_DB = "scan_history.db"
_SCAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT    NOT NULL,
    scanned_at TEXT    NOT NULL,
    port_start INTEGER NOT NULL,
    port_end   INTEGER NOT NULL,
    open_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_ports (
    run_id   INTEGER NOT NULL,
    port     INTEGER NOT NULL,
    service  TEXT    NOT NULL DEFAULT '',
    risk     TEXT    NOT NULL DEFAULT 'LOW',
    banner   TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, port),
    FOREIGN KEY (run_id) REFERENCES scan_runs(id)
);
"""


def _ensure_scan_db() -> None:
    init_db(_SCAN_DB, _SCAN_SCHEMA)


# ── Private / loopback guard ──────────────────────────────────────────────────

_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1",
)


def _is_private_or_loopback(host: str) -> bool:
    try:
        resolved = socket.gethostbyname(host)
        return any(resolved.startswith(p) for p in _PRIVATE_PREFIXES)
    except socket.gaierror:
        return False


# ── Service map ───────────────────────────────────────────────────────────────

_WELL_KNOWN: Dict[int, str] = {
    21:    "FTP",        22:    "SSH",        23:    "Telnet",
    25:    "SMTP",       53:    "DNS",         80:    "HTTP",
    110:   "POP3",       111:   "RPCBind",     119:   "NNTP",
    135:   "MS-RPC",     137:   "NetBIOS-NS",  138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",143:   "IMAP",        161:   "SNMP",
    389:   "LDAP",       443:   "HTTPS",       445:   "SMB",
    465:   "SMTPS",      512:   "rexec",       513:   "rlogin",
    514:   "rsh/syslog", 587:   "SMTP-MSA",    631:   "IPP/CUPS",
    636:   "LDAPS",      993:   "IMAPS",       995:   "POP3S",
    1080:  "SOCKS",      1433:  "MSSQL",       1521:  "Oracle",
    2049:  "NFS",        2375:  "Docker-API",  2376:  "Docker-TLS",
    3306:  "MySQL",      3389:  "RDP",         4444:  "Metasploit",
    5432:  "PostgreSQL", 5900:  "VNC",         5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",6379:  "Redis",       8080:  "HTTP-alt",
    8443:  "HTTPS-alt",  8888:  "Jupyter",     9200:  "Elasticsearch",
    27017: "MongoDB",
}

_HIGH_RISK_PORTS   = {23, 135, 137, 138, 139, 445, 512, 513, 514,
                      1080, 2375, 3389, 4444, 5900, 9200, 27017}
_MEDIUM_RISK_PORTS = {21, 2049, 6379, 5985, 5986, 8888}


def classify_port(port: int) -> str:
    return _WELL_KNOWN.get(port, "unknown")


def port_risk(port: int) -> str:
    if port in _HIGH_RISK_PORTS:   return "HIGH"
    if port in _MEDIUM_RISK_PORTS: return "MEDIUM"
    return "LOW"


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:    int
    state:   str
    service: str = ""
    risk:    str = "LOW"
    banner:  str = ""

    def __post_init__(self):
        if not self.service:
            self.service = classify_port(self.port)
        if self.state == "open":
            self.risk = port_risk(self.port)

    def to_dict(self) -> dict:
        return {
            "port":    self.port,
            "state":   self.state,
            "service": self.service,
            "risk":    self.risk,
            "banner":  self.banner,
        }


# ── Port probe with banner grabbing ──────────────────────────────────────────

def _probe_port(host: str, port: int, timeout: float,
                grab_banner: bool = True) -> PortResult:
    """TCP connect + optional banner read."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            if grab_banner:
                try:
                    sock.settimeout(0.5)
                    data   = sock.recv(512)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
            return PortResult(port=port, state="open", banner=banner)
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except (socket.timeout, OSError):
        return PortResult(port=port, state="filtered")


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_ports(
    host: str = "127.0.0.1",
    start: int = 1,
    end: int = 1024,
    timeout: float = 0.5,
    max_workers: int = 100,
    show_closed: bool = False,
    grab_banner: bool = True,
    save: bool = True,
) -> Tuple[List[PortResult], int]:
    """
    TCP connect-scan *host*:*start*–*end*.

    Returns:
        (results, scan_id) — scan_id is 0 if save=False.

    Raises:
        click.ClickException: If host is not private/loopback.
    """
    if not _is_private_or_loopback(host):
        raise click.ClickException(
            f"Safety guard: '{host}' is not a private/loopback address."
        )

    total = end - start + 1
    log.info("Scan started: host=%s range=%d-%d", host, start, end)

    results: List[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_probe_port, host, p, timeout, grab_banner): p
            for p in range(start, end + 1)
        }
        completed = 0
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            completed += 1
            if r.state == "open" or show_closed:
                results.append(r)
            if completed % max(total // 10, 1) == 0:
                pct = int(completed / total * 100)
                click.echo(click.style(f"  [{pct:3d}%] {completed}/{total} ports…", fg="cyan"))

    results.sort(key=lambda r: r.port)
    open_count = sum(1 for r in results if r.state == "open")
    log.info("Scan complete: %d open ports.", open_count)

    scan_id = 0
    if save:
        scan_id = _save_scan(host, start, end, [r for r in results if r.state == "open"])

    return results, scan_id


def _save_scan(host: str, start: int, end: int, open_results: List[PortResult]) -> int:
    """Persist scan results to scan_history.db. Returns the new scan_run ID."""
    _ensure_scan_db()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(_SCAN_DB) as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (host, scanned_at, port_start, port_end, open_count) "
            "VALUES (?,?,?,?,?)",
            (host, now, start, end, len(open_results)),
        )
        run_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO scan_ports (run_id, port, service, risk, banner) VALUES (?,?,?,?,?)",
            [(run_id, r.port, r.service, r.risk, r.banner) for r in open_results],
        )
    log.info("Scan #%d saved: host=%s open=%d", run_id, host, len(open_results))
    return run_id


def list_scan_history(host: Optional[str] = None, limit: int = 20) -> List[dict]:
    """Return recent scan runs, optionally filtered by host."""
    _ensure_scan_db()
    with get_connection(_SCAN_DB) as conn:
        if host:
            rows = conn.execute(
                "SELECT id, host, scanned_at, port_start, port_end, open_count "
                "FROM scan_runs WHERE host = ? ORDER BY id DESC LIMIT ?",
                (host, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, host, scanned_at, port_start, port_end, open_count "
                "FROM scan_runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_scan_ports(run_id: int) -> List[dict]:
    """Return all open ports for a saved scan run."""
    _ensure_scan_db()
    with get_connection(_SCAN_DB) as conn:
        rows = conn.execute(
            "SELECT port, service, risk, banner FROM scan_ports WHERE run_id = ? ORDER BY port",
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def diff_scans(host: str, since_run_id: int, timeout: float = 0.5,
               max_workers: int = 100) -> dict:
    """
    Compare the current port state of *host* to scan run *since_run_id*.

    Returns:
        dict with 'newly_open', 'newly_closed', 'still_open', 'scan_id'
    """
    old_ports_data = get_scan_ports(since_run_id)
    if not old_ports_data:
        raise ValueError(f"No port data for scan run #{since_run_id}.")

    old_open: Dict[int, dict] = {p["port"]: p for p in old_ports_data}

    # Determine port range from old scan
    with get_connection(_SCAN_DB) as conn:
        run = conn.execute(
            "SELECT port_start, port_end FROM scan_runs WHERE id = ?", (since_run_id,)
        ).fetchone()
    if not run:
        raise ValueError(f"Scan run #{since_run_id} not found.")

    current_results, new_id = scan_ports(
        host=host, start=run["port_start"], end=run["port_end"],
        timeout=timeout, max_workers=max_workers, save=True,
    )
    current_open: Dict[int, PortResult] = {
        r.port: r for r in current_results if r.state == "open"
    }

    newly_open   = [r for port, r in current_open.items() if port not in old_open]
    newly_closed = [old_open[port] for port in old_open if port not in current_open]
    still_open   = [r for port, r in current_open.items() if port in old_open]

    return {
        "newly_open":   newly_open,
        "newly_closed": newly_closed,
        "still_open":   still_open,
        "scan_id":      new_id,
        "since_id":     since_run_id,
    }


def sweep_cidr(
    cidr: str,
    probe_port: int = 80,
    timeout: float = 0.3,
    max_workers: int = 200,
) -> List[str]:
    """
    Discover live hosts in *cidr* by attempting a TCP connect to *probe_port*.

    Args:
        cidr:        CIDR notation e.g. "192.168.1.0/24". Must be RFC-1918.
        probe_port:  Port to probe (default 80).
        timeout:     Connect timeout per host.
        max_workers: Thread pool size.

    Returns:
        List of responding host IP strings.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise click.ClickException(f"Invalid CIDR: {exc}")

    # Safety check: entire range must be private
    first_ip = str(network.network_address)
    if not _is_private_or_loopback(first_ip):
        raise click.ClickException(
            f"Safety guard: {cidr} does not appear to be an RFC-1918 private network."
        )

    hosts = list(network.hosts())
    click.echo(click.style(
        f"  Sweeping {len(hosts)} hosts in {cidr} (port {probe_port}, timeout={timeout}s)…",
        fg="cyan", bold=True,
    ))

    live: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_probe_port, str(h), probe_port, timeout, False): str(h)
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                result = fut.result()
                if result.state == "open":
                    live.append(ip)
                    click.echo(click.style(f"  🟢 {ip}:{probe_port} — OPEN", fg="green"))
            except Exception:
                pass

    live.sort(key=lambda ip: tuple(int(x) for x in ip.split(".")))
    log.info("Sweep complete: %d/%d hosts responded on port %d.", len(live), len(hosts), probe_port)
    return live


def export_scan(run_id: int, output_path: str) -> int:
    """Export a saved scan run to a JSON file. Returns number of ports exported."""
    _ensure_scan_db()
    with get_connection(_SCAN_DB) as conn:
        run = conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if not run:
            raise ValueError(f"Scan run #{run_id} not found.")
        ports = conn.execute(
            "SELECT port, service, risk, banner FROM scan_ports WHERE run_id = ? ORDER BY port",
            (run_id,),
        ).fetchall()

    data = {
        "scan_id":    run_id,
        "host":       run["host"],
        "scanned_at": run["scanned_at"],
        "port_range": f"{run['port_start']}-{run['port_end']}",
        "open_count": run["open_count"],
        "ports": [dict(p) for p in ports],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    log.info("Scan #%d exported → %s.", run_id, output_path)
    return len(ports)


def flag_risky_ports(results: List[PortResult]) -> List[PortResult]:
    return [r for r in results if r.state == "open" and r.risk in ("HIGH", "MEDIUM")]


def print_scan_report(results: List[PortResult], host: str, scan_id: int = 0) -> None:
    open_ports = [r for r in results if r.state == "open"]
    risky      = flag_risky_ports(results)

    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║    PROJECT AEGIS — PORT SCAN REPORT   ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))
    click.echo(f"  Host          : {host}")
    if scan_id:
        click.echo(f"  Scan ID       : #{scan_id}")
    click.echo(f"  Open Ports    : {len(open_ports)}")
    click.echo(click.style(
        f"  High-Risk     : {len(risky)}",
        fg="red" if risky else "green", bold=bool(risky),
    ))
    click.echo("")

    if not open_ports:
        click.echo(click.style("  ✓ No open ports detected.", fg="green", bold=True))
    else:
        click.echo(click.style(
            f"  {'PORT':<8} {'SERVICE':<22} {'RISK':<10} {'BANNER'}",
            fg="cyan", bold=True,
        ))
        click.echo("  " + "─" * 70)
        for r in open_ports:
            rc      = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(r.risk, "white")
            banner  = r.banner[:40].replace("\n", " ") if r.banner else ""
            click.echo(
                f"  {r.port:<8} {r.service:<22} " +
                click.style(f"{r.risk:<10}", fg=rc, bold=(r.risk != "LOW")) +
                f" {banner}"
            )

    if risky:
        click.echo("")
        click.echo(click.style("  ⚠  Risk Advisory:", fg="red", bold=True))
        for r in risky:
            advice = _RISK_ADVICE.get(r.port, f"Port {r.port}/{r.service} — review if expected.")
            click.echo(click.style(f"    • [{r.port}/{r.service}] {advice}", fg="yellow"))
    click.echo("")


_RISK_ADVICE: Dict[int, str] = {
    23:    "Telnet is unencrypted. Replace with SSH immediately.",
    135:   "MS-RPC — common lateral-movement vector. Firewall if unneeded.",
    139:   "NetBIOS — disable if on a modern Windows network.",
    445:   "SMB — ensure patched (EternalBlue MS17-010).",
    512:   "rexec — extremely insecure, disable immediately.",
    513:   "rlogin — extremely insecure, disable immediately.",
    514:   "rsh — extremely insecure, disable immediately.",
    1080:  "SOCKS proxy — verify this is intentional.",
    2375:  "Docker API WITHOUT TLS — critical, full container control exposed.",
    3389:  "RDP — enforce NLA + MFA.",
    4444:  "Port 4444 — common Metasploit reverse-shell. Investigate immediately.",
    5900:  "VNC — ensure password + encryption configured.",
    9200:  "Elasticsearch — enable auth, check for public data exposure.",
    27017: "MongoDB — enable auth (no anonymous access).",
}

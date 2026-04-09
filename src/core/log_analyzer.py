"""
src/core/log_analyzer.py
------------------------
Project Aegis — Module C: Local Log Analyzer.

Responsibilities
~~~~~~~~~~~~~~~~
- **analyze(log_source, lookback_hours, threshold)** : Parse system logs and
  return structured findings.
- Detects:
    - Failed login attempts (Event ID 4625 on Windows; PAM/sshd failures on *nix)
    - Brute-force patterns (≥ *threshold* failures from the same source IP/username
      within *lookback_hours*)
    - Suspicious process executions (Event ID 4688 on Windows; configurable keyword
      list for *nix)

Platform support
~~~~~~~~~~~~~~~~
- **Windows** : ``wevtutil qe`` queries Security and Application Event Logs
  and outputs XML; parsed with the stdlib ``xml.etree.ElementTree``.
- **Linux/macOS** : Reads ``/var/log/auth.log``, ``/var/log/secure``, or
  ``/var/log/syslog`` with regex patterns.

All processing is local; zero network activity.
"""

import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Suspicious process keywords (case-insensitive) ──────────────────────────
SUSPICIOUS_KEYWORDS = [
    "mimikatz", "procdump", "meterpreter", "cobalt", "powersploit",
    "invoke-expression", "iex", "encodedcommand", "-enc", "bypass",
    "downloadstring", "webclient", "certutil", "bitsadmin",
    "net user", "net localgroup", "whoami", "nltest", "dsquery",
    "psexec", "wmic", "regsvr32", "rundll32", "mshta", "cscript",
    "wscript", "curl", "wget",
]

# ── Data Classes ─────────────────────────────────────────────────────────────

class LoginFailure:
    __slots__ = ("timestamp", "username", "source", "raw")

    def __init__(self, timestamp: datetime, username: str, source: str, raw: str) -> None:
        self.timestamp = timestamp
        self.username = username
        self.source = source
        self.raw = raw


class SuspiciousProcess:
    __slots__ = ("timestamp", "process", "command_line", "matched_keyword")

    def __init__(
        self, timestamp: datetime, process: str, command_line: str, matched_keyword: str
    ) -> None:
        self.timestamp = timestamp
        self.process = process
        self.command_line = command_line
        self.matched_keyword = matched_keyword


class AnalysisReport:
    def __init__(self) -> None:
        self.login_failures: List[LoginFailure] = []
        self.suspicious_processes: List[SuspiciousProcess] = []
        self.brute_force_suspects: Dict[str, List[LoginFailure]] = {}
        self.lookback_hours: int = 24
        self.brute_force_threshold: int = 5
        self.source: str = ""
        self.generated_at: datetime = datetime.now(timezone.utc)

    def summary_lines(self) -> List[str]:
        lines = [
            f"  Source       : {self.source}",
            f"  Generated    : {self.generated_at.isoformat()}",
            f"  Lookback     : {self.lookback_hours}h",
            f"  BF Threshold : ≥{self.brute_force_threshold} failures",
            "",
            f"  Failed Logins       : {len(self.login_failures)}",
            f"  Brute-Force Suspects: {len(self.brute_force_suspects)}",
            f"  Suspicious Procs    : {len(self.suspicious_processes)}",
        ]
        return lines


# ── Windows Event Log Parsing ────────────────────────────────────────────────

_WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def _win_query(log_name: str, event_id: int, lookback_hours: int) -> str:
    """Run wevtutil and return raw XML output."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = (
        f"*[System[EventID={event_id}] and "
        f"System[TimeCreated[@SystemTime>='{cutoff_str}']]]"
    )
    cmd = [
        "wevtutil", "qe", log_name,
        "/q:" + xpath,
        "/f:XML",
        "/rd:true",      # newest first
        "/c:500",        # max 500 events per query
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return result.stdout
    except FileNotFoundError:
        log.warning("wevtutil not found — are you running on Windows?")
        return ""
    except subprocess.TimeoutExpired:
        log.warning("wevtutil timed out querying %s (EventID=%d)", log_name, event_id)
        return ""


def _parse_win_xml(xml_blob: str) -> List[ET.Element]:
    """Parse multiple <Event> elements from a wevtutil XML dump."""
    if not xml_blob.strip():
        return []
    # wevtutil outputs bare <Event> elements without a root wrapper
    try:
        root = ET.fromstring(f"<Root>{xml_blob}</Root>")
        return root.findall("Event", _WIN_NS) or root.findall("Event")
    except ET.ParseError as exc:
        log.warning("XML parse error from wevtutil output: %s", exc)
        return []


def _win_failed_logins(lookback_hours: int) -> List[LoginFailure]:
    """Query Security log for Event ID 4625 (failed logon)."""
    xml_blob = _win_query("Security", 4625, lookback_hours)
    events = _parse_win_xml(xml_blob)
    failures: List[LoginFailure] = []

    for ev in events:
        # Namespace-aware search
        ns_map = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        def find(tag: str) -> Optional[str]:
            # Try namespaced first, then plain
            el = ev.find(f".//e:{tag}", ns_map) or ev.find(f".//{tag}")
            return el.text.strip() if el is not None and el.text else ""

        def find_data(name: str) -> str:
            for ns in (ns_map, {}):
                els = ev.findall(".//e:Data[@Name]", ns_map) if ns else ev.findall(".//Data[@Name]")
                for el in els:
                    if el.get("Name") == name:
                        return (el.text or "").strip()
            return ""

        ts_str = find("TimeCreated")
        # TimeCreated is an attribute: SystemTime
        tc_el = ev.find(".//e:TimeCreated", ns_map) or ev.find(".//TimeCreated")
        ts_attr = tc_el.get("SystemTime", "") if tc_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_attr.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        username = find_data("TargetUserName") or "unknown"
        source_ip = find_data("IpAddress") or find_data("WorkstationName") or "local"

        failures.append(LoginFailure(
            timestamp=ts,
            username=username,
            source=source_ip,
            raw=f"EventID=4625 user={username} src={source_ip}",
        ))

    log.debug("Windows: found %d failed login events (4625).", len(failures))
    return failures


def _win_suspicious_processes(lookback_hours: int) -> List[SuspiciousProcess]:
    """Query Security log for Event ID 4688 (process creation)."""
    xml_blob = _win_query("Security", 4688, lookback_hours)
    events = _parse_win_xml(xml_blob)
    procs: List[SuspiciousProcess] = []
    ns_map = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    for ev in events:
        def find_data(name: str) -> str:
            for el in (ev.findall(".//e:Data[@Name]", ns_map) or ev.findall(".//Data[@Name]")):
                if el.get("Name") == name:
                    return (el.text or "").strip()
            return ""

        tc_el = ev.find(".//e:TimeCreated", ns_map) or ev.find(".//TimeCreated")
        ts_attr = tc_el.get("SystemTime", "") if tc_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_attr.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        process = find_data("NewProcessName") or find_data("ProcessName") or "unknown"
        cmdline = find_data("CommandLine") or ""
        combined = f"{process} {cmdline}".lower()

        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in combined:
                procs.append(SuspiciousProcess(
                    timestamp=ts,
                    process=process,
                    command_line=cmdline,
                    matched_keyword=kw,
                ))
                break  # one alert per event

    log.debug("Windows: found %d suspicious process events (4688).", len(procs))
    return procs


# ── Linux/macOS Log Parsing ──────────────────────────────────────────────────

_NIX_LOG_CANDIDATES = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
    Path("/var/log/syslog"),
    Path("/var/log/messages"),
]

# auth.log patterns
_RE_FAILED_PASSWORD = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
_RE_INVALID_USER = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
_RE_PROC_EXEC = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?CMD\s+\((?P<cmd>.+?)\)",
    re.IGNORECASE,
)

_MONTH_MAP = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1
)}


def _parse_syslog_ts(month: str, day: str, time_str: str) -> datetime:
    """Parse syslog timestamp; assume current year."""
    try:
        now = datetime.now()
        m = _MONTH_MAP.get(month.capitalize(), now.month)
        d = int(day)
        h, mi, s = (int(x) for x in time_str.split(":"))
        return datetime(now.year, m, d, h, mi, s, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _find_nix_log() -> Optional[Path]:
    for candidate in _NIX_LOG_CANDIDATES:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _nix_failed_logins(log_path: Path, cutoff: datetime) -> List[LoginFailure]:
    failures: List[LoginFailure] = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for pattern in (_RE_FAILED_PASSWORD, _RE_INVALID_USER):
                    m = pattern.search(line)
                    if m:
                        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
                        if ts >= cutoff:
                            failures.append(LoginFailure(
                                timestamp=ts,
                                username=m.group("user"),
                                source=m.group("ip"),
                                raw=line.strip(),
                            ))
                        break
    except (OSError, PermissionError) as exc:
        log.warning("Cannot read log file %s: %s", log_path, exc)
    return failures


def _nix_suspicious_processes(log_path: Path, cutoff: datetime) -> List[SuspiciousProcess]:
    procs: List[SuspiciousProcess] = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _RE_PROC_EXEC.search(line)
                if m:
                    ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
                    if ts < cutoff:
                        continue
                    cmd = m.group("cmd").lower()
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw.lower() in cmd:
                            procs.append(SuspiciousProcess(
                                timestamp=ts,
                                process="",
                                command_line=m.group("cmd"),
                                matched_keyword=kw,
                            ))
                            break
    except (OSError, PermissionError) as exc:
        log.warning("Cannot read log file %s: %s", log_path, exc)
    return procs


# ── Brute-Force Detection ────────────────────────────────────────────────────

def _detect_brute_force(
    failures: List[LoginFailure], threshold: int
) -> Dict[str, List[LoginFailure]]:
    """Group failures by source; flag sources with ≥ threshold attempts."""
    by_source: Dict[str, List[LoginFailure]] = defaultdict(list)
    for f in failures:
        by_source[f.source].append(f)
    return {src: evts for src, evts in by_source.items() if len(evts) >= threshold}


# ── Public API ───────────────────────────────────────────────────────────────

def analyze(
    log_source: Optional[str] = None,
    lookback_hours: int = 24,
    threshold: int = 5,
) -> AnalysisReport:
    """
    Parse system logs and return an :class:`AnalysisReport`.

    Args:
        log_source:     Optional explicit path to a log file (overrides auto-detect).
                        On Windows, pass "windows" (or leave None) to use wevtutil.
        lookback_hours: How many hours back to analyse (default 24).
        threshold:      Minimum failures from one source to flag as brute-force.

    Returns:
        Populated :class:`AnalysisReport`.
    """
    report = AnalysisReport()
    report.lookback_hours = lookback_hours
    report.brute_force_threshold = threshold
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    is_windows = platform.system() == "Windows"

    if log_source and log_source.lower() != "windows":
        # Explicit file path supplied
        explicit_path = Path(log_source)
        report.source = str(explicit_path)
        log.info("Analyzing log file: %s (lookback=%dh)", explicit_path, lookback_hours)
        report.login_failures = _nix_failed_logins(explicit_path, cutoff)
        report.suspicious_processes = _nix_suspicious_processes(explicit_path, cutoff)

    elif is_windows:
        report.source = "Windows Event Log (Security)"
        log.info("Analyzing Windows Event Log (lookback=%dh)", lookback_hours)
        report.login_failures = _win_failed_logins(lookback_hours)
        report.suspicious_processes = _win_suspicious_processes(lookback_hours)

    else:
        nix_log = _find_nix_log()
        if nix_log is None:
            log.warning("No readable system log found on this platform.")
            report.source = "none (no readable log found)"
        else:
            report.source = str(nix_log)
            log.info("Analyzing %s (lookback=%dh)", nix_log, lookback_hours)
            report.login_failures = _nix_failed_logins(nix_log, cutoff)
            report.suspicious_processes = _nix_suspicious_processes(nix_log, cutoff)

    report.brute_force_suspects = _detect_brute_force(report.login_failures, threshold)
    log.info(
        "Analysis complete: failures=%d bf_suspects=%d suspicious_procs=%d",
        len(report.login_failures),
        len(report.brute_force_suspects),
        len(report.suspicious_processes),
    )
    return report


def print_report(report: AnalysisReport) -> None:
    """Render the analysis report to stdout using click styling."""
    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║       PROJECT AEGIS — LOG REPORT      ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))
    for line in report.summary_lines():
        click.echo(f"  {line}")

    # ── Failed Logins ────────────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(f"  ▸ Failed Login Attempts ({len(report.login_failures)})", fg="yellow", bold=True))
    if not report.login_failures:
        click.echo("    (none)")
    else:
        for f in report.login_failures[:25]:  # cap display at 25
            ts = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            click.echo(f"    [{ts}] user={f.username:<20} src={f.source}")
        if len(report.login_failures) > 25:
            click.echo(f"    … and {len(report.login_failures) - 25} more. See aegis.log.")

    # ── Brute-Force Suspects ─────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(f"  ▸ Brute-Force Suspects ({len(report.brute_force_suspects)})", fg="red", bold=True))
    if not report.brute_force_suspects:
        click.echo("    (none)")
    else:
        for src, evts in sorted(report.brute_force_suspects.items(), key=lambda x: -len(x[1])):
            users = {e.username for e in evts}
            click.echo(
                click.style(
                    f"    ⚠  {src:<20} — {len(evts)} attempts, targets: {', '.join(users)}",
                    fg="red",
                )
            )

    # ── Suspicious Processes ─────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(f"  ▸ Suspicious Executions ({len(report.suspicious_processes)})", fg="magenta", bold=True))
    if not report.suspicious_processes:
        click.echo("    (none)")
    else:
        for p in report.suspicious_processes[:20]:
            ts = p.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            click.echo(
                click.style(
                    f"    [{ts}] keyword='{p.matched_keyword}' cmd={p.command_line[:80]}",
                    fg="magenta",
                )
            )
        if len(report.suspicious_processes) > 20:
            click.echo(f"    … and {len(report.suspicious_processes) - 20} more. See aegis.log.")

    click.echo("")
    click.echo(click.style("  Log written to: ~/aegis_logs/aegis.log", fg="cyan"))
    click.echo("")

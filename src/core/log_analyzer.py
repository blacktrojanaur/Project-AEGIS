"""
src/core/log_analyzer.py
------------------------
Project Aegis — Module C: Local Log Analyzer (v2.0).

Responsibilities
~~~~~~~~~~~~~~~~
- **analyze(log_source, lookback_hours, threshold)** : Parse system logs and
  return structured findings with risk scoring.
- Detects:
    - Failed login attempts (Event ID 4625; PAM/sshd on *nix)
    - Brute-force patterns (≥ threshold failures from a single source)
    - Suspicious process executions (Event ID 4688; keyword list on *nix)
- **timeline(log_source, hours)** : Hourly bar-chart of login failure counts.
- **list_run_history()**          : Trend table of past analysis runs.

v2.0 additions
~~~~~~~~~~~~~~
- Risk scoring: LOW / MEDIUM / HIGH / CRITICAL attached to each finding.
- Persistent run history stored in data/log_history.db.
- PowerShell/Operational event log fallback for non-admin Windows.
- RFC-1918 / loopback IP classification of source IPs.
- Custom keyword file support via --keywords option.

Platform support
~~~~~~~~~~~~~~~~
- Windows  : ``wevtutil qe`` + PowerShell/Operational fallback.
- Linux/macOS: /var/log/auth.log, /var/log/secure, /var/log/syslog.

All processing is local; zero network activity.
"""

import json
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click

from src.utils.db import get_connection, init_db
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Suspicious process keywords (case-insensitive) ───────────────────────────
_DEFAULT_SUSPICIOUS_KEYWORDS = [
    "mimikatz", "procdump", "meterpreter", "cobalt", "powersploit",
    "invoke-expression", "iex", "encodedcommand", "-enc", "bypass",
    "downloadstring", "webclient", "certutil", "bitsadmin",
    "net user", "net localgroup", "whoami", "nltest", "dsquery",
    "psexec", "wmic", "regsvr32", "rundll32", "mshta", "cscript",
    "wscript", "curl", "wget",
]

# ── High-risk ports whose unexpected appearance warrants extra flagging ───────
_HIGH_RISK_KEYWORDS = {"mimikatz", "meterpreter", "cobalt", "powersploit", "encodedcommand"}

# ── RFC-1918 / loopback ranges ───────────────────────────────────────────────
_RFC1918_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.")
_LOOPBACK_PREFIXES = ("127.", "::1")

# ── History DB ───────────────────────────────────────────────────────────────
_HIST_DB = "log_history.db"
_HIST_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at           TEXT    NOT NULL,
    source           TEXT    NOT NULL,
    lookback_hours   INTEGER NOT NULL,
    failed_logins    INTEGER NOT NULL,
    bf_suspects      INTEGER NOT NULL,
    suspicious_procs INTEGER NOT NULL,
    risk_level       TEXT    NOT NULL DEFAULT 'LOW'
);
"""


def _ensure_hist_db() -> None:
    init_db(_HIST_DB, _HIST_SCHEMA)


# ── Risk Scoring ─────────────────────────────────────────────────────────────

def _score_risk(
    failures: int,
    bf_suspects: int,
    suspicious_procs: int,
    has_critical_keyword: bool = False,
) -> str:
    """
    Return overall risk level string: LOW | MEDIUM | HIGH | CRITICAL.
    """
    if has_critical_keyword or (bf_suspects >= 3 and suspicious_procs >= 1):
        return "CRITICAL"
    if bf_suspects >= 1 and suspicious_procs >= 1:
        return "HIGH"
    if bf_suspects >= 1 or suspicious_procs >= 2:
        return "MEDIUM"
    if failures >= 5:
        return "MEDIUM"
    return "LOW"


RISK_COLOUR = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "magenta",
}


# ── IP Classification ─────────────────────────────────────────────────────────

def classify_ip(ip: str) -> str:
    """Return 'loopback', 'private', 'public', or 'unknown'."""
    if not ip or ip in ("-", "local", "unknown", "localhost"):
        return "unknown"
    if any(ip.startswith(p) for p in _LOOPBACK_PREFIXES):
        return "loopback"
    if any(ip.startswith(p) for p in _RFC1918_PREFIXES):
        return "private"
    return "public"


# ── Data Classes ─────────────────────────────────────────────────────────────

class LoginFailure:
    __slots__ = ("timestamp", "username", "source", "ip_class", "risk", "raw")

    def __init__(
        self,
        timestamp: datetime,
        username: str,
        source: str,
        raw: str,
    ) -> None:
        self.timestamp = timestamp
        self.username  = username
        self.source    = source
        self.ip_class  = classify_ip(source)
        self.risk      = "HIGH" if self.ip_class == "public" else "MEDIUM"
        self.raw       = raw


class SuspiciousProcess:
    __slots__ = ("timestamp", "process", "command_line", "matched_keyword", "risk")

    def __init__(
        self,
        timestamp: datetime,
        process: str,
        command_line: str,
        matched_keyword: str,
    ) -> None:
        self.timestamp       = timestamp
        self.process         = process
        self.command_line    = command_line
        self.matched_keyword = matched_keyword
        self.risk = "CRITICAL" if matched_keyword.lower() in _HIGH_RISK_KEYWORDS else "HIGH"


class AnalysisReport:
    def __init__(self) -> None:
        self.login_failures:       List[LoginFailure]             = []
        self.suspicious_processes: List[SuspiciousProcess]        = []
        self.brute_force_suspects: Dict[str, List[LoginFailure]]  = {}
        self.lookback_hours:       int                            = 24
        self.brute_force_threshold: int                           = 5
        self.source:               str                            = ""
        self.generated_at:         datetime                       = datetime.now(timezone.utc)
        self.risk_level:           str                            = "LOW"

    def compute_risk(self) -> None:
        """Compute and set overall risk_level based on findings."""
        has_critical_kw = any(
            p.risk == "CRITICAL" for p in self.suspicious_processes
        )
        self.risk_level = _score_risk(
            len(self.login_failures),
            len(self.brute_force_suspects),
            len(self.suspicious_processes),
            has_critical_kw,
        )

    def summary_lines(self) -> List[str]:
        lines = [
            f"  Source       : {self.source}",
            f"  Generated    : {self.generated_at.isoformat()}",
            f"  Lookback     : {self.lookback_hours}h",
            f"  BF Threshold : ≥{self.brute_force_threshold} failures",
            f"  Risk Level   : {self.risk_level}",
            "",
            f"  Failed Logins       : {len(self.login_failures)}",
            f"  Brute-Force Suspects: {len(self.brute_force_suspects)}",
            f"  Suspicious Procs    : {len(self.suspicious_processes)}",
        ]
        return lines


# ── Windows Event Log Parsing ─────────────────────────────────────────────────

_WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _win_query(log_name: str, event_id: int, lookback_hours: int) -> str:
    """Run wevtutil and return raw XML output."""
    cutoff     = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = (
        f"*[System[EventID={event_id}] and "
        f"System[TimeCreated[@SystemTime>='{cutoff_str}']]]"
    )
    cmd = [
        "wevtutil", "qe", log_name,
        "/q:" + xpath,
        "/f:XML",
        "/rd:true",
        "/c:500",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False,
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
    try:
        root = ET.fromstring(f"<Root>{xml_blob}</Root>")
        return root.findall("Event", _WIN_NS) or root.findall("Event")
    except ET.ParseError as exc:
        log.warning("XML parse error from wevtutil output: %s", exc)
        return []


def _win_failed_logins(lookback_hours: int) -> List[LoginFailure]:
    """Query Security log for Event ID 4625 (failed logon)."""
    xml_blob = _win_query("Security", 4625, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    failures: List[LoginFailure] = []
    ns_map = _WIN_NS

    for ev in events:
        def find_data(name: str) -> str:
            for el in (ev.findall(".//e:Data[@Name]", ns_map) or ev.findall(".//Data[@Name]")):
                if el.get("Name") == name:
                    return (el.text or "").strip()
            return ""

        tc_el   = ev.find(".//e:TimeCreated", ns_map) or ev.find(".//TimeCreated")
        ts_attr = tc_el.get("SystemTime", "") if tc_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_attr.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        username  = find_data("TargetUserName") or "unknown"
        source_ip = find_data("IpAddress") or find_data("WorkstationName") or "local"

        failures.append(LoginFailure(
            timestamp=ts,
            username=username,
            source=source_ip,
            raw=f"EventID=4625 user={username} src={source_ip}",
        ))

    log.debug("Windows: found %d failed login events (4625).", len(failures))
    return failures


def _win_suspicious_processes(
    lookback_hours: int,
    keywords: List[str],
) -> List[SuspiciousProcess]:
    """Query Security log for Event ID 4688 (process creation)."""
    xml_blob = _win_query("Security", 4688, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    procs: List[SuspiciousProcess] = []
    ns_map = _WIN_NS

    for ev in events:
        def find_data(name: str) -> str:
            for el in (ev.findall(".//e:Data[@Name]", ns_map) or ev.findall(".//Data[@Name]")):
                if el.get("Name") == name:
                    return (el.text or "").strip()
            return ""

        tc_el   = ev.find(".//e:TimeCreated", ns_map) or ev.find(".//TimeCreated")
        ts_attr = tc_el.get("SystemTime", "") if tc_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_attr.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        process = find_data("NewProcessName") or find_data("ProcessName") or "unknown"
        cmdline = find_data("CommandLine") or ""
        combined = f"{process} {cmdline}".lower()

        for kw in keywords:
            if kw.lower() in combined:
                procs.append(SuspiciousProcess(
                    timestamp=ts,
                    process=process,
                    command_line=cmdline,
                    matched_keyword=kw,
                ))
                break

    log.debug("Windows: found %d suspicious process events (4688).", len(procs))
    return procs


def _win_powershell_events(lookback_hours: int, keywords: List[str]) -> List[SuspiciousProcess]:
    """
    Fallback: query Microsoft-Windows-PowerShell/Operational (Event ID 4104)
    for script-block logging without requiring Security log admin access.
    """
    xml_blob = _win_query("Microsoft-Windows-PowerShell/Operational", 4104, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    procs: List[SuspiciousProcess] = []
    ns_map = _WIN_NS

    for ev in events:
        def find_data(name: str) -> str:
            for el in (ev.findall(".//e:Data[@Name]", ns_map) or ev.findall(".//Data[@Name]")):
                if el.get("Name") == name:
                    return (el.text or "").strip()
            return ""

        tc_el   = ev.find(".//e:TimeCreated", ns_map) or ev.find(".//TimeCreated")
        ts_attr = tc_el.get("SystemTime", "") if tc_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_attr.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        script_block = find_data("ScriptBlockText") or ""
        combined = script_block.lower()

        for kw in keywords:
            if kw.lower() in combined:
                procs.append(SuspiciousProcess(
                    timestamp=ts,
                    process="powershell.exe",
                    command_line=script_block[:200],
                    matched_keyword=kw,
                ))
                break

    log.debug("PowerShell/Operational: found %d suspicious script-block events.", len(procs))
    return procs


# ── Linux/macOS Log Parsing ───────────────────────────────────────────────────

_NIX_LOG_CANDIDATES = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
    Path("/var/log/syslog"),
    Path("/var/log/messages"),
]

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
    try:
        now = datetime.now()
        m   = _MONTH_MAP.get(month.capitalize(), now.month)
        d   = int(day)
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


def _nix_suspicious_processes(
    log_path: Path,
    cutoff: datetime,
    keywords: List[str],
) -> List[SuspiciousProcess]:
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
                    for kw in keywords:
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


# ── Brute-Force Detection ─────────────────────────────────────────────────────

def _detect_brute_force(
    failures: List[LoginFailure], threshold: int
) -> Dict[str, List[LoginFailure]]:
    by_source: Dict[str, List[LoginFailure]] = defaultdict(list)
    for f in failures:
        by_source[f.source].append(f)
    return {src: evts for src, evts in by_source.items() if len(evts) >= threshold}


# ── Keyword Loading ───────────────────────────────────────────────────────────

def load_keywords(keywords_file: Optional[str] = None) -> List[str]:
    """
    Return the list of suspicious keywords to use.

    If *keywords_file* is provided, load from that JSON file (expected to
    be a list of strings) and merge with defaults.  Otherwise return defaults.
    """
    base = list(_DEFAULT_SUSPICIOUS_KEYWORDS)
    if keywords_file:
        try:
            with open(keywords_file, "r", encoding="utf-8") as fh:
                extra = json.load(fh)
            if isinstance(extra, list):
                merged = list({k.lower() for k in base + extra})
                log.info("Loaded %d extra keywords from %s.", len(extra), keywords_file)
                return merged
            else:
                log.warning("Keywords file %s is not a JSON list; using defaults.", keywords_file)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Cannot load keywords file %s: %s", keywords_file, exc)
    return base


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    log_source: Optional[str] = None,
    lookback_hours: int = 24,
    threshold: int = 5,
    keywords_file: Optional[str] = None,
) -> AnalysisReport:
    """
    Parse system logs and return an :class:`AnalysisReport`.

    Args:
        log_source:     Optional explicit path (overrides auto-detect).
                        Pass "windows" to force wevtutil.
        lookback_hours: How many hours back to analyse.
        threshold:      Minimum failures from one source to flag as brute-force.
        keywords_file:  Optional JSON file with extra suspicious keywords.

    Returns:
        Populated :class:`AnalysisReport` with risk_level set.
    """
    keywords = load_keywords(keywords_file)
    report   = AnalysisReport()
    report.lookback_hours      = lookback_hours
    report.brute_force_threshold = threshold
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    is_windows = platform.system() == "Windows"

    if log_source and log_source.lower() != "windows":
        explicit_path = Path(log_source)
        report.source = str(explicit_path)
        log.info("Analyzing log file: %s (lookback=%dh)", explicit_path, lookback_hours)
        report.login_failures      = _nix_failed_logins(explicit_path, cutoff)
        report.suspicious_processes = _nix_suspicious_processes(explicit_path, cutoff, keywords)

    elif is_windows:
        report.source = "Windows Event Log (Security + PowerShell/Operational)"
        log.info("Analyzing Windows Event Log (lookback=%dh)", lookback_hours)
        report.login_failures       = _win_failed_logins(lookback_hours)
        report.suspicious_processes = (
            _win_suspicious_processes(lookback_hours, keywords)
            + _win_powershell_events(lookback_hours, keywords)
        )

    else:
        nix_log = _find_nix_log()
        if nix_log is None:
            log.warning("No readable system log found on this platform.")
            report.source = "none (no readable log found)"
        else:
            report.source = str(nix_log)
            log.info("Analyzing %s (lookback=%dh)", nix_log, lookback_hours)
            report.login_failures      = _nix_failed_logins(nix_log, cutoff)
            report.suspicious_processes = _nix_suspicious_processes(nix_log, cutoff, keywords)

    report.brute_force_suspects = _detect_brute_force(report.login_failures, threshold)
    report.compute_risk()

    log.info(
        "Analysis complete: failures=%d bf_suspects=%d suspicious_procs=%d risk=%s",
        len(report.login_failures),
        len(report.brute_force_suspects),
        len(report.suspicious_processes),
        report.risk_level,
    )

    # Persist run to history DB
    _ensure_hist_db()
    with get_connection(_HIST_DB) as conn:
        conn.execute(
            "INSERT INTO analysis_runs (run_at, source, lookback_hours, failed_logins, "
            "bf_suspects, suspicious_procs, risk_level) VALUES (?,?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                report.source, lookback_hours,
                len(report.login_failures),
                len(report.brute_force_suspects),
                len(report.suspicious_processes),
                report.risk_level,
            ),
        )

    return report


def print_report(report: AnalysisReport) -> None:
    """Render the analysis report to stdout using click styling."""
    risk_col = RISK_COLOUR.get(report.risk_level, "white")

    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║       PROJECT AEGIS — LOG REPORT      ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))

    for line in report.summary_lines():
        if "Risk Level" in line:
            click.echo(
                f"  " + click.style(f"Risk Level   : ", fg="white") +
                click.style(report.risk_level, fg=risk_col, bold=True)
            )
        else:
            click.echo(f"  {line}")

    # ── Failed Logins ────────────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(f"  ▸ Failed Login Attempts ({len(report.login_failures)})", fg="yellow", bold=True))
    if not report.login_failures:
        click.echo("    (none)")
    else:
        for f in report.login_failures[:25]:
            ts      = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ip_tag  = f"[{f.ip_class.upper()}]"
            ip_col  = "red" if f.ip_class == "public" else "yellow"
            click.echo(
                f"    [{ts}] user={f.username:<18} src={f.source:<18} "
                + click.style(ip_tag, fg=ip_col)
            )
        if len(report.login_failures) > 25:
            click.echo(f"    … and {len(report.login_failures) - 25} more. See aegis.log.")

    # ── Brute-Force Suspects ─────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(f"  ▸ Brute-Force Suspects ({len(report.brute_force_suspects)})", fg="red", bold=True))
    if not report.brute_force_suspects:
        click.echo("    (none)")
    else:
        for src, evts in sorted(report.brute_force_suspects.items(), key=lambda x: -len(x[1])):
            users   = {e.username for e in evts}
            ip_cls  = classify_ip(src)
            ip_col  = "red" if ip_cls == "public" else "yellow"
            click.echo(
                click.style(f"    ⚠  {src:<20} ", fg="red") +
                f"— {len(evts)} attempts, targets: {', '.join(users)} " +
                click.style(f"[{ip_cls.upper()}]", fg=ip_col)
            )

    # ── Suspicious Processes ─────────────────────────────────────────────────
    click.echo("")
    click.echo(click.style(
        f"  ▸ Suspicious Executions ({len(report.suspicious_processes)})",
        fg="magenta", bold=True,
    ))
    if not report.suspicious_processes:
        click.echo("    (none)")
    else:
        for p in report.suspicious_processes[:20]:
            ts      = p.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            risk_c  = RISK_COLOUR.get(p.risk, "white")
            click.echo(
                f"    [{ts}] " +
                click.style(f"[{p.risk}]", fg=risk_c, bold=True) +
                f" kw='{p.matched_keyword}' cmd={p.command_line[:70]}"
            )
        if len(report.suspicious_processes) > 20:
            click.echo(f"    … and {len(report.suspicious_processes) - 20} more. See aegis.log.")

    click.echo("")
    click.echo(click.style("  Log written to: ~/aegis_logs/aegis.log", fg="cyan"))
    click.echo("")


def build_timeline(
    failures: List[LoginFailure],
    lookback_hours: int = 24,
) -> Dict[int, int]:
    """
    Bucket login failures by hour-of-day within the lookback window.

    Returns:
        Dict mapping hour_offset (0 = oldest, lookback_hours-1 = newest) → count.
    """
    buckets: Dict[int, int] = defaultdict(int)
    now = datetime.now(timezone.utc)
    for f in failures:
        delta_hours = int((now - f.timestamp).total_seconds() // 3600)
        if 0 <= delta_hours < lookback_hours:
            bucket = lookback_hours - 1 - delta_hours  # 0 = oldest hour slot
            buckets[bucket] += 1
    return buckets


def print_timeline(failures: List[LoginFailure], lookback_hours: int = 24) -> None:
    """Print an ASCII bar chart of login failures by hour."""
    buckets = build_timeline(failures, lookback_hours)
    max_val = max(buckets.values(), default=1)
    bar_width = 40

    click.echo("")
    click.echo(click.style("  ▸ Login Failure Timeline (hourly)", fg="cyan", bold=True))
    click.echo(f"  {'Hour':<6} {'Count':>5}  {'Bar'}")
    click.echo("  " + "─" * 60)

    now = datetime.now(timezone.utc)
    for slot in range(lookback_hours):
        hour_dt  = now - timedelta(hours=(lookback_hours - 1 - slot))
        label    = hour_dt.strftime("%H:00")
        count    = buckets.get(slot, 0)
        bar_len  = int((count / max_val) * bar_width) if max_val > 0 else 0
        bar      = "█" * bar_len
        colour   = "red" if count >= 5 else "yellow" if count >= 2 else "green"
        click.echo(
            f"  {label:<6} {count:>5}  " +
            click.style(bar, fg=colour)
        )
    click.echo("")


def list_run_history(limit: int = 20) -> List[dict]:
    """Return the most recent *limit* analysis runs from log_history.db."""
    _ensure_hist_db()
    with get_connection(_HIST_DB) as conn:
        rows = conn.execute(
            "SELECT id, run_at, source, lookback_hours, failed_logins, "
            "bf_suspects, suspicious_procs, risk_level "
            "FROM analysis_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]

"""
src/core/log_analyzer.py
------------------------
Project Aegis — Module C: Local Log Analyzer (v3.0).

v3.0 additions
~~~~~~~~~~~~~~
- Local IP blocklist: --blocklist FILE flags known-bad IPs as THREAT-INTEL.
- Known credential-stuffing usernames flagged without threshold requirement.
- Burst detection: ≥N failures within a 5-minute window → BURST alert.
- Event correlation: brute-force source also seen in suspicious procs → CORRELATED ATTACK.
- logs diff: differential report comparing two analysis run IDs.
- logs export: JSON or CEF (ArcSight/SIEM) structured export.
- logs blocklist: manage a persistent local IP blocklist (blocklist.db).

v2.0 features (retained)
~~~~~~~~~~~~~~~~~~~~~~~~
- Risk scoring, IP classification, PowerShell/Operational fallback,
  persistent run history, timeline chart, custom keyword files.
"""

import json
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import click

from src.utils.db import get_connection, init_db
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Keyword lists ─────────────────────────────────────────────────────────────
_DEFAULT_SUSPICIOUS_KEYWORDS = [
    "mimikatz", "procdump", "meterpreter", "cobalt", "powersploit",
    "invoke-expression", "iex", "encodedcommand", "-enc", "bypass",
    "downloadstring", "webclient", "certutil", "bitsadmin",
    "net user", "net localgroup", "whoami", "nltest", "dsquery",
    "psexec", "wmic", "regsvr32", "rundll32", "mshta", "cscript",
    "wscript", "curl", "wget",
]
_HIGH_RISK_KEYWORDS = {"mimikatz", "meterpreter", "cobalt", "powersploit", "encodedcommand"}

# Known credential-stuffing usernames — flag regardless of failure count
_STUFFING_USERNAMES: Set[str] = {
    "admin", "administrator", "root", "guest", "test", "user", "sa",
    "oracle", "postgres", "mysql", "ftp", "ftpuser", "anonymous",
    "support", "backup", "pi", "ubnt", "vagrant", "ubuntu", "centos",
    "ec2-user", "hadoop", "git", "deploy", "nagios", "zabbix",
}

# ── IP classification ─────────────────────────────────────────────────────────
_RFC1918_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
_LOOPBACK_PREFIXES = ("127.", "::1")

# ── History / Blocklist DBs ───────────────────────────────────────────────────
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

_BL_DB = "blocklist.db"
_BL_SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_blocklist (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    added_at   TEXT NOT NULL
);
"""


def _ensure_hist_db() -> None:
    init_db(_HIST_DB, _HIST_SCHEMA)


def _ensure_bl_db() -> None:
    init_db(_BL_DB, _BL_SCHEMA)


# ── Blocklist management ──────────────────────────────────────────────────────

def blocklist_load_db() -> Set[str]:
    """Return set of IPs from the persistent blocklist DB."""
    _ensure_bl_db()
    with get_connection(_BL_DB) as conn:
        rows = conn.execute("SELECT ip FROM ip_blocklist").fetchall()
    return {r["ip"] for r in rows}


def blocklist_add(ip: str, reason: str = "") -> None:
    _ensure_bl_db()
    with get_connection(_BL_DB) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ip_blocklist (ip, reason, added_at) VALUES (?,?,?)",
            (ip, reason, datetime.now(timezone.utc).isoformat()),
        )
    log.info("Blocklist: added %s (%s).", ip, reason)


def blocklist_remove(ip: str) -> bool:
    _ensure_bl_db()
    with get_connection(_BL_DB) as conn:
        cur = conn.execute("DELETE FROM ip_blocklist WHERE ip = ?", (ip,))
    return cur.rowcount > 0


def blocklist_show() -> List[Tuple]:
    _ensure_bl_db()
    with get_connection(_BL_DB) as conn:
        rows = conn.execute(
            "SELECT ip, reason, added_at FROM ip_blocklist ORDER BY added_at DESC"
        ).fetchall()
    return [(r["ip"], r["reason"], r["added_at"]) for r in rows]


def load_blocklist_file(path: str) -> Set[str]:
    """Load a newline-delimited IP blocklist from a plain text file."""
    ips: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    ips.add(ip)
        log.info("Loaded %d IPs from blocklist file %s.", len(ips), path)
    except (OSError, IOError) as exc:
        log.warning("Cannot read blocklist file %s: %s", path, exc)
    return ips


# ── Risk scoring ──────────────────────────────────────────────────────────────

def _score_risk(failures, bf_suspects, suspicious_procs, has_critical_kw=False,
                has_correlated=False, has_threat_intel=False) -> str:
    if has_correlated or has_threat_intel or \
       (has_critical_kw and (bf_suspects >= 1 or suspicious_procs >= 1)):
        return "CRITICAL"
    if has_critical_kw or (bf_suspects >= 1 and suspicious_procs >= 1):
        return "HIGH"
    if bf_suspects >= 1 or suspicious_procs >= 2:
        return "MEDIUM"
    if failures >= 5:
        return "MEDIUM"
    return "LOW"


RISK_COLOUR = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "magenta"}


def classify_ip(ip: str) -> str:
    if not ip or ip in ("-", "local", "unknown", "localhost"):
        return "unknown"
    if any(ip.startswith(p) for p in _LOOPBACK_PREFIXES):
        return "loopback"
    if any(ip.startswith(p) for p in _RFC1918_PREFIXES):
        return "private"
    return "public"


# ── Data classes ──────────────────────────────────────────────────────────────

class LoginFailure:
    __slots__ = ("timestamp", "username", "source", "ip_class", "risk",
                 "raw", "is_stuffing", "is_threat_intel")

    def __init__(self, timestamp, username, source, raw,
                 blocklist: Set[str] = frozenset()):
        self.timestamp   = timestamp
        self.username    = username
        self.source      = source
        self.ip_class    = classify_ip(source)
        self.raw         = raw
        self.is_stuffing     = username.lower() in _STUFFING_USERNAMES
        self.is_threat_intel = source in blocklist
        if self.is_threat_intel:
            self.risk = "CRITICAL"
        elif self.ip_class == "public" or self.is_stuffing:
            self.risk = "HIGH"
        else:
            self.risk = "MEDIUM"


class SuspiciousProcess:
    __slots__ = ("timestamp", "process", "command_line", "matched_keyword", "risk")

    def __init__(self, timestamp, process, command_line, matched_keyword):
        self.timestamp       = timestamp
        self.process         = process
        self.command_line    = command_line
        self.matched_keyword = matched_keyword
        self.risk = "CRITICAL" if matched_keyword.lower() in _HIGH_RISK_KEYWORDS else "HIGH"


class BurstAlert:
    __slots__ = ("source", "username", "count", "window_start", "window_end")

    def __init__(self, source, username, count, window_start, window_end):
        self.source       = source
        self.username     = username
        self.count        = count
        self.window_start = window_start
        self.window_end   = window_end


class AnalysisReport:
    def __init__(self):
        self.login_failures:        List[LoginFailure]            = []
        self.suspicious_processes:  List[SuspiciousProcess]       = []
        self.brute_force_suspects:  Dict[str, List[LoginFailure]] = {}
        self.burst_alerts:          List[BurstAlert]              = []
        self.correlated_attacks:    List[str]                     = []  # source IPs
        self.threat_intel_hits:     List[LoginFailure]            = []
        self.lookback_hours:        int                           = 24
        self.brute_force_threshold: int                           = 5
        self.source:                str                           = ""
        self.generated_at:          datetime                      = datetime.now(timezone.utc)
        self.risk_level:            str                           = "LOW"

    def compute_risk(self):
        has_critical_kw  = any(p.risk == "CRITICAL" for p in self.suspicious_processes)
        has_correlated   = len(self.correlated_attacks) > 0
        has_threat_intel = len(self.threat_intel_hits) > 0
        self.risk_level  = _score_risk(
            len(self.login_failures), len(self.brute_force_suspects),
            len(self.suspicious_processes), has_critical_kw,
            has_correlated, has_threat_intel,
        )

    def summary_lines(self) -> List[str]:
        return [
            f"  Source       : {self.source}",
            f"  Generated    : {self.generated_at.isoformat()}",
            f"  Lookback     : {self.lookback_hours}h",
            f"  BF Threshold : ≥{self.brute_force_threshold} failures",
            f"  Risk Level   : {self.risk_level}",
            "",
            f"  Failed Logins       : {len(self.login_failures)}",
            f"  Brute-Force Suspects: {len(self.brute_force_suspects)}",
            f"  Suspicious Procs    : {len(self.suspicious_processes)}",
            f"  Burst Alerts        : {len(self.burst_alerts)}",
            f"  Correlated Attacks  : {len(self.correlated_attacks)}",
            f"  Threat Intel Hits   : {len(self.threat_intel_hits)}",
        ]


# ── Burst detection ───────────────────────────────────────────────────────────

def _detect_bursts(
    failures: List[LoginFailure],
    window_minutes: int = 5,
    threshold: int = 10,
) -> List[BurstAlert]:
    """Flag sources with ≥ threshold failures within any window_minutes window."""
    by_source: Dict[str, List[LoginFailure]] = defaultdict(list)
    for f in failures:
        by_source[f.source].append(f)

    alerts: List[BurstAlert] = []
    window = timedelta(minutes=window_minutes)

    for source, events in by_source.items():
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        for i, start_event in enumerate(events_sorted):
            window_events = [
                e for e in events_sorted[i:]
                if e.timestamp - start_event.timestamp <= window
            ]
            if len(window_events) >= threshold:
                users = list({e.username for e in window_events})
                alerts.append(BurstAlert(
                    source=source,
                    username=users[0] if len(users) == 1 else f"{len(users)} users",
                    count=len(window_events),
                    window_start=window_events[0].timestamp,
                    window_end=window_events[-1].timestamp,
                ))
                break  # one alert per source

    return alerts


# ── Event correlation ─────────────────────────────────────────────────────────

def _detect_correlations(
    bf_suspects: Dict[str, List[LoginFailure]],
    suspicious_processes: List[SuspiciousProcess],
    window_minutes: int = 10,
) -> List[str]:
    """
    Return source IPs where a brute-force attempt AND a suspicious process
    execution occurred within window_minutes of each other.
    """
    correlated: List[str] = []
    window = timedelta(minutes=window_minutes)

    for source, failures in bf_suspects.items():
        failure_times = [f.timestamp for f in failures]
        for proc in suspicious_processes:
            for ft in failure_times:
                if abs((proc.timestamp - ft).total_seconds()) <= window.total_seconds():
                    correlated.append(source)
                    log.warning(
                        "CORRELATED ATTACK: src=%s bf_time=%s proc_kw=%s",
                        source, ft, proc.matched_keyword,
                    )
                    break
            else:
                continue
            break

    return list(set(correlated))


# ── Brute-force detection ─────────────────────────────────────────────────────

def _detect_brute_force(failures, threshold) -> Dict[str, List[LoginFailure]]:
    by_source: Dict[str, List[LoginFailure]] = defaultdict(list)
    for f in failures:
        by_source[f.source].append(f)
    return {src: evts for src, evts in by_source.items() if len(evts) >= threshold}


# ── Keyword loading ───────────────────────────────────────────────────────────

def load_keywords(keywords_file: Optional[str] = None) -> List[str]:
    base = list(_DEFAULT_SUSPICIOUS_KEYWORDS)
    if keywords_file:
        try:
            with open(keywords_file, "r", encoding="utf-8") as fh:
                extra = json.load(fh)
            if isinstance(extra, list):
                return list({k.lower() for k in base + extra})
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Cannot load keywords: %s", exc)
    return base


# ── Windows event log parsing ─────────────────────────────────────────────────

_WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _win_query(log_name: str, event_id: int, lookback_hours: int) -> str:
    cutoff     = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath      = (f"*[System[EventID={event_id}] and "
                  f"System[TimeCreated[@SystemTime>='{cutoff_str}']]]")
    cmd = ["wevtutil", "qe", log_name, "/q:" + xpath, "/f:XML", "/rd:true", "/c:500"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        return result.stdout
    except FileNotFoundError:
        log.warning("wevtutil not found — are you running on Windows?")
        return ""
    except subprocess.TimeoutExpired:
        return ""


def _parse_win_xml(xml_blob: str) -> List[ET.Element]:
    if not xml_blob.strip():
        return []
    try:
        root = ET.fromstring(f"<Root>{xml_blob}</Root>")
        return root.findall("Event", _WIN_NS) or root.findall("Event")
    except ET.ParseError as exc:
        log.warning("XML parse error: %s", exc)
        return []


def _win_failed_logins(lookback_hours: int, blocklist: Set[str]) -> List[LoginFailure]:
    xml_blob = _win_query("Security", 4625, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    failures: List[LoginFailure] = []
    ns_map   = _WIN_NS

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
            timestamp=ts, username=username, source=source_ip,
            raw=f"EventID=4625 user={username} src={source_ip}",
            blocklist=blocklist,
        ))

    return failures


def _win_suspicious_processes(lookback_hours: int, keywords: List[str]) -> List[SuspiciousProcess]:
    xml_blob = _win_query("Security", 4688, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    procs:   List[SuspiciousProcess] = []
    ns_map   = _WIN_NS

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

        process  = find_data("NewProcessName") or "unknown"
        cmdline  = find_data("CommandLine") or ""
        combined = f"{process} {cmdline}".lower()
        for kw in keywords:
            if kw.lower() in combined:
                procs.append(SuspiciousProcess(ts, process, cmdline, kw))
                break

    return procs


def _win_powershell_events(lookback_hours: int, keywords: List[str]) -> List[SuspiciousProcess]:
    xml_blob = _win_query("Microsoft-Windows-PowerShell/Operational", 4104, lookback_hours)
    events   = _parse_win_xml(xml_blob)
    procs:   List[SuspiciousProcess] = []
    ns_map   = _WIN_NS

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

        script = find_data("ScriptBlockText") or ""
        for kw in keywords:
            if kw.lower() in script.lower():
                procs.append(SuspiciousProcess(ts, "powershell.exe", script[:200], kw))
                break

    return procs


# ── Linux/macOS parsing ───────────────────────────────────────────────────────

_NIX_LOG_CANDIDATES = [
    Path("/var/log/auth.log"), Path("/var/log/secure"),
    Path("/var/log/syslog"),   Path("/var/log/messages"),
]
_RE_FAILED_PASSWORD = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[\d.a-fA-F:]+)", re.IGNORECASE,
)
_RE_INVALID_USER = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)", re.IGNORECASE,
)
_RE_PROC_EXEC = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)"
    r".+?CMD\s+\((?P<cmd>.+?)\)", re.IGNORECASE,
)
_MONTH_MAP = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}


def _parse_syslog_ts(month, day, time_str) -> datetime:
    try:
        now = datetime.now()
        m   = _MONTH_MAP.get(month.capitalize(), now.month)
        h, mi, s = (int(x) for x in time_str.split(":"))
        return datetime(now.year, m, int(day), h, mi, s, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _find_nix_log() -> Optional[Path]:
    for c in _NIX_LOG_CANDIDATES:
        if c.exists() and c.is_file():
            return c
    return None


def _nix_failed_logins(log_path, cutoff, blocklist) -> List[LoginFailure]:
    failures: List[LoginFailure] = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for pat in (_RE_FAILED_PASSWORD, _RE_INVALID_USER):
                    m = pat.search(line)
                    if m:
                        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
                        if ts >= cutoff:
                            failures.append(LoginFailure(
                                ts, m.group("user"), m.group("ip"), line.strip(), blocklist,
                            ))
                        break
    except (OSError, PermissionError) as exc:
        log.warning("Cannot read %s: %s", log_path, exc)
    return failures


def _nix_suspicious_processes(log_path, cutoff, keywords) -> List[SuspiciousProcess]:
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
                            procs.append(SuspiciousProcess(ts, "", m.group("cmd"), kw))
                            break
    except (OSError, PermissionError) as exc:
        log.warning("Cannot read %s: %s", log_path, exc)
    return procs


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    log_source: Optional[str] = None,
    lookback_hours: int = 24,
    threshold: int = 5,
    keywords_file: Optional[str] = None,
    blocklist_file: Optional[str] = None,
    burst_threshold: int = 10,
) -> AnalysisReport:
    """
    Parse system logs and return a populated AnalysisReport.

    v3.0 new args:
        blocklist_file: Path to a newline-delimited IP blocklist file.
        burst_threshold: Failures within 5 min to trigger a BURST alert.
    """
    keywords  = load_keywords(keywords_file)
    db_bl     = blocklist_load_db()
    file_bl   = load_blocklist_file(blocklist_file) if blocklist_file else set()
    blocklist = db_bl | file_bl

    report   = AnalysisReport()
    report.lookback_hours       = lookback_hours
    report.brute_force_threshold = threshold
    cutoff   = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    is_win   = platform.system() == "Windows"

    if log_source and log_source.lower() != "windows":
        path           = Path(log_source)
        report.source  = str(path)
        report.login_failures       = _nix_failed_logins(path, cutoff, blocklist)
        report.suspicious_processes = _nix_suspicious_processes(path, cutoff, keywords)
    elif is_win:
        report.source = "Windows Event Log (Security + PowerShell/Operational)"
        report.login_failures       = _win_failed_logins(lookback_hours, blocklist)
        report.suspicious_processes = (
            _win_suspicious_processes(lookback_hours, keywords)
            + _win_powershell_events(lookback_hours, keywords)
        )
    else:
        nix = _find_nix_log()
        if nix:
            report.source               = str(nix)
            report.login_failures       = _nix_failed_logins(nix, cutoff, blocklist)
            report.suspicious_processes = _nix_suspicious_processes(nix, cutoff, keywords)
        else:
            report.source = "none"

    report.brute_force_suspects = _detect_brute_force(report.login_failures, threshold)
    report.burst_alerts         = _detect_bursts(report.login_failures, threshold=burst_threshold)
    report.correlated_attacks   = _detect_correlations(
        report.brute_force_suspects, report.suspicious_processes)
    report.threat_intel_hits    = [f for f in report.login_failures if f.is_threat_intel]
    report.compute_risk()

    # Persist run
    _ensure_hist_db()
    with get_connection(_HIST_DB) as conn:
        conn.execute(
            "INSERT INTO analysis_runs (run_at, source, lookback_hours, failed_logins, "
            "bf_suspects, suspicious_procs, risk_level) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), report.source, lookback_hours,
             len(report.login_failures), len(report.brute_force_suspects),
             len(report.suspicious_processes), report.risk_level),
        )

    log.info("Analysis: failures=%d bf=%d procs=%d bursts=%d corr=%d ti=%d risk=%s",
        len(report.login_failures), len(report.brute_force_suspects),
        len(report.suspicious_processes), len(report.burst_alerts),
        len(report.correlated_attacks), len(report.threat_intel_hits), report.risk_level)
    return report


def print_report(report: AnalysisReport) -> None:
    risk_col = RISK_COLOUR.get(report.risk_level, "white")
    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║       PROJECT AEGIS — LOG REPORT      ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))
    for line in report.summary_lines():
        if "Risk Level" in line:
            click.echo("  " + click.style("Risk Level   : ", fg="white") +
                       click.style(report.risk_level, fg=risk_col, bold=True))
        else:
            click.echo(f"  {line}")

    # Threat Intel Hits (highest priority)
    if report.threat_intel_hits:
        click.echo("")
        click.echo(click.style(
            f"  ▸ THREAT INTEL HITS ({len(report.threat_intel_hits)}) — KNOWN BAD IPs",
            fg="magenta", bold=True))
        for f in report.threat_intel_hits[:10]:
            ts = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            click.echo(click.style(
                f"    🔴 [{ts}] src={f.source} user={f.username}", fg="magenta", bold=True))

    # Correlated attacks
    if report.correlated_attacks:
        click.echo("")
        click.echo(click.style(
            f"  ▸ CORRELATED ATTACKS ({len(report.correlated_attacks)}) — BF + SUSPICIOUS PROC",
            fg="magenta", bold=True))
        for src in report.correlated_attacks:
            click.echo(click.style(f"    ⚡ {src} — brute-force source also triggered process alert",
                fg="magenta"))

    # Burst alerts
    if report.burst_alerts:
        click.echo("")
        click.echo(click.style(f"  ▸ Burst Alerts ({len(report.burst_alerts)})", fg="red", bold=True))
        for b in report.burst_alerts:
            t0 = b.window_start.strftime("%H:%M:%S")
            t1 = b.window_end.strftime("%H:%M:%S")
            click.echo(click.style(
                f"    ⚡ {b.source} — {b.count} attempts between {t0}–{t1} (user: {b.username})",
                fg="red"))

    # Failed logins
    click.echo("")
    click.echo(click.style(f"  ▸ Failed Login Attempts ({len(report.login_failures)})", fg="yellow", bold=True))
    if not report.login_failures:
        click.echo("    (none)")
    else:
        for f in report.login_failures[:25]:
            ts     = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            ip_col = "red" if f.ip_class == "public" else "yellow"
            stuffing_tag = click.style(" [STUFFING-KW]", fg="red") if f.is_stuffing else ""
            ti_tag = click.style(" [THREAT-INTEL]", fg="magenta") if f.is_threat_intel else ""
            click.echo(
                f"    [{ts}] user={f.username:<18} src={f.source:<18}" +
                click.style(f" [{f.ip_class.upper()}]", fg=ip_col) +
                stuffing_tag + ti_tag
            )
        if len(report.login_failures) > 25:
            click.echo(f"    … and {len(report.login_failures) - 25} more.")

    # Brute-force
    click.echo("")
    click.echo(click.style(f"  ▸ Brute-Force Suspects ({len(report.brute_force_suspects)})", fg="red", bold=True))
    if not report.brute_force_suspects:
        click.echo("    (none)")
    else:
        for src, evts in sorted(report.brute_force_suspects.items(), key=lambda x: -len(x[1])):
            users  = {e.username for e in evts}
            ip_col = "red" if classify_ip(src) == "public" else "yellow"
            click.echo(
                click.style(f"    ⚠  {src:<20} ", fg="red") +
                f"— {len(evts)} attempts, users: {', '.join(users)} " +
                click.style(f"[{classify_ip(src).upper()}]", fg=ip_col)
            )

    # Suspicious processes
    click.echo("")
    click.echo(click.style(
        f"  ▸ Suspicious Executions ({len(report.suspicious_processes)})", fg="magenta", bold=True))
    if not report.suspicious_processes:
        click.echo("    (none)")
    else:
        for p in report.suspicious_processes[:20]:
            ts    = p.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            rc    = RISK_COLOUR.get(p.risk, "white")
            click.echo(f"    [{ts}] " +
                click.style(f"[{p.risk}]", fg=rc, bold=True) +
                f" kw='{p.matched_keyword}' cmd={p.command_line[:70]}")
        if len(report.suspicious_processes) > 20:
            click.echo(f"    … and {len(report.suspicious_processes) - 20} more.")

    click.echo("")
    click.echo(click.style("  Log: ~/aegis_logs/aegis.log", fg="cyan"))
    click.echo("")


# ── Timeline ──────────────────────────────────────────────────────────────────

def build_timeline(failures, lookback_hours=24) -> Dict[int, int]:
    buckets: Dict[int, int] = defaultdict(int)
    now = datetime.now(timezone.utc)
    for f in failures:
        delta_hours = int((now - f.timestamp).total_seconds() // 3600)
        if 0 <= delta_hours < lookback_hours:
            buckets[lookback_hours - 1 - delta_hours] += 1
    return buckets


def print_timeline(failures, lookback_hours=24) -> None:
    buckets   = build_timeline(failures, lookback_hours)
    max_val   = max(buckets.values(), default=1)
    bar_width = 40
    now       = datetime.now(timezone.utc)
    click.echo("")
    click.echo(click.style("  ▸ Login Failure Timeline (hourly)", fg="cyan", bold=True))
    click.echo(f"  {'Hour':<6} {'Count':>5}  Bar")
    click.echo("  " + "─" * 55)
    for slot in range(lookback_hours):
        hour_dt = now - timedelta(hours=(lookback_hours - 1 - slot))
        label   = hour_dt.strftime("%H:00")
        count   = buckets.get(slot, 0)
        bar_len = int((count / max_val) * bar_width) if max_val else 0
        colour  = "red" if count >= 5 else "yellow" if count >= 2 else "green"
        click.echo(f"  {label:<6} {count:>5}  " + click.style("█" * bar_len, fg=colour))
    click.echo("")


def list_run_history(limit=20) -> List[dict]:
    _ensure_hist_db()
    with get_connection(_HIST_DB) as conn:
        rows = conn.execute(
            "SELECT id, run_at, source, lookback_hours, failed_logins, "
            "bf_suspects, suspicious_procs, risk_level "
            "FROM analysis_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def diff_runs(since_run_id: int) -> dict:
    """
    Compare the latest analysis run to run *since_run_id*.
    Returns a dict with 'new_failures', 'resolved_bf', 'risk_change'.
    """
    _ensure_hist_db()
    with get_connection(_HIST_DB) as conn:
        runs = conn.execute(
            "SELECT id, failed_logins, bf_suspects, suspicious_procs, risk_level "
            "FROM analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        old_run = conn.execute(
            "SELECT id, failed_logins, bf_suspects, suspicious_procs, risk_level "
            "FROM analysis_runs WHERE id = ?", (since_run_id,)
        ).fetchone()

    if not runs or not old_run:
        raise ValueError("Could not find comparison runs in history.")

    return {
        "latest_id":        runs["id"],
        "since_id":         old_run["id"],
        "delta_failures":   runs["failed_logins"] - old_run["failed_logins"],
        "delta_bf":         runs["bf_suspects"]   - old_run["bf_suspects"],
        "delta_procs":      runs["suspicious_procs"] - old_run["suspicious_procs"],
        "risk_was":         old_run["risk_level"],
        "risk_now":         runs["risk_level"],
    }


def export_report(report: AnalysisReport, output_path: str, fmt: str = "json") -> None:
    """
    Export the analysis report to *output_path* in 'json' or 'cef' format.
    """
    if fmt == "json":
        data = {
            "generated_at":  report.generated_at.isoformat(),
            "source":        report.source,
            "risk_level":    report.risk_level,
            "lookback_hours": report.lookback_hours,
            "failed_logins": [
                {"timestamp": f.timestamp.isoformat(), "username": f.username,
                 "source": f.source, "ip_class": f.ip_class,
                 "is_stuffing": f.is_stuffing, "is_threat_intel": f.is_threat_intel}
                for f in report.login_failures
            ],
            "brute_force_suspects": {
                src: [{"username": e.username, "timestamp": e.timestamp.isoformat()} for e in evts]
                for src, evts in report.brute_force_suspects.items()
            },
            "suspicious_processes": [
                {"timestamp": p.timestamp.isoformat(), "process": p.process,
                 "command_line": p.command_line, "keyword": p.matched_keyword,
                 "risk": p.risk}
                for p in report.suspicious_processes
            ],
            "burst_alerts": [
                {"source": b.source, "count": b.count,
                 "window_start": b.window_start.isoformat(),
                 "window_end": b.window_end.isoformat()}
                for b in report.burst_alerts
            ],
            "correlated_attacks": report.correlated_attacks,
            "threat_intel_hits":  [f.source for f in report.threat_intel_hits],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    elif fmt == "cef":
        # ArcSight Common Event Format (CEF:0)
        lines = []
        device = "ProjectAegis|LogAnalyzer|3.0"
        for f in report.login_failures:
            sev = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}.get(f.risk, 3)
            lines.append(
                f"CEF:0|{device}|FailedLogin|{sev}|"
                f"src={f.source} duser={f.username} "
                f"rt={int(f.timestamp.timestamp() * 1000)}"
            )
        for p in report.suspicious_processes:
            sev = 10 if p.risk == "CRITICAL" else 8
            lines.append(
                f"CEF:0|{device}|SuspiciousProcess|{sev}|"
                f"cs1={p.matched_keyword} cmd={p.command_line[:100]} "
                f"rt={int(p.timestamp.timestamp() * 1000)}"
            )
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    else:
        raise ValueError(f"Unknown export format: {fmt}. Use 'json' or 'cef'.")

    log.info("Report exported to %s (%s).", output_path, fmt)

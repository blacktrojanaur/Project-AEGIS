"""
src/core/hardening.py
---------------------
Project Aegis — Module E: System Hardening Checker (v3.1).

Performs a read-only inspection of OS security settings and returns
structured findings with PASS / FAIL / WARN / SKIP status per check.

Platform support
~~~~~~~~~~~~~~~~
- Windows : net accounts, reg query, netsh, auditpol, sc query, powershell
- Linux   : /etc/ssh/sshd_config, /etc/passwd, ufw/iptables, find

Design constraints
~~~~~~~~~~~~~~~~~~
- Read-only: zero write operations or state modifications.
- Fully offline: no network calls.
- Degraded mode: checks that require elevation are marked SKIP when
  running without admin privileges rather than crashing.
- Stdlib only: subprocess, pathlib, platform, re.

v3.1 fix
~~~~~~~~
- All Windows built-in commands (net, reg, sc, netsh, auditpol) now run
  via shell=True so they resolve correctly in any environment.
- reg query reads HKCU (user hive) without admin — UAC, AutoRun use HKCU.
- Firewall and WinRM checks work without elevation.
- net user / net accounts work without elevation.
- Verbose error logging added so failures surface in aegis.log.
"""

import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Status constants ──────────────────────────────────────────────────────────

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"

STATUS_COLOUR = {
    PASS: "green",
    FAIL: "red",
    WARN: "yellow",
    SKIP: "cyan",
}


@dataclass
class CheckResult:
    name:        str
    status:      str
    description: str
    detail:      str = ""
    weight:      int = 1


@dataclass
class HardeningReport:
    platform:  str = ""
    checks:    List[CheckResult] = field(default_factory=list)
    score:     int = 0
    is_admin:  bool = False

    def compute_score(self) -> None:
        total_weight  = sum(c.weight for c in self.checks if c.status != SKIP)
        passed_weight = sum(c.weight for c in self.checks if c.status == PASS)
        self.score    = int((passed_weight / total_weight * 100)) if total_weight else 0

    @property
    def passed(self)  -> int: return sum(1 for c in self.checks if c.status == PASS)
    @property
    def failed(self)  -> int: return sum(1 for c in self.checks if c.status == FAIL)
    @property
    def warned(self)  -> int: return sum(1 for c in self.checks if c.status == WARN)
    @property
    def skipped(self) -> int: return sum(1 for c in self.checks if c.status == SKIP)


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run_shell(cmd: str) -> Tuple[str, str, int]:
    """
    Run a shell command string and return (stdout, stderr, returncode).
    Uses shell=True so built-in Windows commands (net, reg, sc, netsh,
    auditpol) resolve without needing a full path.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=True,
        )
        out = result.stdout or ""
        err = result.stderr or ""
        if result.returncode != 0:
            log.debug("cmd=%r  rc=%d  stderr=%r", cmd, result.returncode, err[:200])
        return out, err, result.returncode
    except subprocess.TimeoutExpired:
        log.warning("Command timed out: %s", cmd)
        return "", "timeout", 1
    except Exception as exc:
        log.warning("Command error: %s — %s", cmd, exc)
        return "", str(exc), 1


def _is_admin() -> bool:
    """Best-effort admin/root detection."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


# ════════════════════════════════════════════════════════════════════════════
# WINDOWS CHECKS
# All use _run_shell() so Windows built-ins resolve in any shell context.
# ════════════════════════════════════════════════════════════════════════════

def _win_check_guest_account() -> CheckResult:
    """net user guest — does NOT require admin."""
    out, err, rc = _run_shell("net user guest")
    if rc != 0:
        # Try the alternate locale label "Account active"
        log.debug("net user guest failed: %r", err)
        return CheckResult("Guest Account", SKIP,
            "Could not query guest account status.", err.strip(), weight=2)

    # Extract "Account active   Yes/No"
    m = re.search(r"Account active\s+(Yes|No)", out, re.IGNORECASE)
    if m:
        if m.group(1).lower() == "yes":
            return CheckResult("Guest Account", FAIL,
                "Guest account is ENABLED — disable via: net user guest /active:no",
                weight=2)
        return CheckResult("Guest Account", PASS, "Guest account is disabled. ✓", weight=2)

    # If the key phrase isn't found the account probably doesn't exist
    return CheckResult("Guest Account", PASS,
        "Guest account not found or disabled.", weight=2)


def _win_check_password_policy() -> CheckResult:
    """net accounts — does NOT require admin."""
    out, err, rc = _run_shell("net accounts")
    if rc != 0:
        log.debug("net accounts failed: %r", err)
        return CheckResult("Password Policy", SKIP,
            "Could not query password policy.", err.strip(), weight=3)

    issues = []

    m = re.search(r"Minimum password length\s+(\d+)", out, re.IGNORECASE)
    if m:
        min_len = int(m.group(1))
        issues.append(f"MinLen={min_len}" + (" (recommend ≥12)" if min_len < 12 else " ✓"))

    m = re.search(r"Maximum password age \(days\)\s+(\d+)", out, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))
        issues.append(f"MaxAge={max_age}d" + (" (recommend ≤90)" if max_age > 90 else " ✓"))

    m = re.search(r"Lockout threshold\s+(\S+)", out, re.IGNORECASE)
    if m:
        val = m.group(1)
        if val.lower() == "never":
            issues.append("Lockout=Never (recommend ≤5)")
        else:
            lockout = int(val)
            issues.append(f"Lockout={lockout}" + (" (recommend ≤5)" if lockout > 5 else " ✓"))

    detail = " | ".join(issues)
    bad    = [i for i in issues if "recommend" in i]

    if not issues:
        return CheckResult("Password Policy", SKIP,
            "Could not parse policy values from net accounts.", out[:200], weight=3)
    if bad:
        status = FAIL if len(bad) >= 2 else WARN
        return CheckResult("Password Policy", status,
            "Password policy has weaknesses.", detail, weight=3)
    return CheckResult("Password Policy", PASS,
        "Password policy meets recommendations.", detail, weight=3)


def _win_check_firewall() -> CheckResult:
    """netsh advfirewall — does NOT require admin (read-only query)."""
    out, err, rc = _run_shell("netsh advfirewall show allprofiles state")
    if rc != 0:
        log.debug("netsh failed: %r", err)
        return CheckResult("Firewall", SKIP,
            "Could not query Windows Firewall status.", err.strip(), weight=3)

    states = re.findall(r"State\s+(ON|OFF)", out, re.IGNORECASE)
    if not states:
        return CheckResult("Firewall", SKIP,
            "Could not parse firewall profile states.", out[:200], weight=3)

    off_count = sum(1 for s in states if s.upper() == "OFF")
    if off_count == 0:
        return CheckResult("Firewall", PASS,
            f"Windows Firewall ON for all {len(states)} profile(s). ✓", weight=3)
    return CheckResult("Firewall", FAIL,
        f"Firewall OFF on {off_count}/{len(states)} profile(s).", weight=3)


def _win_check_uac() -> CheckResult:
    """
    reg query HKLM — UAC lives in HKLM and is readable by any user.
    HKCU mirror is not reliable; use HKLM directly.
    """
    key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    out, err, rc = _run_shell(f'reg query "{key}" /v EnableLUA')
    if rc != 0:
        log.debug("UAC reg query failed: %r", err)
        return CheckResult("UAC", SKIP,
            "Could not read UAC registry key.", err.strip(), weight=2)
    if "0x1" in out:
        return CheckResult("UAC", PASS, "User Account Control (UAC) is enabled. ✓", weight=2)
    if "0x0" in out:
        return CheckResult("UAC", FAIL,
            "UAC is DISABLED. All processes run with full admin rights.", weight=2)
    return CheckResult("UAC", WARN, "UAC key found but value is unexpected.", out[:100], weight=2)


def _win_check_autorun() -> CheckResult:
    """
    Checks HKLM (machine policy) then HKCU (user policy).
    Both are readable without admin.
    """
    for hive, label in [
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "HKLM"),
        (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "HKCU"),
    ]:
        out, err, rc = _run_shell(f'reg query "{hive}" /v NoDriveTypeAutoRun')
        if rc == 0 and "NoDriveTypeAutoRun" in out:
            m = re.search(r"NoDriveTypeAutoRun\s+REG_DWORD\s+(\S+)", out)
            if m:
                val = int(m.group(1), 16)
                if val >= 0xFF:
                    return CheckResult("AutoRun", PASS,
                        f"AutoRun disabled for all drives ({label}: 0x{val:02X}). ✓", weight=1)
                return CheckResult("AutoRun", WARN,
                    f"AutoRun partially disabled ({label}: 0x{val:02X}). Recommend 0xFF.", weight=1)

    return CheckResult("AutoRun", WARN,
        "NoDriveTypeAutoRun policy not set — AutoRun may be active for some drives.", weight=1)


def _win_check_smb_signing() -> CheckResult:
    """
    HKLM\SYSTEM — readable by all users without elevation.
    """
    key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    out, err, rc = _run_shell(f'reg query "{key}" /v RequireSecuritySignature')
    if rc != 0:
        log.debug("SMB signing reg query failed: %r", err)
        return CheckResult("SMB Signing", SKIP,
            "Could not read SMB signing registry key.", err.strip(), weight=3)

    m = re.search(r"RequireSecuritySignature\s+REG_DWORD\s+(\S+)", out)
    if m:
        val = int(m.group(1), 16)
        if val == 1:
            return CheckResult("SMB Signing", PASS,
                "SMB server signing is required. ✓", weight=3)
        return CheckResult("SMB Signing", FAIL,
            "SMB signing NOT required — vulnerable to NTLM relay attacks.", weight=3)

    return CheckResult("SMB Signing", WARN,
        "RequireSecuritySignature key not found (using OS default).", weight=3)


def _win_check_rdp_nla() -> CheckResult:
    """HKLM\SYSTEM — readable by all users."""
    key = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    out, err, rc = _run_shell(f'reg query "{key}" /v UserAuthentication')
    if rc != 0:
        log.debug("RDP NLA reg query failed: %r", err)
        # RDP may not be configured at all
        return CheckResult("RDP NLA", SKIP,
            "Could not read RDP registry key (RDP may be disabled).", err.strip(), weight=3)

    m = re.search(r"UserAuthentication\s+REG_DWORD\s+(\S+)", out)
    if m:
        val = int(m.group(1), 16)
        if val == 1:
            return CheckResult("RDP NLA", PASS, "RDP NLA (Network Level Auth) enforced. ✓", weight=3)
        return CheckResult("RDP NLA", FAIL,
            "RDP NLA NOT enforced — credentials are exposed before authentication.", weight=3)

    return CheckResult("RDP NLA", WARN, "UserAuthentication key not found.", weight=3)


def _win_check_audit_policy() -> CheckResult:
    """auditpol requires admin — returns SKIP gracefully otherwise."""
    out, err, rc = _run_shell("auditpol /get /subcategory:Logon")
    if rc != 0:
        log.debug("auditpol failed (need admin): %r", err)
        return CheckResult("Audit Policy (Logon)", SKIP,
            "auditpol requires Administrator privileges.", "", weight=2)

    out_lower = out.lower()
    if "success and failure" in out_lower:
        return CheckResult("Audit Policy (Logon)", PASS,
            "Logon events: Success + Failure audited. ✓", weight=2)
    if "success" in out_lower:
        return CheckResult("Audit Policy (Logon)", WARN,
            "Only Logon Success is audited — add Failure auditing.", weight=2)
    return CheckResult("Audit Policy (Logon)", FAIL,
        "Logon events NOT audited. Run: auditpol /set /subcategory:Logon /failure:enable",
        weight=2)


def _win_check_winrm() -> CheckResult:
    """sc query — readable without admin."""
    out, err, rc = _run_shell("sc query WinRM")
    if rc != 0:
        # Service not found = not installed = good
        if "1060" in err or "does not exist" in (out + err).lower():
            return CheckResult("WinRM", PASS, "WinRM service not installed. ✓", weight=1)
        log.debug("sc query WinRM failed: %r", err)
        return CheckResult("WinRM", SKIP, "Could not query WinRM service.", err.strip(), weight=1)

    if "running" in out.lower():
        return CheckResult("WinRM", WARN,
            "WinRM is RUNNING — ensure HTTPS-only listener and strong auth.", weight=1)
    return CheckResult("WinRM", PASS, "WinRM service is not running. ✓", weight=1)


def _win_check_defender() -> CheckResult:
    """
    Uses PowerShell Get-MpComputerStatus.
    Tries a shorter command with -NoProfile for reliability in non-interactive shells.
    """
    out, err, rc = _run_shell(
        'powershell -NoProfile -NonInteractive -Command '
        '"(Get-MpComputerStatus).AntivirusEnabled"'
    )
    if rc != 0 or not out.strip():
        # Fallback: check Windows Security Center via WMI
        out2, err2, rc2 = _run_shell(
            'powershell -NoProfile -NonInteractive -Command '
            '"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct '
            '| Select-Object -ExpandProperty displayName"'
        )
        if rc2 == 0 and out2.strip():
            return CheckResult("Windows Defender", PASS,
                f"AV product detected: {out2.strip()[:60]}. ✓", weight=2)
        log.debug("Defender check failed: rc=%d err=%r", rc, err)
        return CheckResult("Windows Defender", SKIP,
            "Could not query Defender status (may need PowerShell policy).",
            err.strip()[:100], weight=2)

    val = out.strip().lower()
    if val == "true":
        return CheckResult("Windows Defender", PASS,
            "Windows Defender real-time protection is ENABLED. ✓", weight=2)
    return CheckResult("Windows Defender", FAIL,
        "Windows Defender appears DISABLED — ensure an AV product is active.", weight=2)


def _win_check_windows_update() -> CheckResult:
    """
    Check if Windows Update service (wuauserv) is running.
    Does NOT require admin.
    """
    out, err, rc = _run_shell("sc query wuauserv")
    if rc != 0:
        return CheckResult("Windows Update Service", SKIP,
            "Could not query Windows Update service.", weight=1)
    if "running" in out.lower():
        return CheckResult("Windows Update Service", PASS,
            "Windows Update service is running. ✓", weight=1)
    return CheckResult("Windows Update Service", WARN,
        "Windows Update service is NOT running.", weight=1)


def run_windows_checks(is_admin: bool = False) -> List[CheckResult]:
    checks = [
        _win_check_guest_account(),
        _win_check_password_policy(),
        _win_check_firewall(),
        _win_check_uac(),
        _win_check_autorun(),
        _win_check_smb_signing(),
        _win_check_rdp_nla(),
        _win_check_audit_policy(),
        _win_check_winrm(),
        _win_check_defender(),
        _win_check_windows_update(),
    ]
    return checks


# ════════════════════════════════════════════════════════════════════════════
# LINUX / macOS CHECKS
# ════════════════════════════════════════════════════════════════════════════

def _nix_check_ssh_root_login() -> CheckResult:
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        return CheckResult("SSH Root Login", SKIP, "/etc/ssh/sshd_config not found.", weight=3)
    text = cfg.read_text(errors="replace")
    m    = re.search(r"^\s*PermitRootLogin\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
    val  = m.group(1).lower() if m else "yes"
    if val in ("no", "prohibit-password", "forced-commands-only"):
        return CheckResult("SSH Root Login", PASS, f"PermitRootLogin={val} ✓", weight=3)
    return CheckResult("SSH Root Login", FAIL,
        f"PermitRootLogin={val}. Set to 'no' in /etc/ssh/sshd_config.", weight=3)


def _nix_check_ssh_password_auth() -> CheckResult:
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        return CheckResult("SSH Password Auth", SKIP, "/etc/ssh/sshd_config not found.", weight=2)
    text = cfg.read_text(errors="replace")
    m    = re.search(r"^\s*PasswordAuthentication\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
    val  = m.group(1).lower() if m else "yes"
    if val == "no":
        return CheckResult("SSH Password Auth", PASS,
            "SSH password auth disabled (key-only). ✓", weight=2)
    return CheckResult("SSH Password Auth", WARN,
        "SSH password auth ENABLED — prefer key-based auth.", weight=2)


def _nix_check_ssh_port() -> CheckResult:
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        return CheckResult("SSH Default Port", SKIP, "/etc/ssh/sshd_config not found.", weight=1)
    text = cfg.read_text(errors="replace")
    m    = re.search(r"^\s*Port\s+(\d+)", text, re.IGNORECASE | re.MULTILINE)
    port = int(m.group(1)) if m else 22
    if port != 22:
        return CheckResult("SSH Default Port", PASS,
            f"SSH on non-default port {port}. ✓", weight=1)
    return CheckResult("SSH Default Port", WARN,
        "SSH on port 22 (default). Consider a non-standard port.", weight=1)


def _nix_check_firewall() -> CheckResult:
    out, _, rc = _run_shell("ufw status")
    if rc == 0:
        if "active" in out.lower():
            return CheckResult("Firewall (ufw)", PASS, "ufw firewall active. ✓", weight=3)
        return CheckResult("Firewall (ufw)", FAIL,
            "ufw installed but INACTIVE. Run: ufw enable", weight=3)
    out, _, rc = _run_shell("iptables -L -n")
    if rc == 0:
        non_empty = any(
            line.strip() and not line.startswith("Chain") and not line.startswith("target")
            for line in out.splitlines()
        )
        if non_empty:
            return CheckResult("Firewall (iptables)", PASS, "iptables rules present. ✓", weight=3)
        return CheckResult("Firewall (iptables)", WARN,
            "iptables has no rules.", weight=3)
    return CheckResult("Firewall", SKIP, "Neither ufw nor iptables found.", weight=3)


def _nix_check_empty_password_users() -> CheckResult:
    try:
        text  = Path("/etc/shadow").read_text(errors="replace")
        empty = [
            line.split(":")[0] for line in text.splitlines()
            if len(line.split(":")) >= 2 and line.split(":")[1] == ""
        ]
        if empty:
            return CheckResult("Empty Password Accounts", FAIL,
                f"Accounts with empty passwords: {', '.join(empty)}", weight=3)
        return CheckResult("Empty Password Accounts", PASS,
            "No empty-password accounts. ✓", weight=3)
    except PermissionError:
        return CheckResult("Empty Password Accounts", SKIP,
            "/etc/shadow requires root.", weight=3)
    except FileNotFoundError:
        return CheckResult("Empty Password Accounts", SKIP,
            "/etc/shadow not found.", weight=3)


def _nix_check_world_writable_path() -> CheckResult:
    path_dirs = os.environ.get("PATH", "").split(":")
    suspicious = []
    for d in path_dirs:
        p = Path(d)
        if p.exists():
            try:
                if p.stat().st_mode & 0o002:
                    suspicious.append(d)
            except OSError:
                pass
    if suspicious:
        return CheckResult("World-Writable PATH dirs", FAIL,
            f"World-writable dirs in PATH: {', '.join(suspicious)}", weight=2)
    return CheckResult("World-Writable PATH dirs", PASS,
        "No world-writable directories in PATH. ✓", weight=2)


def run_linux_checks() -> List[CheckResult]:
    return [
        _nix_check_ssh_root_login(),
        _nix_check_ssh_password_auth(),
        _nix_check_ssh_port(),
        _nix_check_firewall(),
        _nix_check_empty_password_users(),
        _nix_check_world_writable_path(),
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def run_checks() -> HardeningReport:
    report          = HardeningReport()
    report.platform = platform.system()
    report.is_admin = _is_admin()

    log.info("Hardening check started (platform=%s admin=%s).", report.platform, report.is_admin)

    if report.platform == "Windows":
        report.checks = run_windows_checks(is_admin=report.is_admin)
    else:
        report.checks = run_linux_checks()

    report.compute_score()
    log.info(
        "Hardening check complete: score=%d pass=%d fail=%d warn=%d skip=%d",
        report.score, report.passed, report.failed, report.warned, report.skipped,
    )
    return report


def format_report_text(report: HardeningReport) -> str:
    lines = [
        "Project Aegis — System Hardening Report",
        f"Platform : {report.platform}",
        f"Score    : {report.score}/100",
        f"Pass/Fail/Warn/Skip : {report.passed}/{report.failed}/{report.warned}/{report.skipped}",
        "=" * 60,
        "",
    ]
    for c in report.checks:
        indicator = {"PASS": "[✓]", "FAIL": "[✗]", "WARN": "[!]", "SKIP": "[-]"}.get(c.status, "[?]")
        lines.append(f"{indicator} {c.name:<32} {c.status}")
        if c.description:
            lines.append(f"    {c.description}")
        if c.detail:
            lines.append(f"    Detail: {c.detail}")
        lines.append("")
    return "\n".join(lines)

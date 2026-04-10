"""
aegis.py
--------
Project Aegis — Unified CLI Entry Point (v2.0).

Usage
~~~~~
    python aegis.py --help
    python aegis.py integrity scan   <path> [--exclude PATTERN]...
    python aegis.py integrity watch  <path> [--interval N] [--quiet]
    python aegis.py integrity check  <path>
    python aegis.py integrity diff   <path> [--since SCAN_ID]
    python aegis.py integrity export <path> [--output FILE]
    python aegis.py integrity history

    python aegis.py vault set        <name> [--tag CATEGORY] [--notes TEXT]
    python aegis.py vault get        <name> [--show]
    python aegis.py vault list
    python aegis.py vault search     <pattern>
    python aegis.py vault rename     <old> <new>
    python aegis.py vault audit      [--days N]
    python aegis.py vault delete     <name>
    python aegis.py vault export     --output FILE
    python aegis.py vault import     --input FILE [--overwrite]

    python aegis.py logs analyze     [--source PATH] [--hours N] [--threshold N] [--keywords FILE]
    python aegis.py logs report      [--source PATH] [--hours N] [--threshold N] [--output FILE]
    python aegis.py logs timeline    [--source PATH] [--hours N]
    python aegis.py logs history     [--limit N]

    python aegis.py scan ports       [--host HOST] [--range START-END] [--timeout N]
    python aegis.py scan summary     [--host HOST]

Design principles
~~~~~~~~~~~~~~~~~
- Air-gapped: zero network calls except Module D's local socket probes.
- Zero-Trust: secrets always encrypted at rest; master password never stored.
- Rotating logs written to ~/aegis_logs/aegis.log automatically.
"""

import sys
import os

# ── Ensure project root is on sys.path ──────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import click

from src.utils.logger import set_verbosity

# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ___  ___  __  _     ___ ___     ___  ___  _  ___
 | _ \| _ \/ / | |   | __/ __|  / _ \| __|| |/ __|
 |  _/|   / _ \| |__ | _| (_ | | (_) | _| | |\__ \
 |_|  |_|_\___/|____||___\___|  \___/|___|___|___/

         [ Offline Cybersecurity Suite v2.0 ]
         [ Air-Gapped | Zero-Trust | Python  ]
"""


def _print_banner() -> None:
    click.echo(click.style(BANNER, fg="cyan", bold=True))


# ── Root Command Group ───────────────────────────────────────────────────────

@click.group()
@click.version_option(version="2.0.0", prog_name="Project Aegis")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable DEBUG console output.")
@click.option("--quiet",   "-q", is_flag=True, default=False, help="Suppress WARNING output (ERRORs only).")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """
    \b
    Project Aegis — Offline Cybersecurity Suite v2.0
    ==================================================
    Modules:
      integrity  File Integrity Monitor    (Module A)
      vault      Encrypted Secret Vault    (Module B)
      logs       Local Log Analyzer        (Module C)
      scan       Network Port Scanner      (Module D)

    Run `aegis <module> --help` for module-specific usage.
    """
    _print_banner()
    set_verbosity(verbose=verbose, quiet=quiet)


# ════════════════════════════════════════════════════════════════════════════
# MODULE A — File Integrity
# ════════════════════════════════════════════════════════════════════════════

@cli.group("integrity")
def integrity_group() -> None:
    """
    \b
    Module A: File Integrity Monitor
    ---------------------------------
    Monitor directories using SHA-256 + BLAKE2b fingerprints stored in a
    local SQLite database.  Alerts on MODIFIED, ADDED, and DELETED files.
    """


@integrity_group.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--exclude", "-x",
    multiple=True,
    metavar="PATTERN",
    help="Glob pattern to exclude (repeatable). E.g. --exclude '*.pyc' --exclude '.git/*'",
)
def integrity_scan(path: str, exclude: tuple) -> None:
    """
    Perform a baseline scan of PATH and record SHA-256 + BLAKE2b fingerprints.

    \b
    Examples:
        python aegis.py integrity scan ./src
        python aegis.py integrity scan ./src --exclude '*.pyc' --exclude '__pycache__/*'
    """
    from src.core.integrity import baseline_scan
    try:
        baseline_scan(path, exclude=list(exclude))
    except ValueError as exc:
        raise click.ClickException(str(exc))


@integrity_group.command("check")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def integrity_check(path: str) -> None:
    """
    Compare the current state of PATH against its stored baseline.

    \b
    Example:
        python aegis.py integrity check ./src
    """
    from src.core.integrity import check_and_report
    check_and_report(path)


@integrity_group.command("watch")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--interval", "-i",
    default=5, show_default=True,
    type=click.IntRange(1, 3600),
    help="Polling interval in seconds.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True, default=False,
    help="Only print output when anomalies are detected.",
)
def integrity_watch(path: str, interval: int, quiet: bool) -> None:
    """
    Continuously monitor PATH, alerting on any integrity violations.

    Runs until interrupted with Ctrl+C.

    \b
    Examples:
        python aegis.py integrity watch ./src --interval 10
        python aegis.py integrity watch ./src --quiet
    """
    from src.core.integrity import watch
    watch(path, interval, quiet=quiet)


@integrity_group.command("diff")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--since", "-s",
    default=None,
    type=int,
    metavar="SCAN_ID",
    help="Compare against this historical scan ID (from `integrity history`).",
)
def integrity_diff(path: str, since: int) -> None:
    """
    Show what has changed in PATH since a previous scan.

    Without --since, compares against the current stored baseline.

    \b
    Examples:
        python aegis.py integrity diff ./src
        python aegis.py integrity diff ./src --since 3
    """
    from src.core.integrity import diff, _emit_events
    try:
        events = diff(path, since_scan_id=since)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    if not events:
        label = f"scan #{since}" if since else "baseline"
        click.echo(click.style(f"  ✓ No changes since {label}.", fg="green", bold=True))
    else:
        label = f"scan #{since}" if since else "baseline"
        click.echo(click.style(f"  ⚠  {len(events)} change(s) since {label}:", fg="red", bold=True))
        _emit_events(events)


@integrity_group.command("history")
def integrity_history() -> None:
    """
    List all past baseline scan sessions.

    \b
    Example:
        python aegis.py integrity history
    """
    from src.core.integrity import list_history
    sessions = list_history()
    if not sessions:
        click.echo(click.style("  No scan history found. Run `integrity scan` first.", fg="yellow"))
        return

    click.echo(click.style(
        f"\n  {'ID':<5} {'Scanned At':<35} {'Files':>7} {'Skipped':>8} {'Size (MB)':>10}  Root",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 90)
    for s in sessions:
        size_mb = s["total_bytes"] / (1024 * 1024) if s.get("total_bytes") else 0
        click.echo(
            f"  {s['id']:<5} {s['scanned_at']:<35} {s['file_count']:>7} "
            f"{s['skipped']:>8} {size_mb:>10.2f}  {s['root']}"
        )
    click.echo(f"\n  {len(sessions)} session(s) found.\n")


@integrity_group.command("export")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--output", "-o",
    default="baseline_export.json",
    show_default=True,
    type=click.Path(dir_okay=False, writable=True),
    help="Output JSON file path.",
)
def integrity_export(path: str, output: str) -> None:
    """
    Export the baseline fingerprints for PATH to a JSON file.

    \b
    Example:
        python aegis.py integrity export ./src --output backup.json
    """
    from src.core.integrity import export_baseline
    count = export_baseline(path, output)
    click.echo(click.style(
        f"  ✓ Exported {count} fingerprint records to: {output}",
        fg="green", bold=True,
    ))


# ════════════════════════════════════════════════════════════════════════════
# MODULE B — Encrypted Vault
# ════════════════════════════════════════════════════════════════════════════

@cli.group("vault")
def vault_group() -> None:
    """
    \b
    Module B: Encrypted Secret Vault
    ----------------------------------
    Store and retrieve sensitive strings encrypted at rest using Fernet
    (AES-128-CBC + HMAC-SHA256) with a PBKDF2-derived master key.
    The master password is NEVER stored.
    """


@vault_group.command("set")
@click.argument("name")
@click.option("--value",  "-v", default=None,  help="Secret value (prompted if omitted).")
@click.option("--tag",    "-t", default="",    help="Category/tag label (e.g. 'database').")
@click.option("--notes",  "-n", default="",    help="Non-sensitive note to attach.")
def vault_set(name: str, value: str, tag: str, notes: str) -> None:
    """
    Store (or update) a secret under NAME.

    \b
    Examples:
        python aegis.py vault set DB_PASSWORD
        python aegis.py vault set API_KEY --value "s3cr3t!" --tag api --notes "Prod key"
    """
    from src.core.vault import set_secret

    if value is None:
        value = click.prompt(f"  Enter value for '{name}'", hide_input=True, confirmation_prompt=True)

    password = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    set_secret(name, value, password, category=tag, notes=notes)


@vault_group.command("get")
@click.argument("name")
@click.option("--show", is_flag=True, default=False, help="Print the decrypted value to stdout.")
def vault_get(name: str, show: bool) -> None:
    """
    Retrieve and decrypt the secret stored under NAME.

    \b
    Examples:
        python aegis.py vault get DB_PASSWORD
        python aegis.py vault get DB_PASSWORD --show
    """
    from src.core.vault import get_secret

    password  = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    plaintext = get_secret(name, password)

    if plaintext is None:
        click.echo(click.style(f"  Secret '{name}' not found.", fg="red"))
        sys.exit(1)

    if show:
        click.echo(click.style(f"  {name} = {plaintext}", fg="green", bold=True))
    else:
        click.echo(click.style(f"  ✓ Secret '{name}' retrieved. Use --show to print.", fg="green"))


@vault_group.command("list")
def vault_list() -> None:
    """
    List all stored secret names (no values are revealed).

    \b
    Example:
        python aegis.py vault list
    """
    from src.core.vault import list_keys

    keys = list_keys()
    if not keys:
        click.echo(click.style("  Vault is empty.", fg="yellow"))
        return

    click.echo(click.style(
        f"\n  {'NAME':<28} {'CATEGORY':<14} {'UPDATED':<32} {'LAST ACCESSED'}",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 95)
    for name, category, created_at, updated_at, accessed_at in keys:
        acc = accessed_at or "never"
        click.echo(f"  {name:<28} {(category or ''):<14} {updated_at:<32} {acc}")
    click.echo(f"\n  {len(keys)} secret(s) stored.\n")


@vault_group.command("search")
@click.argument("pattern")
def vault_search(pattern: str) -> None:
    """
    Search secret names and categories using a regex or substring.

    \b
    Example:
        python aegis.py vault search api
        python aegis.py vault search "DB_.*"
    """
    from src.core.vault import search_secrets

    matches = search_secrets(pattern)
    if not matches:
        click.echo(click.style(f"  No secrets match '{pattern}'.", fg="yellow"))
        return

    click.echo(click.style(
        f"\n  {'NAME':<30} {'CATEGORY':<16} {'UPDATED'}",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 75)
    for name, category, updated_at in matches:
        click.echo(f"  {name:<30} {(category or ''):<16} {updated_at}")
    click.echo(f"\n  {len(matches)} match(es).\n")


@vault_group.command("rename")
@click.argument("old_name")
@click.argument("new_name")
def vault_rename(old_name: str, new_name: str) -> None:
    """
    Rename a secret without re-encrypting it.

    \b
    Example:
        python aegis.py vault rename OLD_KEY NEW_KEY
    """
    from src.core.vault import rename_secret

    renamed = rename_secret(old_name, new_name)
    if not renamed:
        click.echo(click.style(f"  Secret '{old_name}' not found.", fg="red"))
        sys.exit(1)
    click.echo(click.style(f"  ✓ Renamed '{old_name}' → '{new_name}'.", fg="green", bold=True))


@vault_group.command("audit")
@click.option(
    "--days", "-d",
    default=90, show_default=True, type=int,
    help="Flag secrets not rotated in this many days.",
)
def vault_audit(days: int) -> None:
    """
    List secrets that have NOT been updated in >= DAYS days.

    \b
    Example:
        python aegis.py vault audit --days 60
    """
    from src.core.vault import audit_secrets

    stale = audit_secrets(days)
    if not stale:
        click.echo(click.style(f"  ✓ All secrets updated within the last {days} days.", fg="green", bold=True))
        return

    click.echo(click.style(
        f"\n  ⚠  {len(stale)} stale secret(s) (not rotated in ≥{days} days):\n",
        fg="yellow", bold=True,
    ))
    click.echo(click.style(
        f"  {'NAME':<28} {'CATEGORY':<14} {'LAST UPDATED':<32} {'AGE (days)'}",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 85)
    for name, category, updated_at, age_days in stale:
        age_col = "red" if age_days > 180 else "yellow"
        click.echo(
            f"  {name:<28} {(category or ''):<14} {updated_at:<32} " +
            click.style(f"{age_days}", fg=age_col, bold=True)
        )
    click.echo("")


@vault_group.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Are you sure you want to delete this secret?")
def vault_delete(name: str) -> None:
    """
    Permanently delete the secret named NAME.

    \b
    Example:
        python aegis.py vault delete OLD_KEY
    """
    from src.core.vault import delete_secret

    deleted = delete_secret(name)
    if not deleted:
        click.echo(click.style(f"  Secret '{name}' not found.", fg="red"))
        sys.exit(1)


@vault_group.command("export")
@click.option(
    "--output", "-o",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="Path for the encrypted backup file.",
)
def vault_export(output: str) -> None:
    """
    Export all secrets to an AES-256-GCM encrypted backup file.

    You will need the same master password to import the backup.

    \b
    Example:
        python aegis.py vault export --output vault_backup.aegis
    """
    from src.core.vault import export_vault

    password = click.prompt("  Master password for export", hide_input=True, confirmation_prompt=True, prompt_suffix=" > ")
    count = export_vault(output, password)
    click.echo(click.style(f"  ✓ {count} secrets exported (AES-256-GCM) → {output}", fg="green", bold=True))


@vault_group.command("import")
@click.option(
    "--input", "-i", "input_path",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Path to the encrypted backup file.",
)
@click.option(
    "--overwrite", is_flag=True, default=False,
    help="Overwrite existing secrets with the same name.",
)
def vault_import(input_path: str, overwrite: bool) -> None:
    """
    Import secrets from an AES-256-GCM encrypted backup file.

    \b
    Example:
        python aegis.py vault import --input vault_backup.aegis
        python aegis.py vault import --input vault_backup.aegis --overwrite
    """
    from src.core.vault import import_vault

    password = click.prompt("  Master password (used during export)", hide_input=True, prompt_suffix=" > ")
    imported, skipped = import_vault(input_path, password, overwrite=overwrite)
    click.echo(click.style(
        f"  ✓ Import complete — {imported} imported, {skipped} skipped.",
        fg="green", bold=True,
    ))


# ════════════════════════════════════════════════════════════════════════════
# MODULE C — Log Analyzer
# ════════════════════════════════════════════════════════════════════════════

def _shared_log_options(fn):
    """Decorator to attach common log analysis options."""
    fn = click.option(
        "--threshold", "-t",
        default=5, show_default=True, type=int,
        help="Min failures from one source to flag as brute-force.",
    )(fn)
    fn = click.option(
        "--hours", "-H",
        default=24, show_default=True, type=int,
        help="How many hours back to analyse.",
    )(fn)
    fn = click.option(
        "--source", "-s",
        default=None,
        help="Path to a log file (auto-detected if omitted). Pass 'windows' to force wevtutil.",
    )(fn)
    fn = click.option(
        "--keywords", "-k",
        default=None,
        type=click.Path(exists=True, file_okay=True, dir_okay=False),
        help="JSON file with extra suspicious keywords (list of strings).",
    )(fn)
    return fn


@cli.group("logs")
def logs_group() -> None:
    """
    \b
    Module C: Local Log Analyzer
    ------------------------------
    Parse system logs for failed login attempts, brute-force patterns,
    suspicious process executions, and more. Fully offline.
    """


@logs_group.command("analyze")
@_shared_log_options
def logs_analyze(source: str, hours: int, threshold: int, keywords: str) -> None:
    """
    Analyze system logs and print a formatted security report with risk scoring.

    \b
    Examples:
        python aegis.py logs analyze
        python aegis.py logs analyze --hours 48 --threshold 3
        python aegis.py logs analyze --source /var/log/auth.log
        python aegis.py logs analyze --source windows --keywords custom_kw.json
    """
    from src.core.log_analyzer import analyze, print_report

    click.echo(click.style(
        f"  Analyzing logs (lookback={hours}h, bf_threshold={threshold})…",
        fg="cyan",
    ))
    report = analyze(log_source=source, lookback_hours=hours, threshold=threshold, keywords_file=keywords)
    print_report(report)


@logs_group.command("report")
@_shared_log_options
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Save report to a text file in addition to printing.",
)
def logs_report(source: str, hours: int, threshold: int, keywords: str, output: str) -> None:
    """
    Analyze logs and optionally save the report to a file.

    \b
    Example:
        python aegis.py logs report --output report.txt
    """
    from src.core.log_analyzer import analyze, print_report

    report = analyze(log_source=source, lookback_hours=hours, threshold=threshold, keywords_file=keywords)
    print_report(report)

    if output:
        click.echo(f"  Saving report to {output}…", err=True)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write("Project Aegis — Log Analysis Report\n")
            fh.write(f"Generated: {report.generated_at.isoformat()}\n")
            fh.write(f"Risk Level: {report.risk_level}\n")
            fh.write("=" * 60 + "\n\n")
            for line in report.summary_lines():
                fh.write(line + "\n")
            fh.write("\nFailed Logins:\n")
            for f in report.login_failures:
                fh.write(f"  [{f.timestamp}] user={f.username} src={f.source} [{f.ip_class.upper()}]\n")
            fh.write("\nBrute-Force Suspects:\n")
            for src, evts in report.brute_force_suspects.items():
                users = {e.username for e in evts}
                fh.write(f"  {src} — {len(evts)} attempts, users: {', '.join(users)}\n")
            fh.write("\nSuspicious Processes:\n")
            for p in report.suspicious_processes:
                fh.write(f"  [{p.timestamp}] [{p.risk}] kw='{p.matched_keyword}' cmd={p.command_line}\n")
        click.echo(click.style(f"  ✓ Report saved to {output}", fg="green"))


@logs_group.command("timeline")
@click.option("--source", "-s", default=None, help="Log source (auto-detected if omitted).")
@click.option("--hours", "-H", default=24, show_default=True, type=int, help="Lookback window in hours.")
@click.option("--keywords", "-k", default=None, type=click.Path(exists=True), help="Custom keywords JSON file.")
def logs_timeline(source: str, hours: int, keywords: str) -> None:
    """
    Print an hourly bar chart of login failure counts.

    \b
    Example:
        python aegis.py logs timeline --hours 48
    """
    from src.core.log_analyzer import analyze, print_timeline

    click.echo(click.style(f"  Building timeline (lookback={hours}h)…", fg="cyan"))
    report = analyze(log_source=source, lookback_hours=hours, keywords_file=keywords)
    print_timeline(report.login_failures, lookback_hours=hours)


@logs_group.command("history")
@click.option("--limit", "-l", default=20, show_default=True, type=int, help="Max rows to show.")
def logs_history(limit: int) -> None:
    """
    Show a trend table of past analysis runs.

    \b
    Example:
        python aegis.py logs history --limit 10
    """
    from src.core.log_analyzer import list_run_history, RISK_COLOUR

    runs = list_run_history(limit=limit)
    if not runs:
        click.echo(click.style("  No analysis history yet. Run `logs analyze` first.", fg="yellow"))
        return

    click.echo(click.style(
        f"\n  {'ID':<5} {'Run At':<35} {'Hrs':>4} {'Logins':>7} {'BF':>4} {'Procs':>6}  {'Risk':<10}  Source",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 100)
    for r in runs:
        risk_col = RISK_COLOUR.get(r["risk_level"], "white")
        src = r["source"][:35] + "…" if len(r["source"]) > 35 else r["source"]
        click.echo(
            f"  {r['id']:<5} {r['run_at']:<35} {r['lookback_hours']:>4} "
            f"{r['failed_logins']:>7} {r['bf_suspects']:>4} {r['suspicious_procs']:>6}  " +
            click.style(f"{r['risk_level']:<10}", fg=risk_col, bold=True) +
            f"  {src}"
        )
    click.echo(f"\n  {len(runs)} run(s) shown.\n")


# ════════════════════════════════════════════════════════════════════════════
# MODULE D — Network Port Scanner
# ════════════════════════════════════════════════════════════════════════════

@cli.group("scan")
def scan_group() -> None:
    """
    \b
    Module D: Local Network Port Scanner
    --------------------------------------
    TCP connect-scan localhost or RFC-1918 addresses for open ports.
    Identifies services and flags high-risk findings.
    No packets sent to public internet addresses.
    """


@scan_group.command("ports")
@click.option("--host",    "-H", default="127.0.0.1", show_default=True, help="Target host (loopback or private IP).")
@click.option("--range",   "-r", "port_range", default="1-1024", show_default=True, help="Port range, e.g. '1-1024' or '80-443'.")
@click.option("--timeout", "-t", default=0.5, show_default=True, type=float, help="Per-port connect timeout in seconds.")
@click.option("--workers", "-w", default=100, show_default=True, type=int, help="Number of parallel scan threads.")
@click.option("--all",     "-a", "show_all", is_flag=True, default=False, help="Also show closed/filtered ports.")
def scan_ports(host: str, port_range: str, timeout: float, workers: int, show_all: bool) -> None:
    """
    TCP port scan HOST within the specified port RANGE.

    \b
    Examples:
        python aegis.py scan ports
        python aegis.py scan ports --host 192.168.1.1 --range 1-65535
        python aegis.py scan ports --range 80-1024 --timeout 1.0
    """
    from src.core.netscanner import scan_ports as do_scan, print_scan_report

    try:
        start_s, end_s = port_range.split("-")
        start, end = int(start_s.strip()), int(end_s.strip())
    except (ValueError, AttributeError):
        raise click.ClickException("Invalid port range. Use format: START-END (e.g. 1-1024)")

    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise click.ClickException("Port numbers must be between 1–65535 and START ≤ END.")

    click.echo(click.style(
        f"  Scanning {host} (ports {start}–{end}, timeout={timeout}s, workers={workers})…",
        fg="cyan", bold=True,
    ))

    results = do_scan(host=host, start=start, end=end, timeout=timeout, max_workers=workers, show_closed=show_all)
    print_scan_report(results, host)


@scan_group.command("summary")
@click.option("--host", "-H", default="127.0.0.1", show_default=True, help="Target host.")
def scan_summary(host: str) -> None:
    """
    Quick top-100 port scan of HOST with risk summary only.

    \b
    Example:
        python aegis.py scan summary
        python aegis.py scan summary --host 192.168.1.10
    """
    from src.core.netscanner import scan_ports as do_scan, flag_risky_ports, print_scan_report, _WELL_KNOWN

    # Scan only the well-known ports list for speed
    top_ports = sorted(_WELL_KNOWN.keys())[:100]
    click.echo(click.style(f"  Quick scan of {len(top_ports)} known ports on {host}…", fg="cyan", bold=True))

    # We scan known ports individually
    import concurrent.futures
    from src.core.netscanner import _probe_port, PortResult
    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_probe_port, host, p, 0.5): p for p in top_ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r.port)
    print_scan_report(results, host)


# ════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()

"""
aegis.py
--------
Project Aegis — Unified CLI Entry Point (v3.0).

Usage
~~~~~
    python aegis.py --help

    # Module A — Integrity
    python aegis.py integrity scan   <path> [--exclude PATTERN]...
    python aegis.py integrity check  <path>
    python aegis.py integrity watch  <path> [--interval N] [--quiet]
    python aegis.py integrity diff   <path> [--since SCAN_ID]
    python aegis.py integrity history
    python aegis.py integrity export <path> [--output FILE]
    python aegis.py integrity import --input FILE [--overwrite]
    python aegis.py integrity verify <file>
    python aegis.py integrity sign   [--password P]
    python aegis.py integrity verify-db [--password P]

    # Module B — Vault
    python aegis.py vault set    <name> [--tag T] [--notes N] [--expires-in DAYS]
    python aegis.py vault get    <name> [--show] [--clip]
    python aegis.py vault list
    python aegis.py vault search <pattern>
    python aegis.py vault rename <old> <new>
    python aegis.py vault audit  [--days N]
    python aegis.py vault delete <name>
    python aegis.py vault export --output FILE
    python aegis.py vault import --input FILE [--overwrite]
    python aegis.py vault rekey
    python aegis.py vault totp add  <name>
    python aegis.py vault totp code <name>
    python aegis.py vault totp list

    # Module C — Logs
    python aegis.py logs analyze   [--source S] [--hours N] [--threshold N]
                                   [--keywords FILE] [--blocklist FILE]
    python aegis.py logs report    [--output FILE] ...
    python aegis.py logs timeline  [--hours N]
    python aegis.py logs history   [--limit N]
    python aegis.py logs diff      --since RUN_ID
    python aegis.py logs export    --format json|cef --output FILE
    python aegis.py logs blocklist show
    python aegis.py logs blocklist add  <ip> [--reason TEXT]
    python aegis.py logs blocklist remove <ip>

    # Module D — Scan
    python aegis.py scan ports   [--host H] [--range S-E] [--timeout N]
    python aegis.py scan summary [--host H]
    python aegis.py scan history [--host H] [--limit N]
    python aegis.py scan diff    --since SCAN_ID [--host H]
    python aegis.py scan sweep   --cidr CIDR [--port P] [--timeout N]
    python aegis.py scan export  --since SCAN_ID --output FILE

    # Module E — Hardening
    python aegis.py harden check
    python aegis.py harden score
    python aegis.py harden report [--output FILE]
"""

import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import click

from src.utils.logger import set_verbosity

BANNER = r"""
  ___  ___  __  _     ___ ___     ___  ___  _  ___
 | _ \| _ \/ / | |   | __/ __|  / _ \| __|| |/ __|
 |  _/|   / _ \| |__ | _| (_ | | (_) | _| | |\__ \
 |_|  |_|_\___/|____||___\___|  \___/|___|___|___/

         [ Offline Cybersecurity Suite v3.0 ]
         [ Air-Gapped | Zero-Trust | Python  ]
"""


def _print_banner():
    click.echo(click.style(BANNER, fg="cyan", bold=True))


# ── Root ──────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="3.0.0", prog_name="Project Aegis")
@click.option("--verbose", "-v", is_flag=True, default=False, help="DEBUG console output.")
@click.option("--quiet",   "-q", is_flag=True, default=False, help="ERROR-only console output.")
@click.pass_context
def cli(ctx, verbose, quiet):
    """
    \b
    Project Aegis — Offline Cybersecurity Suite v3.0
    ==================================================
    Modules:
      integrity  File Integrity Monitor     (Module A)
      vault      Encrypted Secret Vault     (Module B)
      logs       Local Log Analyzer         (Module C)
      scan       Network Port Scanner       (Module D)
      harden     System Hardening Checker   (Module E)
    """
    _print_banner()
    set_verbosity(verbose=verbose, quiet=quiet)


# ════════════════════════════════════════════════════════════════════════════
# MODULE A — Integrity
# ════════════════════════════════════════════════════════════════════════════

@cli.group("integrity")
def integrity_group():
    """Module A: File Integrity Monitor — SHA-256 + BLAKE2b + tamper detection."""


@integrity_group.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--exclude", "-x", multiple=True, metavar="PATTERN",
              help="Glob to exclude (repeatable). Auto-merges .aegisignore.")
def integrity_scan(path, exclude):
    """Baseline scan PATH (SHA-256 + BLAKE2b). Reads .aegisignore if present.\n\n
    \b
    Example:
        python aegis.py integrity scan ./src --exclude '__pycache__/*'"""
    from src.core.integrity import baseline_scan
    try:
        baseline_scan(path, exclude=list(exclude))
    except ValueError as exc:
        raise click.ClickException(str(exc))


@integrity_group.command("check")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def integrity_check(path):
    """Compare current state of PATH against its baseline.\n\n
    \b
    Example:
        python aegis.py integrity check ./src"""
    from src.core.integrity import check_and_report
    check_and_report(path)


@integrity_group.command("watch")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--interval", "-i", default=5, show_default=True, type=click.IntRange(1, 3600),
              help="Polling interval in seconds.")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Only print when anomalies detected.")
def integrity_watch(path, interval, quiet):
    """Continuously monitor PATH for integrity violations (Ctrl+C to stop)."""
    from src.core.integrity import watch
    watch(path, interval, quiet=quiet)


@integrity_group.command("diff")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--since", "-s", default=None, type=int, metavar="SCAN_ID",
              help="Compare against this historical scan ID.")
def integrity_diff(path, since):
    """Show changes in PATH since a previous scan.
    \b
    Example:
        python aegis.py integrity diff ./src --since 3"""
    from src.core.integrity import diff, _emit_events
    try:
        events = diff(path, since_scan_id=since)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    label = f"scan #{since}" if since else "baseline"
    if not events:
        click.echo(click.style(f"  ✓ No changes since {label}.", fg="green", bold=True))
    else:
        click.echo(click.style(f"  ⚠  {len(events)} change(s) since {label}:", fg="red", bold=True))
        _emit_events(events)


@integrity_group.command("history")
def integrity_history():
    """List all past baseline scan sessions."""
    from src.core.integrity import list_history
    sessions = list_history()
    if not sessions:
        click.echo(click.style("  No scan history. Run `integrity scan` first.", fg="yellow"))
        return
    click.echo(click.style(
        f"\n  {'ID':<5} {'Scanned At':<35} {'Files':>7} {'Skipped':>8} {'MB':>8}  Root",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 85)
    for s in sessions:
        mb = s.get("total_bytes", 0) / (1024 * 1024)
        click.echo(f"  {s['id']:<5} {s['scanned_at']:<35} {s['file_count']:>7} "
                   f"{s['skipped']:>8} {mb:>8.2f}  {s['root']}")
    click.echo(f"\n  {len(sessions)} session(s).\n")


@integrity_group.command("export")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--output", "-o", default="baseline_export.json", show_default=True,
              type=click.Path(dir_okay=False, writable=True))
def integrity_export(path, output):
    """Export baseline fingerprints for PATH to a JSON file."""
    from src.core.integrity import export_baseline
    count = export_baseline(path, output)
    click.echo(click.style(f"  ✓ {count} records exported → {output}", fg="green", bold=True))


@integrity_group.command("import")
@click.option("--input", "-i", "input_path", required=True,
              type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option("--overwrite", is_flag=True, default=False,
              help="Overwrite existing records with same path.")
def integrity_import(input_path, overwrite):
    """Restore baseline from a JSON export file.
    \b
    Example:
        python aegis.py integrity import --input baseline_export.json"""
    from src.core.integrity import import_baseline
    imp, skipped = import_baseline(input_path, overwrite=overwrite)
    click.echo(click.style(
        f"  ✓ Import complete — {imp} imported, {skipped} skipped.",
        fg="green", bold=True,
    ))


@integrity_group.command("verify")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, resolve_path=True))
def integrity_verify(file):
    """Verify a single FILE against its baseline entry.
    \b
    Example:
        python aegis.py integrity verify ./src/core/vault.py"""
    from src.core.integrity import verify_file
    result = verify_file(file)
    if result is None:
        click.echo(click.style(f"  ✓ {file} — matches baseline.", fg="green", bold=True))
    else:
        event_type, path, detail = result
        colours = {"MODIFIED": "yellow", "DELETED": "red",
                   "NOT_BASELINED": "cyan", "UNREADABLE": "red"}
        click.echo(click.style(
            f"  [{event_type}] {path}\n  {detail}",
            fg=colours.get(event_type, "white"), bold=True,
        ))


@integrity_group.command("sign")
@click.option("--password", "-p", default=None, help="Password for HMAC key derivation.")
def integrity_sign(password):
    """HMAC-sign integrity.db to detect future tampering.
    \b
    Example:
        python aegis.py integrity sign"""
    from src.utils.crypto import hmac_sign_file
    from src.utils.db import DATA_DIR
    if password is None:
        password = click.prompt("  Signing password", hide_input=True,
                                confirmation_prompt=True, prompt_suffix=" > ")
    db_path = str(DATA_DIR / "integrity.db")
    try:
        digest = hmac_sign_file(db_path, password)
        click.echo(click.style(f"  ✓ integrity.db signed. HMAC={digest[:24]}…", fg="green", bold=True))
        click.echo(click.style("  Signature stored in data/integrity.db.sig", fg="cyan"))
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc))


@integrity_group.command("verify-db")
@click.option("--password", "-p", default=None)
def integrity_verify_db(password):
    """Verify HMAC signature of integrity.db (detect if DB was tampered).
    \b
    Example:
        python aegis.py integrity verify-db"""
    from src.utils.crypto import hmac_verify_file
    from src.utils.db import DATA_DIR
    if password is None:
        password = click.prompt("  Signing password", hide_input=True, prompt_suffix=" > ")
    db_path = str(DATA_DIR / "integrity.db")
    try:
        ok = hmac_verify_file(db_path, password)
        if ok:
            click.echo(click.style("  ✓ integrity.db HMAC verified — database is intact.", fg="green", bold=True))
        else:
            click.echo(click.style("  ✗ HMAC MISMATCH — integrity.db may have been tampered!", fg="red", bold=True))
            sys.exit(1)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc))
    except ValueError as exc:
        raise click.ClickException(str(exc))


# ════════════════════════════════════════════════════════════════════════════
# MODULE B — Vault
# ════════════════════════════════════════════════════════════════════════════

@cli.group("vault")
def vault_group():
    """Module B: Encrypted Secret Vault — Fernet + AES-256-GCM + TOTP."""


@vault_group.command("set")
@click.argument("name")
@click.option("--value",      "-v", default=None)
@click.option("--tag",        "-t", default="", help="Category/tag label.")
@click.option("--notes",      "-n", default="", help="Non-sensitive note.")
@click.option("--expires-in", "-e", "expires_in", default=None, type=int,
              metavar="DAYS", help="Secret TTL in days.")
def vault_set(name, value, tag, notes, expires_in):
    """Store (or update) a secret. Shows password strength rating.
    \b
    Examples:
        python aegis.py vault set DB_PASSWORD
        python aegis.py vault set API_KEY --value "s3cr3t" --tag api --expires-in 90"""
    from src.core.vault import set_secret
    if value is None:
        value = click.prompt(f"  Value for '{name}'", hide_input=True, confirmation_prompt=True)
    password = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    set_secret(name, value, password, category=tag, notes=notes,
               expires_in_days=expires_in, show_strength=True)


@vault_group.command("get")
@click.argument("name")
@click.option("--show", is_flag=True, default=False, help="Print decrypted value.")
@click.option("--clip", is_flag=True, default=False, help="Copy to clipboard.")
def vault_get(name, show, clip):
    """Retrieve and decrypt secret NAME.
    \b
    Examples:
        python aegis.py vault get DB_PASSWORD --show
        python aegis.py vault get API_KEY --clip"""
    from src.core.vault import get_secret
    password  = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    plaintext = get_secret(name, password, clip=clip)
    if plaintext is None:
        click.echo(click.style(f"  Secret '{name}' not found.", fg="red"))
        sys.exit(1)
    if show and not clip:
        click.echo(click.style(f"  {name} = {plaintext}", fg="green", bold=True))
    elif not clip:
        click.echo(click.style(f"  ✓ Secret retrieved. Use --show to print.", fg="green"))


@vault_group.command("list")
def vault_list():
    """List all stored secret names (no values)."""
    from src.core.vault import list_keys
    keys = list_keys()
    if not keys:
        click.echo(click.style("  Vault is empty.", fg="yellow"))
        return
    click.echo(click.style(
        f"\n  {'NAME':<26} {'TAG':<12} {'UPDATED':<30} {'EXPIRES':<26} {'LAST ACCESS'}",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 105)
    for name, cat, _, updated, accessed, expires in keys:
        acc = accessed or "never"
        exp = expires or "never"
        click.echo(f"  {name:<26} {(cat or ''):<12} {updated:<30} {exp:<26} {acc}")
    click.echo(f"\n  {len(keys)} secret(s).\n")


@vault_group.command("search")
@click.argument("pattern")
def vault_search(pattern):
    """Search secret names/categories by regex or substring."""
    from src.core.vault import search_secrets
    matches = search_secrets(pattern)
    if not matches:
        click.echo(click.style(f"  No secrets match '{pattern}'.", fg="yellow"))
        return
    click.echo(click.style(f"\n  {'NAME':<30} {'TAG':<16} {'UPDATED'}", fg="cyan", bold=True))
    click.echo("  " + "─" * 72)
    for name, cat, updated in matches:
        click.echo(f"  {name:<30} {(cat or ''):<16} {updated}")
    click.echo(f"\n  {len(matches)} match(es).\n")


@vault_group.command("rename")
@click.argument("old_name")
@click.argument("new_name")
def vault_rename(old_name, new_name):
    """Rename a secret without re-encrypting it."""
    from src.core.vault import rename_secret
    if not rename_secret(old_name, new_name):
        click.echo(click.style(f"  Secret '{old_name}' not found.", fg="red"))
        sys.exit(1)
    click.echo(click.style(f"  ✓ Renamed '{old_name}' → '{new_name}'.", fg="green", bold=True))


@vault_group.command("audit")
@click.option("--days", "-d", default=90, show_default=True, type=int)
def vault_audit(days):
    """List secrets not updated in >= DAYS days (also flags expired)."""
    from src.core.vault import audit_secrets
    stale = audit_secrets(days)
    if not stale:
        click.echo(click.style(f"  ✓ All secrets rotated within {days} days.", fg="green", bold=True))
        return
    click.echo(click.style(f"\n  ⚠  {len(stale)} stale/expired secret(s):\n", fg="yellow", bold=True))
    click.echo(click.style(
        f"  {'NAME':<26} {'TAG':<12} {'LAST UPDATED':<30} {'AGE':<8} STATUS",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 85)
    for name, cat, updated, age, expired in stale:
        status = click.style("EXPIRED", fg="red", bold=True) if expired else click.style("STALE", fg="yellow")
        age_col = "red" if age > 180 else "yellow"
        click.echo(
            f"  {name:<26} {cat:<12} {updated:<30} " +
            click.style(f"{age:<8}", fg=age_col) + status
        )
    click.echo("")


@vault_group.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Permanently delete this secret?")
def vault_delete(name):
    """Permanently remove secret NAME."""
    from src.core.vault import delete_secret
    if not delete_secret(name):
        click.echo(click.style(f"  Secret '{name}' not found.", fg="red"))
        sys.exit(1)


@vault_group.command("export")
@click.option("--output", "-o", required=True, type=click.Path(dir_okay=False, writable=True))
def vault_export(output):
    """Export all secrets to an AES-256-GCM encrypted backup file."""
    from src.core.vault import export_vault
    password = click.prompt("  Export password", hide_input=True,
                            confirmation_prompt=True, prompt_suffix=" > ")
    count = export_vault(output, password)
    click.echo(click.style(f"  ✓ {count} secrets exported → {output}", fg="green", bold=True))


@vault_group.command("import")
@click.option("--input", "-i", "input_path", required=True,
              type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option("--overwrite", is_flag=True, default=False)
def vault_import(input_path, overwrite):
    """Import secrets from an AES-256-GCM encrypted backup file."""
    from src.core.vault import import_vault
    password = click.prompt("  Export password (used during export)", hide_input=True, prompt_suffix=" > ")
    imp, skipped = import_vault(input_path, password, overwrite=overwrite)
    click.echo(click.style(f"  ✓ {imp} imported, {skipped} skipped.", fg="green", bold=True))


@vault_group.command("rekey")
def vault_rekey():
    """Re-encrypt ALL secrets under a new master password."""
    from src.core.vault import rekey
    click.echo(click.style("  ⚠  This will re-encrypt all secrets. Ensure you remember the new password!", fg="yellow"))
    old_pw = click.prompt("  Current master password", hide_input=True, prompt_suffix=" > ")
    new_pw = click.prompt("  New master password",     hide_input=True,
                          confirmation_prompt=True, prompt_suffix=" > ")
    count = rekey(old_pw, new_pw)
    click.echo(click.style(f"  ✓ {count} secret(s) re-encrypted under new password.", fg="green", bold=True))


@vault_group.group("totp")
def vault_totp():
    """TOTP (2FA) seed storage and one-time code generation."""


@vault_totp.command("add")
@click.argument("name")
@click.option("--digits", default=6, show_default=True, type=click.IntRange(6, 8))
@click.option("--period", default=30, show_default=True, type=int)
def vault_totp_add(name, digits, period):
    """Store an encrypted TOTP seed under NAME.
    \b
    Example:
        python aegis.py vault totp add GITHUB_2FA"""
    from src.core.vault import totp_add
    seed = click.prompt(f"  Base32 TOTP seed for '{name}'", hide_input=True)
    password = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    totp_add(name, seed, password, digits=digits, period=period)


@vault_totp.command("code")
@click.argument("name")
def vault_totp_code(name):
    """Generate a live OTP code for NAME (decrypts seed, generates code).
    \b
    Example:
        python aegis.py vault totp code GITHUB_2FA"""
    from src.core.vault import totp_code
    password = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    code = totp_code(name, password)
    if code is None:
        click.echo(click.style(f"  TOTP entry '{name}' not found.", fg="red"))
        sys.exit(1)


@vault_totp.command("list")
def vault_totp_list():
    """List all stored TOTP entries (no seeds revealed)."""
    from src.core.vault import totp_list
    entries = totp_list()
    if not entries:
        click.echo(click.style("  No TOTP entries stored.", fg="yellow"))
        return
    click.echo(click.style(
        f"\n  {'NAME':<30} {'DIGITS':>7} {'PERIOD':>7}  CREATED",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 70)
    for name, digits, period, created in entries:
        click.echo(f"  {name:<30} {digits:>7} {period:>7}s  {created}")
    click.echo(f"\n  {len(entries)} TOTP entry(ies).\n")


# ════════════════════════════════════════════════════════════════════════════
# MODULE C — Logs
# ════════════════════════════════════════════════════════════════════════════

def _shared_log_options(fn):
    fn = click.option("--threshold", "-t", default=5, show_default=True, type=int)(fn)
    fn = click.option("--hours",     "-H", default=24, show_default=True, type=int)(fn)
    fn = click.option("--source",    "-s", default=None)(fn)
    fn = click.option("--keywords",  "-k", default=None,
                      type=click.Path(exists=True, file_okay=True, dir_okay=False))(fn)
    fn = click.option("--blocklist", "-b", default=None,
                      type=click.Path(exists=True, file_okay=True, dir_okay=False),
                      help="Newline-delimited IP blocklist file.")(fn)
    return fn


@cli.group("logs")
def logs_group():
    """Module C: Local Log Analyzer — risk scoring, correlation, SIEM export."""


@logs_group.command("analyze")
@_shared_log_options
@click.option("--burst-threshold", default=10, show_default=True, type=int,
              help="Failures within 5 min from one source to trigger a burst alert.")
def logs_analyze(source, hours, threshold, keywords, blocklist, burst_threshold):
    """Analyze system logs with risk scoring, burst/correlation detection."""
    from src.core.log_analyzer import analyze, print_report
    click.echo(click.style(f"  Analyzing (lookback={hours}h, bf≥{threshold})…", fg="cyan"))
    report = analyze(source, hours, threshold, keywords, blocklist, burst_threshold)
    print_report(report)


@logs_group.command("report")
@_shared_log_options
@click.option("--output", "-o", default=None, type=click.Path(dir_okay=False, writable=True))
@click.option("--burst-threshold", default=10, show_default=True, type=int)
def logs_report(source, hours, threshold, keywords, blocklist, output, burst_threshold):
    """Analyze logs and optionally save report to a file."""
    from src.core.log_analyzer import analyze, print_report
    report = analyze(source, hours, threshold, keywords, blocklist, burst_threshold)
    print_report(report)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write("Project Aegis — Log Analysis Report\n")
            fh.write(f"Risk Level: {report.risk_level}\n")
            fh.write("=" * 60 + "\n")
            for line in report.summary_lines():
                fh.write(line + "\n")
        click.echo(click.style(f"  ✓ Report saved → {output}", fg="green"))


@logs_group.command("timeline")
@click.option("--source",  "-s", default=None)
@click.option("--hours",   "-H", default=24, show_default=True, type=int)
@click.option("--keywords","-k", default=None, type=click.Path(exists=True))
@click.option("--blocklist","-b", default=None, type=click.Path(exists=True))
def logs_timeline(source, hours, keywords, blocklist):
    """Print an hourly bar chart of login failure counts."""
    from src.core.log_analyzer import analyze, print_timeline
    report = analyze(source, hours, keywords_file=keywords, blocklist_file=blocklist)
    print_timeline(report.login_failures, lookback_hours=hours)


@logs_group.command("history")
@click.option("--limit", "-l", default=20, show_default=True, type=int)
def logs_history(limit):
    """Show a trend table of past analysis runs."""
    from src.core.log_analyzer import list_run_history, RISK_COLOUR
    runs = list_run_history(limit=limit)
    if not runs:
        click.echo(click.style("  No history yet. Run `logs analyze` first.", fg="yellow"))
        return
    click.echo(click.style(
        f"\n  {'ID':<5} {'Run At':<35} {'Hrs':>4} {'Logins':>7} {'BF':>4} {'Procs':>6}  {'Risk':<10}  Source",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 100)
    for r in runs:
        rc  = RISK_COLOUR.get(r["risk_level"], "white")
        src = r["source"][:33] + "…" if len(r["source"]) > 33 else r["source"]
        click.echo(
            f"  {r['id']:<5} {r['run_at']:<35} {r['lookback_hours']:>4} "
            f"{r['failed_logins']:>7} {r['bf_suspects']:>4} {r['suspicious_procs']:>6}  " +
            click.style(f"{r['risk_level']:<10}", fg=rc, bold=True) + f"  {src}"
        )
    click.echo(f"\n  {len(runs)} run(s).\n")


@logs_group.command("diff")
@click.option("--since", "-s", required=True, type=int, metavar="RUN_ID")
def logs_diff(since):
    """Compare the latest run to RUN_ID (delta in failures/suspects/procs).
    \b
    Example:
        python aegis.py logs diff --since 1"""
    from src.core.log_analyzer import diff_runs, RISK_COLOUR
    try:
        d = diff_runs(since)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    click.echo(click.style(f"\n  Differential Report: Run #{d['since_id']} → Run #{d['latest_id']}\n",
        fg="cyan", bold=True))

    def _delta(val: int) -> str:
        if val > 0: return click.style(f"+{val}", fg="red",   bold=True)
        if val < 0: return click.style(f"{val}", fg="green",  bold=True)
        return click.style("  0", fg="white")

    click.echo(f"  Failed Logins  : {_delta(d['delta_failures'])}")
    click.echo(f"  BF Suspects    : {_delta(d['delta_bf'])}")
    click.echo(f"  Suspicious Prcs: {_delta(d['delta_procs'])}")
    click.echo(
        f"\n  Risk: " +
        click.style(d['risk_was'], fg=RISK_COLOUR.get(d['risk_was'], "white")) +
        " → " +
        click.style(d['risk_now'], fg=RISK_COLOUR.get(d['risk_now'], "white"), bold=True)
    )
    click.echo("")


@logs_group.command("export")
@click.option("--format",  "-f", "fmt", default="json", show_default=True,
              type=click.Choice(["json", "cef"], case_sensitive=False))
@click.option("--output",  "-o", required=True, type=click.Path(dir_okay=False, writable=True))
@click.option("--source",  "-s", default=None)
@click.option("--hours",   "-H", default=24, show_default=True, type=int)
@click.option("--blocklist","-b", default=None, type=click.Path(exists=True))
def logs_export(fmt, output, source, hours, blocklist):
    """Export analysis findings as JSON or CEF (SIEM-compatible).
    \b
    Example:
        python aegis.py logs export --format json --output events.json"""
    from src.core.log_analyzer import analyze, export_report
    report = analyze(source, hours, blocklist_file=blocklist)
    export_report(report, output, fmt=fmt)
    click.echo(click.style(f"  ✓ Report exported ({fmt.upper()}) → {output}", fg="green", bold=True))


@logs_group.group("blocklist")
def logs_blocklist():
    """Manage the persistent local IP threat-intel blocklist."""


@logs_blocklist.command("show")
def blocklist_show_cmd():
    """Show all IPs in the local blocklist."""
    from src.core.log_analyzer import blocklist_show
    entries = blocklist_show()
    if not entries:
        click.echo(click.style("  Blocklist is empty.", fg="yellow"))
        return
    click.echo(click.style(f"\n  {'IP':<20} {'ADDED AT':<35} REASON", fg="cyan", bold=True))
    click.echo("  " + "─" * 70)
    for ip, reason, added in entries:
        click.echo(f"  {ip:<20} {added:<35} {reason}")
    click.echo(f"\n  {len(entries)} IP(s).\n")


@logs_blocklist.command("add")
@click.argument("ip")
@click.option("--reason", "-r", default="", help="Optional reason text.")
def blocklist_add_cmd(ip, reason):
    """Add IP to the persistent blocklist."""
    from src.core.log_analyzer import blocklist_add
    blocklist_add(ip, reason)
    click.echo(click.style(f"  ✓ {ip} added to blocklist.", fg="green", bold=True))


@logs_blocklist.command("remove")
@click.argument("ip")
def blocklist_remove_cmd(ip):
    """Remove IP from the persistent blocklist."""
    from src.core.log_analyzer import blocklist_remove
    if blocklist_remove(ip):
        click.echo(click.style(f"  ✓ {ip} removed.", fg="yellow", bold=True))
    else:
        click.echo(click.style(f"  IP '{ip}' not found in blocklist.", fg="red"))


# ════════════════════════════════════════════════════════════════════════════
# MODULE D — Scan
# ════════════════════════════════════════════════════════════════════════════

@cli.group("scan")
def scan_group():
    """Module D: Local Network Port Scanner — banners, history, CIDR sweep."""


@scan_group.command("ports")
@click.option("--host",    "-H", default="127.0.0.1", show_default=True)
@click.option("--range",   "-r", "port_range", default="1-1024", show_default=True)
@click.option("--timeout", "-t", default=0.5, show_default=True, type=float)
@click.option("--workers", "-w", default=100, show_default=True, type=int)
@click.option("--all",     "-a", "show_all", is_flag=True, default=False,
              help="Show closed/filtered ports too.")
@click.option("--no-banner", is_flag=True, default=False, help="Skip banner grabbing.")
def scan_ports(host, port_range, timeout, workers, show_all, no_banner):
    """TCP port scan with service ID, risk flags, and banner grabbing.
    \b
    Examples:
        python aegis.py scan ports
        python aegis.py scan ports --host 192.168.1.1 --range 1-65535"""
    from src.core.netscanner import scan_ports as do_scan, print_scan_report
    try:
        start, end = (int(x.strip()) for x in port_range.split("-"))
    except ValueError:
        raise click.ClickException("Invalid range. Use: START-END (e.g. 1-1024)")
    click.echo(click.style(f"  Scanning {host}:{start}-{end}…", fg="cyan", bold=True))
    results, scan_id = do_scan(host, start, end, timeout, workers, show_all, grab_banner=not no_banner)
    print_scan_report(results, host, scan_id=scan_id)


@scan_group.command("summary")
@click.option("--host", "-H", default="127.0.0.1", show_default=True)
def scan_summary(host):
    """Quick scan of ~46 well-known ports with risk summary."""
    from src.core.netscanner import _WELL_KNOWN, _probe_port, PortResult, print_scan_report, _save_scan
    import concurrent.futures
    top_ports = sorted(_WELL_KNOWN.keys())
    click.echo(click.style(f"  Quick scan of {len(top_ports)} known ports on {host}…", fg="cyan", bold=True))
    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_probe_port, host, p, 0.5, True): p for p in top_ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r.port)
    open_results = [r for r in results if r.state == "open"]
    scan_id = _save_scan(host, min(top_ports), max(top_ports), open_results)
    print_scan_report(results, host, scan_id=scan_id)


@scan_group.command("history")
@click.option("--host",  "-H", default=None, help="Filter by host.")
@click.option("--limit", "-l", default=20, show_default=True, type=int)
def scan_history(host, limit):
    """View past scan runs, optionally filtered by host."""
    from src.core.netscanner import list_scan_history
    runs = list_scan_history(host=host, limit=limit)
    if not runs:
        click.echo(click.style("  No scan history yet.", fg="yellow"))
        return
    click.echo(click.style(
        f"\n  {'ID':<5} {'Host':<18} {'Scanned At':<35} {'Range':<14} {'Open'}",
        fg="cyan", bold=True,
    ))
    click.echo("  " + "─" * 78)
    for r in runs:
        rng = f"{r['port_start']}-{r['port_end']}"
        click.echo(f"  {r['id']:<5} {r['host']:<18} {r['scanned_at']:<35} {rng:<14} {r['open_count']}")
    click.echo(f"\n  {len(runs)} run(s).\n")


@scan_group.command("diff")
@click.option("--since", "-s", required=True, type=int, metavar="SCAN_ID")
@click.option("--host",  "-H", default="127.0.0.1", show_default=True)
@click.option("--timeout", "-t", default=0.5, type=float)
def scan_diff(since, host, timeout):
    """Compare current port state to a saved scan (detect new/closed ports).
    \b
    Example:
        python aegis.py scan diff --since 1"""
    from src.core.netscanner import diff_scans
    click.echo(click.style(f"  Comparing current state of {host} to scan #{since}…", fg="cyan", bold=True))
    try:
        d = diff_scans(host, since, timeout=timeout)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    click.echo(click.style(f"\n  Scan Diff: #{d['since_id']} → #{d['scan_id']}\n", fg="cyan", bold=True))

    if d["newly_open"]:
        click.echo(click.style(f"  🔴 Newly OPEN ({len(d['newly_open'])} ports):", fg="red", bold=True))
        for r in d["newly_open"]:
            click.echo(click.style(f"    + {r.port}/{r.service} [{r.risk}]  {r.banner[:50]}", fg="red"))

    if d["newly_closed"]:
        click.echo(click.style(f"\n  🟢 Newly CLOSED ({len(d['newly_closed'])} ports):", fg="green", bold=True))
        for p in d["newly_closed"]:
            click.echo(click.style(f"    - {p['port']}/{p['service']}", fg="green"))

    if not d["newly_open"] and not d["newly_closed"]:
        click.echo(click.style("  ✓ No port changes detected.", fg="green", bold=True))

    click.echo(f"\n  Still open: {len(d['still_open'])} ports. New scan saved as #{d['scan_id']}.\n")


@scan_group.command("sweep")
@click.option("--cidr",    "-c", required=True, help="CIDR e.g. 192.168.1.0/24")
@click.option("--port",    "-p", default=80, show_default=True, type=int,
              help="Port to probe for host discovery.")
@click.option("--timeout", "-t", default=0.3, show_default=True, type=float)
@click.option("--workers", "-w", default=200, show_default=True, type=int)
def scan_sweep(cidr, port, timeout, workers):
    """TCP-based subnet host discovery (no ICMP/ping required).
    \b
    Example:
        python aegis.py scan sweep --cidr 192.168.1.0/24 --port 22"""
    from src.core.netscanner import sweep_cidr
    live = sweep_cidr(cidr, probe_port=port, timeout=timeout, max_workers=workers)
    click.echo(click.style(
        f"\n  Found {len(live)} live host(s) in {cidr} (port {port}):\n", fg="cyan", bold=True))
    for ip in live:
        click.echo(click.style(f"    🟢 {ip}", fg="green"))
    click.echo("")


@scan_group.command("export")
@click.option("--since",  "-s", required=True, type=int, metavar="SCAN_ID")
@click.option("--output", "-o", required=True, type=click.Path(dir_okay=False, writable=True))
def scan_export(since, output):
    """Export a saved scan run to JSON.
    \b
    Example:
        python aegis.py scan export --since 1 --output scan1.json"""
    from src.core.netscanner import export_scan
    try:
        count = export_scan(since, output)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    click.echo(click.style(f"  ✓ Scan #{since} exported ({count} ports) → {output}", fg="green", bold=True))


# ════════════════════════════════════════════════════════════════════════════
# MODULE E — Hardening
# ════════════════════════════════════════════════════════════════════════════

@cli.group("harden")
def harden_group():
    """Module E: System Hardening Checker — read-only OS security inspection."""


@harden_group.command("check")
def harden_check():
    """Run all hardening checks and print PASS/FAIL/WARN/SKIP per item."""
    from src.core.hardening import run_checks, STATUS_COLOUR
    click.echo(click.style("  Running hardening checks…\n", fg="cyan", bold=True))
    report = run_checks()

    if not report.is_admin:
        click.echo(click.style(
            "  ℹ  Not running as administrator — some checks will be SKIP.\n"
            "  Tip: run PowerShell as Administrator for full results.\n",
            fg="yellow",
        ))

    for c in report.checks:
        colour    = STATUS_COLOUR.get(c.status, "white")
        indicator = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "SKIP": "-"}.get(c.status, "?")
        click.echo(
            click.style(f"  [{indicator}] ", fg=colour, bold=True) +
            click.style(f"{c.name:<32}", fg="white") +
            click.style(c.status, fg=colour, bold=True)
        )
        if c.description and c.status != "PASS":
            click.echo(f"      {c.description}")

    click.echo("")
    score_col = "green" if report.score >= 70 else "yellow" if report.score >= 45 else "red"
    click.echo(
        "  Score: " +
        click.style(f"{report.score}/100", fg=score_col, bold=True) +
        f"  (Pass={report.passed} Fail={report.failed} Warn={report.warned} Skip={report.skipped})"
    )
    click.echo("")


@harden_group.command("score")
def harden_score():
    """Print hardening score (0–100) without full check output."""
    from src.core.hardening import run_checks
    report    = run_checks()
    score_col = "green" if report.score >= 70 else "yellow" if report.score >= 45 else "red"
    click.echo(
        "\n  Hardening Score: " +
        click.style(f"{report.score}/100", fg=score_col, bold=True) +
        f"  [{report.platform}]"
        f"  Pass={report.passed} Fail={report.failed} Warn={report.warned} Skip={report.skipped}\n"
    )


@harden_group.command("report")
@click.option("--output", "-o", default=None, type=click.Path(dir_okay=False, writable=True),
              help="Save report to a text file.")
def harden_report(output):
    """Full hardening report with PASS/FAIL/WARN details and optional file export."""
    from src.core.hardening import run_checks, STATUS_COLOUR, format_report_text
    report = run_checks()

    click.echo("")
    click.echo(click.style("╔═══════════════════════════════════════╗", fg="cyan", bold=True))
    click.echo(click.style("║  PROJECT AEGIS — HARDENING REPORT     ║", fg="cyan", bold=True))
    click.echo(click.style("╚═══════════════════════════════════════╝", fg="cyan", bold=True))
    click.echo(f"  Platform : {report.platform}")
    score_col = "green" if report.score >= 70 else "yellow" if report.score >= 45 else "red"
    click.echo("  Score    : " + click.style(f"{report.score}/100", fg=score_col, bold=True))
    click.echo(f"  Pass/Fail/Warn/Skip : {report.passed}/{report.failed}/{report.warned}/{report.skipped}")
    click.echo("")

    for c in report.checks:
        colour    = STATUS_COLOUR.get(c.status, "white")
        indicator = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "SKIP": "-"}.get(c.status, "?")
        click.echo(
            click.style(f"  [{indicator}] ", fg=colour, bold=True) +
            click.style(f"{c.name:<32}", fg="white") +
            click.style(c.status, fg=colour, bold=True)
        )
        if c.description:
            click.echo(f"      {c.description}")
        if c.detail:
            click.echo(click.style(f"      → {c.detail}", fg="cyan"))
    click.echo("")

    if output:
        text = format_report_text(report)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        click.echo(click.style(f"  ✓ Report saved → {output}", fg="green", bold=True))


# ════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()

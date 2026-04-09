"""
aegis.py
--------
Project Aegis — Unified CLI Entry Point.

Usage
~~~~~
    python aegis.py --help
    python aegis.py integrity scan   <path>
    python aegis.py integrity watch  <path> [--interval N]
    python aegis.py integrity check  <path>
    python aegis.py vault set        <name>
    python aegis.py vault get        <name>
    python aegis.py vault list
    python aegis.py vault delete     <name>
    python aegis.py logs analyze     [--source PATH] [--hours N] [--threshold N]
    python aegis.py logs report      [--source PATH] [--hours N] [--threshold N]

Design principles
~~~~~~~~~~~~~~~~~
- Air-gapped: zero network calls, all logic in local modules.
- Zero-Trust: secrets are always encrypted at rest; master password never stored.
- Rotating logs written to ~/aegis_logs/aegis.log automatically.
"""

import sys
import os

# ── Ensure project root is on sys.path ──────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import click

# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ___  ___  __  _     ___ ___     ___  ___  _  ___
 | _ \| _ \/ / | |   | __/ __|  / _ \| __|| |/ __|
 |  _/|   / _ \| |__ | _| (_ | | (_) | _| | |\__ \
 |_|  |_|_\___/|____||___\___|  \___/|___|___|___/

         [ Offline Cybersecurity Suite v1.0 ]
         [ Air-Gapped | Zero-Trust | Python  ]
"""


def _print_banner() -> None:
    click.echo(click.style(BANNER, fg="cyan", bold=True))


# ── Root Command Group ───────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="Project Aegis")
def cli() -> None:
    """
    \b
    Project Aegis — Offline Cybersecurity Suite
    ============================================
    Modules:
      integrity  File Integrity Monitor  (Module A)
      vault      Encrypted Secret Vault  (Module B)
      logs       Local Log Analyzer      (Module C)

    Run `aegis <module> --help` for module-specific usage.
    """
    _print_banner()


# ════════════════════════════════════════════════════════════════════════════
# MODULE A — File Integrity
# ════════════════════════════════════════════════════════════════════════════

@cli.group("integrity")
def integrity_group() -> None:
    """
    \b
    Module A: File Integrity Monitor
    ---------------------------------
    Monitor directories using SHA-256 fingerprints stored in a local SQLite
    database.  Alerts on MODIFIED, ADDED, and DELETED files.
    """


@integrity_group.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def integrity_scan(path: str) -> None:
    """
    Perform a baseline scan of PATH and record SHA-256 fingerprints.

    \b
    Example:
        python aegis.py integrity scan ./src
        python aegis.py integrity scan C:\\Users\\you\\Documents
    """
    from src.core.integrity import baseline_scan
    try:
        baseline_scan(path)
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
    default=5,
    show_default=True,
    type=click.IntRange(1, 3600),
    help="Polling interval in seconds.",
)
def integrity_watch(path: str, interval: int) -> None:
    """
    Continuously monitor PATH, alerting on any integrity violations.

    Runs until interrupted with Ctrl+C.

    \b
    Example:
        python aegis.py integrity watch ./src --interval 10
    """
    from src.core.integrity import watch
    watch(path, interval)


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
@click.option(
    "--value", "-v",
    default=None,
    help="Secret value. If omitted, you will be prompted (hidden input).",
)
def vault_set(name: str, value: str) -> None:
    """
    Store (or update) a secret under NAME.

    \b
    Example:
        python aegis.py vault set DB_PASSWORD
        python aegis.py vault set API_KEY --value "s3cr3t!"
    """
    from src.core.vault import set_secret

    if value is None:
        value = click.prompt(f"  Enter value for '{name}'", hide_input=True, confirmation_prompt=True)

    password = click.prompt(
        "  Master password",
        hide_input=True,
        prompt_suffix=" > ",
    )
    set_secret(name, value, password)


@vault_group.command("get")
@click.argument("name")
@click.option("--show", is_flag=True, default=False, help="Print the decrypted value to stdout.")
def vault_get(name: str, show: bool) -> None:
    """
    Retrieve and decrypt the secret stored under NAME.

    \b
    Example:
        python aegis.py vault get DB_PASSWORD
        python aegis.py vault get DB_PASSWORD --show
    """
    from src.core.vault import get_secret

    password = click.prompt("  Master password", hide_input=True, prompt_suffix=" > ")
    plaintext = get_secret(name, password)

    if plaintext is None:
        click.echo(click.style(f"[VAULT] Secret '{name}' not found.", fg="red"))
        sys.exit(1)

    if show:
        click.echo(click.style(f"[VAULT] {name} = {plaintext}", fg="green", bold=True))
    else:
        # Copy to clipboard if pyperclip available, else just confirm
        click.echo(
            click.style(
                f"[VAULT] ✓ Secret '{name}' retrieved. Use --show to print it.",
                fg="green",
            )
        )


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
        click.echo(click.style("[VAULT] Vault is empty.", fg="yellow"))
        return

    click.echo(click.style(f"\n  {'NAME':<30} {'CREATED':<26} {'UPDATED'}", fg="cyan", bold=True))
    click.echo("  " + "─" * 80)
    for name, created, updated in keys:
        click.echo(f"  {name:<30} {created:<26} {updated}")
    click.echo(f"\n  {len(keys)} secret(s) stored.\n")


@vault_group.command("delete")
@click.argument("name")
@click.confirmation_option(prompt=f"Are you sure you want to delete this secret?")
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
        click.echo(click.style(f"[VAULT] Secret '{name}' not found.", fg="red"))
        sys.exit(1)


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
    return fn


@cli.group("logs")
def logs_group() -> None:
    """
    \b
    Module C: Local Log Analyzer
    ------------------------------
    Parse system logs for failed login attempts, brute-force patterns,
    and suspicious process executions. Fully offline.
    """


@logs_group.command("analyze")
@_shared_log_options
def logs_analyze(source: str, hours: int, threshold: int) -> None:
    """
    Analyze system logs and print a formatted security report.

    \b
    Examples:
        python aegis.py logs analyze
        python aegis.py logs analyze --hours 48 --threshold 3
        python aegis.py logs analyze --source /var/log/auth.log
        python aegis.py logs analyze --source windows
    """
    from src.core.log_analyzer import analyze, print_report

    click.echo(click.style(f"[AEGIS] Analyzing logs (lookback={hours}h, bf_threshold={threshold})…", fg="cyan"))
    report = analyze(log_source=source, lookback_hours=hours, threshold=threshold)
    print_report(report)


@logs_group.command("report")
@_shared_log_options
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Save report to a text file in addition to printing.",
)
def logs_report(source: str, hours: int, threshold: int, output: str) -> None:
    """
    Alias for 'analyze' with optional file output.

    \b
    Example:
        python aegis.py logs report --output report.txt
    """
    from src.core.log_analyzer import analyze, print_report
    import io
    from contextlib import redirect_stdout

    report = analyze(log_source=source, lookback_hours=hours, threshold=threshold)
    print_report(report)

    if output:
        # Capture click output (which goes to stdout) by monkey-patching temporarily
        buf = io.StringIO()
        click.echo(f"\n[AEGIS] Saving report to {output}…", err=True)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(f"Project Aegis — Log Analysis Report\n")
            fh.write(f"Generated: {report.generated_at.isoformat()}\n")
            fh.write("=" * 60 + "\n\n")
            for line in report.summary_lines():
                fh.write(line + "\n")
            fh.write("\nFailed Logins:\n")
            for f in report.login_failures:
                fh.write(f"  [{f.timestamp}] user={f.username} src={f.source}\n")
            fh.write("\nBrute-Force Suspects:\n")
            for src, evts in report.brute_force_suspects.items():
                users = {e.username for e in evts}
                fh.write(f"  {src} — {len(evts)} attempts, users: {', '.join(users)}\n")
            fh.write("\nSuspicious Processes:\n")
            for p in report.suspicious_processes:
                fh.write(f"  [{p.timestamp}] kw='{p.matched_keyword}' cmd={p.command_line}\n")
        click.echo(click.style(f"[AEGIS] Report saved to {output}", fg="green"))


# ════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()

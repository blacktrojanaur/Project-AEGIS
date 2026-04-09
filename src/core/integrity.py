"""
src/core/integrity.py
---------------------
Project Aegis — Module A: File Integrity Monitor.

Responsibilities
~~~~~~~~~~~~~~~~
- **baseline_scan(path)**  : Walk a directory, compute SHA-256 for every
  file, and store results in data/integrity.db.
- **check(path)**          : Compare current hashes against the baseline and
  report ADDED / MODIFIED / DELETED files.
- **watch(path, interval)**: Continuous polling loop that calls check()
  repeatedly and emits real-time alerts.

Database schema (integrity.db)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    fingerprints(
        path       TEXT PRIMARY KEY,
        sha256     TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        mtime      REAL NOT NULL,
        scanned_at TEXT NOT NULL        -- ISO-8601 UTC
    )
"""

import hashlib
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import click

from src.utils.db import get_connection, init_db
from src.utils.logger import get_logger

log = get_logger(__name__)

_DB = "integrity.db"
_CHUNK = 65_536  # 64 KB read chunk for large-file hashing

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    path       TEXT    PRIMARY KEY,
    sha256     TEXT    NOT NULL,
    size_bytes INTEGER NOT NULL,
    mtime      REAL    NOT NULL,
    scanned_at TEXT    NOT NULL
);
"""

# ── Internal Representation ──────────────────────────────────────────────────

class FileRecord:
    """Lightweight data class for a single file fingerprint."""
    __slots__ = ("path", "sha256", "size_bytes", "mtime", "scanned_at")

    def __init__(
        self,
        path: str,
        sha256: str,
        size_bytes: int,
        mtime: float,
        scanned_at: str,
    ) -> None:
        self.path = path
        self.sha256 = sha256
        self.size_bytes = size_bytes
        self.mtime = mtime
        self.scanned_at = scanned_at


# ── Hashing ──────────────────────────────────────────────────────────────────

def _hash_file(file_path: Path) -> Optional[str]:
    """
    Compute SHA-256 hex digest of *file_path*.

    Returns None if the file cannot be read (permissions, race condition, etc.)
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError) as exc:
        log.warning("Cannot hash %s: %s", file_path, exc)
        return None


def _walk(root: Path) -> Iterator[Path]:
    """Yield all *files* under *root* (recursive, follows symlinks=False)."""
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            yield Path(dirpath) / fname


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── DB Helpers ───────────────────────────────────────────────────────────────

def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)


def _load_baseline() -> Dict[str, FileRecord]:
    """Return the stored baseline as {path: FileRecord}."""
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT path, sha256, size_bytes, mtime, scanned_at FROM fingerprints"
        ).fetchall()
    return {
        r["path"]: FileRecord(
            r["path"], r["sha256"], r["size_bytes"], r["mtime"], r["scanned_at"]
        )
        for r in rows
    }


def _upsert(conn, record: FileRecord) -> None:
    conn.execute(
        """
        INSERT INTO fingerprints (path, sha256, size_bytes, mtime, scanned_at)
        VALUES (:path, :sha256, :size_bytes, :mtime, :scanned_at)
        ON CONFLICT(path) DO UPDATE SET
            sha256     = excluded.sha256,
            size_bytes = excluded.size_bytes,
            mtime      = excluded.mtime,
            scanned_at = excluded.scanned_at
        """,
        {
            "path": record.path,
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "mtime": record.mtime,
            "scanned_at": record.scanned_at,
        },
    )


def _delete_missing(conn, paths_to_remove: List[str]) -> None:
    conn.executemany(
        "DELETE FROM fingerprints WHERE path = ?",
        [(p,) for p in paths_to_remove],
    )


# ── Public API ───────────────────────────────────────────────────────────────

def baseline_scan(root: str) -> Tuple[int, int]:
    """
    Walk *root* and store SHA-256 fingerprints of every file.

    Existing records are updated (upserted). Files in the DB that no longer
    exist under *root* are removed from the baseline.

    Returns:
        (files_scanned, files_skipped)  — skipped means unreadable.
    """
    _ensure_db()
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Path is not a directory: {root_path}")

    log.info("Baseline scan started: %s", root_path)
    click.echo(click.style(f"[AEGIS] Scanning: {root_path}", fg="cyan", bold=True))

    scanned, skipped = 0, 0
    now = _utcnow()
    current_paths: set[str] = set()

    with get_connection(_DB) as conn:
        for file_path in _walk(root_path):
            digest = _hash_file(file_path)
            if digest is None:
                skipped += 1
                continue

            stat = file_path.stat()
            record = FileRecord(
                path=str(file_path),
                sha256=digest,
                size_bytes=stat.st_size,
                mtime=stat.st_mtime,
                scanned_at=now,
            )
            _upsert(conn, record)
            current_paths.add(str(file_path))
            scanned += 1

        # Remove stale entries that belong to this root but no longer exist
        # (only prune paths under this root to avoid clobbering other dirs)
        prefix = str(root_path)
        old_paths = [
            p for p in _load_all_paths(conn)
            if p.startswith(prefix) and p not in current_paths
        ]
        if old_paths:
            _delete_missing(conn, old_paths)
            log.info("Pruned %d stale baseline entries.", len(old_paths))

    log.info("Baseline scan complete. scanned=%d skipped=%d", scanned, skipped)
    click.echo(
        click.style(
            f"[AEGIS] Baseline complete — {scanned} files indexed, {skipped} skipped.",
            fg="green", bold=True,
        )
    )
    return scanned, skipped


def _load_all_paths(conn) -> List[str]:
    return [r[0] for r in conn.execute("SELECT path FROM fingerprints").fetchall()]


def check(root: str) -> List[Tuple[str, str, str]]:
    """
    Compare current filesystem state under *root* against stored baseline.

    Returns:
        List of (event_type, path, detail) tuples, where event_type is one of:
        "MODIFIED", "ADDED", "DELETED".
    """
    _ensure_db()
    root_path = Path(root).resolve()
    baseline = _load_baseline()
    events: List[Tuple[str, str, str]] = []

    # Restrict baseline to this root
    relevant = {
        p: r for p, r in baseline.items() if p.startswith(str(root_path))
    }
    seen: set[str] = set()

    for file_path in _walk(root_path):
        key = str(file_path)
        seen.add(key)
        digest = _hash_file(file_path)
        if digest is None:
            continue

        if key not in relevant:
            events.append(("ADDED", key, f"sha256={digest[:16]}…"))
        elif relevant[key].sha256 != digest:
            events.append((
                "MODIFIED",
                key,
                f"expected={relevant[key].sha256[:16]}… got={digest[:16]}…",
            ))

    for path in relevant:
        if path not in seen:
            events.append(("DELETED", path, "file no longer present"))

    return events


def _emit_events(events: List[Tuple[str, str, str]]) -> None:
    """Pretty-print integrity events to the terminal and the log."""
    colour_map = {
        "MODIFIED": "yellow",
        "ADDED":    "blue",
        "DELETED":  "red",
    }
    for event_type, path, detail in events:
        colour = colour_map.get(event_type, "white")
        msg = f"[{event_type}] {path} — {detail}"
        click.echo(click.style(msg, fg=colour, bold=True))
        log.warning("INTEGRITY ALERT: %s | %s | %s", event_type, path, detail)


def check_and_report(root: str) -> None:
    """Run integrity check and print results; intended for CLI use."""
    click.echo(click.style(f"[AEGIS] Checking integrity: {root}", fg="cyan", bold=True))
    events = check(root)
    if not events:
        click.echo(click.style("[AEGIS] ✓ All files match their baseline.", fg="green"))
        log.info("Integrity check passed — no changes detected for %s", root)
    else:
        click.echo(
            click.style(
                f"[AEGIS] ⚠  {len(events)} anomal{'y' if len(events) == 1 else 'ies'} detected!",
                fg="red", bold=True,
            )
        )
        _emit_events(events)


def watch(root: str, interval: int = 5) -> None:
    """
    Continuously monitor *root* for integrity violations by polling every
    *interval* seconds.

    Runs until interrupted (Ctrl+C).
    """
    click.echo(
        click.style(
            f"[AEGIS] Watch mode active — polling every {interval}s. Press Ctrl+C to stop.",
            fg="cyan", bold=True,
        )
    )
    log.info("Watch mode started: path=%s interval=%ds", root, interval)
    try:
        while True:
            events = check(root)
            if events:
                _emit_events(events)
            else:
                ts = datetime.now().strftime("%H:%M:%S")
                click.echo(
                    click.style(f"[{ts}] ✓ No changes detected.", fg="green"),
                    err=False,
                )
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo(click.style("\n[AEGIS] Watch mode stopped.", fg="yellow"))
        log.info("Watch mode stopped by user.")
        sys.exit(0)

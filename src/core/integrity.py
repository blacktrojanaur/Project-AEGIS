"""
src/core/integrity.py
---------------------
Project Aegis — Module A: File Integrity Monitor (v2.0).

Responsibilities
~~~~~~~~~~~~~~~~
- **baseline_scan(path)**  : Walk a directory, compute SHA-256 + BLAKE2b for
  every file, and store results in data/integrity.db.  Logs every scan to a
  scan_history table.
- **check(path)**          : Compare current hashes against the baseline and
  report ADDED / MODIFIED / DELETED files.
- **watch(path, interval)**: Continuous polling loop (--quiet optional).
- **diff(path, scan_id)**  : Compare filesystem against a historical scan.
- **export_baseline(path)**: Dump current baseline for *path* to JSON.
- **list_history()**       : Return all past scan sessions.

Database schema (integrity.db)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    fingerprints(
        path       TEXT PRIMARY KEY,
        sha256     TEXT NOT NULL,
        blake2b    TEXT NOT NULL,          -- NEW v2.0
        size_bytes INTEGER NOT NULL,
        mtime      REAL NOT NULL,
        scanned_at TEXT NOT NULL           -- ISO-8601 UTC
    )

    scan_history(                          -- NEW v2.0
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        root       TEXT    NOT NULL,
        scanned_at TEXT    NOT NULL,
        file_count INTEGER NOT NULL,
        skipped    INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL
    )
"""

import fnmatch
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

import click

from src.utils.db import get_connection, init_db, migrate_db
from src.utils.logger import get_logger

log = get_logger(__name__)

_DB = "integrity.db"
_CHUNK = 65_536  # 64 KB read chunk

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    path       TEXT    PRIMARY KEY,
    sha256     TEXT    NOT NULL,
    blake2b    TEXT    NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL,
    mtime      REAL    NOT NULL,
    scanned_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    root        TEXT    NOT NULL,
    scanned_at  TEXT    NOT NULL,
    file_count  INTEGER NOT NULL,
    skipped     INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL
);
"""

_MIGRATIONS = [
    "ALTER TABLE fingerprints ADD COLUMN blake2b TEXT NOT NULL DEFAULT ''",
    """CREATE TABLE IF NOT EXISTS scan_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        root        TEXT    NOT NULL,
        scanned_at  TEXT    NOT NULL,
        file_count  INTEGER NOT NULL,
        skipped     INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL
    )""",
]


# ── Internal Representation ──────────────────────────────────────────────────

class FileRecord:
    """Lightweight data class for a single file fingerprint."""
    __slots__ = ("path", "sha256", "blake2b", "size_bytes", "mtime", "scanned_at")

    def __init__(
        self,
        path: str,
        sha256: str,
        blake2b: str,
        size_bytes: int,
        mtime: float,
        scanned_at: str,
    ) -> None:
        self.path = path
        self.sha256 = sha256
        self.blake2b = blake2b
        self.size_bytes = size_bytes
        self.mtime = mtime
        self.scanned_at = scanned_at


# ── Hashing ──────────────────────────────────────────────────────────────────

def _hash_file(file_path: Path) -> Optional[Tuple[str, str]]:
    """
    Compute SHA-256 and BLAKE2b hex digests of *file_path* in one pass.

    Returns:
        (sha256_hex, blake2b_hex) or None if the file cannot be read.
    """
    sha256  = hashlib.sha256()
    blake2b = hashlib.blake2b()
    try:
        with open(file_path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                sha256.update(chunk)
                blake2b.update(chunk)
        return sha256.hexdigest(), blake2b.hexdigest()
    except (OSError, PermissionError) as exc:
        log.warning("Cannot hash %s: %s", file_path, exc)
        return None


def _walk(root: Path, exclude: Sequence[str] = ()) -> Iterator[Path]:
    """
    Yield all *files* under *root* (recursive, follows symlinks=False).

    Args:
        root:    Directory to walk.
        exclude: Sequence of glob patterns to skip (e.g. ["*.pyc", ".git/*"]).
    """
    for dirpath, dirs, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        # Filter out excluded directories in-place to avoid descending
        dirs[:] = [
            d for d in dirs
            if not any(fnmatch.fnmatch(str(rel_dir / d), pat) for pat in exclude)
        ]
        for fname in filenames:
            full = Path(dirpath) / fname
            rel  = full.relative_to(root)
            if any(fnmatch.fnmatch(str(rel), pat) for pat in exclude):
                continue
            yield full


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── DB Helpers ───────────────────────────────────────────────────────────────

def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)
    migrate_db(_DB, _MIGRATIONS)


def _load_baseline() -> Dict[str, FileRecord]:
    """Return the stored baseline as {path: FileRecord}."""
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT path, sha256, blake2b, size_bytes, mtime, scanned_at FROM fingerprints"
        ).fetchall()
    return {
        r["path"]: FileRecord(
            r["path"], r["sha256"], r["blake2b"] or "",
            r["size_bytes"], r["mtime"], r["scanned_at"],
        )
        for r in rows
    }


def _upsert(conn, record: FileRecord) -> None:
    conn.execute(
        """
        INSERT INTO fingerprints (path, sha256, blake2b, size_bytes, mtime, scanned_at)
        VALUES (:path, :sha256, :blake2b, :size_bytes, :mtime, :scanned_at)
        ON CONFLICT(path) DO UPDATE SET
            sha256     = excluded.sha256,
            blake2b    = excluded.blake2b,
            size_bytes = excluded.size_bytes,
            mtime      = excluded.mtime,
            scanned_at = excluded.scanned_at
        """,
        {
            "path":       record.path,
            "sha256":     record.sha256,
            "blake2b":    record.blake2b,
            "size_bytes": record.size_bytes,
            "mtime":      record.mtime,
            "scanned_at": record.scanned_at,
        },
    )


def _delete_missing(conn, paths_to_remove: List[str]) -> None:
    conn.executemany(
        "DELETE FROM fingerprints WHERE path = ?",
        [(p,) for p in paths_to_remove],
    )


def _load_all_paths(conn) -> List[str]:
    return [r[0] for r in conn.execute("SELECT path FROM fingerprints").fetchall()]


def _log_scan_history(conn, root: str, file_count: int, skipped: int, total_bytes: int) -> int:
    """Insert a scan_history record and return its rowid."""
    cur = conn.execute(
        """
        INSERT INTO scan_history (root, scanned_at, file_count, skipped, total_bytes)
        VALUES (?, ?, ?, ?, ?)
        """,
        (root, _utcnow(), file_count, skipped, total_bytes),
    )
    return cur.lastrowid


# ── Public API ───────────────────────────────────────────────────────────────

def baseline_scan(
    root: str,
    exclude: Sequence[str] = (),
) -> Tuple[int, int]:
    """
    Walk *root* and store SHA-256 + BLAKE2b fingerprints of every file.

    Existing records are updated (upserted). Files in the DB that no longer
    exist under *root* are removed from the baseline.

    Args:
        root:    Directory path to scan.
        exclude: Glob patterns to skip (e.g. ["*.pyc", ".git/*"]).

    Returns:
        (files_scanned, files_skipped) — skipped means unreadable.
    """
    _ensure_db()
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Path is not a directory: {root_path}")

    log.info("Baseline scan started: %s (exclude=%s)", root_path, list(exclude))
    click.echo(click.style(f"[AEGIS] Scanning: {root_path}", fg="cyan", bold=True))

    scanned, skipped, total_bytes = 0, 0, 0
    now = _utcnow()
    current_paths: set[str] = set()

    with get_connection(_DB) as conn:
        for file_path in _walk(root_path, exclude=exclude):
            result = _hash_file(file_path)
            if result is None:
                skipped += 1
                continue

            sha256_hex, blake2b_hex = result
            stat = file_path.stat()
            record = FileRecord(
                path=str(file_path),
                sha256=sha256_hex,
                blake2b=blake2b_hex,
                size_bytes=stat.st_size,
                mtime=stat.st_mtime,
                scanned_at=now,
            )
            _upsert(conn, record)
            current_paths.add(str(file_path))
            total_bytes += stat.st_size
            scanned += 1

        # Remove stale entries belonging to this root that no longer exist
        prefix = str(root_path)
        old_paths = [
            p for p in _load_all_paths(conn)
            if p.startswith(prefix) and p not in current_paths
        ]
        if old_paths:
            _delete_missing(conn, old_paths)
            log.info("Pruned %d stale baseline entries.", len(old_paths))

        scan_id = _log_scan_history(conn, str(root_path), scanned, skipped, total_bytes)

    total_mb = total_bytes / (1024 * 1024)
    log.info("Baseline scan complete. scanned=%d skipped=%d scan_id=%d", scanned, skipped, scan_id)
    click.echo(
        click.style(
            f"[AEGIS] Baseline complete — {scanned} files ({total_mb:.2f} MB) indexed, "
            f"{skipped} skipped. [Scan ID #{scan_id}]",
            fg="green", bold=True,
        )
    )
    return scanned, skipped


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

    relevant = {
        p: r for p, r in baseline.items() if p.startswith(str(root_path))
    }
    seen: set[str] = set()

    for file_path in _walk(root_path):
        key = str(file_path)
        seen.add(key)
        result = _hash_file(file_path)
        if result is None:
            continue
        sha256_hex, blake2b_hex = result

        if key not in relevant:
            events.append(("ADDED", key, f"sha256={sha256_hex[:16]}…"))
        elif relevant[key].sha256 != sha256_hex:
            events.append((
                "MODIFIED",
                key,
                f"sha256: expected={relevant[key].sha256[:16]}… got={sha256_hex[:16]}…",
            ))
        # Secondary BLAKE2b cross-check (tamper detection on hash collision)
        elif relevant[key].blake2b and relevant[key].blake2b != blake2b_hex:
            events.append((
                "MODIFIED",
                key,
                f"blake2b mismatch (sha256 matched — possible collision attack!)",
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
        click.echo(click.style("  ✓ All files match their baseline.", fg="green", bold=True))
        log.info("Integrity check passed — no changes detected for %s", root)
    else:
        click.echo(
            click.style(
                f"  ⚠  {len(events)} anomal{'y' if len(events) == 1 else 'ies'} detected!",
                fg="red", bold=True,
            )
        )
        _emit_events(events)


def watch(root: str, interval: int = 5, quiet: bool = False) -> None:
    """
    Continuously monitor *root* for integrity violations by polling every
    *interval* seconds.

    Args:
        root:     Directory path to monitor.
        interval: Polling interval in seconds.
        quiet:    If True, only print output when anomalies are detected.
    """
    click.echo(
        click.style(
            f"[AEGIS] Watch mode active — polling every {interval}s. Press Ctrl+C to stop.",
            fg="cyan", bold=True,
        )
    )
    log.info("Watch mode started: path=%s interval=%ds quiet=%s", root, interval, quiet)
    try:
        while True:
            events = check(root)
            if events:
                _emit_events(events)
            elif not quiet:
                ts = datetime.now().strftime("%H:%M:%S")
                click.echo(click.style(f"  [{ts}] ✓ No changes detected.", fg="green"))
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo(click.style("\n[AEGIS] Watch mode stopped.", fg="yellow"))
        log.info("Watch mode stopped by user.")
        sys.exit(0)


def list_history() -> List[dict]:
    """
    Return all past scan sessions from scan_history, newest first.

    Returns:
        List of dicts with keys: id, root, scanned_at, file_count, skipped, total_bytes.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT id, root, scanned_at, file_count, skipped, total_bytes "
            "FROM scan_history ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def diff(root: str, since_scan_id: Optional[int] = None) -> List[Tuple[str, str, str]]:
    """
    Show what has changed in *root* compared to either the current baseline
    (using check()) or all files recorded at a specific scan session.

    Args:
        root:          Directory to compare.
        since_scan_id: If given, compare against files scanned during that session.
                       If None, delegates to check() against current baseline.

    Returns:
        List of (event_type, path, detail) tuples.
    """
    if since_scan_id is None:
        return check(root)

    # Retrieve fingerprints as they were during the given scan session
    _ensure_db()
    with get_connection(_DB) as conn:
        # Verify scan ID exists
        session = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?", (since_scan_id,)
        ).fetchone()
        if session is None:
            raise ValueError(f"Scan ID #{since_scan_id} not found in history.")
        session_ts = session["scanned_at"]

        # Load fingerprints that existed at or before that scan time
        rows = conn.execute(
            "SELECT path, sha256, blake2b FROM fingerprints "
            "WHERE path LIKE ? AND scanned_at <= ?",
            (str(Path(root).resolve()) + "%", session_ts),
        ).fetchall()

    historical: Dict[str, Tuple[str, str]] = {
        r["path"]: (r["sha256"], r["blake2b"] or "") for r in rows
    }

    root_path = Path(root).resolve()
    events: List[Tuple[str, str, str]] = []
    seen: set[str] = set()

    for file_path in _walk(root_path):
        key = str(file_path)
        seen.add(key)
        result = _hash_file(file_path)
        if result is None:
            continue
        sha256_hex, _ = result

        if key not in historical:
            events.append(("ADDED", key, f"sha256={sha256_hex[:16]}… (new since scan #{since_scan_id})"))
        elif historical[key][0] != sha256_hex:
            events.append(("MODIFIED", key, f"changed since scan #{since_scan_id}"))

    for path in historical:
        if path not in seen:
            events.append(("DELETED", path, f"removed since scan #{since_scan_id}"))

    return events


def export_baseline(root: str, output_path: str) -> int:
    """
    Export the current baseline for *root* to a JSON file.

    Args:
        root:        Directory whose baseline to export.
        output_path: Destination JSON file path.

    Returns:
        Number of records exported.
    """
    _ensure_db()
    root_path = Path(root).resolve()
    baseline = _load_baseline()
    relevant = {
        p: r for p, r in baseline.items() if p.startswith(str(root_path))
    }

    export_data = {
        "generated_at": _utcnow(),
        "root": str(root_path),
        "record_count": len(relevant),
        "records": [
            {
                "path":       r.path,
                "sha256":     r.sha256,
                "blake2b":    r.blake2b,
                "size_bytes": r.size_bytes,
                "mtime":      r.mtime,
                "scanned_at": r.scanned_at,
            }
            for r in relevant.values()
        ],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(export_data, fh, indent=2)

    log.info("Baseline exported: %d records → %s", len(relevant), output_path)
    return len(relevant)

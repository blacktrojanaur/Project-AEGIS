"""
src/core/integrity.py
---------------------
Project Aegis — Module A: File Integrity Monitor (v3.0).

v3.0 additions
~~~~~~~~~~~~~~
- .aegisignore support  : Auto-loads exclusion patterns from scan root.
- File-type stats       : Scan summary shows top extensions by count/size.
- integrity verify      : Check a single file against its baseline entry.
- integrity import      : Restore baseline from a JSON export file.
- integrity sign        : HMAC-sign integrity.db for tamper detection.
- integrity verify-db   : Verify HMAC signature of integrity.db.

v2.0 features (retained)
~~~~~~~~~~~~~~~~~~~~~~~~
- Dual-hash: SHA-256 + BLAKE2b in one pass.
- --exclude glob patterns.
- Scan history table with session IDs.
- integrity diff / history / export commands.
- Watch mode with --quiet flag.
"""

import fnmatch
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

import click

from src.utils.db import get_connection, init_db, migrate_db
from src.utils.logger import get_logger

log = get_logger(__name__)

_DB      = "integrity.db"
_CHUNK   = 65_536

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
    __slots__ = ("path", "sha256", "blake2b", "size_bytes", "mtime", "scanned_at")

    def __init__(self, path, sha256, blake2b, size_bytes, mtime, scanned_at):
        self.path       = path
        self.sha256     = sha256
        self.blake2b    = blake2b
        self.size_bytes = size_bytes
        self.mtime      = mtime
        self.scanned_at = scanned_at


# ── Hashing ──────────────────────────────────────────────────────────────────

def _hash_file(file_path: Path) -> Optional[Tuple[str, str]]:
    """Compute (sha256_hex, blake2b_hex) in one pass. Returns None on error."""
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


# ── .aegisignore support ──────────────────────────────────────────────────────

def _load_aegisignore(root: Path) -> List[str]:
    """
    Load exclusion patterns from *root*/.aegisignore if it exists.
    Lines starting with # are comments; blank lines are skipped.
    """
    ignore_file = root / ".aegisignore"
    if not ignore_file.exists():
        return []
    patterns = []
    with open(ignore_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    if patterns:
        log.info("Loaded %d pattern(s) from .aegisignore", len(patterns))
    return patterns


# ── Directory walker with exclusion ──────────────────────────────────────────

def _walk(root: Path, exclude: Sequence[str] = ()) -> Iterator[Path]:
    """
    Yield all files under *root*, respecting *exclude* glob patterns.
    Auto-merges patterns from .aegisignore in root.
    """
    all_exc = list(exclude) + _load_aegisignore(root)
    for dirpath, dirs, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        dirs[:] = [
            d for d in dirs
            if not any(fnmatch.fnmatch(str(rel_dir / d), pat) for pat in all_exc)
        ]
        for fname in filenames:
            full = Path(dirpath) / fname
            rel  = full.relative_to(root)
            if any(fnmatch.fnmatch(str(rel), pat) for pat in all_exc):
                continue
            yield full


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── DB Helpers ───────────────────────────────────────────────────────────────

def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)
    migrate_db(_DB, _MIGRATIONS)


def _load_baseline() -> Dict[str, FileRecord]:
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


def _delete_missing(conn, paths: List[str]) -> None:
    conn.executemany("DELETE FROM fingerprints WHERE path = ?", [(p,) for p in paths])


def _load_all_paths(conn) -> List[str]:
    return [r[0] for r in conn.execute("SELECT path FROM fingerprints").fetchall()]


def _log_scan_history(conn, root, file_count, skipped, total_bytes) -> int:
    cur = conn.execute(
        "INSERT INTO scan_history (root, scanned_at, file_count, skipped, total_bytes) VALUES (?,?,?,?,?)",
        (root, _utcnow(), file_count, skipped, total_bytes),
    )
    return cur.lastrowid


# ── File-type statistics ──────────────────────────────────────────────────────

def _ext_stats(records: Dict[str, FileRecord]) -> List[Tuple[str, int, int]]:
    """
    Return list of (extension, file_count, total_bytes) sorted by count desc.
    Top 5 only.
    """
    by_ext: Dict[str, list] = defaultdict(lambda: [0, 0])
    for r in records.values():
        ext = Path(r.path).suffix.lower() or "(no ext)"
        by_ext[ext][0] += 1
        by_ext[ext][1] += r.size_bytes
    results = [(ext, cnt, sz) for ext, (cnt, sz) in by_ext.items()]
    results.sort(key=lambda x: -x[1])
    return results[:5]


# ── Public API ───────────────────────────────────────────────────────────────

def baseline_scan(root: str, exclude: Sequence[str] = ()) -> Tuple[int, int]:
    """
    Walk *root* and store SHA-256 + BLAKE2b fingerprints of every file.
    Prints file-type statistics in the summary.
    """
    _ensure_db()
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Path is not a directory: {root_path}")

    log.info("Baseline scan started: %s", root_path)
    click.echo(click.style(f"  Scanning: {root_path}", fg="cyan", bold=True))

    scanned, skipped, total_bytes = 0, 0, 0
    now = _utcnow()
    current_paths: set[str] = set()
    records_this_scan: Dict[str, FileRecord] = {}

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
            records_this_scan[str(file_path)] = record

        prefix    = str(root_path)
        old_paths = [
            p for p in _load_all_paths(conn)
            if p.startswith(prefix) and p not in current_paths
        ]
        if old_paths:
            _delete_missing(conn, old_paths)

        scan_id = _log_scan_history(conn, str(root_path), scanned, skipped, total_bytes)

    total_mb = total_bytes / (1024 * 1024)
    click.echo(click.style(
        f"  ✓ Baseline complete — {scanned} files ({total_mb:.2f} MB), "
        f"{skipped} skipped. [Scan #{scan_id}]",
        fg="green", bold=True,
    ))

    # File-type breakdown
    stats = _ext_stats(records_this_scan)
    if stats:
        click.echo(click.style("\n  Top file types:", fg="cyan"))
        for ext, cnt, sz in stats:
            click.echo(f"    {ext:<14} {cnt:>4} files  {sz/1024:.1f} KB")
        click.echo("")

    log.info("Scan complete. scanned=%d skipped=%d scan_id=%d", scanned, skipped, scan_id)
    return scanned, skipped


def check(root: str) -> List[Tuple[str, str, str]]:
    _ensure_db()
    root_path = Path(root).resolve()
    baseline  = _load_baseline()
    events:   List[Tuple[str, str, str]] = []
    relevant  = {p: r for p, r in baseline.items() if p.startswith(str(root_path))}
    seen:     set[str] = set()

    for file_path in _walk(root_path):
        key    = str(file_path)
        seen.add(key)
        result = _hash_file(file_path)
        if result is None:
            continue
        sha256_hex, blake2b_hex = result

        if key not in relevant:
            events.append(("ADDED", key, f"sha256={sha256_hex[:16]}…"))
        elif relevant[key].sha256 != sha256_hex:
            events.append(("MODIFIED", key,
                f"sha256: expected={relevant[key].sha256[:16]}… got={sha256_hex[:16]}…"))
        elif relevant[key].blake2b and relevant[key].blake2b != blake2b_hex:
            events.append(("MODIFIED", key, "blake2b mismatch (sha256 matched — possible collision)"))

    for path in relevant:
        if path not in seen:
            events.append(("DELETED", path, "file no longer present"))

    return events


def _emit_events(events: List[Tuple[str, str, str]]) -> None:
    colour_map = {"MODIFIED": "yellow", "ADDED": "blue", "DELETED": "red"}
    for event_type, path, detail in events:
        msg = f"  [{event_type}] {path} — {detail}"
        click.echo(click.style(msg, fg=colour_map.get(event_type, "white"), bold=True))
        log.warning("INTEGRITY ALERT: %s | %s | %s", event_type, path, detail)


def check_and_report(root: str) -> None:
    click.echo(click.style(f"  Checking integrity: {root}", fg="cyan", bold=True))
    events = check(root)
    if not events:
        click.echo(click.style("  ✓ All files match their baseline.", fg="green", bold=True))
        log.info("Integrity check passed for %s", root)
    else:
        click.echo(click.style(
            f"  ⚠  {len(events)} anomal{'y' if len(events)==1 else 'ies'} detected!",
            fg="red", bold=True,
        ))
        _emit_events(events)


def watch(root: str, interval: int = 5, quiet: bool = False) -> None:
    click.echo(click.style(
        f"  Watch mode — polling every {interval}s. Ctrl+C to stop.",
        fg="cyan", bold=True,
    ))
    log.info("Watch mode started: path=%s interval=%ds", root, interval)
    try:
        while True:
            events = check(root)
            if events:
                _emit_events(events)
            elif not quiet:
                ts = datetime.now().strftime("%H:%M:%S")
                click.echo(click.style(f"  [{ts}] ✓ No changes.", fg="green"))
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo(click.style("\n  Watch mode stopped.", fg="yellow"))
        log.info("Watch mode stopped by user.")
        sys.exit(0)


def list_history() -> List[dict]:
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT id, root, scanned_at, file_count, skipped, total_bytes "
            "FROM scan_history ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def diff(root: str, since_scan_id: Optional[int] = None) -> List[Tuple[str, str, str]]:
    if since_scan_id is None:
        return check(root)
    _ensure_db()
    with get_connection(_DB) as conn:
        session = conn.execute(
            "SELECT scanned_at FROM scan_history WHERE id = ?", (since_scan_id,)
        ).fetchone()
        if session is None:
            raise ValueError(f"Scan ID #{since_scan_id} not found.")
        session_ts = session["scanned_at"]
        rows = conn.execute(
            "SELECT path, sha256, blake2b FROM fingerprints "
            "WHERE path LIKE ? AND scanned_at <= ?",
            (str(Path(root).resolve()) + "%", session_ts),
        ).fetchall()

    historical: Dict[str, Tuple[str, str]] = {
        r["path"]: (r["sha256"], r["blake2b"] or "") for r in rows
    }
    root_path = Path(root).resolve()
    events:    List[Tuple[str, str, str]] = []
    seen:      set[str] = set()

    for file_path in _walk(root_path):
        key    = str(file_path)
        seen.add(key)
        result = _hash_file(file_path)
        if result is None:
            continue
        sha256_hex, _ = result
        if key not in historical:
            events.append(("ADDED", key, f"new since scan #{since_scan_id}"))
        elif historical[key][0] != sha256_hex:
            events.append(("MODIFIED", key, f"changed since scan #{since_scan_id}"))

    for path in historical:
        if path not in seen:
            events.append(("DELETED", path, f"removed since scan #{since_scan_id}"))

    return events


def export_baseline(root: str, output_path: str) -> int:
    _ensure_db()
    root_path = Path(root).resolve()
    baseline  = _load_baseline()
    relevant  = {p: r for p, r in baseline.items() if p.startswith(str(root_path))}

    data = {
        "generated_at": _utcnow(),
        "root":         str(root_path),
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
        json.dump(data, fh, indent=2)
    log.info("Baseline exported: %d records → %s", len(relevant), output_path)
    return len(relevant)


def import_baseline(input_path: str, overwrite: bool = False) -> Tuple[int, int]:
    """
    Restore baseline fingerprints from a JSON file produced by export_baseline().

    Args:
        input_path: Path to the JSON export file.
        overwrite:  If True, existing entries for the same path are updated.

    Returns:
        (imported, skipped) counts.
    """
    _ensure_db()
    with open(input_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    records = data.get("records", [])
    imported, skipped = 0, 0

    with get_connection(_DB) as conn:
        for rec in records:
            path = rec.get("path", "")
            if not path:
                skipped += 1
                continue
            existing = conn.execute(
                "SELECT path FROM fingerprints WHERE path = ?", (path,)
            ).fetchone()
            if existing and not overwrite:
                skipped += 1
                continue
            conn.execute(
                """
                INSERT INTO fingerprints (path, sha256, blake2b, size_bytes, mtime, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    sha256=excluded.sha256, blake2b=excluded.blake2b,
                    size_bytes=excluded.size_bytes, mtime=excluded.mtime,
                    scanned_at=excluded.scanned_at
                """,
                (
                    path,
                    rec.get("sha256", ""),
                    rec.get("blake2b", ""),
                    rec.get("size_bytes", 0),
                    rec.get("mtime", 0.0),
                    rec.get("scanned_at", _utcnow()),
                ),
            )
            imported += 1

    log.info("Baseline import: %d imported, %d skipped.", imported, skipped)
    return imported, skipped


def verify_file(file_path: str) -> Optional[Tuple[str, str, str]]:
    """
    Verify a single file against its baseline entry.

    Returns:
        None if the file matches its baseline.
        (event_type, path, detail) tuple if there is a mismatch or the
        file is not found in the baseline.
    """
    _ensure_db()
    abs_path = str(Path(file_path).resolve())

    with get_connection(_DB) as conn:
        row = conn.execute(
            "SELECT sha256, blake2b FROM fingerprints WHERE path = ?", (abs_path,)
        ).fetchone()

    if row is None:
        return ("NOT_BASELINED", abs_path, "File has no baseline entry — run `integrity scan` first")

    result = _hash_file(Path(abs_path))
    if result is None:
        return ("UNREADABLE", abs_path, "Cannot read file")

    sha256_hex, blake2b_hex = result
    if row["sha256"] != sha256_hex:
        return ("MODIFIED", abs_path,
            f"sha256: expected={row['sha256'][:16]}… got={sha256_hex[:16]}…")
    if row["blake2b"] and row["blake2b"] != blake2b_hex:
        return ("MODIFIED", abs_path, "blake2b mismatch despite sha256 match")

    return None

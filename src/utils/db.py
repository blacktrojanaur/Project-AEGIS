"""
src/utils/db.py
---------------
Project Aegis — SQLite connection helper.

Provides a context manager that yields a WAL-mode, row-factory enabled
connection. Each module uses its own DB file to maintain separation of
concerns.

v2.0 Addition: migrate_db() for safe, idempotent schema migrations.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List

from src.utils.logger import get_logger

log = get_logger(__name__)

# Resolve data/ directory relative to this file's package root
# (two levels up: utils/ -> src/ -> project_aegis/)
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = _BASE_DIR / "data"


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_connection(db_name: str) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for a SQLite connection.

    - WAL journal mode for concurrent read/write safety.
    - Row factory enables column-name access (row["col"]).
    - Auto-commits on clean exit; rolls back on exception.

    Usage::

        from src.utils.db import get_connection
        with get_connection("integrity.db") as conn:
            conn.execute("SELECT * FROM fingerprints")
    """
    _ensure_data_dir()
    db_path = DATA_DIR / db_name
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        log.exception("DB transaction rolled back for %s", db_name)
        raise
    finally:
        conn.close()


def init_db(db_name: str, schema_sql: str) -> None:
    """
    Initialise a database with the given DDL (idempotent — uses IF NOT EXISTS).

    Args:
        db_name:    Filename (e.g. "integrity.db") inside data/.
        schema_sql: One or more CREATE TABLE IF NOT EXISTS statements.
    """
    with get_connection(db_name) as conn:
        conn.executescript(schema_sql)
    log.debug("Database '%s' initialised.", db_name)


def migrate_db(db_name: str, migrations: List[str]) -> None:
    """
    Apply a list of SQL migration statements to *db_name*, each guarded
    so that already-applied changes are silently skipped.

    Each migration string should be a single ALTER TABLE or CREATE TABLE
    statement.  Failures due to "duplicate column" are caught and ignored;
    all other errors are re-raised.

    Args:
        db_name:    Filename inside data/ (e.g. "vault.db").
        migrations: Ordered list of DDL statements to apply.

    Example::

        migrate_db("vault.db", [
            "ALTER TABLE secrets ADD COLUMN category TEXT DEFAULT ''",
        ])
    """
    _ensure_data_dir()
    db_path = DATA_DIR / db_name
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        for stmt in migrations:
            try:
                conn.execute(stmt)
                conn.commit()
                log.debug("Migration applied to %s: %.60s…", db_name, stmt.strip())
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                # SQLite raises "duplicate column name" when column already exists
                if "duplicate column" in msg or "already exists" in msg:
                    log.debug("Migration already applied (skipping): %s", msg)
                else:
                    conn.rollback()
                    log.error("Migration failed for %s: %s", db_name, exc)
                    raise
    finally:
        conn.close()

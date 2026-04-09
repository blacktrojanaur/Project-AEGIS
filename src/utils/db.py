"""
src/utils/db.py
---------------
Project Aegis — SQLite connection helper.

Provides a context manager that yields a WAL-mode, row-factory enabled
connection. Each module uses its own DB file to maintain separation of
concerns.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

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

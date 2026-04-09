"""
src/utils/logger.py
-------------------
Project Aegis — Rotating file logger.

All modules import `get_logger(__name__)` to obtain a named logger that
writes to ~/aegis_logs/aegis.log (5 MB × 5 backups) AND echoes to stderr.
"""

import logging
import logging.handlers
import sys
from pathlib import Path

_LOG_DIR = Path.home() / "aegis_logs"
_LOG_FILE = _LOG_DIR / "aegis.log"
_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per file
_BACKUP_COUNT = 5
_FMT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FMT = "%Y-%m-%dT%H:%M:%S"

# ── internal singleton flag ──────────────────────────────────────────────────
_configured = False


def _configure_root() -> None:
    """
    One-time root logger configuration.
    Called lazily on first get_logger() invocation.
    """
    global _configured
    if _configured:
        return

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(_FMT, datefmt=_DATE_FMT)

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)

    root = logging.getLogger("aegis")
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'aegis' root namespace.

    Usage::

        from src.utils.logger import get_logger
        log = get_logger(__name__)
        log.info("Module initialised")
    """
    _configure_root()
    # Ensure the name is under the aegis namespace
    if not name.startswith("aegis"):
        name = f"aegis.{name}"
    return logging.getLogger(name)

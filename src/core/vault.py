"""
src/core/vault.py
-----------------
Project Aegis — Module B: Encrypted Secret Vault (v2.0).

Responsibilities
~~~~~~~~~~~~~~~~
- **set(name, value, password)** : Encrypt *value* under *name* using a key
  derived from *password* + a fresh per-secret salt.
- **get(name, password)**        : Retrieve and decrypt the stored secret.
  Records accessed_at timestamp.
- **list_keys()**                : Return stored key names (no plaintext).
- **delete(name)**               : Remove a secret from the vault.
- **search(pattern)**            : Regex/substring search over key names.
- **rename(old, new)**           : Rename a key without re-encrypting.
- **audit(days)**                : List secrets not updated in >= days.
- **export_vault(...)** / **import_vault(...)** : AES-256-GCM encrypted backup.

Security model
~~~~~~~~~~~~~~
- Per-secret salt: each entry uses an independent PBKDF2 derivation.
- 480,000 PBKDF2-SHA256 iterations (OWASP 2024 recommendation).
- Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256).
- Export files use AES-256-GCM (via gcm_encrypt/gcm_decrypt in crypto.py).
"""

import json
import re
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

import click

from src.utils.crypto import (
    decrypt, derive_key, encrypt, generate_salt, InvalidToken,
    gcm_encrypt, gcm_decrypt,
)
from src.utils.db import get_connection, init_db, migrate_db
from src.utils.logger import get_logger

log = get_logger(__name__)

_DB = "vault.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    name        TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    salt        BLOB NOT NULL,
    category    TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    accessed_at TEXT
);
"""

_MIGRATIONS = [
    "ALTER TABLE secrets ADD COLUMN category    TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE secrets ADD COLUMN notes       TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE secrets ADD COLUMN accessed_at TEXT",
]


def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)
    migrate_db(_DB, _MIGRATIONS)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Public API ───────────────────────────────────────────────────────────────

def set_secret(
    name: str,
    value: str,
    password: str,
    category: str = "",
    notes: str = "",
) -> None:
    """
    Encrypt *value* and store it under *name* in the vault.

    If *name* already exists the ciphertext and salt are refreshed
    (re-encrypted with a new salt; old data is overwritten).

    Args:
        name:     Logical key name (e.g. "DB_PASSWORD").
        value:    The sensitive string to store.
        password: The master password used to derive the encryption key.
        category: Optional tag/category label (e.g. "database", "api").
        notes:    Optional non-sensitive note attached to the secret.
    """
    _ensure_db()
    salt = generate_salt()
    fernet_key = derive_key(password, salt)
    ciphertext = encrypt(value, fernet_key)
    now = _utcnow()

    with get_connection(_DB) as conn:
        existing = conn.execute(
            "SELECT created_at FROM secrets WHERE name = ?", (name,)
        ).fetchone()

        created_at = existing["created_at"] if existing else now

        conn.execute(
            """
            INSERT INTO secrets (name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(name) DO UPDATE SET
                ciphertext  = excluded.ciphertext,
                salt        = excluded.salt,
                category    = excluded.category,
                notes       = excluded.notes,
                updated_at  = excluded.updated_at
            """,
            (name, ciphertext, salt, category, notes, created_at, now),
        )

    log.info("Vault: secret '%s' stored/updated (category=%s).", name, category or "none")
    click.echo(click.style(f"  ✓ Secret '{name}' stored successfully.", fg="green", bold=True))


def get_secret(name: str, password: str) -> Optional[str]:
    """
    Retrieve and decrypt the secret stored under *name*.
    Updates accessed_at timestamp on success.

    Returns:
        Decrypted plaintext string, or None if the key does not exist.

    Raises:
        click.ClickException: If the password is wrong or data is tampered.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        row = conn.execute(
            "SELECT ciphertext, salt FROM secrets WHERE name = ?", (name,)
        ).fetchone()

        if row is None:
            log.warning("Vault: secret '%s' not found.", name)
            return None

        fernet_key = derive_key(password, bytes(row["salt"]))
        try:
            plaintext = decrypt(bytes(row["ciphertext"]), fernet_key)
        except InvalidToken:
            log.error("Vault: decryption failed for '%s' — wrong password or tampered data.", name)
            raise click.ClickException(
                "Decryption failed. Wrong master password or data has been tampered with."
            )

        # Record access time
        conn.execute(
            "UPDATE secrets SET accessed_at = ? WHERE name = ?",
            (_utcnow(), name),
        )

    log.info("Vault: secret '%s' retrieved successfully.", name)
    return plaintext


def list_keys() -> List[Tuple]:
    """Return a list of (name, category, created_at, updated_at, accessed_at)."""
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, category, created_at, updated_at, accessed_at "
            "FROM secrets ORDER BY name"
        ).fetchall()
    return [(r["name"], r["category"], r["created_at"], r["updated_at"], r["accessed_at"]) for r in rows]


def delete_secret(name: str) -> bool:
    """Permanently remove the secret named *name* from the vault."""
    _ensure_db()
    with get_connection(_DB) as conn:
        cursor = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
        deleted = cursor.rowcount > 0

    if deleted:
        log.info("Vault: secret '%s' deleted.", name)
        click.echo(click.style(f"  Secret '{name}' deleted.", fg="yellow", bold=True))
    else:
        log.warning("Vault: attempted to delete non-existent secret '%s'.", name)

    return deleted


def search_secrets(pattern: str) -> List[Tuple]:
    """
    Search secret names (and categories) using a case-insensitive regex or
    plain substring.

    Returns:
        List of (name, category, updated_at) tuples for matching secrets.
    """
    _ensure_db()
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        rx = re.compile(re.escape(pattern), re.IGNORECASE)

    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, category, updated_at FROM secrets ORDER BY name"
        ).fetchall()

    return [
        (r["name"], r["category"], r["updated_at"])
        for r in rows
        if rx.search(r["name"]) or rx.search(r["category"] or "")
    ]


def rename_secret(old_name: str, new_name: str) -> bool:
    """
    Rename secret *old_name* to *new_name* without re-encrypting the value.

    Returns:
        True if renamed; False if *old_name* not found.

    Raises:
        click.ClickException: If *new_name* already exists.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        existing = conn.execute(
            "SELECT name FROM secrets WHERE name = ?", (old_name,)
        ).fetchone()
        if existing is None:
            return False

        conflict = conn.execute(
            "SELECT name FROM secrets WHERE name = ?", (new_name,)
        ).fetchone()
        if conflict is not None:
            raise click.ClickException(f"Secret '{new_name}' already exists.")

        conn.execute(
            "UPDATE secrets SET name = ?, updated_at = ? WHERE name = ?",
            (new_name, _utcnow(), old_name),
        )

    log.info("Vault: renamed '%s' → '%s'.", old_name, new_name)
    return True


def audit_secrets(days: int = 90) -> List[Tuple]:
    """
    Return secrets that have NOT been updated in >= *days* days.

    Returns:
        List of (name, category, updated_at, days_stale) tuples.
    """
    _ensure_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, category, updated_at FROM secrets ORDER BY updated_at ASC"
        ).fetchall()

    results = []
    for r in rows:
        try:
            updated = datetime.fromisoformat(r["updated_at"])
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            if updated <= cutoff:
                age_days = (datetime.now(timezone.utc) - updated).days
                results.append((r["name"], r["category"] or "", r["updated_at"], age_days))
        except (ValueError, TypeError):
            pass
    return results


def export_vault(output_path: str, password: str) -> int:
    """
    Export all secrets (encrypted) to *output_path* using AES-256-GCM.

    The ciphertexts are re-encrypted under *password* at the file level.
    The per-secret salts and ciphertexts are included so that the original
    master password is required when importing.

    Args:
        output_path: Path to write the encrypted backup file.
        password:    Master password used to encrypt the export file.

    Returns:
        Number of secrets exported.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at "
            "FROM secrets ORDER BY name"
        ).fetchall()

    secrets_list = [
        {
            "name":        r["name"],
            "ciphertext":  bytes(r["ciphertext"]).hex(),
            "salt":        bytes(r["salt"]).hex(),
            "category":    r["category"] or "",
            "notes":       r["notes"] or "",
            "created_at":  r["created_at"],
            "updated_at":  r["updated_at"],
            "accessed_at": r["accessed_at"],
        }
        for r in rows
    ]

    payload = json.dumps({
        "version":      "2.0",
        "exported_at":  _utcnow(),
        "count":        len(secrets_list),
        "secrets":      secrets_list,
    }, indent=2).encode("utf-8")

    blob = gcm_encrypt(payload, password)
    with open(output_path, "wb") as fh:
        fh.write(blob)

    log.info("Vault: exported %d secrets to %s (AES-256-GCM).", len(secrets_list), output_path)
    return len(secrets_list)


def import_vault(input_path: str, password: str, overwrite: bool = False) -> Tuple[int, int]:
    """
    Import secrets from an encrypted backup produced by export_vault().

    Args:
        input_path: Path to the encrypted backup file.
        password:   Password used during export (for GCM decryption).
        overwrite:  If True, existing secrets with the same name are overwritten.

    Returns:
        (imported, skipped) counts.
    """
    _ensure_db()
    with open(input_path, "rb") as fh:
        blob = fh.read()

    try:
        payload = gcm_decrypt(blob, password)
    except ValueError as exc:
        raise click.ClickException(f"Import failed: {exc}")

    try:
        data = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise click.ClickException(f"Import file is corrupt or wrong format: {exc}")

    imported, skipped = 0, 0
    now = _utcnow()

    with get_connection(_DB) as conn:
        for s in data.get("secrets", []):
            name = s["name"]
            existing = conn.execute(
                "SELECT name FROM secrets WHERE name = ?", (name,)
            ).fetchone()

            if existing and not overwrite:
                skipped += 1
                continue

            try:
                ciphertext = bytes.fromhex(s["ciphertext"])
                salt       = bytes.fromhex(s["salt"])
            except (ValueError, KeyError):
                log.warning("Vault import: skipping malformed entry '%s'.", name)
                skipped += 1
                continue

            conn.execute(
                """
                INSERT INTO secrets (name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    ciphertext  = excluded.ciphertext,
                    salt        = excluded.salt,
                    category    = excluded.category,
                    notes       = excluded.notes,
                    updated_at  = excluded.updated_at
                """,
                (
                    name, ciphertext, salt,
                    s.get("category", ""), s.get("notes", ""),
                    s.get("created_at", now), s.get("updated_at", now),
                    s.get("accessed_at"),
                ),
            )
            imported += 1

    log.info("Vault import: %d imported, %d skipped.", imported, skipped)
    return imported, skipped

"""
src/core/vault.py
-----------------
Project Aegis — Module B: Encrypted Secret Vault.

Responsibilities
~~~~~~~~~~~~~~~~
- **set(name, value, password)** : Encrypt *value* under *name* using a key
  derived from *password* + a fresh per-secret salt.
- **get(name, password)**        : Retrieve and decrypt the stored secret.
- **list_keys()**                : Return stored key names (no plaintext).
- **delete(name)**               : Remove a secret from the vault.

All secrets are stored encrypted at rest in data/vault.db.
The master password is NEVER stored; only the salt is persisted.

Database schema (vault.db)
~~~~~~~~~~~~~~~~~~~~~~~~~~
    secrets(
        name        TEXT PRIMARY KEY,
        ciphertext  BLOB NOT NULL,
        salt        BLOB NOT NULL,      -- 32-byte random PBKDF2 salt
        created_at  TEXT NOT NULL,      -- ISO-8601 UTC
        updated_at  TEXT NOT NULL
    )

Security model
~~~~~~~~~~~~~~
- Per-secret salt: each entry uses an independent PBKDF2 derivation, meaning
  a leaked ciphertext + salt for key A cannot help decrypt key B.
- 480,000 PBKDF2-SHA256 iterations (OWASP 2024 recommendation).
- Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256).
  Any tampering of stored ciphertext will raise InvalidToken.
"""

from datetime import datetime, timezone
from typing import List, Optional

import click

from src.utils.crypto import decrypt, derive_key, encrypt, generate_salt, InvalidToken
from src.utils.db import get_connection, init_db
from src.utils.logger import get_logger

log = get_logger(__name__)

_DB = "vault.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    name        TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    salt        BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Public API ───────────────────────────────────────────────────────────────

def set_secret(name: str, value: str, password: str) -> None:
    """
    Encrypt *value* and store it under *name* in the vault.

    If *name* already exists the ciphertext and salt are refreshed
    (re-encrypted with a new salt; old data is overwritten).

    Args:
        name:     Logical key name (e.g. "DB_PASSWORD").
        value:    The sensitive string to store.
        password: The master password used to derive the encryption key.
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
            INSERT INTO secrets (name, ciphertext, salt, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                salt       = excluded.salt,
                updated_at = excluded.updated_at
            """,
            (name, ciphertext, salt, created_at, now),
        )

    log.info("Vault: secret '%s' stored/updated.", name)
    click.echo(click.style(f"[VAULT] ✓ Secret '{name}' stored successfully.", fg="green", bold=True))


def get_secret(name: str, password: str) -> Optional[str]:
    """
    Retrieve and decrypt the secret stored under *name*.

    Args:
        name:     The key name to look up.
        password: The master password.

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

    log.info("Vault: secret '%s' retrieved successfully.", name)
    return plaintext


def list_keys() -> List[str]:
    """
    Return a list of all stored secret names (plaintext keys only; no values).
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, created_at, updated_at FROM secrets ORDER BY name"
        ).fetchall()
    return [(r["name"], r["created_at"], r["updated_at"]) for r in rows]


def delete_secret(name: str) -> bool:
    """
    Permanently remove the secret named *name* from the vault.

    Returns:
        True if the secret existed and was deleted; False if not found.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        cursor = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
        deleted = cursor.rowcount > 0

    if deleted:
        log.info("Vault: secret '%s' deleted.", name)
        click.echo(click.style(f"[VAULT] Secret '{name}' deleted.", fg="yellow", bold=True))
    else:
        log.warning("Vault: attempted to delete non-existent secret '%s'.", name)

    return deleted

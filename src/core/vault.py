"""
src/core/vault.py
-----------------
Project Aegis — Module B: Encrypted Secret Vault (v3.0).

v3.0 additions
~~~~~~~~~~~~~~
- Password strength meter (entropy-based) shown on vault set.
- --expires-in DAYS: TTL on secrets; vault audit flags expired items.
- vault get --clip: copy to clipboard (Windows clip.exe / Linux xclip).
- vault rekey: re-encrypt all secrets under a new master password atomically.
- vault totp add/code/list: RFC 6238 TOTP seed storage and live code generation.

v2.0 features (retained)
~~~~~~~~~~~~~~~~~~~~~~~~
- search, rename, audit (stale secrets), export/import (AES-256-GCM),
  category/notes/accessed_at metadata.
"""

import base64
import json
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

import click

from src.utils.crypto import (
    decrypt, derive_key, encrypt, generate_salt, InvalidToken,
    gcm_encrypt, gcm_decrypt,
    totp_generate, totp_remaining_seconds,
    password_strength,
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
    accessed_at TEXT,
    expires_at  TEXT
);

CREATE TABLE IF NOT EXISTS totp_seeds (
    name        TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    salt        BLOB NOT NULL,
    digits      INTEGER NOT NULL DEFAULT 6,
    period      INTEGER NOT NULL DEFAULT 30,
    created_at  TEXT NOT NULL
);
"""

_MIGRATIONS = [
    "ALTER TABLE secrets ADD COLUMN category    TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE secrets ADD COLUMN notes       TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE secrets ADD COLUMN accessed_at TEXT",
    "ALTER TABLE secrets ADD COLUMN expires_at  TEXT",
    """CREATE TABLE IF NOT EXISTS totp_seeds (
        name        TEXT PRIMARY KEY,
        ciphertext  BLOB NOT NULL,
        salt        BLOB NOT NULL,
        digits      INTEGER NOT NULL DEFAULT 6,
        period      INTEGER NOT NULL DEFAULT 30,
        created_at  TEXT NOT NULL
    )""",
]


def _ensure_db() -> None:
    init_db(_DB, _SCHEMA)
    migrate_db(_DB, _MIGRATIONS)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Clipboard helper ──────────────────────────────────────────────────────────

def _copy_to_clipboard(text: str) -> bool:
    """
    Copy *text* to the system clipboard.
    Returns True on success, False if no clipboard tool found.
    """
    try:
        if sys.platform == "win32":
            proc = subprocess.run(
                ["clip"], input=text.encode("utf-16-le"),
                capture_output=True, check=True
            )
            return proc.returncode == 0
        else:
            # Try xclip, then xsel
            for tool in (["xclip", "-selection", "clipboard"],
                         ["xsel", "--clipboard", "--input"]):
                try:
                    proc = subprocess.run(
                        tool, input=text.encode("utf-8"),
                        capture_output=True, check=True
                    )
                    if proc.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
    except Exception as exc:
        log.warning("Clipboard copy failed: %s", exc)
    return False


# ── Public API — Secrets ──────────────────────────────────────────────────────

def set_secret(
    name: str,
    value: str,
    password: str,
    category: str = "",
    notes: str = "",
    expires_in_days: Optional[int] = None,
    show_strength: bool = True,
) -> None:
    """Encrypt and store *value* under *name*."""
    _ensure_db()

    if show_strength:
        label, colour = password_strength(value)
        click.echo(
            "  Secret strength: " +
            click.style(label, fg=colour, bold=True)
        )

    salt       = generate_salt()
    fernet_key = derive_key(password, salt)
    ciphertext = encrypt(value, fernet_key)
    now        = _utcnow()
    expires_at = None
    if expires_in_days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()

    with get_connection(_DB) as conn:
        existing   = conn.execute(
            "SELECT created_at FROM secrets WHERE name = ?", (name,)
        ).fetchone()
        created_at = existing["created_at"] if existing else now

        conn.execute(
            """
            INSERT INTO secrets
                (name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at, expires_at)
            VALUES (?,?,?,?,?,?,?,NULL,?)
            ON CONFLICT(name) DO UPDATE SET
                ciphertext=excluded.ciphertext, salt=excluded.salt,
                category=excluded.category, notes=excluded.notes,
                updated_at=excluded.updated_at, expires_at=excluded.expires_at
            """,
            (name, ciphertext, salt, category, notes, created_at, now, expires_at),
        )

    log.info("Vault: '%s' stored (cat=%s expires=%s).", name, category or "none", expires_at or "never")
    click.echo(click.style(f"  ✓ Secret '{name}' stored.", fg="green", bold=True))
    if expires_at:
        click.echo(click.style(f"  Expires: {expires_at}", fg="yellow"))


def get_secret(name: str, password: str, clip: bool = False) -> Optional[str]:
    """Retrieved and decrypt *name*.  Optionally copies to clipboard."""
    _ensure_db()
    with get_connection(_DB) as conn:
        row = conn.execute(
            "SELECT ciphertext, salt, expires_at FROM secrets WHERE name = ?", (name,)
        ).fetchone()

        if row is None:
            log.warning("Vault: '%s' not found.", name)
            return None

        # Expiry check
        if row["expires_at"]:
            try:
                exp = datetime.fromisoformat(row["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    click.echo(click.style(
                        f"  ⚠  Secret '{name}' expired on {row['expires_at']}.",
                        fg="yellow", bold=True,
                    ))
            except (ValueError, TypeError):
                pass

        fernet_key = derive_key(password, bytes(row["salt"]))
        try:
            plaintext = decrypt(bytes(row["ciphertext"]), fernet_key)
        except InvalidToken:
            log.error("Vault: decryption failed for '%s'.", name)
            raise click.ClickException("Decryption failed. Wrong master password or tampered data.")

        conn.execute("UPDATE secrets SET accessed_at = ? WHERE name = ?", (_utcnow(), name))

    if clip:
        if _copy_to_clipboard(plaintext):
            click.echo(click.style(f"  ✓ '{name}' copied to clipboard.", fg="green"))
        else:
            click.echo(click.style(
                "  ✗ Clipboard not available. Install xclip/xsel on Linux.",
                fg="yellow",
            ))

    log.info("Vault: '%s' retrieved.", name)
    return plaintext


def list_keys() -> List[Tuple]:
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, category, created_at, updated_at, accessed_at, expires_at "
            "FROM secrets ORDER BY name"
        ).fetchall()
    return [
        (r["name"], r["category"], r["created_at"], r["updated_at"],
         r["accessed_at"], r["expires_at"])
        for r in rows
    ]


def delete_secret(name: str) -> bool:
    _ensure_db()
    with get_connection(_DB) as conn:
        cursor  = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
        deleted = cursor.rowcount > 0
    if deleted:
        log.info("Vault: '%s' deleted.", name)
        click.echo(click.style(f"  Secret '{name}' deleted.", fg="yellow", bold=True))
    return deleted


def search_secrets(pattern: str) -> List[Tuple]:
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
    _ensure_db()
    with get_connection(_DB) as conn:
        if conn.execute("SELECT name FROM secrets WHERE name = ?", (old_name,)).fetchone() is None:
            return False
        if conn.execute("SELECT name FROM secrets WHERE name = ?", (new_name,)).fetchone():
            raise click.ClickException(f"Secret '{new_name}' already exists.")
        conn.execute(
            "UPDATE secrets SET name = ?, updated_at = ? WHERE name = ?",
            (new_name, _utcnow(), old_name),
        )
    log.info("Vault: renamed '%s' → '%s'.", old_name, new_name)
    return True


def audit_secrets(days: int = 90) -> List[Tuple]:
    """Return stale (>= days old) and expired secrets."""
    _ensure_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    now    = datetime.now(timezone.utc)
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, category, updated_at, expires_at FROM secrets ORDER BY updated_at ASC"
        ).fetchall()

    results = []
    for r in rows:
        try:
            updated = datetime.fromisoformat(r["updated_at"])
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        age_days = (now - updated).days
        expired  = False
        if r["expires_at"]:
            try:
                exp = datetime.fromisoformat(r["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                expired = now > exp
            except (ValueError, TypeError):
                pass

        if updated <= cutoff or expired:
            results.append((r["name"], r["category"] or "", r["updated_at"], age_days, expired))

    return results


def rekey(old_password: str, new_password: str) -> int:
    """
    Re-encrypt every secret under *new_password* atomically.
    Decrypts each secret with *old_password*, then re-encrypts.

    Returns:
        Number of secrets re-keyed.

    Raises:
        click.ClickException: If any secret fails to decrypt (wrong old password).
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, ciphertext, salt FROM secrets"
        ).fetchall()

        rekyed = 0
        for row in rows:
            old_key = derive_key(old_password, bytes(row["salt"]))
            try:
                plaintext = decrypt(bytes(row["ciphertext"]), old_key)
            except InvalidToken:
                raise click.ClickException(
                    f"Rekey failed: wrong old password (or tampered data for '{row['name']}')."
                )
            new_salt  = generate_salt()
            new_key   = derive_key(new_password, new_salt)
            new_ct    = encrypt(plaintext, new_key)
            conn.execute(
                "UPDATE secrets SET ciphertext = ?, salt = ?, updated_at = ? WHERE name = ?",
                (new_ct, new_salt, _utcnow(), row["name"]),
            )
            rekyed += 1

    log.info("Vault rekey: %d secrets re-encrypted.", rekyed)
    return rekyed


def export_vault(output_path: str, password: str) -> int:
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at, expires_at "
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
            "expires_at":  r["expires_at"],
        }
        for r in rows
    ]
    payload = json.dumps({"version": "3.0", "exported_at": _utcnow(),
        "count": len(secrets_list), "secrets": secrets_list}, indent=2).encode()
    blob = gcm_encrypt(payload, password)
    with open(output_path, "wb") as fh:
        fh.write(blob)
    log.info("Vault: exported %d secrets → %s.", len(secrets_list), output_path)
    return len(secrets_list)


def import_vault(input_path: str, password: str, overwrite: bool = False) -> Tuple[int, int]:
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
        raise click.ClickException(f"Import file corrupt: {exc}")

    imported, skipped = 0, 0
    now = _utcnow()
    with get_connection(_DB) as conn:
        for s in data.get("secrets", []):
            name = s.get("name", "")
            if not name:
                skipped += 1
                continue
            existing = conn.execute("SELECT name FROM secrets WHERE name = ?", (name,)).fetchone()
            if existing and not overwrite:
                skipped += 1
                continue
            try:
                ct   = bytes.fromhex(s["ciphertext"])
                salt = bytes.fromhex(s["salt"])
            except (ValueError, KeyError):
                skipped += 1
                continue
            conn.execute(
                """
                INSERT INTO secrets
                    (name, ciphertext, salt, category, notes, created_at, updated_at, accessed_at, expires_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                    ciphertext=excluded.ciphertext, salt=excluded.salt,
                    category=excluded.category, notes=excluded.notes,
                    updated_at=excluded.updated_at, expires_at=excluded.expires_at
                """,
                (name, ct, salt, s.get("category",""), s.get("notes",""),
                 s.get("created_at", now), s.get("updated_at", now),
                 s.get("accessed_at"), s.get("expires_at")),
            )
            imported += 1
    log.info("Vault import: %d imported, %d skipped.", imported, skipped)
    return imported, skipped


# ── Public API — TOTP ─────────────────────────────────────────────────────────

def totp_add(name: str, seed_b32: str, password: str,
             digits: int = 6, period: int = 30) -> None:
    """
    Store an encrypted TOTP seed under *name*.

    Args:
        name:     Identifier (e.g. "GITHUB_2FA").
        seed_b32: Base32-encoded TOTP seed (as shown in QR code / backup key).
        password: Master password for encryption.
        digits:   OTP length (default 6).
        period:   Time step in seconds (default 30).
    """
    _ensure_db()
    # Normalise base32 (strip spaces, uppercase)
    seed_b32_clean = seed_b32.replace(" ", "").upper()
    try:
        seed_bytes = base64.b32decode(seed_b32_clean, casefold=True)
    except Exception as exc:
        raise click.ClickException(f"Invalid base32 seed: {exc}")

    salt       = generate_salt()
    fernet_key = derive_key(password, salt)
    ciphertext = encrypt(seed_b32_clean, fernet_key)
    now        = _utcnow()

    with get_connection(_DB) as conn:
        conn.execute(
            """
            INSERT INTO totp_seeds (name, ciphertext, salt, digits, period, created_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                ciphertext=excluded.ciphertext, salt=excluded.salt,
                digits=excluded.digits, period=excluded.period
            """,
            (name, ciphertext, salt, digits, period, now),
        )
    log.info("TOTP seed '%s' stored.", name)
    click.echo(click.style(f"  ✓ TOTP seed '{name}' stored (digits={digits}, period={period}s).",
        fg="green", bold=True))


def totp_code(name: str, password: str) -> Optional[str]:
    """
    Decrypt the TOTP seed for *name* and return the current OTP code.

    Returns:
        Current OTP code string, or None if *name* not found.
    """
    _ensure_db()
    with get_connection(_DB) as conn:
        row = conn.execute(
            "SELECT ciphertext, salt, digits, period FROM totp_seeds WHERE name = ?", (name,)
        ).fetchone()

    if row is None:
        return None

    fernet_key = derive_key(password, bytes(row["salt"]))
    try:
        seed_b32 = decrypt(bytes(row["ciphertext"]), fernet_key)
    except InvalidToken:
        raise click.ClickException("Decryption failed. Wrong master password.")

    try:
        seed_bytes = base64.b32decode(seed_b32.replace(" ", "").upper(), casefold=True)
    except Exception as exc:
        raise click.ClickException(f"Stored seed is corrupt: {exc}")

    code      = totp_generate(seed_bytes, digits=row["digits"], period=row["period"])
    remaining = totp_remaining_seconds(row["period"])
    click.echo(
        click.style(f"\n  {name} — OTP: ", fg="cyan") +
        click.style(code, fg="green", bold=True) +
        click.style(f"  (expires in {remaining}s)\n", fg="yellow")
    )
    return code


def totp_list() -> List[Tuple]:
    """Return list of (name, digits, period, created_at)."""
    _ensure_db()
    with get_connection(_DB) as conn:
        rows = conn.execute(
            "SELECT name, digits, period, created_at FROM totp_seeds ORDER BY name"
        ).fetchall()
    return [(r["name"], r["digits"], r["period"], r["created_at"]) for r in rows]

"""
src/utils/crypto.py
-------------------
Project Aegis — PBKDF2 + Fernet key derivation & AES-256-GCM file encryption.

v2.0 additions:
  - hash_string() for consistent text hashing across modules.
  - gcm_encrypt() / gcm_decrypt() — AES-256-GCM for vault export files
    (stronger than Fernet's AES-128-CBC for bulk data encryption).
    Uses only stdlib-compatible primitives from `cryptography.hazmat`.

All cryptographic primitives use the `cryptography` library only.
No external network calls; fully offline.
"""

import os
import base64
import struct

from cryptography.hazmat.primitives import hashes, hmac as hazmat_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet, InvalidToken

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── PBKDF2 parameters — NIST SP 800-132 compliant ───────────────────────────
_SALT_BYTES  = 32          # 256-bit salt
_ITERATIONS  = 480_000     # OWASP 2024 recommendation for SHA-256
_KEY_LENGTH  = 32          # 256-bit key → 32 bytes → 44-char base64url

# ── AES-256-GCM parameters ───────────────────────────────────────────────────
_GCM_NONCE_BYTES = 12      # 96-bit nonce (NIST recommended)
_GCM_KEY_BYTES   = 32      # 256-bit key


def generate_salt() -> bytes:
    """Return a cryptographically random 32-byte salt."""
    return os.urandom(_SALT_BYTES)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from *password* using PBKDF2-HMAC-SHA256.

    The derived key is returned as a URL-safe base64-encoded bytes object
    suitable for direct use with :class:`cryptography.fernet.Fernet`.

    Args:
        password: The master password (plain text).
        salt:     A 32-byte random salt.  Use :func:`generate_salt` to create.

    Returns:
        URL-safe base64-encoded 32-byte key (44 bytes total).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt(plaintext: str, fernet_key: bytes) -> bytes:
    """
    Encrypt *plaintext* with the given Fernet key.

    Args:
        plaintext:   The secret string to encrypt.
        fernet_key:  A URL-safe base64-encoded 32-byte key.

    Returns:
        Fernet token (opaque encrypted bytes).
    """
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt(token: bytes, fernet_key: bytes) -> str:
    """
    Decrypt a Fernet *token* with the given key.

    Args:
        token:      Fernet ciphertext bytes.
        fernet_key: The key used during encryption.

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the key is wrong or token is tampered.
    """
    f = Fernet(fernet_key)
    return f.decrypt(token).decode("utf-8")


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Return a hex-digest hash of *text*.

    Args:
        text:      The string to hash.
        algorithm: "sha256" (default) or "blake2b".

    Returns:
        Lowercase hex string digest.
    """
    import hashlib
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


# ── AES-256-GCM (for vault export files) ────────────────────────────────────

def gcm_derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a raw 32-byte AES-256-GCM key from *password* using PBKDF2.
    Unlike derive_key(), this returns raw bytes (not base64) for use with AESGCM.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_GCM_KEY_BYTES,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def gcm_encrypt(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt *plaintext* bytes with AES-256-GCM derived from *password*.

    Wire format: [salt (32 bytes)] [nonce (12 bytes)] [ciphertext + 16-byte tag]

    Args:
        plaintext: Raw bytes to encrypt (e.g. JSON-encoded vault export).
        password:  Master password string.

    Returns:
        Opaque bytes blob suitable for writing to a file.
    """
    salt  = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_GCM_NONCE_BYTES)
    key   = gcm_derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def gcm_decrypt(blob: bytes, password: str) -> bytes:
    """
    Decrypt a blob produced by :func:`gcm_encrypt`.

    Args:
        blob:     Bytes from file (salt + nonce + ciphertext).
        password: Master password string.

    Returns:
        Decrypted raw bytes.

    Raises:
        ValueError: If the blob is too short or decryption fails (wrong password / tampered).
    """
    min_len = _SALT_BYTES + _GCM_NONCE_BYTES + 16  # 16 = GCM auth tag
    if len(blob) < min_len:
        raise ValueError("Encrypted blob is too short — file may be corrupt.")
    salt      = blob[:_SALT_BYTES]
    nonce     = blob[_SALT_BYTES:_SALT_BYTES + _GCM_NONCE_BYTES]
    ciphertext = blob[_SALT_BYTES + _GCM_NONCE_BYTES:]
    key = gcm_derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(f"GCM decryption failed: {exc}") from exc


__all__ = [
    "generate_salt", "derive_key", "encrypt", "decrypt", "InvalidToken",
    "hash_string",
    "gcm_encrypt", "gcm_decrypt",
]

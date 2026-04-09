"""
src/utils/crypto.py
-------------------
Project Aegis — PBKDF2 + Fernet key derivation.

All cryptographic primitives use the `cryptography` library only.
No external network calls; fully offline.
"""

import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

from src.utils.logger import get_logger

log = get_logger(__name__)

# PBKDF2 parameters — NIST SP 800-132 compliant
_SALT_BYTES = 32          # 256-bit salt
_ITERATIONS = 480_000     # per OWASP 2024 recommendation for SHA-256
_KEY_LENGTH = 32          # 256-bit key → 32 bytes → 44-char base64url


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


__all__ = ["generate_salt", "derive_key", "encrypt", "decrypt", "InvalidToken"]

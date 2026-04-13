"""
src/utils/crypto.py
-------------------
Project Aegis — PBKDF2 + Fernet + AES-256-GCM + TOTP + HMAC file signing.

v3.0 additions:
  - totp_generate(seed_bytes, digits, period) — RFC 6238 TOTP, stdlib only.
  - hmac_sign_file(path, password)  — Write a .sig sidecar for a file.
  - hmac_verify_file(path, password) — Verify the sidecar; raise on mismatch.

All cryptographic primitives use the `cryptography` library or stdlib only.
No external network calls; fully offline.
"""

import base64
import hashlib
import hmac as _hmac
import os
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet, InvalidToken

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── PBKDF2 parameters ────────────────────────────────────────────────────────
_SALT_BYTES  = 32
_ITERATIONS  = 480_000     # OWASP 2024
_KEY_LENGTH  = 32

# ── AES-256-GCM ──────────────────────────────────────────────────────────────
_GCM_NONCE_BYTES = 12
_GCM_KEY_BYTES   = 32


# ── Core KDF ─────────────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Return a cryptographically random 32-byte salt."""
    return os.urandom(_SALT_BYTES)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-ready key from *password* using PBKDF2-HMAC-SHA256.
    Returns URL-safe base64-encoded bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


# ── Fernet (per-secret vault) ────────────────────────────────────────────────

def encrypt(plaintext: str, fernet_key: bytes) -> bytes:
    """Encrypt *plaintext* with the given Fernet key."""
    return Fernet(fernet_key).encrypt(plaintext.encode("utf-8"))


def decrypt(token: bytes, fernet_key: bytes) -> str:
    """Decrypt a Fernet *token*. Raises InvalidToken on failure."""
    return Fernet(fernet_key).decrypt(token).decode("utf-8")


# ── AES-256-GCM (vault export files) ─────────────────────────────────────────

def gcm_derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_GCM_KEY_BYTES,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def gcm_encrypt(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt *plaintext* bytes with AES-256-GCM.
    Wire format: [salt 32B] [nonce 12B] [ciphertext + 16B tag]
    """
    salt  = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_GCM_NONCE_BYTES)
    key   = gcm_derive_key(password, salt)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def gcm_decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt a blob produced by gcm_encrypt()."""
    min_len = _SALT_BYTES + _GCM_NONCE_BYTES + 16
    if len(blob) < min_len:
        raise ValueError("Encrypted blob is too short — file may be corrupt.")
    salt      = blob[:_SALT_BYTES]
    nonce     = blob[_SALT_BYTES:_SALT_BYTES + _GCM_NONCE_BYTES]
    ct        = blob[_SALT_BYTES + _GCM_NONCE_BYTES:]
    key       = gcm_derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise ValueError(f"GCM decryption failed: {exc}") from exc


# ── Misc helpers ──────────────────────────────────────────────────────────────

def hash_string(text: str, algorithm: str = "sha256") -> str:
    """Return a hex-digest hash of *text*."""
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


# ── TOTP — RFC 6238 (stdlib only) ────────────────────────────────────────────

def totp_generate(
    seed_bytes: bytes,
    digits: int = 6,
    period: int = 30,
    at_time: float | None = None,
) -> str:
    """
    Generate an RFC 6238 TOTP code from raw *seed_bytes*.

    Args:
        seed_bytes: The raw (decoded) TOTP seed bytes.
        digits:     Code length (default 6).
        period:     Time step in seconds (default 30).
        at_time:    Unix timestamp to use; defaults to time.time().

    Returns:
        Zero-padded string of *digits* length (e.g. "012345").
    """
    t = int((at_time if at_time is not None else time.time()) / period)
    msg = struct.pack(">Q", t)                        # 8-byte big-endian counter
    mac = _hmac.new(seed_bytes, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code   = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_remaining_seconds(period: int = 30) -> int:
    """Return seconds remaining in the current TOTP window."""
    return period - (int(time.time()) % period)


# ── HMAC file signing (DB integrity protection) ───────────────────────────────

_HMAC_SALT_BYTES = 32
_HMAC_ITER       = 200_000   # lighter than vault KDF; sign/verify is frequent


def _derive_hmac_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte HMAC key from *password* + *salt*."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_HMAC_ITER,
    )
    return kdf.derive(password.encode("utf-8"))


def hmac_sign_file(file_path: str, password: str) -> str:
    """
    Compute HMAC-SHA256 over *file_path* contents and write a sidecar
    ``<file_path>.sig`` containing: [salt 32B] [hmac 32B].

    Args:
        file_path: Path to the file to sign (e.g. "data/integrity.db").
        password:  Password from which the HMAC key is derived.

    Returns:
        Hex string of the HMAC digest.
    """
    from pathlib import Path
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    salt = os.urandom(_HMAC_SALT_BYTES)
    key  = _derive_hmac_key(password, salt)

    mac = _hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as fh:
        while chunk := fh.read(65_536):
            mac.update(chunk)
    digest = mac.digest()

    sig_path = Path(str(path) + ".sig")
    sig_path.write_bytes(salt + digest)
    log.info("HMAC signature written: %s", sig_path)
    return digest.hex()


def hmac_verify_file(file_path: str, password: str) -> bool:
    """
    Verify *file_path* against its sidecar ``<file_path>.sig``.

    Returns:
        True if the file matches the signature.

    Raises:
        FileNotFoundError: If the file or sidecar is missing.
        ValueError:        If the sidecar is malformed.
    """
    from pathlib import Path
    path     = Path(file_path)
    sig_path = Path(str(path) + ".sig")

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    sig_data = sig_path.read_bytes()
    if len(sig_data) < _HMAC_SALT_BYTES + 32:
        raise ValueError("Signature file is malformed.")

    salt           = sig_data[:_HMAC_SALT_BYTES]
    stored_digest  = sig_data[_HMAC_SALT_BYTES:]
    key            = _derive_hmac_key(password, salt)

    mac = _hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as fh:
        while chunk := fh.read(65_536):
            mac.update(chunk)

    return _hmac.compare_digest(mac.digest(), stored_digest)


# ── Password strength rating ──────────────────────────────────────────────────

def password_strength(value: str) -> tuple[str, str]:
    """
    Rate the strength of *value* as a secret.

    Returns:
        (label, colour) where label is WEAK / FAIR / GOOD / STRONG
        and colour is a click fg colour string.
    """
    import math
    charset = 0
    if any(c.islower() for c in value): charset += 26
    if any(c.isupper() for c in value): charset += 26
    if any(c.isdigit() for c in value): charset += 10
    if any(not c.isalnum() for c in value): charset += 32

    entropy = len(value) * math.log2(charset) if charset else 0

    if entropy < 28:
        return "WEAK",   "red"
    if entropy < 50:
        return "FAIR",   "yellow"
    if entropy < 70:
        return "GOOD",   "cyan"
    return "STRONG", "green"


__all__ = [
    "generate_salt", "derive_key", "encrypt", "decrypt", "InvalidToken",
    "hash_string",
    "gcm_encrypt", "gcm_decrypt",
    "totp_generate", "totp_remaining_seconds",
    "hmac_sign_file", "hmac_verify_file",
    "password_strength",
]

# Project Aegis 🛡️

**Offline Cybersecurity Suite — Air-Gapped | Zero-Trust | Python 3.10+**

Project Aegis is a modular, locally-run cybersecurity toolkit designed for
air-gapped and high-security environments.  
**Zero external API calls. All sensitive data encrypted at rest.**

---

## Modules

| Module | Command Group | Description |
|--------|--------------|-------------|
| A — File Integrity Monitor | `integrity` | SHA-256 fingerprinting with SQLite baseline; alerts on MODIFIED / ADDED / DELETED files |
| B — Encrypted Vault        | `vault`     | Fernet + PBKDF2 secret manager; master password never stored |
| C — Local Log Analyzer     | `logs`      | Windows Event Log / Linux syslog parser with brute-force detection |

---

## File Structure

```
project_aegis/
├── aegis.py                  # Unified CLI entry point
├── requirements.txt          # 2 non-stdlib deps: click, cryptography
├── README.md
│
├── src/
│   ├── core/
│   │   ├── integrity.py      # Module A
│   │   ├── vault.py          # Module B
│   │   └── log_analyzer.py   # Module C
│   └── utils/
│       ├── logger.py         # Rotating file logger → ~/aegis_logs/
│       ├── db.py             # SQLite context manager (WAL mode)
│       └── crypto.py         # PBKDF2-HMAC-SHA256 + Fernet helpers
│
└── data/
    ├── integrity.db          # File fingerprint baseline (auto-created)
    └── vault.db              # Encrypted secrets (auto-created)
```

---

## Installation

### Online (standard)

```bash
pip install -r requirements.txt
```

### Offline (air-gapped)

On an internet-connected machine:
```bash
pip download -r requirements.txt -d ./wheels
```

Transfer the `wheels/` folder to the air-gapped machine, then:
```bash
pip install --no-index --find-links=./wheels -r requirements.txt
```

---

## Quick Start

```bash
# Show help
python aegis.py --help

# ── Module A: File Integrity ──────────────────────────────────────
# Create baseline fingerprints of a directory
python aegis.py integrity scan ./src

# Check for changes
python aegis.py integrity check ./src

# Continuously watch a directory (5-second polling)
python aegis.py integrity watch ./src --interval 5

# ── Module B: Encrypted Vault ─────────────────────────────────────
# Store a secret (will prompt for value + master password)
python aegis.py vault set DB_PASSWORD

# Retrieve a secret
python aegis.py vault get DB_PASSWORD --show

# List all stored key names
python aegis.py vault list

# Delete a secret
python aegis.py vault delete OLD_KEY

# ── Module C: Log Analyzer ────────────────────────────────────────
# Analyze system logs (auto-detects Windows Event Log or syslog)
python aegis.py logs analyze

# Analyze with custom lookback window and brute-force threshold
python aegis.py logs analyze --hours 48 --threshold 3

# Analyze a specific log file
python aegis.py logs analyze --source /var/log/auth.log

# Save report to file
python aegis.py logs report --output security_report.txt
```

---

## Security Architecture

### Module B — Vault Key Derivation

```
master_password  +  per_secret_salt (32 bytes, random)
        │
        ▼
  PBKDF2-HMAC-SHA256
  (480,000 iterations)
        │
        ▼
  32-byte raw key
        │
        ▼
  base64url → Fernet key
        │
        ▼
  Fernet.encrypt(plaintext)   →   ciphertext stored in vault.db
```

- **The master password is never stored.**  
- Each secret uses an independent salt → compromise of one entry cannot help decrypt another.  
- Fernet provides AES-128-CBC + HMAC-SHA256 (authenticated encryption).

### Module A — Integrity DB

All fingerprints stored in `data/integrity.db` (SQLite, WAL mode).  
The database itself is not encrypted — it stores only hashes, not file content.  
If you want the baseline to be tamper-evident, store `integrity.db` on read-only media.

---

## Logging

All activity is written to `~/aegis_logs/aegis.log`:

- **Rotating**: 5 MB per file, 5 backups retained.
- **Format**: `TIMESTAMP | LEVEL | MODULE | MESSAGE`
- `WARNING` and above are also echoed to stderr.

---

## Requirements

- Python 3.10+
- `click >= 8.1.7`
- `cryptography >= 42.0.5`
- Windows: `wevtutil` must be in PATH (built-in on all modern Windows)
- Linux/macOS: read access to `/var/log/auth.log`, `/var/log/secure`, or `/var/log/syslog`

---

## Zero-Trust Checklist

- [x] No internet access required at runtime
- [x] No cloud/API calls of any kind
- [x] Secrets encrypted at rest with authenticated encryption
- [x] Master password never persisted (memory only)
- [x] Per-secret salts prevent cross-entry key reuse
- [x] Rotating logs with configurable retention
- [x] SQLite WAL mode prevents corruption under concurrent access

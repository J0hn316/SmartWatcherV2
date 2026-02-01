# Smart Watcher – SQLite Audit & Integrity Tool

Smart Watcher is a Python-based file monitoring and integrity verification tool.
It records filesystem activity into a SQLite audit log and can later verify file
integrity using cryptographic hashes (SHA-256).

This project was built as a **Tier 3 learning project**, focusing on:

- real-world architecture
- database-backed auditing
- concurrency safety
- CLI design
- security concepts (integrity verification)

---

## 🚀 Features

- Event-driven file watching (create / modify / move / delete)
- Persistent SQLite audit trail
- Thread-safe database writes
- Noise reduction via ignore patterns
- Debounced “modified” events
- Optional SHA-256 hashing
- Integrity verification (`verify` command)
- Searchable audit log
- JSON export for verification reports
- Quiet runtime, inspectable on demand

---

## 🧠 How It Works (High Level)

```
Filesystem Events
       ↓
Watchdog Observer (threaded)
       ↓
AuditEventHandler
  - ignore patterns
  - debounce logic
  - optional hashing
       ↓
AuditLogger
  - thread-safe SQLite writes
       ↓
SQLite Database
```

Verification (`verify`) works by:

1. Reading the latest recorded hash per file
2. Computing the current hash
3. Comparing results
4. Reporting OK / CHANGED / MISSING / UNHASHED

---

## 📂 Project Structure

```
smart_watcher_sqlite/
├── watcher/
│   ├── main.py        # CLI entry point
│   ├── watcher.py     # Observer lifecycle
│   └── handlers.py    # Event → audit logic
│
├── db/
│   ├── database.py    # SQLite connection + setup
│   └── audit_logger.py
│
├── data/              # SQLite database (gitignored)
├── tests/
└── README.md
```

---

## 🛠 Requirements

- Python 3.10+
- SQLite (bundled with Python)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### Create and activate a virtual environment

**Windows (Git Bash / Bash in VS Code)**

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install watchdog

```

---

## ▶️ Usage

### Watch a folder (quiet by default)

```bash
python -m watcher.main watch --folder watch_test --recursive
```

### Watch with hashing enabled

```bash
python -m watcher.main watch --folder watch_test --recursive --hash
```

### Tail recent audit events

```bash
python -m watcher.main tail --limit 20
```

### Tail with hashes shown

```bash
python -m watcher.main tail --limit 20 --show-hash
```

### Search audit events

```bash
python -m watcher.main search --type deleted
python -m watcher.main search --contains ".txt"
python -m watcher.main search --since "2026-01-31T08:00:00"
```

### Verify file integrity

```bash
python -m watcher.main verify --folder watch_test
```

### Verify and export JSON report

```bash
python -m watcher.main verify --folder watch_test --json reports/verify.json
```

---

## 🔍 Verify Output States

| Status   | Meaning                                   |
| -------- | ----------------------------------------- |
| OK       | File hash matches recorded value          |
| CHANGED  | File contents differ from last known hash |
| MISSING  | File no longer exists                     |
| UNHASHED | File exists but could not be hashed       |

---

## 🔐 Security Notes

- SHA-256 hashing is optional (`--hash`) due to performance cost
- Hashing runs in the watcher thread (acceptable for local tooling)
- This tool detects **changes**, not _who_ made them
- Integrity verification assumes trusted baseline data

---

## 🧪 Design Highlights

- Thread-safe SQLite access (`check_same_thread=False` + locks)
- ISO-8601 UTC timestamps (safe lexical ordering)
- Config-driven CLI structure
- Clear separation of concerns:
  - handler = relevance logic
  - logger = persistence
  - CLI = orchestration

---

## 📌 Why SQLite?

- No server required
- ACID compliant
- Reliable for local tools
- Perfect for audit trails

---

## 📜 License

MIT License

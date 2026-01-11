# Smart Watcher (SQLite Audit Trail)

A Python-based file monitoring tool that records a full audit trail of file system events into a local SQLite database.

This project is designed as a **Tier 3 learning project**, focusing on:

- Clean architecture
- Database-backed auditing
- Real-world automation patterns
- Security-minded design

---

## 🚀 Features

- Monitors a target folder for file events
- Records file activity to SQLite
- Creates a persistent audit trail
- No external database server required
- Designed for extensibility (hashing, alerts, integrity checks)

---

## 🧠 Why SQLite?

SQLite is:

- Serverless
- Reliable
- ACID-compliant
- Perfect for local automation tools

The database lives as a single `.db` file, making this project easy to run, test, and deploy.

---

---

## 🛠 Requirements

- Python 3.10+
- SQLite (bundled with Python)

Optional:

- DB Browser for SQLite (for inspection)
- VS Code SQLite extensions

---

## ▶️ Usage (Coming Soon)

```bash
python -m watcher.main --folder ./watch --apply
```

from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path("data") / "watcher_audit.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Create a SQLite connection with sensible defaults.
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)

    # Gives access columns by name
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON;")

    # safer concurrency
    conn.execute("PRAGMA journal_mode = WAL;")

    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """
    Initialize the database schema (safe to run multiple times).
    """

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema_sql)
    conn.commit()

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    event_time: str
    event_type: str
    src_path: str | None = None
    dest_path: str | None = None
    file_size_bytes: int | None = None
    sha256: str | None = None
    extra: dict[str, Any] | None = None


class AuditLogger:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.Lock()

    def log(
        self,
        *,
        event_type: str,
        src_path: Path | str | None = None,
        dest_path: Path | str | None = None,
        file_size_bytes: int | None = None,
        sha256: str | None = None,
        extra: dict[str, Any] | None = None,
        event_time: str | None = None,
    ) -> int:
        """
        Insert an audit event row.
        Returns the inserted row id.
        """

        src_str = str(src_path) if src_path is not None else None
        dest_str = str(dest_path) if dest_path is not None else None
        extra_json = (
            json.dumps(extra, ensure_ascii=False) if extra is not None else None
        )
        time_str = event_time or utc_now_iso()

        with self._lock:
            cur = self._conn.execute(
                """
            INSERT INTO audit_events (
            event_time, event_type, src_path, dest_path,
            file_size_bytes, sha256, extra_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    time_str,
                    event_type,
                    src_str,
                    dest_str,
                    file_size_bytes,
                    sha256,
                    extra_json,
                ),
            )
        self._conn.commit()
        return int(cur.lastrowid)

    def latest(self, limit: int = 10) -> list[sqlite3.Row]:
        """
        Fetch latest audit events (most recent first).
        """
        with self._lock:
            cur = self._conn.execute(
                """
            SELECT id, event_time, event_type, src_path, dest_path, file_size_bytes, sha256, extra_json
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
                (limit,),
            )
        return list(cur.fetchall())

    def search(
        self,
        *,
        event_type: str | None = None,
        contains: str | None = None,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        """
        Search audit events with optional filters:
        - event_type: exact match (e.g., 'deleted', 'moved')
        - contains: substring match against src_path OR dest_path
        Returns most recent first.
        """

        where_clauses: list[str] = []
        params: list[Any] = []

        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type)

        if contains:
            # Search in src_path and dest_path
            like = f"%{contains}%"
            where_clauses.append("(src_path LIKE ? OR dest_path LIKE ?)")
            params.extend([like, like])

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        sql = f"""
            SELECT id, event_time, event_type, src_path, dest_path, file_size_bytes, sha256, extra_json
            FROM audit_events
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(limit)

        with self._lock:
            cur = self._conn.execute(sql, params)
            return list(cur.fetchall())

    def latest_hashes(self) -> dict[str, str]:
        """
        Return a mapping of file path -> latest recorded sha256.
        Only includes rows where sha256 is not NULL.
        """

        sql = """
        SELECT src_path, sha256
        FROM audit_events
        WHERE sha256 IS NOT NULL
        ORDER BY id DESC
        """

        results: dict[str, str] = {}

        with self._lock:
            cur = self._conn.execute(sql)
            for row in cur.fetchall():
                path = row["src_path"]
                if path and path not in results:
                    results[path] = row["sha256"]

        return results

from __future__ import annotations

import json
import sqlite3
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

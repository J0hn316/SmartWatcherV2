from __future__ import annotations

from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from db.audit_logger import AuditLogger


def safe_file_size(path: Path) -> int | None:
    """
    Try to read a file size. Returns None if the file doesn't exist
    (common for deleted events or transient changes).
    """
    try:
        if path.is_file():
            return path.stat().st_size
        return None
    except OSError:
        return None


class AuditEventHandler(FileSystemEventHandler):
    """
    Watchdog callback handler that logs filesystem events to SQLite.
    """

    def __init__(self, logger: AuditLogger, *, include_dirs: bool = False) -> None:
        self._logger = logger
        self._include_dirs = include_dirs

    def _should_log(self, is_directory: bool) -> bool:
        return self._include_dirs or (not is_directory)

    def on_created(self, event: FileCreatedEvent) -> None:
        if not self._should_log(event.is_directory):
            return

        src = Path(event.src_path)
        self._logger.log(
            event_type="created",
            src_path=src,
            file_size_bytes=safe_file_size(src),
            extra={"is_directory": event.is_directory},
        )

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not self._should_log(event.is_directory):
            return

        src = Path(event.src_path)
        self._logger.log(
            event_type="modified",
            src_path=src,
            file_size_bytes=safe_file_size(src),
            extra={"is_directory": event.is_directory},
        )

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if not self._should_log(event.is_directory):
            return

        src = Path(event.src_path)
        self._logger.log(
            event_type="deleted",
            src_path=src,
            extra={"is_directory": event.is_directory},
        )

    def on_moved(self, event: FileMovedEvent) -> None:
        if not self._should_log(event.is_directory):
            return

        src = Path(event.src_path)
        dest = Path(event.dest_path)
        self._logger.log(
            event_type="moved",
            src_path=src,
            dest_path=dest,
            file_size_bytes=safe_file_size(dest),
            extra={"is_directory": event.is_directory},
        )

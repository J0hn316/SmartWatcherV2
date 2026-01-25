from __future__ import annotations

import time
import fnmatch
from typing import Any
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from db.audit_logger import AuditLogger

DEFAULT_IGNORE_PATTERNS: tuple[str, ...] = (
    # OS / metadata
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    # Editor / temp / swap
    "*.tmp",
    "*.temp",
    "*.swp",
    "*.swo",
    "*~",
    "~$*",
    # Download partials
    "*.crdownload",
    "*.part",
    # Common lock files
    "*.lock",
)


def should_ignore(path: Path, patterns: list[str]) -> bool:
    """
    Returns True if `path` matches any ignore pattern.
    Matches against both the filename and the full path.
    """

    name = path.name
    full = str(path)

    # On Windows, paths can differ in case; normalize for matching
    name_lower = name.lower()
    full_lower = full.lower()

    for pattern in patterns:
        pattern_lower = pattern.lower()
        if fnmatch.fnmatch(name_lower, pattern_lower) or fnmatch.fnmatch(
            full_lower, pattern_lower
        ):
            return True
    return False


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

    def __init__(
        self,
        logger: AuditLogger,
        *,
        include_dirs: bool = False,
        ignore_patterns: list[str] | None = None,
        modified_debounce_seconds: float = 1.0,
    ) -> None:
        self._logger = logger
        self._include_dirs = include_dirs

        self._ignore_patterns = list(DEFAULT_IGNORE_PATTERNS)
        if ignore_patterns:
            self._ignore_patterns.extend(ignore_patterns)

        self._modified_debounce_seconds = modified_debounce_seconds
        self._last_modified_logged_at: dict[str, float] = {}

    def _should_log(self, is_directory: bool) -> bool:
        return self._include_dirs or (not is_directory)

    def _should_log_modified(self, path: Path) -> bool:
        """
        Debounce modified events per path.
        Returns True if enough time has passed since the last logged modified event.
        """

        key = str(path)
        now = time.monotonic()

        last = self._last_modified_logged_at.get(key)
        if last is not None and (now - last) < self._modified_debounce_seconds:
            return False

        self._last_modified_logged_at[key] = now
        return True

    def _should_ignore_path(self, path: Path) -> bool:
        return should_ignore(path, self._ignore_patterns)

    def on_created(self, event: FileCreatedEvent) -> None:
        if not self._should_log(event.is_directory):
            return

        src = Path(event.src_path)
        if self._should_ignore_path(src):
            return

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
        if self._should_ignore_path(src):
            return

        if not self._should_log_modified(src):
            return

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
        if self._should_ignore_path(src):
            return

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

        if self._should_ignore_path(src) or self._should_ignore_path(dest):
            return

        self._logger.log(
            event_type="moved",
            src_path=src,
            dest_path=dest,
            file_size_bytes=safe_file_size(dest),
            extra={"is_directory": event.is_directory},
        )

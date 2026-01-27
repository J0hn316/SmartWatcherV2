from __future__ import annotations

import time
from pathlib import Path

from watchdog.observers import Observer

from db.audit_logger import AuditLogger
from watcher.handlers import AuditEventHandler


def run_watcher(
    *,
    folder: Path,
    logger: AuditLogger,
    recursive: bool = True,
    include_dirs: bool = False,
    ignore_patterns: list[str] | None = None,
    verbose: bool = False,
    hash_enabled: bool = False,
) -> None:
    """
    Start watching `folder` and log filesystem events using `logger`.
    Ctrl+C to stop.
    """

    folder = folder.resolve()

    if not folder.exists():
        raise FileNotFoundError(f"Watch folder does not exist: {folder}")

    if not folder.is_dir():
        raise NotADirectoryError(f"Watch path is not a folder: {folder}")

    handler = AuditEventHandler(
        logger,
        include_dirs=include_dirs,
        ignore_patterns=ignore_patterns,
        hash_enabled=hash_enabled,
    )

    observer = Observer()
    observer.schedule(handler, str(folder), recursive=recursive)
    observer.start()

    logger.log(
        event_type="startup",
        src_path=str(folder),
        extra={"recursive": recursive, "hash_enabled": hash_enabled},
    )

    if verbose:
        print(
            f"👀 Watching: {folder} (recursive={recursive}, include_dirs={include_dirs})"
        )
        print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        if verbose:
            print("\n🛑 Stopping watcher...")
    finally:
        logger.log(event_type="shutdown", src_path=str(folder))
        observer.stop()
        observer.join()

from __future__ import annotations

import argparse
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from db.audit_logger import AuditLogger
from db.database import get_connection, init_db
from watcher.watcher import run_watcher

DEFAULT_DB_PATH = Path("data") / "watcher_audit.db"


def print_rows(rows: list[sqlite3.Row]) -> None:
    """
    Print rows in a consistent, readable format.
    Expects rows ordered newest->oldest, prints oldest->newest (tail-like).
    """

    for row in reversed(rows):
        src = row["src_path"] or ""
        dest = row["dest_path"] or ""
        arrow = f" -> {dest}" if dest else ""
        print(
            f"#{row['id']} | {row['event_time']} | {row['event_type']} | {src}{arrow}"
        )


@dataclass(frozen=True)
class ArgSpec:
    flags: tuple[str, ...]
    kwargs: dict[str, Any]


def add_args(p: argparse.ArgumentParser, specs: list[ArgSpec]) -> None:
    for spec in specs:
        p.add_argument(*spec.flags, **spec.kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smart-watcher",
        description="Smart Watcher (SQLite audit trail)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Define args per command using specs
    command_specs: dict[str, dict[str, Any]] = {
        "watch": {
            "help": "Watch a folder and log events to SQLite",
            "args": [
                ArgSpec(
                    ("--folder",),
                    {"type": Path, "required": True, "help": "Folder to watch"},
                ),
                ArgSpec(
                    ("--db",),
                    {
                        "type": Path,
                        "default": DEFAULT_DB_PATH,
                        "help": "Path to SQLite database file",
                    },
                ),
                ArgSpec(
                    ("--recursive",),
                    {"action": "store_true", "help": "Watch subfolders too"},
                ),
                ArgSpec(
                    ("--include-dirs",),
                    {
                        "action": "store_true",
                        "help": "Log directory events too (default: files only)",
                    },
                ),
                ArgSpec(
                    ("--verbose",),
                    {"action": "store_true", "help": "Print watcher status messages"},
                ),
                ArgSpec(
                    ("--ignore",),
                    {
                        "action": "append",
                        "default": [],
                        "help": "Ignore pattern (can be repeated). Example: --ignore '*.log' --ignore 'node_modules/*'",
                    },
                ),
            ],
        },
        "tail": {
            "help": "Print the most recent audit events",
            "args": [
                ArgSpec(
                    ("--db",),
                    {
                        "type": Path,
                        "default": DEFAULT_DB_PATH,
                        "help": "Path to SQLite database file",
                    },
                ),
                ArgSpec(
                    ("--limit",),
                    {
                        "type": int,
                        "default": 20,
                        "help": "Number of rows to print (default: 20)",
                    },
                ),
            ],
        },
        "search": {
            "help": "Search audit events with filters",
            "args": [
                ArgSpec(
                    ("--db",),
                    {
                        "type": Path,
                        "default": DEFAULT_DB_PATH,
                        "help": "Path to SQLite database file",
                    },
                ),
                ArgSpec(
                    ("--type",),
                    {
                        "dest": "event_type",
                        "type": str,
                        "help": "Filter by event type (e.g., created, deleted)",
                    },
                ),
                ArgSpec(
                    ("--contains",),
                    {"type": str, "help": "Substring match for src/dest path"},
                ),
                ArgSpec(
                    ("--limit",),
                    {
                        "type": int,
                        "default": 50,
                        "help": "Max rows to print (default: 50)",
                    },
                ),
            ],
        },
    }

    # Create subparsers in a loop
    for cmd_name, spec in command_specs.items():
        p = subparsers.add_parser(cmd_name, help=spec["help"])
        add_args(p, spec["args"])

    return parser


def cmd_watch(args: argparse.Namespace) -> None:
    conn = get_connection(args.db)
    init_db(conn)
    logger = AuditLogger(conn)

    run_watcher(
        folder=args.folder,
        logger=logger,
        recursive=args.recursive,
        include_dirs=args.include_dirs,
        ignore_patterns=args.ignore,
        verbose=args.verbose,
    )


def cmd_tail(args: argparse.Namespace) -> None:
    conn = get_connection(args.db)
    init_db(conn)
    logger = AuditLogger(conn)

    rows = logger.latest(args.limit)

    if not rows:
        print("No audit events found.")
        return

    print_rows(rows)


def cmd_search(args: argparse.Namespace) -> None:
    conn = get_connection(args.db)
    init_db(conn)
    logger = AuditLogger(conn)

    rows = logger.search(
        event_type=args.event_type,
        contains=args.contains,
        limit=args.limit,
    )

    if not rows:
        print("No matching audit events found.")
        return

    print_rows(rows)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "watch":
        cmd_watch(args)
    elif args.command == "tail":
        cmd_tail(args)
    elif args.command == "search":
        cmd_search(args)
    else:
        parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()

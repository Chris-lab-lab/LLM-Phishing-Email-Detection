"""
Simple Metadata Agent

This module provides a tiny demonstration of reading file metadata
(size, creation/modification times) and a helper to summarize metadata
for a given path. It's intended for demonstration and unit testing.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class FileMetadata:
    path: str
    size_bytes: int
    created_at: Optional[datetime]
    modified_at: Optional[datetime]

    def human_readable_size(self) -> str:
        # simple human-friendly size
        size = self.size_bytes
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024.0:
                return f"{size:3.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


def get_file_metadata(path: str) -> FileMetadata:
    """Return metadata for a file path. Raises FileNotFoundError if missing."""
    stat = os.stat(path)
    created = None
    try:
        # On Windows, st_ctime is creation time; on Unix it's change time.
        created = datetime.fromtimestamp(stat.st_ctime)
    except Exception:
        created = None
    modified = datetime.fromtimestamp(stat.st_mtime)

    return FileMetadata(
        path=path,
        size_bytes=stat.st_size,
        created_at=created,
        modified_at=modified,
    )


def summarize_metadata(path: str) -> str:
    """Return a one-line summary for the path's metadata."""
    md = get_file_metadata(path)
    created = md.created_at.isoformat(sep=" ") if md.created_at else "N/A"
    modified = md.modified_at.isoformat(sep=" ") if md.modified_at else "N/A"
    size = md.human_readable_size()
    return f"{md.path} — {size} — created: {created} — modified: {modified}"


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint for quick demonstration.

    Usage: python -m agents.metadata_agent <path>
    """
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: python -m agents.metadata_agent <path>")
        return 2

    path = argv[0]
    if not os.path.exists(path):
        print(f"Path not found: {path}")
        return 1

    try:
        print(summarize_metadata(path))
    except Exception as exc:  # Keep demo robust
        print(f"Error reading metadata for {path}: {exc}")
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

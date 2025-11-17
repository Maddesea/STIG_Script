"""
History lifecycle manager with deduplication.

This module provides the HistMgr class for managing vulnerability
history entries with automatic deduplication, sorting, and compression.

Thread-safe: Yes (uses threading.RLock for all operations)
"""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Union
from contextlib import suppress

# Import from local models module
from .models import Hist

# TODO: Replace with modular imports once other teams complete their work
# from stig_assessor.core.config import Cfg
# from stig_assessor.core.logging import LOG
# from stig_assessor.xml.sanitizer import San
# from stig_assessor.io.file_ops import FO
# from stig_assessor.exceptions import ParseError, ValidationError
# Temporary imports from monolithic file
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from STIG_Script import Cfg, LOG, San, FO, ParseError, ValidationError


class HistMgr:
    """
    History lifecycle manager with deduplication and sorting.

    Manages vulnerability history entries per VID (Vulnerability ID),
    providing:
    - Automatic deduplication based on content hash
    - Sorted insertion (newest first)
    - Automatic compression when history exceeds limits
    - Export/import to/from JSON
    - Merge finding details and comments with history

    Thread-safe: Yes (uses RLock for all operations)

    Attributes:
        _h: Dictionary mapping VID to list of history entries
        _lock: Reentrant lock for thread safety
    """

    def __init__(self):
        """Initialize history manager with empty storage."""
        self._h: Dict[str, List[Hist]] = defaultdict(list)
        self._lock = threading.RLock()

    def add(
        self,
        vid: str,
        stat: str,
        find: str,
        comm: str,
        src: str,
        sev: str = "medium",
        who: str = "",
    ) -> bool:
        """
        Add history entry for a vulnerability.

        Args:
            vid: Vulnerability ID (e.g., 'V-12345')
            stat: Status value
            find: Finding details text
            comm: Comments text
            src: Source of entry (e.g., 'xccdf', 'manual', 'merge')
            sev: Severity level (default: 'medium')
            who: Username (default: from environment)

        Returns:
            True if entry was added, False if duplicate or validation failed

        Thread-safe: Yes
        """
        with self._lock:
            # Validate and normalize input
            try:
                vid = San.vuln(vid)
                stat = San.status(stat)
                sev = San.sev(sev)
            except (ValidationError, ValueError) as exc:
                LOG.w(f"Failed to add history for {vid}: validation error: {exc}")
                return False

            # Require at least one of finding or comments
            if not find and not comm:
                return False

            # Compute content hash for deduplication
            summary = f"{stat}|{find}|{comm}|{sev}|{who}"
            try:
                digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:16]
            except (UnicodeEncodeError, AttributeError) as exc:
                LOG.w(f"Failed to compute digest for {vid}, using fallback: {exc}")
                digest = f"chk_{uuid.uuid4().hex[:6]}"

            # Check for duplicates
            # Performance optimization: check recent entries first
            recent_entries = self._h[vid][-Cfg.DEDUP_CHECK_WINDOW:]
            if any(entry.chk == digest for entry in recent_entries):
                return False

            # If history is longer than window, check older entries too
            if len(self._h[vid]) > Cfg.DEDUP_CHECK_WINDOW:
                older_entries = self._h[vid][:-Cfg.DEDUP_CHECK_WINDOW]
                if any(entry.chk == digest for entry in older_entries):
                    LOG.d(f"Duplicate found in older history for {vid}")
                    return False

            # Set default username if not provided
            if not who:
                who = os.getenv("USER") or os.getenv("USERNAME") or "System"

            # Create new history entry
            entry = Hist(
                ts=datetime.now(timezone.utc),
                stat=stat,
                find=find or "",
                comm=comm or "",
                src=src,
                chk=digest,
                sev=sev,
                who=who,
            )

            # Use bisect.insort for O(n) insertion instead of O(n log n) sort
            # History entries are ordered by timestamp (Hist dataclass has order=True)
            bisect.insort(self._h[vid], entry)

            # Compress if history exceeds maximum
            if len(self._h[vid]) > Cfg.MAX_HIST:
                self._compress(vid)

            return True

    def _compress(self, vid: str) -> None:
        """
        Compress history when it exceeds maximum entries.

        Keeps the first N (head) and last M (tail) entries,
        and creates a single compressed entry for the middle.

        Args:
            vid: Vulnerability ID
        """
        entries = self._h[vid]
        if len(entries) <= Cfg.MAX_HIST:
            return

        # Keep head and tail entries, compress middle
        head = entries[:Cfg.HIST_COMPRESS_HEAD]
        tail = entries[-Cfg.HIST_COMPRESS_TAIL:]
        middle = entries[Cfg.HIST_COMPRESS_HEAD:-Cfg.HIST_COMPRESS_TAIL]

        if middle:
            # Create compressed entry representing middle entries
            compressed = Hist(
                ts=middle[0].ts,
                stat="compressed",
                find=f"[{len(middle)} historical entries compressed]",
                comm="",
                src="system",
                chk="compressed",
                sev="medium",  # Use valid severity
                who="system",
            )
            self._h[vid] = head + [compressed] + tail
        else:
            self._h[vid] = head + tail

    def merge_find(self, vid: str, current: str = "") -> str:
        """
        Merge finding details with history for display.

        Creates a formatted string showing current finding followed
        by historical entries in reverse chronological order.

        Args:
            vid: Vulnerability ID
            current: Current finding details text

        Returns:
            Formatted finding details with history

        Thread-safe: Yes
        """
        with self._lock:
            history = self._h.get(vid)
            if not history:
                return current

            parts: List[str] = []

            # Add current assessment section if present
            if current.strip():
                parts.extend(
                    [
                        "┌" + "─" * 78 + "┐",
                        "│ CURRENT ASSESSMENT".center(80) + "│",
                        "└" + "─" * 78 + "┘",
                        "",
                        current.strip(),
                        "",
                    ]
                )

            # Add history header
            parts.extend(
                [
                    "┌" + "─" * 78 + "┐",
                    "│ HISTORY (Most Recent → Oldest)".center(80) + "│",
                    "└" + "─" * 78 + "┘",
                    "",
                ]
            )

            # Add history entries (newest first)
            for idx, entry in enumerate(reversed(history), 1):
                ts = entry.ts.strftime("%Y-%m-%d %H:%M:%S UTC")
                parts.extend(
                    [
                        f"╓─ Entry #{idx} {'★ CURRENT ★' if idx == 1 else ''}",
                        f"║ Time: {ts}",
                        f"║ Source: {entry.src}",
                        f"║ Status: {entry.stat} | Severity: {entry.sev}",
                        f"║ Assessor: {entry.who}",
                        "╟" + "─" * 79,
                        entry.find.strip() or "[No details]",
                        "╙" + "─" * 79,
                        "",
                    ]
                )

            # Assemble and truncate if necessary
            result = "\n".join(parts)
            if len(result) > Cfg.MAX_FIND:
                result = result[: Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
            return result

    def merge_comm(self, vid: str, current: str = "") -> str:
        """
        Merge comments with history for display.

        Creates a formatted string showing current comment followed
        by historical comments in reverse chronological order.

        Args:
            vid: Vulnerability ID
            current: Current comments text

        Returns:
            Formatted comments with history

        Thread-safe: Yes
        """
        with self._lock:
            history = self._h.get(vid)
            if not history:
                return current

            parts: List[str] = []

            # Add current comment section if present
            if current.strip():
                parts.extend(["═" * 80, "[CURRENT COMMENT]", current.strip(), "", ""])

            # Add history header
            parts.extend(["═" * 80, "[COMMENT HISTORY]", "═" * 80, ""])

            # Add historical comments (only entries with non-empty comments)
            count = 0
            for entry in reversed(history):
                if not entry.comm.strip():
                    continue
                count += 1
                ts = entry.ts.strftime("%Y-%m-%d %H:%M:%S UTC")
                parts.append(f"[{count}] {ts} | {entry.src} | {entry.stat}")
                parts.append(entry.comm.strip())
                parts.append("─" * 80)

            # Assemble and truncate if necessary
            result = "\n".join(parts)
            if len(result) > Cfg.MAX_COMM:
                result = result[: Cfg.MAX_COMM - 15] + "\n[TRUNCATED]"
            return result

    def export(self, path: Union[str, Path]) -> None:
        """
        Export history to JSON file.

        Args:
            path: Output file path

        Thread-safe: Yes
        """
        path = San.path(path, mkpar=True)
        with self._lock:
            payload = {
                "meta": {
                    "generated": datetime.now(timezone.utc).isoformat(),
                    "version": "7.3.0",  # TODO: Import from constants
                    "nvulns": len(self._h),
                    "nentries": sum(len(vals) for vals in self._h.values()),
                },
                "history": {
                    vid: [entry.as_dict() for entry in entries]
                    for vid, entries in self._h.items()
                },
            }

        # Use atomic write
        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

        LOG.i(f"Exported history for {len(payload['history'])} vulnerabilities")

    def imp(self, path: Union[str, Path]) -> int:
        """
        Import history from JSON file.

        Args:
            path: Input file path

        Returns:
            Number of entries imported

        Raises:
            ParseError: If JSON is invalid

        Thread-safe: Yes
        """
        path = San.path(path, exist=True, file=True)
        try:
            payload = json.loads(FO.read(path))
        except Exception:
            raise ParseError("Invalid history JSON")

        imported = 0
        with self._lock:
            history_data = payload.get("history", {})
            for vid, entries in history_data.items():
                # Validate VID
                try:
                    vid = San.vuln(vid)
                except Exception:
                    continue

                # Import entries
                slot = self._h[vid]
                for entry_data in entries:
                    try:
                        entry = Hist.from_dict(entry_data)
                    except Exception:
                        continue

                    # Skip duplicates
                    if any(existing.chk == entry.chk for existing in slot):
                        continue

                    slot.append(entry)
                    imported += 1

                # Sort entries by timestamp
                slot.sort(key=lambda e: e.ts)

        LOG.i(f"Imported {imported} history entries")
        return imported

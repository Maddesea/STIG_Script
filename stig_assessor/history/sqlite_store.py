"""
SQLite history and drift tracking engine.
Provides persistent storage, rule justification retention, and configuration drift analysis
using the standard library `sqlite3`.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from stig_assessor.xml.sanitizer import San


class SQLiteStore:
    """
    SQLite persistent storage for STIG Assessor history.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = San.path(db_path, mkpar=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a configured sqlite3 connection."""
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        # Enable PRAGMA optimizations for performance and reliability
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # Assessments metadata
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_file TEXT,
                    stig_title TEXT
                )
            """
            )

            # Findings linking to assessments
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    vid TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    finding_details TEXT,
                    comments TEXT,
                    chk TEXT,
                    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                )
            """
            )

            # Justifications (Persistent POA&M tracking)
            # This stores the latest user justification for a specific VID
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS justifications (
                    vid TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    comments TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    who TEXT NOT NULL
                )
            """
            )

            # Indices for performance
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_vid ON findings(vid)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_assess_id ON findings(assessment_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_assessments_asset ON assessments(asset_name, timestamp)"
            )
            conn.commit()

    def save_assessment(
        self,
        asset_name: str,
        source_file: str,
        stig_title: str,
        results: List[Dict[str, Any]],
    ) -> int:
        """
        Save a complete assessment to the database.
        results should be a list of dicts with:
        ['vid', 'status', 'severity', 'find', 'comm', 'chk']
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Insert assessment metadata
            cursor.execute(
                "INSERT INTO assessments (asset_name, timestamp, source_file, stig_title) VALUES (?, ?, ?, ?)",
                (asset_name, timestamp, str(source_file), stig_title),
            )
            assessment_id = cursor.lastrowid

            if assessment_id is None:
                raise RuntimeError("Failed to insert assessment record.")

            # Insert findings
            cursor.executemany(
                """
                INSERT INTO findings (assessment_id, vid, status, severity, finding_details, comments, chk)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        assessment_id,
                        r["vid"],
                        r["status"],
                        r["severity"],
                        r.get("find", ""),
                        r.get("comm", ""),
                        r.get("chk", ""),
                    )
                    for r in results
                ],
            )

            # Database Size Boundary Maintenance
            # Delete assessments keeping only the most recent MAX_HIST entries for this specific asset
            # (Assumes core.config is available - using local import wrapper for safety)
            from stig_assessor.core.config import Cfg

            cursor.execute(
                """
                DELETE FROM assessments 
                WHERE asset_name = ? AND id NOT IN (
                    SELECT id FROM assessments WHERE asset_name = ? ORDER BY timestamp DESC LIMIT ?
                )
                """,
                (asset_name, asset_name, Cfg.MAX_HIST),
            )

            conn.commit()
            return assessment_id

    def save_justification(
        self, vid: str, status: str, comments: str, who: str
    ) -> None:
        """Save a persistent justification that will apply to future scans."""
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO justifications (vid, status, comments, updated_at, who)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(vid) DO UPDATE SET
                    status=excluded.status,
                    comments=excluded.comments,
                    updated_at=excluded.updated_at,
                    who=excluded.who
                """,
                (vid, status, comments, timestamp, who),
            )
            conn.commit()

    def get_justification(self, vid: str) -> Optional[Dict[str, str]]:
        """Retrieve a persistent justification for a VID."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status, comments, updated_at, who FROM justifications WHERE vid = ?",
                (vid,),
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_drift(self, asset_name: str, current_assessment_id: int) -> Dict[str, Any]:
        """
        Compare the current assessment with the most recent previous assessment for the same asset.
        Returns a dict highlighting fixed rules, regressions, and unchanged rules.
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Find the previous assessment ID
            cursor.execute(
                """
                SELECT id FROM assessments 
                WHERE asset_name = ? AND id < ? 
                ORDER BY timestamp DESC LIMIT 1
            """,
                (asset_name, current_assessment_id),
            )

            prev_row = cursor.fetchone()
            if not prev_row:
                return {"error": "No previous assessment found for drift comparison."}

            prev_assessment_id = prev_row[0]

            # Get findings for both
            cursor.execute(
                "SELECT vid, status FROM findings WHERE assessment_id = ?",
                (prev_assessment_id,),
            )
            prev_findings = {row["vid"]: row["status"] for row in cursor.fetchall()}

            cursor.execute(
                "SELECT vid, status FROM findings WHERE assessment_id = ?",
                (current_assessment_id,),
            )
            curr_findings = {row["vid"]: row["status"] for row in cursor.fetchall()}

        drift = {
            "fixed": [],  # Open -> NotAFinding
            "regressed": [],  # NotAFinding -> Open
            "changed": [],  # Any other status change
            "unchanged": [],
            "new": [],  # VID not in prev
            "removed": [],  # VID not in curr
        }

        for vid, curr_status in curr_findings.items():
            if vid not in prev_findings:
                drift["new"].append({"vid": vid, "status": curr_status})
            else:
                prev_status = prev_findings[vid]
                if curr_status == prev_status:
                    drift["unchanged"].append({"vid": vid, "status": curr_status})
                elif (
                    prev_status.lower() in ("open", "not_reviewed")
                    and curr_status.lower() == "notafinding"
                ):
                    drift["fixed"].append(
                        {"vid": vid, "from": prev_status, "to": curr_status}
                    )
                elif prev_status.lower() == "notafinding" and curr_status.lower() in (
                    "open",
                    "not_reviewed",
                ):
                    drift["regressed"].append(
                        {"vid": vid, "from": prev_status, "to": curr_status}
                    )
                else:
                    drift["changed"].append(
                        {"vid": vid, "from": prev_status, "to": curr_status}
                    )

        for vid in prev_findings:
            if vid not in curr_findings:
                drift["removed"].append({"vid": vid})

        return drift

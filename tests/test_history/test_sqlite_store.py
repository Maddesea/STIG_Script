"""Unit tests for the SQLite history and drift tracking engine."""

import shutil
import tempfile
import unittest
from pathlib import Path

from stig_assessor.history.sqlite_store import SQLiteStore


class TestSQLiteStore(unittest.TestCase):
    """Tests for SQLiteStore persistence, assessment saving, and drift analysis."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_history.sqlite"
        self.store = SQLiteStore(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ─────────────────────────────── Schema ────────────────────────────────

    def test_db_file_created(self):
        """Database file should exist after initialization."""
        self.assertTrue(self.db_path.exists())

    def test_tables_created(self):
        """Schema should contain assessments, findings, and justifications tables."""
        with self.store._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = {row[0] for row in cursor.fetchall()}
        self.assertIn("assessments", tables)
        self.assertIn("findings", tables)
        self.assertIn("justifications", tables)

    def test_indices_created(self):
        """Performance indices should be present."""
        with self.store._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indices = {row[0] for row in cursor.fetchall()}
        self.assertIn("idx_findings_vid", indices)
        self.assertIn("idx_findings_assess_id", indices)
        self.assertIn("idx_assessments_asset", indices)

    # ─────────────────────────────── Save ────────────────────────────────

    def test_save_assessment_returns_id(self):
        """save_assessment should return a positive integer ID."""
        results = [
            {
                "vid": "V-12345",
                "status": "Open",
                "severity": "high",
                "find": "details",
                "comm": "comment",
            },
        ]
        aid = self.store.save_assessment(
            "SERVER-01", "test.ckl", "Windows STIG", results
        )
        self.assertIsInstance(aid, int)
        self.assertGreater(aid, 0)

    def test_save_assessment_persists_findings(self):
        """Saved findings should be queryable from the findings table."""
        results = [
            {"vid": "V-100", "status": "NotAFinding", "severity": "medium"},
            {
                "vid": "V-200",
                "status": "Open",
                "severity": "high",
                "find": "open finding",
            },
        ]
        aid = self.store.save_assessment("SERVER-01", "test.ckl", "RHEL STIG", results)

        with self.store._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT vid, status FROM findings WHERE assessment_id = ? ORDER BY vid",
                (aid,),
            )
            rows = cursor.fetchall()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["vid"], "V-100")
        self.assertEqual(rows[0]["status"], "NotAFinding")
        self.assertEqual(rows[1]["vid"], "V-200")
        self.assertEqual(rows[1]["status"], "Open")

    def test_save_multiple_assessments(self):
        """Multiple assessments for the same asset should each get unique IDs."""
        r = [{"vid": "V-1", "status": "Open", "severity": "low"}]
        aid1 = self.store.save_assessment("SRV", "a.ckl", "STIG", r)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r)
        self.assertNotEqual(aid1, aid2)
        self.assertGreater(aid2, aid1)

    # ─────────────────────────────── Justifications ─────────────────────

    def test_save_and_get_justification(self):
        """Justifications should round-trip correctly."""
        self.store.save_justification(
            "V-999", "NotAFinding", "Mitigated by policy", "admin"
        )
        just = self.store.get_justification("V-999")
        self.assertIsNotNone(just)
        self.assertEqual(just["status"], "NotAFinding")
        self.assertEqual(just["comments"], "Mitigated by policy")
        self.assertEqual(just["who"], "admin")

    def test_justification_upsert(self):
        """Saving a justification again for the same VID should update, not duplicate."""
        self.store.save_justification("V-500", "Open", "Initial", "user1")
        self.store.save_justification("V-500", "NotAFinding", "Fixed now", "user2")
        just = self.store.get_justification("V-500")
        self.assertEqual(just["status"], "NotAFinding")
        self.assertEqual(just["comments"], "Fixed now")
        self.assertEqual(just["who"], "user2")

    def test_get_justification_missing(self):
        """Getting a justification for a nonexistent VID should return None."""
        self.assertIsNone(self.store.get_justification("V-NONEXISTENT"))

    # ─────────────────────────────── Drift ──────────────────────────────

    def test_drift_no_previous(self):
        """Drift with only one assessment should return an error message."""
        r = [{"vid": "V-1", "status": "Open", "severity": "high"}]
        aid = self.store.save_assessment("SRV", "a.ckl", "STIG", r)
        drift = self.store.get_drift("SRV", aid)
        self.assertIn("error", drift)

    def test_drift_fixed(self):
        """Rules going Open → NotAFinding should appear in 'fixed'."""
        r1 = [{"vid": "V-1", "status": "Open", "severity": "high"}]
        r2 = [{"vid": "V-1", "status": "NotAFinding", "severity": "high"}]
        aid1 = self.store.save_assessment("SRV", "a.ckl", "STIG", r1)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r2)
        drift = self.store.get_drift("SRV", aid2)
        self.assertEqual(len(drift["fixed"]), 1)
        self.assertEqual(drift["fixed"][0]["vid"], "V-1")

    def test_drift_regressed(self):
        """Rules going NotAFinding → Open should appear in 'regressed'."""
        r1 = [{"vid": "V-1", "status": "NotAFinding", "severity": "medium"}]
        r2 = [{"vid": "V-1", "status": "Open", "severity": "medium"}]
        self.store.save_assessment("SRV", "a.ckl", "STIG", r1)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r2)
        drift = self.store.get_drift("SRV", aid2)
        self.assertEqual(len(drift["regressed"]), 1)

    def test_drift_unchanged(self):
        """Rules with same status should appear in 'unchanged'."""
        r = [{"vid": "V-1", "status": "Open", "severity": "low"}]
        self.store.save_assessment("SRV", "a.ckl", "STIG", r)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r)
        drift = self.store.get_drift("SRV", aid2)
        self.assertEqual(len(drift["unchanged"]), 1)

    def test_drift_new_rules(self):
        """Rules present only in the current assessment should appear in 'new'."""
        r1 = [{"vid": "V-1", "status": "Open", "severity": "high"}]
        r2 = [
            {"vid": "V-1", "status": "Open", "severity": "high"},
            {"vid": "V-2", "status": "NotAFinding", "severity": "low"},
        ]
        self.store.save_assessment("SRV", "a.ckl", "STIG", r1)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r2)
        drift = self.store.get_drift("SRV", aid2)
        self.assertEqual(len(drift["new"]), 1)
        self.assertEqual(drift["new"][0]["vid"], "V-2")

    def test_drift_removed_rules(self):
        """Rules absent from the current assessment should appear in 'removed'."""
        r1 = [
            {"vid": "V-1", "status": "Open", "severity": "high"},
            {"vid": "V-2", "status": "Open", "severity": "medium"},
        ]
        r2 = [{"vid": "V-1", "status": "Open", "severity": "high"}]
        self.store.save_assessment("SRV", "a.ckl", "STIG", r1)
        aid2 = self.store.save_assessment("SRV", "b.ckl", "STIG", r2)
        drift = self.store.get_drift("SRV", aid2)
        self.assertEqual(len(drift["removed"]), 1)
        self.assertEqual(drift["removed"][0]["vid"], "V-2")

    def test_drift_different_asset(self):
        """Drift should only compare assessments for the same asset."""
        r = [{"vid": "V-1", "status": "Open", "severity": "high"}]
        self.store.save_assessment("SRV-A", "a.ckl", "STIG", r)
        aid2 = self.store.save_assessment("SRV-B", "b.ckl", "STIG", r)
        drift = self.store.get_drift("SRV-B", aid2)
        self.assertIn("error", drift)  # No previous for SRV-B


if __name__ == "__main__":
    unittest.main()

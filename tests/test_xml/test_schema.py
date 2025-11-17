"""Tests for XML schema module (Sch class).

Tests cover:
- Schema constants and element names
- Valid value sets (status, severity, markings)
- Default values dictionary
"""

import unittest
from stig_assessor.xml.schema import Sch


class TestSchemaConstants(unittest.TestCase):
    """Test schema constant definitions."""

    def test_root_element(self):
        """Verify root element is CHECKLIST."""
        self.assertEqual(Sch.ROOT, "CHECKLIST")

    def test_comment_contains_version(self):
        """Verify comment includes STIG Viewer version."""
        self.assertIn("DISA STIG Viewer", Sch.COMMENT)
        self.assertIn("2.18", Sch.COMMENT)

    def test_asset_tuple_not_empty(self):
        """Verify ASSET tuple contains expected elements."""
        self.assertIsInstance(Sch.ASSET, tuple)
        self.assertGreater(len(Sch.ASSET), 0)
        self.assertIn("ROLE", Sch.ASSET)
        self.assertIn("HOST_NAME", Sch.ASSET)
        self.assertIn("HOST_IP", Sch.ASSET)
        self.assertIn("HOST_MAC", Sch.ASSET)

    def test_stig_tuple_not_empty(self):
        """Verify STIG tuple contains expected elements."""
        self.assertIsInstance(Sch.STIG, tuple)
        self.assertGreater(len(Sch.STIG), 0)
        self.assertIn("version", Sch.STIG)
        self.assertIn("stigid", Sch.STIG)
        self.assertIn("title", Sch.STIG)

    def test_vuln_tuple_not_empty(self):
        """Verify VULN tuple contains expected elements."""
        self.assertIsInstance(Sch.VULN, tuple)
        self.assertGreater(len(Sch.VULN), 0)
        self.assertIn("Vuln_Num", Sch.VULN)
        self.assertIn("Severity", Sch.VULN)
        self.assertIn("Rule_ID", Sch.VULN)
        self.assertIn("Check_Content", Sch.VULN)
        self.assertIn("Fix_Text", Sch.VULN)

    def test_status_tuple_not_empty(self):
        """Verify STATUS tuple contains expected elements."""
        self.assertIsInstance(Sch.STATUS, tuple)
        self.assertGreater(len(Sch.STATUS), 0)
        self.assertIn("STATUS", Sch.STATUS)
        self.assertIn("FINDING_DETAILS", Sch.STATUS)
        self.assertIn("COMMENTS", Sch.STATUS)


class TestValidValues(unittest.TestCase):
    """Test valid value sets."""

    def test_status_values(self):
        """Verify all valid status values are present."""
        expected_statuses = {
            "NotAFinding",
            "Open",
            "Not_Reviewed",
            "Not_Applicable"
        }
        self.assertEqual(Sch.STAT_VALS, expected_statuses)
        self.assertIsInstance(Sch.STAT_VALS, frozenset)

    def test_severity_values(self):
        """Verify all valid severity values are present."""
        expected_severities = {"high", "medium", "low"}
        self.assertEqual(Sch.SEV_VALS, expected_severities)
        self.assertIsInstance(Sch.SEV_VALS, frozenset)

    def test_markings(self):
        """Verify security markings are defined."""
        self.assertIsInstance(Sch.MARKS, frozenset)
        self.assertIn("CUI", Sch.MARKS)
        self.assertIn("UNCLASSIFIED", Sch.MARKS)
        self.assertIn("SECRET", Sch.MARKS)

    def test_status_membership(self):
        """Test membership checks for status values."""
        self.assertIn("NotAFinding", Sch.STAT_VALS)
        self.assertIn("Open", Sch.STAT_VALS)
        self.assertNotIn("Invalid", Sch.STAT_VALS)
        self.assertNotIn("", Sch.STAT_VALS)

    def test_severity_membership(self):
        """Test membership checks for severity values."""
        self.assertIn("high", Sch.SEV_VALS)
        self.assertIn("medium", Sch.SEV_VALS)
        self.assertIn("low", Sch.SEV_VALS)
        self.assertNotIn("critical", Sch.SEV_VALS)
        self.assertNotIn("", Sch.SEV_VALS)


class TestDefaults(unittest.TestCase):
    """Test default values dictionary."""

    def test_defaults_is_dict(self):
        """Verify DEFS is a dictionary."""
        self.assertIsInstance(Sch.DEFS, dict)

    def test_defaults_not_empty(self):
        """Verify DEFS contains default values."""
        self.assertGreater(len(Sch.DEFS), 0)

    def test_vuln_defaults(self):
        """Verify vulnerability-related defaults."""
        self.assertEqual(Sch.DEFS.get("Check_Content_Ref"), "M")
        self.assertEqual(Sch.DEFS.get("Weight"), "10.0")
        self.assertEqual(Sch.DEFS.get("Class"), "Unclass")
        self.assertEqual(Sch.DEFS.get("Documentable"), "false")

    def test_asset_defaults(self):
        """Verify asset-related defaults."""
        self.assertEqual(Sch.DEFS.get("MARKING"), "CUI")
        self.assertEqual(Sch.DEFS.get("ROLE"), "None")
        self.assertEqual(Sch.DEFS.get("ASSET_TYPE"), "Computing")
        self.assertEqual(Sch.DEFS.get("WEB_OR_DATABASE"), "false")

    def test_stig_info_defaults(self):
        """Verify STIG_INFO defaults."""
        self.assertEqual(Sch.DEFS.get("notice"), "terms-of-use")
        self.assertEqual(Sch.DEFS.get("source"), "STIG.DOD.MIL")
        self.assertEqual(Sch.DEFS.get("classification"), "UNCLASSIFIED")


if __name__ == "__main__":
    unittest.main()

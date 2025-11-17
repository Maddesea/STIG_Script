"""Tests for constants module."""

import unittest
from stig_assessor.core.constants import VERSION, Status, Severity


class TestConstants(unittest.TestCase):
    """Test constants and enumerations."""

    def test_version_format(self):
        """Verify version string format."""
        self.assertIsInstance(VERSION, str)
        parts = VERSION.split(".")
        self.assertEqual(len(parts), 3)

    def test_status_values(self):
        """Verify Status enum values."""
        self.assertEqual(Status.NOT_A_FINDING.value, "NotAFinding")
        self.assertEqual(Status.OPEN.value, "Open")
        self.assertEqual(Status.NOT_REVIEWED.value, "Not_Reviewed")
        self.assertEqual(Status.NOT_APPLICABLE.value, "Not_Applicable")

    def test_status_validation(self):
        """Test Status.is_valid method."""
        self.assertTrue(Status.is_valid("NotAFinding"))
        self.assertTrue(Status.is_valid("Open"))
        self.assertFalse(Status.is_valid("Invalid"))

    def test_severity_values(self):
        """Verify Severity enum values."""
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")

    def test_severity_validation(self):
        """Test Severity.is_valid method."""
        self.assertTrue(Severity.is_valid("high"))
        self.assertTrue(Severity.is_valid("medium"))
        self.assertFalse(Severity.is_valid("critical"))


if __name__ == "__main__":
    unittest.main()

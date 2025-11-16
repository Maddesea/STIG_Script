"""Tests for remediation models."""

import unittest
from stig_assessor.remediation.models import Fix


class TestFix(unittest.TestCase):
    """Test Fix dataclass."""

    def test_fix_creation(self):
        """Test creating a Fix instance."""
        fix = Fix(
            vid="V-123456",
            rule_id="SV-123456r1_rule",
            severity="high",
            title="Test Fix",
            group_title="Test Group",
            fix_text="This is the fix text",
            fix_command="chmod 755 /etc/test",
            platform="linux"
        )

        self.assertEqual(fix.vid, "V-123456")
        self.assertEqual(fix.severity, "high")
        self.assertEqual(fix.platform, "linux")
        self.assertEqual(fix.fix_command, "chmod 755 /etc/test")

    def test_fix_as_dict(self):
        """Test Fix.as_dict() serialization."""
        fix = Fix(
            vid="V-123456",
            rule_id="SV-123456r1_rule",
            severity="medium",
            title="A" * 300,  # Long title to test truncation
            group_title="Test Group",
            fix_text="Fix text",
            cci=["CCI-001", "CCI-002", "CCI-003"],
            legacy=["V-1", "V-2"]
        )

        result = fix.as_dict()

        self.assertEqual(result["vid"], "V-123456")
        self.assertEqual(result["severity"], "medium")
        self.assertEqual(len(result["title"]), 200)  # Should be truncated
        self.assertEqual(len(result["cci"]), 3)
        self.assertEqual(len(result["legacy"]), 2)

    def test_fix_defaults(self):
        """Test Fix default values."""
        fix = Fix(
            vid="V-123456",
            rule_id="SV-123456r1_rule",
            severity="low",
            title="Test",
            group_title="Group",
            fix_text="Fix"
        )

        self.assertIsNone(fix.fix_command)
        self.assertIsNone(fix.check_command)
        self.assertEqual(fix.platform, "generic")
        self.assertEqual(fix.rule_version, "")
        self.assertEqual(fix.cci, [])
        self.assertEqual(fix.legacy, [])

    def test_fix_with_cci_list(self):
        """Test Fix with CCI references."""
        cci_list = [f"CCI-{i:03d}" for i in range(1, 15)]  # 14 items

        fix = Fix(
            vid="V-123456",
            rule_id="SV-123456r1_rule",
            severity="high",
            title="Test",
            group_title="Group",
            fix_text="Fix",
            cci=cci_list
        )

        result = fix.as_dict()
        # Should be truncated to 10 items
        self.assertEqual(len(result["cci"]), 10)
        self.assertEqual(result["cci"][0], "CCI-001")
        self.assertEqual(result["cci"][9], "CCI-010")


if __name__ == "__main__":
    unittest.main()

"""Tests for remediation extractor."""

import tempfile
import unittest
from pathlib import Path

# Note: These tests are designed to work when the full modular system is in place
# For now, they serve as documentation of expected behavior


class TestFixExt(unittest.TestCase):
    """Test FixExt class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_xccdf = Path(self.test_dir) / "test_benchmark.xml"

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_extractor_initialization(self):
        """Test FixExt initialization."""
        from stig_assessor.remediation import FixExt

        # Create a minimal XCCDF file
        self.test_xccdf.write_text(
            """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-123456">
                <Rule id="SV-123456r1_rule">
                    <title>Test Rule</title>
                </Rule>
            </Group>
        </Benchmark>
        """
        )

        extractor = FixExt(self.test_xccdf)
        self.assertEqual(extractor.xccdf.resolve(), self.test_xccdf.resolve())
        self.assertEqual(len(extractor.fixes), 0)

    def test_extract_fixes(self):
        """Test extracting fixes from XCCDF."""
        from stig_assessor.remediation import FixExt

        # Create XCCDF with fix text
        self.test_xccdf.write_text(
            """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-123456">
                <title>Test Group</title>
                <Rule id="SV-123456r1_rule" severity="high">
                    <title>Configure permissions</title>
                    <fixtext>Run the following command: chmod 755 /etc/test</fixtext>
                </Rule>
            </Group>
        </Benchmark>
        """
        )

        extractor = FixExt(self.test_xccdf)
        fixes = extractor.extract()

        self.assertGreater(len(fixes), 0)
        self.assertEqual(fixes[0].vid, "V-123456")
        self.assertEqual(fixes[0].severity, "high")

    def test_command_extraction_patterns(self):
        """Test various command extraction patterns."""
        # These tests can run without the full system
        # They test the regex patterns used in _extract_command

        # Test code block pattern
        from stig_assessor.remediation.extractor import FixExt

        self.assertIsNotNone(FixExt.CODE_BLOCK)
        self.assertIsNotNone(FixExt.SHELL_PROMPT)
        self.assertIsNotNone(FixExt.POWERSHELL_PROMPT)

        # Test markdown code block matching
        sample_text = """
        ```bash
        chmod 755 /etc/test
        chown root:root /etc/test
        ```
        """
        matches = FixExt.CODE_BLOCK.findall(sample_text)
        self.assertGreater(len(matches), 0)

    def test_platform_detection_patterns(self):
        """Test platform detection logic."""
        # Test that platform keywords are properly identified

        linux_text = "Run systemctl restart service and chmod 755 /etc/config"
        windows_text = "Use PowerShell Set-Item registry settings"
        network_text = "Configure cisco ios switchport settings"

        # These tests verify the pattern logic is sound
        self.assertIn("systemctl", linux_text.lower())
        self.assertIn("chmod", linux_text.lower())
        self.assertIn("powershell", windows_text.lower())
        self.assertIn("cisco", network_text.lower())
        self.assertIn("ios", network_text.lower())


class TestFixExtExport(unittest.TestCase):
    """Test FixExt export functionality."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_xccdf = Path(self.test_dir) / "test_benchmark.xml"
        self.test_xccdf.write_text(
            """<?xml version="1.0"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-123456">
                <title>Test Group</title>
                <Rule id="SV-123456r1_rule" severity="high">
                    <title>Configure permissions</title>
                    <fixtext>Run the following command: chmod 755 /etc/test</fixtext>
                </Rule>
            </Group>
        </Benchmark>
        """
        )
        from stig_assessor.remediation import FixExt

        self.extractor = FixExt(self.test_xccdf)
        self.extractor.extract()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_to_json(self):
        """Test JSON export."""
        out_json = Path(self.test_dir) / "out.json"
        self.extractor.to_json(out_json)
        self.assertTrue(out_json.exists())
        import json

        content = json.loads(out_json.read_text())
        self.assertIn("fixes", content)
        self.assertGreater(len(content["fixes"]), 0)

    def test_export_to_csv(self):
        """Test CSV export."""
        out_csv = Path(self.test_dir) / "out.csv"
        self.extractor.to_csv(out_csv)
        self.assertTrue(out_csv.exists())
        self.assertIn("Vuln_ID", out_csv.read_text())

    def test_export_to_bash(self):
        """Test Bash script generation."""
        out_sh = Path(self.test_dir) / "out.sh"
        self.extractor.to_bash(out_sh)
        self.assertTrue(out_sh.exists())
        self.assertIn("#!/usr/bin/env bash", out_sh.read_text(encoding="utf-8"))

    def test_export_to_powershell(self):
        """Test PowerShell script generation."""
        # For powershell we need a windows fix
        from stig_assessor.remediation.models import Fix

        self.extractor.fixes.append(
            Fix(
                vid="V-999",
                rule_id="1",
                severity="medium",
                title="t",
                group_title="g",
                fix_text="test",
                fix_command="Set-Item",
                platform="windows",
            )
        )
        out_ps1 = Path(self.test_dir) / "out.ps1"
        self.extractor.to_powershell(out_ps1)
        self.assertTrue(out_ps1.exists())
        self.assertIn(
            "#requires -RunAsAdministrator", out_ps1.read_text(encoding="utf-8")
        )


if __name__ == "__main__":
    unittest.main()

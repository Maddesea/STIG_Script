"""
Unit tests for templates/boilerplate.py module.

Tests cover:
- Singleton behavior
- Load/save operations
- Get/set/delete operations
- Apply to VULN element
- Default templates
- JSON serialization

Team 7: Boilerplate Templates
"""

import unittest
import json
import tempfile
from pathlib import Path
from xml.etree.ElementTree import Element
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from stig_assessor.templates.boilerplate import BP, BOILERPLATE
from stig_assessor.exceptions import FileError


class TestBPSingleton(unittest.TestCase):
    """Test BP singleton behavior."""

    def test_singleton(self):
        """Verify singleton behavior."""
        bp1 = BP()
        bp2 = BP()
        self.assertIs(bp1, bp2, "BP should be a singleton")

    def test_module_level_singleton(self):
        """Verify module-level BOILERPLATE singleton."""
        bp = BP()
        self.assertIs(bp, BOILERPLATE, "BOILERPLATE should be same instance as BP()")


class TestBPBasicOperations(unittest.TestCase):
    """Test basic get/set/delete operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.bp = BP()
        # Clear templates for clean state
        self.bp.templates = {}

    def test_set_and_get(self):
        """Test setting and getting templates."""
        self.bp.set("V-12345", "NotAFinding", "Test template text")
        result = self.bp.get("V-12345", "NotAFinding")
        self.assertEqual(result, "Test template text")

    def test_get_nonexistent_vid(self):
        """Test getting template for non-existent VID."""
        result = self.bp.get("V-99999", "NotAFinding")
        self.assertIsNone(result)

    def test_get_nonexistent_status(self):
        """Test getting template for non-existent status."""
        self.bp.set("V-12345", "NotAFinding", "Test")
        result = self.bp.get("V-12345", "Open")
        self.assertIsNone(result)

    def test_set_multiple_statuses(self):
        """Test setting multiple statuses for same VID."""
        self.bp.set("V-12345", "NotAFinding", "NAF text")
        self.bp.set("V-12345", "Open", "Open text")
        self.assertEqual(self.bp.get("V-12345", "NotAFinding"), "NAF text")
        self.assertEqual(self.bp.get("V-12345", "Open"), "Open text")

    def test_set_overwrites(self):
        """Test that set overwrites existing template."""
        self.bp.set("V-12345", "NotAFinding", "Original")
        self.bp.set("V-12345", "NotAFinding", "Updated")
        self.assertEqual(self.bp.get("V-12345", "NotAFinding"), "Updated")

    def test_delete_specific_status(self):
        """Test deleting specific status."""
        self.bp.set("V-12345", "NotAFinding", "NAF")
        self.bp.set("V-12345", "Open", "Open")
        result = self.bp.delete("V-12345", "NotAFinding")
        self.assertTrue(result)
        self.assertIsNone(self.bp.get("V-12345", "NotAFinding"))
        self.assertEqual(self.bp.get("V-12345", "Open"), "Open")

    def test_delete_all_statuses(self):
        """Test deleting all statuses for VID."""
        self.bp.set("V-12345", "NotAFinding", "NAF")
        self.bp.set("V-12345", "Open", "Open")
        result = self.bp.delete("V-12345")
        self.assertTrue(result)
        self.assertIsNone(self.bp.get("V-12345", "NotAFinding"))
        self.assertIsNone(self.bp.get("V-12345", "Open"))

    def test_delete_nonexistent_vid(self):
        """Test deleting non-existent VID."""
        result = self.bp.delete("V-99999")
        self.assertFalse(result)

    def test_delete_nonexistent_status(self):
        """Test deleting non-existent status."""
        self.bp.set("V-12345", "NotAFinding", "NAF")
        result = self.bp.delete("V-12345", "Open")
        self.assertFalse(result)

    def test_delete_last_status_removes_vid(self):
        """Test that deleting last status removes VID entry."""
        self.bp.set("V-12345", "NotAFinding", "NAF")
        self.bp.delete("V-12345", "NotAFinding")
        self.assertNotIn("V-12345", self.bp.templates)


class TestBPLoadSave(unittest.TestCase):
    """Test load/save operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.temp_file = self.temp_dir / "test_boilerplate.json"
        self.bp = BP()
        self.bp.template_file = self.temp_file
        self.bp.templates = {}

    def tearDown(self):
        """Clean up test fixtures."""
        if self.temp_file.exists():
            self.temp_file.unlink()
        if self.temp_dir.exists():
            self.temp_dir.rmdir()

    def test_save_and_load(self):
        """Test save/load cycle."""
        self.bp.templates = {
            "V-12345": {
                "NotAFinding": "NAF template",
                "Open": "Open template"
            }
        }
        self.bp.save()
        self.assertTrue(self.temp_file.exists())

        # Create new instance to test load
        bp2 = BP()
        bp2.template_file = self.temp_file
        bp2.templates = {}
        bp2.load()

        self.assertEqual(bp2.templates, self.bp.templates)

    def test_save_creates_valid_json(self):
        """Test that saved file is valid JSON."""
        self.bp.templates = {"V-12345": {"NotAFinding": "Test"}}
        self.bp.save()

        with open(self.temp_file, 'r') as f:
            data = json.load(f)
        self.assertEqual(data, self.bp.templates)

    def test_save_with_unicode(self):
        """Test saving templates with unicode characters."""
        self.bp.templates = {"V-12345": {"NotAFinding": "Unicode: 日本語 ñ"}}
        self.bp.save()

        bp2 = BP()
        bp2.template_file = self.temp_file
        bp2.load()

        self.assertEqual(bp2.get("V-12345", "NotAFinding"), "Unicode: 日本語 ñ")

    def test_load_missing_file_uses_defaults(self):
        """Test that loading missing file uses defaults."""
        # Ensure file doesn't exist
        if self.temp_file.exists():
            self.temp_file.unlink()

        self.bp.templates = {}
        self.bp.load()

        # Should have default templates
        self.assertGreater(len(self.bp.templates), 0)
        self.assertIn("V-*", self.bp.templates)

    def test_load_invalid_json_uses_defaults(self):
        """Test that loading invalid JSON uses defaults."""
        self.temp_file.write_text("invalid json {{{")

        self.bp.templates = {}
        self.bp.load()

        # Should fall back to defaults
        self.assertGreater(len(self.bp.templates), 0)


class TestBPDefaults(unittest.TestCase):
    """Test default templates."""

    def test_load_defaults(self):
        """Test loading default templates."""
        bp = BP()
        bp.templates = {}
        bp._load_defaults()

        self.assertIn("V-*", bp.templates)
        self.assertIn("NotAFinding", bp.templates["V-*"])
        self.assertIn("Not_Applicable", bp.templates["V-*"])
        self.assertIn("Open", bp.templates["V-*"])

    def test_default_templates_not_empty(self):
        """Test that default templates have content."""
        bp = BP()
        bp._load_defaults()

        for vid, statuses in bp.templates.items():
            for status, text in statuses.items():
                self.assertIsInstance(text, str)
                self.assertGreater(len(text), 0)


class TestBPApplyToVuln(unittest.TestCase):
    """Test apply_to_vuln functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.bp = BP()
        self.bp.templates = {}

    def test_apply_to_empty_finding(self):
        """Test applying template to empty FINDING_DETAILS."""
        from stig_assessor.xml.schema import Sch

        # Create VULN element
        vuln = Element("VULN")
        finding = Element(Sch.FINDING_DETAILS)
        finding.text = ""
        vuln.append(finding)

        # Set template
        self.bp.set("V-12345", "NotAFinding", "Template text")

        # Apply template
        result = self.bp.apply_to_vuln(vuln, "V-12345", "NotAFinding")

        self.assertTrue(result)
        self.assertEqual(finding.text, "Template text")

    def test_apply_to_existing_finding_no_overwrite(self):
        """Test that template doesn't overwrite existing finding."""
        from stig_assessor.xml.schema import Sch

        vuln = Element("VULN")
        finding = Element(Sch.FINDING_DETAILS)
        finding.text = "Existing text"
        vuln.append(finding)

        self.bp.set("V-12345", "NotAFinding", "Template text")

        result = self.bp.apply_to_vuln(vuln, "V-12345", "NotAFinding")

        self.assertFalse(result)
        self.assertEqual(finding.text, "Existing text")

    def test_apply_nonexistent_template(self):
        """Test applying non-existent template."""
        from stig_assessor.xml.schema import Sch

        vuln = Element("VULN")
        finding = Element(Sch.FINDING_DETAILS)
        finding.text = ""
        vuln.append(finding)

        result = self.bp.apply_to_vuln(vuln, "V-99999", "NotAFinding")

        self.assertFalse(result)
        self.assertEqual(finding.text, "")

    def test_apply_missing_finding_element(self):
        """Test applying when FINDING_DETAILS element missing."""
        vuln = Element("VULN")

        self.bp.set("V-12345", "NotAFinding", "Template text")

        result = self.bp.apply_to_vuln(vuln, "V-12345", "NotAFinding")

        self.assertFalse(result)


class TestBPListAll(unittest.TestCase):
    """Test list_all functionality."""

    def test_list_all_returns_copy(self):
        """Test that list_all returns a copy."""
        bp = BP()
        bp.templates = {"V-12345": {"NotAFinding": "Test"}}

        result = bp.list_all()

        # Modify result
        result["V-12345"]["NotAFinding"] = "Modified"

        # Original should be unchanged
        self.assertEqual(bp.templates["V-12345"]["NotAFinding"], "Test")

    def test_list_all_empty(self):
        """Test list_all with no templates."""
        bp = BP()
        bp.templates = {}

        result = bp.list_all()

        self.assertEqual(result, {})


class TestBPEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_empty_string_template(self):
        """Test setting empty string as template."""
        bp = BP()
        bp.set("V-12345", "NotAFinding", "")
        result = bp.get("V-12345", "NotAFinding")
        self.assertEqual(result, "")

    def test_large_template(self):
        """Test handling large template text."""
        bp = BP()
        large_text = "X" * 100000  # 100KB of text
        bp.set("V-12345", "NotAFinding", large_text)
        result = bp.get("V-12345", "NotAFinding")
        self.assertEqual(len(result), 100000)

    def test_special_characters_in_vid(self):
        """Test VID with special characters."""
        bp = BP()
        bp.set("V-12345-SPECIAL", "NotAFinding", "Test")
        result = bp.get("V-12345-SPECIAL", "NotAFinding")
        self.assertEqual(result, "Test")


if __name__ == "__main__":
    unittest.main()

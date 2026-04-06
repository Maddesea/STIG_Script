"""
Tests for STIG Viewer 2.18 compatibility validator.

Team 5 Validation Module Tests 
(Migrated to standard unittest for zero-dependencies)
"""

import unittest
from pathlib import Path
import tempfile
import shutil
import xml.etree.ElementTree as ET

from tests.test_utils import sample_ckl_content


class TestValValidation(unittest.TestCase):
    """Test suite for the Val class validation methods."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="stig_val_test_"))
        
        # Valid CKL fixture
        self.valid_ckl_content = sample_ckl_content()
        self.valid_ckl_file = self.temp_dir / "valid.ckl"
        self.valid_ckl_file.write_text(self.valid_ckl_content, encoding='utf-8')

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_valid_ckl(self):
        """Test validation of a valid CKL file."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(self.valid_ckl_file)
            self.assertTrue(is_valid)
            self.assertEqual(len(errors), 0)
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_missing_file(self):
        """Test validation of non-existent file."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(self.temp_dir / "nonexistent.ckl")
            self.assertFalse(is_valid)
            self.assertGreater(len(errors), 0)
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_invalid_xml(self):
        """Test validation of invalid XML content."""
        try:
            from stig_assessor.validation import Val
            bad_file = self.temp_dir / "bad.ckl"
            bad_file.write_text("<CHECKLIST><NOT_CLOSED>", encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            self.assertFalse(is_valid)
            self.assertTrue(any("parse" in e.lower() or "xml" in e.lower() for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_missing_asset(self):
        """Test validation of CKL missing ASSET element."""
        try:
            from stig_assessor.validation import Val
            content = """<?xml version="1.0"?>
<CHECKLIST>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
        </iSTIG>
    </STIGS>
</CHECKLIST>"""
            bad_file = self.temp_dir / "no_asset.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            self.assertFalse(is_valid)
            self.assertTrue(any("ASSET" in e for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_missing_stigs(self):
        """Test validation of CKL missing STIGS element."""
        try:
            from stig_assessor.validation import Val
            content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <MARKING>CUI</MARKING>
        <HOST_NAME>TEST</HOST_NAME>
        <TARGET_KEY>1234</TARGET_KEY>
        <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
    </ASSET>
</CHECKLIST>"""
            bad_file = self.temp_dir / "no_stigs.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            self.assertFalse(is_valid)
            self.assertTrue(any("STIGS" in e for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_invalid_status(self):
        """Test validation catches invalid STATUS values."""
        try:
            from stig_assessor.validation import Val
            content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <MARKING>CUI</MARKING>
        <HOST_NAME>TEST</HOST_NAME>
        <TARGET_KEY>1234</TARGET_KEY>
        <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
            <VULN>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STATUS>InvalidStatus</STATUS>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>"""
            bad_file = self.temp_dir / "bad_status.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            self.assertFalse(is_valid)
            self.assertTrue(any("STATUS" in e or "Invalid" in e for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_invalid_web_or_database(self):
        """Test validation catches invalid WEB_OR_DATABASE values."""
        try:
            from stig_assessor.validation import Val
            content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <MARKING>CUI</MARKING>
        <HOST_NAME>TEST</HOST_NAME>
        <TARGET_KEY>1234</TARGET_KEY>
        <WEB_OR_DATABASE>yes</WEB_OR_DATABASE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
            <VULN>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STATUS>Not_Reviewed</STATUS>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>"""
            bad_file = self.temp_dir / "bad_web.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            self.assertFalse(is_valid)
            self.assertTrue(any("WEB_OR_DATABASE" in e for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_statistics(self):
        """Test that validation returns statistics in info."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(self.valid_ckl_file)
            self.assertTrue(any("vulnerabilities" in i.lower() for i in info))
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_strict_raises(self):
        """Test that validate_strict raises ValidationError on failure."""
        try:
            from stig_assessor.validation import Val
            from stig_assessor.exceptions import ValidationError
            content = "<CHECKLIST></CHECKLIST>"
            bad_file = self.temp_dir / "minimal.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            with self.assertRaises(ValidationError):
                validator.validate_strict(bad_file)
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_non_standard_marking_warning(self):
        """Test that non-standard MARKING produces a warning."""
        try:
            from stig_assessor.validation import Val
            content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <MARKING>CUSTOM_MARKING</MARKING>
        <HOST_NAME>TEST</HOST_NAME>
        <TARGET_KEY>1234</TARGET_KEY>
        <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
            <VULN>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STATUS>Not_Reviewed</STATUS>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>"""
            file = self.temp_dir / "custom_marking.ckl"
            file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(file)
            self.assertTrue(any("MARKING" in w for w in warnings))
        except ImportError:
            self.skipTest("Modular package not fully available")


class TestValXmlStructure(unittest.TestCase):
    """Test XML structure validation methods."""

    def test_validate_xml_structure_valid(self):
        """Test XML structure validation with valid root."""
        try:
            from stig_assessor.validation import Val
            xml_str = """<CHECKLIST>
                <ASSET></ASSET>
                <STIGS>
                    <iSTIG>
                        <STIG_INFO></STIG_INFO>
                    </iSTIG>
                </STIGS>
            </CHECKLIST>"""
            root = ET.fromstring(xml_str)
            validator = Val()
            is_valid, errors = validator.validate_xml_structure(root)
            self.assertTrue(is_valid)
            self.assertEqual(len(errors), 0)
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_validate_xml_structure_wrong_root(self):
        """Test XML structure validation with wrong root element."""
        try:
            from stig_assessor.validation import Val
            xml_str = "<WRONGROOT></WRONGROOT>"
            root = ET.fromstring(xml_str)
            validator = Val()
            is_valid, errors = validator.validate_xml_structure(root)
            self.assertFalse(is_valid)
            self.assertTrue(any("CHECKLIST" in e for e in errors))
        except ImportError:
            self.skipTest("Modular package not fully available")


class TestValSingletonInstance(unittest.TestCase):
    """Test the singleton validator instance."""

    def test_singleton_available(self):
        """Test that singleton validator instance is available."""
        try:
            from stig_assessor.validation import validator
            self.assertIsNotNone(validator)
        except ImportError:
            self.skipTest("Modular package not fully available")

    def test_singleton_is_val_instance(self):
        """Test that singleton is an instance of Val."""
        try:
            from stig_assessor.validation import Val, validator
            self.assertIsInstance(validator, Val)
        except ImportError:
            self.skipTest("Modular package not fully available")

if __name__ == '__main__':
    unittest.main()

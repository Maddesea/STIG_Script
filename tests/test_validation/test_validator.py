"""
Tests for STIG Viewer 2.18 compatibility validator.

Team 5 Validation Module Tests
"""

import pytest
from pathlib import Path
import tempfile
import shutil


class TestValValidation:
    """Test suite for the Val class validation methods."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        tmp = Path(tempfile.mkdtemp(prefix="stig_val_test_"))
        yield tmp
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)

    @pytest.fixture
    def valid_ckl_content(self):
        """Generate valid CKL content."""
        return """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
    <ASSET>
        <ROLE>Member Server</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <MARKING>CUI</MARKING>
        <HOST_NAME>TEST-SERVER</HOST_NAME>
        <HOST_IP>192.168.1.100</HOST_IP>
        <HOST_MAC>00:11:22:33:44:55</HOST_MAC>
        <HOST_FQDN>test-server.example.com</HOST_FQDN>
        <TARGET_COMMENT></TARGET_COMMENT>
        <TECH_AREA></TECH_AREA>
        <TARGET_KEY>1234</TARGET_KEY>
        <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
        <WEB_DB_SITE></WEB_DB_SITE>
        <WEB_DB_INSTANCE></WEB_DB_INSTANCE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO>
                <SI_DATA>
                    <SID_NAME>version</SID_NAME>
                    <SID_DATA>1</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>title</SID_NAME>
                    <SID_DATA>Test STIG</SID_DATA>
                </SI_DATA>
            </STIG_INFO>
            <VULN>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STATUS>Not_Reviewed</STATUS>
                <FINDING_DETAILS></FINDING_DETAILS>
                <COMMENTS></COMMENTS>
                <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
                <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>"""

    @pytest.fixture
    def valid_ckl_file(self, temp_dir, valid_ckl_content):
        """Create a valid CKL file."""
        ckl_file = temp_dir / "valid.ckl"
        ckl_file.write_text(valid_ckl_content, encoding='utf-8')
        return ckl_file

    def test_validate_valid_ckl(self, valid_ckl_file):
        """Test validation of a valid CKL file."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(valid_ckl_file)
            assert is_valid is True
            assert len(errors) == 0
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_missing_file(self, temp_dir):
        """Test validation of non-existent file."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(temp_dir / "nonexistent.ckl")
            assert is_valid is False
            assert len(errors) > 0
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_invalid_xml(self, temp_dir):
        """Test validation of invalid XML content."""
        try:
            from stig_assessor.validation import Val
            bad_file = temp_dir / "bad.ckl"
            bad_file.write_text("<CHECKLIST><NOT_CLOSED>", encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            assert is_valid is False
            assert any("parse" in e.lower() or "xml" in e.lower() for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_missing_asset(self, temp_dir):
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
            bad_file = temp_dir / "no_asset.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            assert is_valid is False
            assert any("ASSET" in e for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_missing_stigs(self, temp_dir):
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
            bad_file = temp_dir / "no_stigs.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            assert is_valid is False
            assert any("STIGS" in e for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_invalid_status(self, temp_dir):
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
            bad_file = temp_dir / "bad_status.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            assert is_valid is False
            assert any("STATUS" in e or "Invalid" in e for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_invalid_web_or_database(self, temp_dir):
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
            bad_file = temp_dir / "bad_web.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(bad_file)
            assert is_valid is False
            assert any("WEB_OR_DATABASE" in e for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_statistics(self, valid_ckl_file):
        """Test that validation returns statistics in info."""
        try:
            from stig_assessor.validation import Val
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(valid_ckl_file)
            assert any("vulnerabilities" in i.lower() for i in info)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_strict_raises(self, temp_dir):
        """Test that validate_strict raises ValidationError on failure."""
        try:
            from stig_assessor.validation import Val
            from stig_assessor.exceptions import ValidationError
            content = "<CHECKLIST></CHECKLIST>"
            bad_file = temp_dir / "minimal.ckl"
            bad_file.write_text(content, encoding='utf-8')
            validator = Val()
            with pytest.raises(ValidationError):
                validator.validate_strict(bad_file)
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_non_standard_marking_warning(self, temp_dir):
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
            file = temp_dir / "custom_marking.ckl"
            file.write_text(content, encoding='utf-8')
            validator = Val()
            is_valid, errors, warnings, info = validator.validate(file)
            # Non-standard marking should produce warning, not error
            assert any("MARKING" in w for w in warnings)
        except ImportError:
            pytest.skip("Modular package not fully available")


class TestValXmlStructure:
    """Test XML structure validation methods."""

    def test_validate_xml_structure_valid(self):
        """Test XML structure validation with valid root."""
        try:
            from stig_assessor.validation import Val
            import xml.etree.ElementTree as ET
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
            assert is_valid is True
            assert len(errors) == 0
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_validate_xml_structure_wrong_root(self):
        """Test XML structure validation with wrong root element."""
        try:
            from stig_assessor.validation import Val
            import xml.etree.ElementTree as ET
            xml_str = "<WRONGROOT></WRONGROOT>"
            root = ET.fromstring(xml_str)
            validator = Val()
            is_valid, errors = validator.validate_xml_structure(root)
            assert is_valid is False
            assert any("CHECKLIST" in e for e in errors)
        except ImportError:
            pytest.skip("Modular package not fully available")


class TestValSingletonInstance:
    """Test the singleton validator instance."""

    def test_singleton_available(self):
        """Test that singleton validator instance is available."""
        try:
            from stig_assessor.validation import validator
            assert validator is not None
        except ImportError:
            pytest.skip("Modular package not fully available")

    def test_singleton_is_val_instance(self):
        """Test that singleton is an instance of Val."""
        try:
            from stig_assessor.validation import Val, validator
            assert isinstance(validator, Val)
        except ImportError:
            pytest.skip("Modular package not fully available")

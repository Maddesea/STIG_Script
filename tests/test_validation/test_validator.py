"""
Tests for STIG Viewer validation module.

Tests CKL and XCCDF validation functions for STIG Viewer 2.18 compatibility.
"""

from __future__ import annotations
import pytest
import xml.etree.ElementTree as ET
from pathlib import Path

from stig_assessor.validation.validator import Val
from stig_assessor.exceptions import ValidationError
from stig_assessor.core.constants import Status, Severity


class TestValValidateCKL:
    """Tests for Val.validate_ckl() method."""

    def test_valid_minimal_ckl(self):
        """Test validation of minimal valid CKL structure."""
        xml_content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>TestHost</HOST_NAME>
        <HOST_IP>192.168.1.1</HOST_IP>
        <HOST_MAC>00:11:22:33:44:55</HOST_MAC>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO>
                <SI_DATA>
                    <SID_NAME>version</SID_NAME>
                    <SID_DATA>1</SID_DATA>
                </SI_DATA>
            </STIG_INFO>
            <VULN>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test Group</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>TEST-01</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test Rule</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test discussion</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test check</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test fix</ATTRIBUTE_DATA>
                </STIG_DATA>
                <STATUS>Not_Reviewed</STATUS>
                <FINDING_DETAILS></FINDING_DETAILS>
                <COMMENTS></COMMENTS>
            </VULN>
        </iSTIG>
    </STIGS>
</CHECKLIST>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["valid"] is True
        assert len(report["errors"]) == 0
        assert report["vuln_count"] == 1

    def test_invalid_root_element(self):
        """Test validation fails with invalid root element."""
        xml_content = """<?xml version="1.0"?>
<INVALID_ROOT>
    <ASSET><ROLE>None</ROLE></ASSET>
</INVALID_ROOT>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["valid"] is False
        assert any("Invalid root element" in e for e in report["errors"])

    def test_missing_asset_element(self):
        """Test validation fails when ASSET element is missing."""
        xml_content = """<?xml version="1.0"?>
<CHECKLIST>
    <STIGS>
        <iSTIG></iSTIG>
    </STIGS>
</CHECKLIST>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["valid"] is False
        assert any("Missing required ASSET" in e for e in report["errors"])

    def test_missing_stigs_element(self):
        """Test validation fails when STIGS element is missing."""
        xml_content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>Test</HOST_NAME>
    </ASSET>
</CHECKLIST>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["valid"] is False
        assert any("Missing required STIGS" in e for e in report["errors"])

    def test_missing_istig_element(self):
        """Test validation fails when iSTIG element is missing."""
        xml_content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>Test</HOST_NAME>
    </ASSET>
    <STIGS>
    </STIGS>
</CHECKLIST>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["valid"] is False
        assert any("Missing required iSTIG" in e for e in report["errors"])

    def test_no_vulnerabilities_warning(self):
        """Test warning is generated when no vulnerabilities found."""
        xml_content = """<?xml version="1.0"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
        <HOST_NAME>Test</HOST_NAME>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO></STIG_INFO>
        </iSTIG>
    </STIGS>
</CHECKLIST>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))
        report = Val.validate_ckl(tree, strict=False)

        assert report["vuln_count"] == 0
        assert any("No vulnerabilities" in w for w in report["warnings"])

    def test_strict_mode_raises_exception(self):
        """Test strict mode raises ValidationError on validation failure."""
        xml_content = """<?xml version="1.0"?>
<INVALID_ROOT>
</INVALID_ROOT>
"""
        tree = ET.ElementTree(ET.fromstring(xml_content))

        with pytest.raises(ValidationError) as exc_info:
            Val.validate_ckl(tree, strict=True)

        assert "validation failed" in str(exc_info.value).lower()


class TestValValidateVuln:
    """Tests for Val._validate_vuln() method."""

    def test_valid_vuln_element(self):
        """Test validation of valid VULN element."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>TEST-01</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STATUS>NotAFinding</STATUS>
    <FINDING_DETAILS>Test details</FINDING_DETAILS>
    <COMMENTS>Test comments</COMMENTS>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert len(errors) == 0

    def test_missing_required_attributes(self):
        """Test validation detects missing required attributes."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STATUS>Open</STATUS>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert len(errors) > 0
        assert any("Missing required attributes" in e for e in errors)

    def test_missing_status_element(self):
        """Test validation detects missing STATUS element."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert any("Missing STATUS" in e for e in errors)

    def test_invalid_status_value(self):
        """Test validation detects invalid STATUS value."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>TEST-01</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STATUS>InvalidStatus</STATUS>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert any("Invalid status" in e for e in errors)

    def test_invalid_severity_value(self):
        """Test validation detects invalid Severity value."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>invalid</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>TEST-01</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STATUS>Open</STATUS>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert any("Invalid severity" in e for e in errors)

    def test_empty_status_element(self):
        """Test validation detects empty STATUS element."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>V-123456</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>TEST-01</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>Test</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STATUS></STATUS>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        errors = Val._validate_vuln(vuln)

        assert any("STATUS element is empty" in e for e in errors)


class TestValFindStigData:
    """Tests for Val._find_stig_data() helper method."""

    def test_find_existing_attribute(self):
        """Test finding an existing STIG_DATA attribute."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
    </STIG_DATA>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>SV-123456r1_rule</ATTRIBUTE_DATA>
    </STIG_DATA>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        severity = Val._find_stig_data(vuln, "Severity")

        assert severity == "medium"

    def test_find_nonexistent_attribute(self):
        """Test finding a nonexistent STIG_DATA attribute returns None."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
    </STIG_DATA>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        result = Val._find_stig_data(vuln, "NonExistent")

        assert result is None

    def test_find_attribute_whitespace_handling(self):
        """Test that attribute values are stripped of whitespace."""
        vuln_xml = """
<VULN>
    <STIG_DATA>
        <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
        <ATTRIBUTE_DATA>  low  </ATTRIBUTE_DATA>
    </STIG_DATA>
</VULN>
"""
        vuln = ET.fromstring(vuln_xml)
        severity = Val._find_stig_data(vuln, "Severity")

        assert severity == "low"


class TestValValidateXCCDF:
    """Tests for Val.validate_xccdf() method."""

    def test_valid_xccdf_with_namespace(self):
        """Test validation of valid XCCDF with namespace."""
        xccdf_xml = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
    <Group id="V-123456">
        <title>Test Group</title>
        <Rule id="SV-123456r1_rule" severity="high">
            <title>Test Rule</title>
        </Rule>
    </Group>
</Benchmark>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert report["valid"] is True
        assert len(report["errors"]) == 0
        assert report["rule_count"] == 1
        assert report["group_count"] == 1

    def test_valid_xccdf_without_namespace(self):
        """Test validation of valid XCCDF without namespace."""
        xccdf_xml = """<?xml version="1.0"?>
<Benchmark>
    <Group id="V-123456">
        <title>Test Group</title>
        <Rule id="SV-123456r1_rule" severity="high">
            <title>Test Rule</title>
        </Rule>
    </Group>
</Benchmark>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert report["valid"] is True
        assert report["rule_count"] == 1
        assert report["group_count"] == 1

    def test_invalid_xccdf_root(self):
        """Test validation fails with invalid root element."""
        xccdf_xml = """<?xml version="1.0"?>
<InvalidRoot>
</InvalidRoot>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert report["valid"] is False
        assert any("Invalid root element" in e for e in report["errors"])

    def test_xccdf_no_groups_warning(self):
        """Test warning when no groups found in XCCDF."""
        xccdf_xml = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
</Benchmark>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert any("No Group elements" in w for w in report["warnings"])

    def test_xccdf_no_rules_warning(self):
        """Test warning when no rules found in XCCDF."""
        xccdf_xml = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
    <Group id="test">
        <title>Test</title>
    </Group>
</Benchmark>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert any("No Rule elements" in w for w in report["warnings"])

    def test_xccdf_multiple_groups_and_rules(self):
        """Test XCCDF with multiple groups and rules."""
        xccdf_xml = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
    <Group id="V-123456">
        <Rule id="SV-123456r1_rule" severity="high">
            <title>Rule 1</title>
        </Rule>
        <Rule id="SV-123457r1_rule" severity="medium">
            <title>Rule 2</title>
        </Rule>
    </Group>
    <Group id="V-789012">
        <Rule id="SV-789012r1_rule" severity="low">
            <title>Rule 3</title>
        </Rule>
    </Group>
</Benchmark>
"""
        tree = ET.ElementTree(ET.fromstring(xccdf_xml))
        report = Val.validate_xccdf(tree)

        assert report["valid"] is True
        assert report["group_count"] == 2
        assert report["rule_count"] == 3


class TestValCheckErrorThreshold:
    """Tests for Val.check_error_threshold() method."""

    def test_zero_total_no_exception(self):
        """Test no exception when total is 0."""
        # Should not raise
        Val.check_error_threshold(total=0, errors=0)

    def test_under_threshold_no_exception(self):
        """Test no exception when error rate is under threshold."""
        # 10% error rate (under 25% threshold)
        Val.check_error_threshold(total=100, errors=10)

    def test_at_threshold_no_exception(self):
        """Test no exception when error rate equals threshold."""
        # 25% error rate (at 25% threshold)
        Val.check_error_threshold(total=100, errors=25)

    def test_over_threshold_raises_exception(self):
        """Test exception raised when error rate exceeds threshold."""
        # 30% error rate (over 25% threshold)
        with pytest.raises(ValidationError) as exc_info:
            Val.check_error_threshold(total=100, errors=30)

        error_msg = str(exc_info.value)
        assert "30.0%" in error_msg or "30%" in error_msg
        assert "25" in error_msg
        assert "30/100" in error_msg

    def test_high_error_rate(self):
        """Test exception with very high error rate."""
        # 50% error rate
        with pytest.raises(ValidationError):
            Val.check_error_threshold(total=200, errors=100)

    def test_edge_case_one_error(self):
        """Test with minimal error count."""
        # 1% error rate (well under threshold)
        Val.check_error_threshold(total=100, errors=1)

    def test_edge_case_all_errors(self):
        """Test with all items failed."""
        # 100% error rate (well over threshold)
        with pytest.raises(ValidationError):
            Val.check_error_threshold(total=50, errors=50)


class TestValRequiredAttrs:
    """Tests for REQUIRED_ATTRS constant."""

    def test_required_attrs_is_frozenset(self):
        """Test REQUIRED_ATTRS is a frozen set."""
        assert isinstance(Val.REQUIRED_ATTRS, frozenset)

    def test_required_attrs_contains_critical_fields(self):
        """Test REQUIRED_ATTRS contains critical vulnerability fields."""
        critical_fields = [
            "Vuln_Num",
            "Severity",
            "Group_Title",
            "Rule_ID",
            "Rule_Ver",
            "Rule_Title",
            "Vuln_Discuss",
            "Check_Content",
            "Fix_Text",
        ]

        for field in critical_fields:
            assert field in Val.REQUIRED_ATTRS

    def test_required_attrs_not_empty(self):
        """Test REQUIRED_ATTRS is not empty."""
        assert len(Val.REQUIRED_ATTRS) > 0

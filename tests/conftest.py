"""
Pytest configuration and shared fixtures for STIG Assessor tests.

This module provides:
- Common test fixtures
- Test data generators
- Mock objects
- Temporary file/directory management
- Shared test utilities
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import xml.etree.ElementTree as ET


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files.

    Yields:
        Path to temporary directory

    Cleanup:
        Automatically removes directory after test
    """
    tmp = Path(tempfile.mkdtemp(prefix="stig_test_"))
    try:
        yield tmp
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_xccdf_content() -> str:
    """Generate sample XCCDF benchmark content for testing.

    Returns:
        Valid XCCDF XML string
    """
    return """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           id="TEST_STIG">
    <title>Test STIG Benchmark</title>
    <description>Sample STIG for testing</description>
    <version>1</version>
    <Group id="V-123456">
        <title>Test Vulnerability</title>
        <description>Test description</description>
        <Rule id="SV-123456r1_rule" severity="medium">
            <version>TEST-001</version>
            <title>Test Rule Title</title>
            <description>Rule description</description>
            <fixtext fixref="F-123456">
                Run this command:
                systemctl enable test.service
            </fixtext>
            <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <check-content>Check content here</check-content>
            </check>
            <ident system="http://cyber.mil/cci">CCI-000001</ident>
        </Rule>
    </Group>
    <Group id="V-234567">
        <title>Another Vulnerability</title>
        <description>Another test</description>
        <Rule id="SV-234567r1_rule" severity="high">
            <version>TEST-002</version>
            <title>Second Rule</title>
            <description>Second rule description</description>
            <fixtext fixref="F-234567">No fix available</fixtext>
            <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <check-content>Check this</check-content>
            </check>
            <ident system="http://cyber.mil/cci">CCI-000002</ident>
        </Rule>
    </Group>
</Benchmark>"""


@pytest.fixture
def sample_ckl_content() -> str:
    """Generate sample CKL checklist content for testing.

    Returns:
        Valid CKL XML string
    """
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
                    <SID_NAME>releaseinfo</SID_NAME>
                    <SID_DATA>Release: 1 Benchmark Date: 01 Jan 2025</SID_DATA>
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
                <STIG_DATA>
                    <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
                    <ATTRIBUTE_DATA>Test Rule Title</ATTRIBUTE_DATA>
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
def sample_xccdf_file(temp_dir: Path, sample_xccdf_content: str) -> Path:
    """Create a temporary XCCDF file for testing.

    Args:
        temp_dir: Temporary directory fixture
        sample_xccdf_content: Sample XCCDF content fixture

    Returns:
        Path to created XCCDF file
    """
    xccdf_file = temp_dir / "test_benchmark.xml"
    xccdf_file.write_text(sample_xccdf_content, encoding='utf-8')
    return xccdf_file


@pytest.fixture
def sample_ckl_file(temp_dir: Path, sample_ckl_content: str) -> Path:
    """Create a temporary CKL file for testing.

    Args:
        temp_dir: Temporary directory fixture
        sample_ckl_content: Sample CKL content fixture

    Returns:
        Path to created CKL file
    """
    ckl_file = temp_dir / "test_checklist.ckl"
    ckl_file.write_text(sample_ckl_content, encoding='utf-8')
    return ckl_file


@pytest.fixture
def sample_remediation_json() -> str:
    """Generate sample remediation results JSON for testing.

    Returns:
        JSON string with remediation results
    """
    return """{
    "results": [
        {
            "vid": "V-123456",
            "status": "NotAFinding",
            "finding_details": "Fix applied successfully. Service enabled.",
            "comments": "Automated remediation completed on 2025-11-16"
        },
        {
            "vid": "V-234567",
            "status": "Open",
            "finding_details": "Fix failed. Manual intervention required.",
            "comments": "Error: Permission denied"
        }
    ]
}"""


# ============================================================================
# Mock Object Fixtures
# ============================================================================

@pytest.fixture
def mock_logger(monkeypatch):
    """Create a mock logger that captures log messages.

    Usage:
        def test_something(mock_logger):
            # Your test code
            assert "Expected message" in mock_logger.messages
    """
    class MockLogger:
        def __init__(self):
            self.messages = []

        def debug(self, msg, **kwargs):
            self.messages.append(("DEBUG", msg))

        def info(self, msg, **kwargs):
            self.messages.append(("INFO", msg))

        def warning(self, msg, **kwargs):
            self.messages.append(("WARNING", msg))

        def error(self, msg, **kwargs):
            self.messages.append(("ERROR", msg))

        def critical(self, msg, **kwargs):
            self.messages.append(("CRITICAL", msg))

    logger = MockLogger()
    return logger


# ============================================================================
# Test Utilities
# ============================================================================

def create_test_ckl(temp_dir: Path, num_vulns: int = 100) -> Path:
    """Create a test CKL file with specified number of vulnerabilities.

    Args:
        temp_dir: Directory to create file in
        num_vulns: Number of VULN elements to create

    Returns:
        Path to created CKL file
    """
    root = ET.Element("CHECKLIST")

    # Add ASSET with all required fields
    asset = ET.SubElement(root, "ASSET")
    ET.SubElement(asset, "ROLE").text = "Member Server"
    ET.SubElement(asset, "ASSET_TYPE").text = "Computing"
    ET.SubElement(asset, "MARKING").text = "CUI"
    ET.SubElement(asset, "HOST_NAME").text = "TEST-SERVER"
    ET.SubElement(asset, "HOST_IP").text = "192.168.1.100"
    ET.SubElement(asset, "HOST_MAC").text = "00:11:22:33:44:55"
    ET.SubElement(asset, "HOST_FQDN").text = "test-server.example.com"
    ET.SubElement(asset, "TARGET_COMMENT").text = ""
    ET.SubElement(asset, "TECH_AREA").text = ""
    ET.SubElement(asset, "TARGET_KEY").text = "1234"
    ET.SubElement(asset, "WEB_OR_DATABASE").text = "false"
    ET.SubElement(asset, "WEB_DB_SITE").text = ""
    ET.SubElement(asset, "WEB_DB_INSTANCE").text = ""

    # Add STIGS
    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")

    # Add STIG_INFO
    stig_info = ET.SubElement(istig, "STIG_INFO")
    si_data = ET.SubElement(stig_info, "SI_DATA")
    ET.SubElement(si_data, "SID_NAME").text = "title"
    ET.SubElement(si_data, "SID_DATA").text = "Test STIG"

    # Add VULNs
    for i in range(num_vulns):
        vuln = ET.SubElement(istig, "VULN")

        # Vuln_Num
        sd = ET.SubElement(vuln, "STIG_DATA")
        ET.SubElement(sd, "VULN_ATTRIBUTE").text = "Vuln_Num"
        ET.SubElement(sd, "ATTRIBUTE_DATA").text = f"V-{100000 + i}"

        # Severity
        sd = ET.SubElement(vuln, "STIG_DATA")
        ET.SubElement(sd, "VULN_ATTRIBUTE").text = "Severity"
        ET.SubElement(sd, "ATTRIBUTE_DATA").text = "medium"

        # Status
        ET.SubElement(vuln, "STATUS").text = "Not_Reviewed"
        ET.SubElement(vuln, "FINDING_DETAILS").text = ""
        ET.SubElement(vuln, "COMMENTS").text = ""

    # Write file
    tree = ET.ElementTree(root)
    output_path = temp_dir / f"test_{num_vulns}_vulns.ckl"
    tree.write(output_path, encoding='utf-8', xml_declaration=True)

    return output_path


def assert_valid_ckl_structure(ckl_path: Path) -> bool:
    """Validate that a CKL file has the correct structure.

    Args:
        ckl_path: Path to CKL file

    Returns:
        True if valid

    Raises:
        AssertionError if structure is invalid
    """
    tree = ET.parse(ckl_path)
    root = tree.getroot()

    assert root.tag == "CHECKLIST", "Root element must be CHECKLIST"
    assert root.find("ASSET") is not None, "ASSET element required"
    assert root.find("STIGS") is not None, "STIGS element required"

    asset = root.find("ASSET")
    assert asset.find("ROLE") is not None, "ASSET/ROLE required"
    assert asset.find("ASSET_TYPE") is not None, "ASSET/ASSET_TYPE required"
    assert asset.find("HOST_NAME") is not None, "ASSET/HOST_NAME required"

    stigs = root.find("STIGS")
    istig = stigs.find("iSTIG")
    assert istig is not None, "iSTIG element required"
    assert istig.find("STIG_INFO") is not None, "STIG_INFO required"

    return True


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "gui: marks tests that require GUI (tkinter)"
    )

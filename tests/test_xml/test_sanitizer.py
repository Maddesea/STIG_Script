"""Tests for XML sanitizer module (San class).

Tests cover:
- Path validation and security checks
- IP address validation
- MAC address validation
- Vulnerability ID validation
- Status and severity validation
- XML sanitization and entity escaping
"""

import unittest
import tempfile
from pathlib import Path

from stig_assessor.xml.sanitizer import San
from stig_assessor.exceptions import ValidationError


class TestPathValidation(unittest.TestCase):
    """Test path validation and sanitization."""

    def test_valid_path(self):
        """Test validation of a valid path."""
        result = San.path("/tmp/test.txt")
        self.assertIsInstance(result, Path)

    def test_empty_path_raises(self):
        """Test that empty path raises ValidationError."""
        with self.assertRaises(ValidationError):
            San.path("")
        with self.assertRaises(ValidationError):
            San.path("   ")

    def test_null_byte_raises(self):
        """Test that null byte in path raises ValidationError."""
        with self.assertRaises(ValidationError):
            San.path("/tmp/test\x00.txt")

    def test_path_expansion(self):
        """Test that ~ is expanded in paths."""
        result = San.path("~/test.txt")
        self.assertNotIn("~", str(result))

    def test_mkpar_creates_parent(self):
        """Test that mkpar creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "subdir" / "file.txt"
            result = San.path(test_path, mkpar=True)
            self.assertTrue(result.parent.exists())

    def test_exist_check(self):
        """Test exist parameter validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            try:
                # Should not raise for existing file
                San.path(tf.name, exist=True)

                # Should raise for non-existent file
                with self.assertRaises(ValidationError):
                    San.path("/nonexistent/file.txt", exist=True)
            finally:
                Path(tf.name).unlink()

    def test_file_check(self):
        """Test file parameter validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            try:
                # Should not raise for file
                San.path(tf.name, file=True)
            finally:
                Path(tf.name).unlink()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Should raise for directory
            with self.assertRaises(ValidationError):
                San.path(tmpdir, file=True)

    def test_dir_check(self):
        """Test dir parameter validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not raise for directory
            San.path(tmpdir, dir=True)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            try:
                # Should raise for file
                with self.assertRaises(ValidationError):
                    San.path(tf.name, dir=True)
            finally:
                Path(tf.name).unlink()


class TestIPValidation(unittest.TestCase):
    """Test IP address validation."""

    def test_valid_ip(self):
        """Test validation of valid IP addresses."""
        self.assertEqual(San.ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(San.ip("10.0.0.1"), "10.0.0.1")
        self.assertEqual(San.ip("255.255.255.255"), "255.255.255.255")
        self.assertEqual(San.ip("0.0.0.0"), "0.0.0.0")

    def test_empty_ip(self):
        """Test that empty IP returns empty string."""
        self.assertEqual(San.ip(""), "")
        self.assertEqual(San.ip("   "), "")

    def test_invalid_ip_raises(self):
        """Test that invalid IP formats raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.ip("256.1.1.1")  # Octet > 255
        with self.assertRaises(ValidationError):
            San.ip("192.168.1")  # Only 3 octets
        with self.assertRaises(ValidationError):
            San.ip("192.168.1.1.1")  # 5 octets
        with self.assertRaises(ValidationError):
            San.ip("abc.def.ghi.jkl")  # Non-numeric

    def test_leading_zeros_raises(self):
        """Test that leading zeros in octets raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.ip("192.001.001.001")
        with self.assertRaises(ValidationError):
            San.ip("010.0.0.1")


class TestMACValidation(unittest.TestCase):
    """Test MAC address validation."""

    def test_valid_mac_colon(self):
        """Test validation of MAC address with colon separators."""
        result = San.mac("00:11:22:33:44:55")
        self.assertEqual(result, "00:11:22:33:44:55")

    def test_valid_mac_hyphen(self):
        """Test validation of MAC address with hyphen separators."""
        result = San.mac("00-11-22-33-44-55")
        self.assertEqual(result, "00:11:22:33:44:55")  # Normalized to colons

    def test_empty_mac(self):
        """Test that empty MAC returns empty string."""
        self.assertEqual(San.mac(""), "")
        self.assertEqual(San.mac("   "), "")

    def test_uppercase_normalization(self):
        """Test that MAC address is normalized to uppercase."""
        result = San.mac("aa:bb:cc:dd:ee:ff")
        self.assertEqual(result, "AA:BB:CC:DD:EE:FF")

    def test_invalid_mac_raises(self):
        """Test that invalid MAC formats raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.mac("00:11:22:33:44")  # Too short
        with self.assertRaises(ValidationError):
            San.mac("00:11:22:33:44:55:66")  # Too long
        with self.assertRaises(ValidationError):
            San.mac("ZZ:11:22:33:44:55")  # Invalid hex


class TestVulnIDValidation(unittest.TestCase):
    """Test vulnerability ID validation."""

    def test_valid_vuln_id(self):
        """Test validation of valid vulnerability IDs."""
        self.assertEqual(San.vuln("V-123456"), "V-123456")
        self.assertEqual(San.vuln("V-1"), "V-1")
        self.assertEqual(San.vuln("V-1234567890"), "V-1234567890")

    def test_empty_vuln_raises(self):
        """Test that empty vulnerability ID raises ValidationError."""
        with self.assertRaises(ValidationError):
            San.vuln("")
        with self.assertRaises(ValidationError):
            San.vuln("   ")

    def test_invalid_vuln_raises(self):
        """Test that invalid vulnerability ID formats raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.vuln("123456")  # Missing V-
        with self.assertRaises(ValidationError):
            San.vuln("V123456")  # Missing hyphen
        with self.assertRaises(ValidationError):
            San.vuln("V-")  # No number
        with self.assertRaises(ValidationError):
            San.vuln("V-ABC")  # Non-numeric


class TestStatusValidation(unittest.TestCase):
    """Test status value validation."""

    def test_valid_status(self):
        """Test validation of valid status values."""
        self.assertEqual(San.status("NotAFinding"), "NotAFinding")
        self.assertEqual(San.status("Open"), "Open")
        self.assertEqual(San.status("Not_Reviewed"), "Not_Reviewed")
        self.assertEqual(San.status("Not_Applicable"), "Not_Applicable")

    def test_empty_status_defaults(self):
        """Test that empty status defaults to Not_Reviewed."""
        self.assertEqual(San.status(""), "Not_Reviewed")
        self.assertEqual(San.status(None), "Not_Reviewed")

    def test_invalid_status_raises(self):
        """Test that invalid status values raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.status("Invalid")
        with self.assertRaises(ValidationError):
            San.status("OPEN")  # Wrong case


class TestSeverityValidation(unittest.TestCase):
    """Test severity value validation."""

    def test_valid_severity(self):
        """Test validation of valid severity values."""
        self.assertEqual(San.sev("high"), "high")
        self.assertEqual(San.sev("medium"), "medium")
        self.assertEqual(San.sev("low"), "low")

    def test_case_normalization(self):
        """Test that severity values are normalized to lowercase."""
        self.assertEqual(San.sev("HIGH"), "high")
        self.assertEqual(San.sev("Medium"), "medium")
        self.assertEqual(San.sev("LOW"), "low")

    def test_empty_severity_defaults(self):
        """Test that empty severity defaults to medium (non-strict mode)."""
        self.assertEqual(San.sev(""), "medium")
        self.assertEqual(San.sev(None), "medium")

    def test_empty_severity_strict_raises(self):
        """Test that empty severity raises in strict mode."""
        with self.assertRaises(ValidationError):
            San.sev("", strict=True)

    def test_invalid_severity_defaults(self):
        """Test that invalid severity defaults to medium (non-strict mode)."""
        self.assertEqual(San.sev("invalid"), "medium")
        self.assertEqual(San.sev("critical"), "medium")

    def test_invalid_severity_strict_raises(self):
        """Test that invalid severity raises in strict mode."""
        with self.assertRaises(ValidationError):
            San.sev("invalid", strict=True)


class TestAssetValidation(unittest.TestCase):
    """Test asset name validation."""

    def test_valid_asset(self):
        """Test validation of valid asset names."""
        self.assertEqual(San.asset("SERVER-01"), "SERVER-01")
        self.assertEqual(San.asset("web.server.01"), "web.server.01")
        self.assertEqual(San.asset("test_server"), "test_server")

    def test_empty_asset_raises(self):
        """Test that empty asset name raises ValidationError."""
        with self.assertRaises(ValidationError):
            San.asset("")
        with self.assertRaises(ValidationError):
            San.asset("   ")

    def test_asset_truncation(self):
        """Test that asset name is truncated to 255 characters."""
        long_name = "a" * 300
        result = San.asset(long_name)
        self.assertEqual(len(result), 255)

    def test_invalid_asset_raises(self):
        """Test that invalid asset names raise ValidationError."""
        with self.assertRaises(ValidationError):
            San.asset("server name")  # Space not allowed
        with self.assertRaises(ValidationError):
            San.asset("server@host")  # @ not allowed


class TestXMLSanitization(unittest.TestCase):
    """Test XML sanitization and entity escaping."""

    def test_entity_escaping(self):
        """Test that XML entities are properly escaped."""
        result = San.xml("test & value")
        self.assertEqual(result, "test &amp; value")

        result = San.xml("<tag>")
        self.assertEqual(result, "&lt;tag&gt;")

        result = San.xml('"quoted"')
        self.assertEqual(result, "&quot;quoted&quot;")

        result = San.xml("'quoted'")
        self.assertEqual(result, "&apos;quoted&apos;")

    def test_control_character_removal(self):
        """Test that control characters are removed."""
        result = San.xml("test\x00value")
        self.assertEqual(result, "testvalue")

        result = San.xml("test\x1Fvalue")
        self.assertEqual(result, "testvalue")

    def test_none_returns_empty(self):
        """Test that None returns empty string."""
        self.assertEqual(San.xml(None), "")

    def test_non_string_conversion(self):
        """Test that non-strings are converted."""
        self.assertEqual(San.xml(123), "123")
        self.assertEqual(San.xml(45.67), "45.67")

    def test_truncation(self):
        """Test that long strings are truncated."""
        long_string = "a" * 1000
        result = San.xml(long_string, mx=100)
        self.assertLess(len(result), 100)
        self.assertIn("[TRUNCATED]", result)

    def test_combined_escaping(self):
        """Test multiple escape sequences."""
        result = San.xml("<script>alert('test & \"value\"')</script>")
        self.assertEqual(
            result,
            "&lt;script&gt;alert(&apos;test &amp; &quot;value&quot;&apos;)&lt;/script&gt;"
        )


if __name__ == "__main__":
    unittest.main()

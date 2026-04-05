#!/usr/bin/env python3
"""Quick test script for Team 3 file operations.

This script tests basic functionality of the file operations module to ensure
Team 3's implementation is working correctly.
"""

import tempfile
from pathlib import Path

from stig_assessor.io import FO, retry


def test_atomic_write():
    """Test atomic write operation."""
    print("Testing atomic write...")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.txt"
        content = "Hello, STIG Assessor!"

        with FO.atomic(test_file) as f:
            f.write(content)

        assert test_file.exists(), "File was not created"
        assert test_file.read_text() == content, "Content mismatch"
        print("✓ Atomic write successful")


def test_read_with_encoding():
    """Test read with encoding detection."""
    print("Testing read with encoding detection...")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "utf8.txt"
        content = "UTF-8 content with emojis: 🎉 🚀"
        test_file.write_text(content, encoding="utf-8")

        result = FO.read(test_file)
        assert result == content, "UTF-8 read failed"
        print("✓ Encoding detection successful")


def test_parse_xml():
    """Test XML parsing."""
    print("Testing XML parsing...")
    with tempfile.TemporaryDirectory() as tmpdir:
        xml_file = Path(tmpdir) / "test.xml"
        xml_content = '<?xml version="1.0"?><root><item id="1">Test</item></root>'
        xml_file.write_text(xml_content)

        tree = FO.parse_xml(xml_file)
        root = tree.getroot()
        assert root.tag == "root", "XML parse failed"
        assert root.find("item").text == "Test", "XML content mismatch"
        print("✓ XML parsing successful")


def test_zip_creation():
    """Test ZIP archive creation."""
    print("Testing ZIP archive creation...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Create test files
        file1 = tmpdir_path / "file1.txt"
        file2 = tmpdir_path / "file2.txt"
        file1.write_text("Content 1")
        file2.write_text("Content 2")

        # Create ZIP
        zip_path = tmpdir_path / "archive.zip"
        files = {"file1.txt": file1, "file2.txt": file2}

        result = FO.zip(zip_path, files)
        assert result.exists(), "ZIP not created"
        assert result == zip_path, "ZIP path mismatch"
        print("✓ ZIP creation successful")


def test_retry_decorator():
    """Test retry decorator."""
    print("Testing retry decorator...")

    call_count = [0]

    @retry(attempts=3, delay=0.01)
    def failing_function():
        call_count[0] += 1
        if call_count[0] < 2:
            raise IOError("Temporary failure")
        return "success"

    result = failing_function()
    assert result == "success", "Retry failed"
    assert call_count[0] == 2, f"Expected 2 calls, got {call_count[0]}"
    print("✓ Retry decorator successful")


def main():
    """Run all tests."""
    print("=" * 60)
    print("TEAM 3 FILE OPERATIONS TEST SUITE")
    print("=" * 60)
    print()

    tests = [
        test_atomic_write,
        test_read_with_encoding,
        test_parse_xml,
        test_zip_creation,
        test_retry_decorator,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
            print()
        except Exception as e:
            failed += 1
            print(f"✗ Test failed: {e}")
            print()

    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)

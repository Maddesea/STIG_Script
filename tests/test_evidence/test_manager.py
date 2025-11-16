"""Tests for evidence manager.

Team: 9 - Evidence Management
"""

import unittest
import tempfile
import shutil
import json
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from stig_assessor.evidence.manager import EvidenceMgr
from stig_assessor.evidence.models import EvidenceMeta


class TestEvidenceMgr(unittest.TestCase):
    """Test cases for EvidenceMgr class."""

    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for testing
        self.test_dir = Path(tempfile.mkdtemp())
        self.evidence_dir = self.test_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Create test files
        self.test_file1 = self.test_dir / "test1.txt"
        self.test_file1.write_text("Test content 1", encoding="utf-8")

        self.test_file2 = self.test_dir / "test2.txt"
        self.test_file2.write_text("Test content 2", encoding="utf-8")

        self.test_image = self.test_dir / "screenshot.png"
        self.test_image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"fake png data")

    def tearDown(self):
        """Clean up test environment."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def create_manager(self) -> EvidenceMgr:
        """Create evidence manager with custom base directory."""
        mgr = EvidenceMgr()
        mgr.base = self.evidence_dir
        mgr.meta_file = self.evidence_dir / "meta.json"
        mgr._meta = defaultdict(list)
        return mgr

    def test_init(self):
        """Test manager initialization."""
        mgr = self.create_manager()
        self.assertTrue(mgr.base.exists())
        self.assertIsInstance(mgr._meta, dict)

    def test_import_file(self):
        """Test importing evidence file."""
        mgr = self.create_manager()

        result = mgr.import_file(
            "V-123456",
            self.test_file1,
            description="Test evidence",
            category="config"
        )

        # Check file was copied
        self.assertTrue(result.exists())
        self.assertTrue(result.parent.name == "V-123456")

        # Check metadata was saved
        self.assertIn("V-123456", mgr._meta)
        self.assertEqual(len(mgr._meta["V-123456"]), 1)

        meta = mgr._meta["V-123456"][0]
        self.assertEqual(meta.vid, "V-123456")
        self.assertEqual(meta.description, "Test evidence")
        self.assertEqual(meta.category, "config")
        self.assertGreater(meta.file_size, 0)
        self.assertNotEqual(meta.file_hash, "")

    def test_import_duplicate(self):
        """Test importing duplicate file (by hash)."""
        mgr = self.create_manager()

        # Import file first time
        result1 = mgr.import_file("V-123456", self.test_file1)

        # Import same file again (should detect duplicate)
        result2 = mgr.import_file("V-123456", self.test_file1)

        # Should return existing file
        self.assertEqual(result1, result2)

        # Should only have one metadata entry
        self.assertEqual(len(mgr._meta["V-123456"]), 1)

    def test_import_multiple_files(self):
        """Test importing multiple files for same VID."""
        mgr = self.create_manager()

        # Import different files for same VID
        mgr.import_file("V-123456", self.test_file1, category="config")
        mgr.import_file("V-123456", self.test_file2, category="log")

        # Should have two metadata entries
        self.assertEqual(len(mgr._meta["V-123456"]), 2)

    def test_import_different_vids(self):
        """Test importing files for different VIDs."""
        mgr = self.create_manager()

        mgr.import_file("V-123456", self.test_file1)
        mgr.import_file("V-789012", self.test_file2)

        # Should have two VIDs
        self.assertEqual(len(mgr._meta), 2)
        self.assertIn("V-123456", mgr._meta)
        self.assertIn("V-789012", mgr._meta)

    def test_export_all(self):
        """Test exporting all evidence."""
        mgr = self.create_manager()

        # Import some files
        mgr.import_file("V-123456", self.test_file1, category="config")
        mgr.import_file("V-789012", self.test_file2, category="log")

        # Export
        export_dir = self.test_dir / "export"
        count = mgr.export_all(export_dir)

        # Check files were exported
        self.assertEqual(count, 2)
        self.assertTrue((export_dir / "V-123456").exists())
        self.assertTrue((export_dir / "V-789012").exists())

        # Check metadata was exported
        meta_file = export_dir / "evidence_meta.json"
        self.assertTrue(meta_file.exists())

        # Verify metadata content
        meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
        self.assertIn("V-123456", meta_data)
        self.assertIn("V-789012", meta_data)

    def test_export_empty(self):
        """Test exporting with no evidence."""
        mgr = self.create_manager()

        export_dir = self.test_dir / "export"
        count = mgr.export_all(export_dir)

        self.assertEqual(count, 0)
        self.assertTrue(export_dir.exists())

    def test_package(self):
        """Test packaging evidence into ZIP."""
        mgr = self.create_manager()

        # Import some files
        mgr.import_file("V-123456", self.test_file1)
        mgr.import_file("V-789012", self.test_file2)

        # Package
        zip_path = self.test_dir / "evidence.zip"
        result = mgr.package(zip_path)

        # Check ZIP was created
        self.assertTrue(result.exists())
        self.assertTrue(zipfile.is_zipfile(result))

        # Verify ZIP contents
        with zipfile.ZipFile(result, 'r') as zf:
            names = zf.namelist()
            # Should contain meta.json and evidence files
            self.assertTrue(any("meta.json" in name for name in names))
            self.assertTrue(any("V-123456" in name for name in names))
            self.assertTrue(any("V-789012" in name for name in names))

    def test_import_package(self):
        """Test importing evidence from package."""
        mgr = self.create_manager()

        # Create a package
        mgr.import_file("V-123456", self.test_file1, description="Test 1")
        mgr.import_file("V-789012", self.test_file2, description="Test 2")

        zip_path = self.test_dir / "evidence.zip"
        mgr.package(zip_path)

        # Create new manager and import package
        mgr2 = self.create_manager()
        mgr2.base = self.test_dir / "evidence2"
        mgr2.base.mkdir(parents=True, exist_ok=True)
        mgr2.meta_file = mgr2.base / "meta.json"

        count = mgr2.import_package(zip_path)

        # Should have imported files
        self.assertEqual(count, 2)
        self.assertIn("V-123456", mgr2._meta)
        self.assertIn("V-789012", mgr2._meta)

    def test_import_package_security_absolute_path(self):
        """Test that absolute paths in ZIP are rejected."""
        # Create malicious ZIP with absolute path
        zip_path = self.test_dir / "malicious.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("/etc/passwd", "malicious content")

        mgr = self.create_manager()

        # Should raise error
        with self.assertRaises(Exception):  # ValidationError
            mgr.import_package(zip_path)

    def test_import_package_security_path_traversal(self):
        """Test that path traversal in ZIP is rejected."""
        # Create malicious ZIP with path traversal
        zip_path = self.test_dir / "malicious.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("../../etc/passwd", "malicious content")

        mgr = self.create_manager()

        # Should raise error
        with self.assertRaises(Exception):  # ValidationError
            mgr.import_package(zip_path)

    def test_summary(self):
        """Test getting evidence summary."""
        mgr = self.create_manager()

        # Import files
        mgr.import_file("V-123456", self.test_file1)
        mgr.import_file("V-123456", self.test_file2)
        mgr.import_file("V-789012", self.test_image)

        # Get summary
        summary = mgr.summary()

        self.assertEqual(summary["vulnerabilities"], 2)  # 2 VIDs
        self.assertEqual(summary["files"], 3)  # 3 files total
        self.assertGreater(summary["size_bytes"], 0)
        self.assertGreater(summary["size_mb"], 0)
        self.assertIn("storage", summary)

    def test_save_and_load_metadata(self):
        """Test saving and loading metadata."""
        mgr = self.create_manager()

        # Import file
        mgr.import_file("V-123456", self.test_file1, description="Test")

        # Save explicitly
        mgr._save()

        # Create new manager and load
        mgr2 = self.create_manager()
        mgr2._load()

        # Should have loaded metadata
        self.assertIn("V-123456", mgr2._meta)
        self.assertEqual(len(mgr2._meta["V-123456"]), 1)
        self.assertEqual(mgr2._meta["V-123456"][0].description, "Test")

    def test_hash_computation(self):
        """Test file hash computation."""
        mgr = self.create_manager()

        # Import same content twice with different filenames
        result1 = mgr.import_file("V-123456", self.test_file1)

        # Create another file with same content
        test_file3 = self.test_dir / "test3.txt"
        test_file3.write_text("Test content 1", encoding="utf-8")

        result2 = mgr.import_file("V-123456", test_file3)

        # Should detect as duplicate (same hash)
        self.assertEqual(result1, result2)
        self.assertEqual(len(mgr._meta["V-123456"]), 1)

    def test_large_file_import(self):
        """Test importing large file."""
        mgr = self.create_manager()

        # Create a larger test file (>10MB to trigger progress message)
        large_file = self.test_dir / "large.bin"
        with large_file.open("wb") as f:
            # Write 11MB of data
            f.write(b"x" * (11 * 1024 * 1024))

        # Import should succeed
        result = mgr.import_file("V-123456", large_file)
        self.assertTrue(result.exists())

        # Check metadata
        meta = mgr._meta["V-123456"][0]
        self.assertEqual(meta.file_size, 11 * 1024 * 1024)

    def test_special_characters_in_filename(self):
        """Test importing file with special characters in name."""
        mgr = self.create_manager()

        # Create file with special characters
        special_file = self.test_dir / "test file (copy) #1.txt"
        special_file.write_text("Test content", encoding="utf-8")

        # Import should sanitize filename
        result = mgr.import_file("V-123456", special_file)
        self.assertTrue(result.exists())

        # Filename should be sanitized
        self.assertIn("_", result.name)


if __name__ == "__main__":
    unittest.main()

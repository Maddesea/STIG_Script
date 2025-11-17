"""Tests for evidence metadata models.

Team: 9 - Evidence Management
"""

import unittest
from datetime import datetime, timezone
from stig_assessor.evidence.models import EvidenceMeta


class TestEvidenceMeta(unittest.TestCase):
    """Test cases for EvidenceMeta dataclass."""

    def test_create_instance(self):
        """Test creating EvidenceMeta instance."""
        now = datetime.now(timezone.utc)
        meta = EvidenceMeta(
            vid="V-123456",
            filename="20250101_120000_screenshot.png",
            imported=now,
            file_hash="abc123def456",
            file_size=1024,
            description="Test evidence",
            category="screenshot",
            who="testuser",
        )

        self.assertEqual(meta.vid, "V-123456")
        self.assertEqual(meta.filename, "20250101_120000_screenshot.png")
        self.assertEqual(meta.imported, now)
        self.assertEqual(meta.file_hash, "abc123def456")
        self.assertEqual(meta.file_size, 1024)
        self.assertEqual(meta.description, "Test evidence")
        self.assertEqual(meta.category, "screenshot")
        self.assertEqual(meta.who, "testuser")

    def test_default_values(self):
        """Test default values for optional fields."""
        now = datetime.now(timezone.utc)
        meta = EvidenceMeta(
            vid="V-123456",
            filename="test.txt",
            imported=now,
            file_hash="hash123",
            file_size=100,
        )

        self.assertEqual(meta.description, "")
        self.assertEqual(meta.category, "general")
        self.assertEqual(meta.who, "System")

    def test_as_dict(self):
        """Test converting to dictionary."""
        now = datetime.now(timezone.utc)
        meta = EvidenceMeta(
            vid="V-123456",
            filename="test.txt",
            imported=now,
            file_hash="hash123",
            file_size=100,
            description="Test",
            category="config",
            who="admin",
        )

        result = meta.as_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["vid"], "V-123456")
        self.assertEqual(result["filename"], "test.txt")
        self.assertEqual(result["imported"], now.isoformat())
        self.assertEqual(result["hash"], "hash123")
        self.assertEqual(result["size"], 100)
        self.assertEqual(result["description"], "Test")
        self.assertEqual(result["category"], "config")
        self.assertEqual(result["who"], "admin")

    def test_from_dict_valid(self):
        """Test creating from valid dictionary."""
        now = datetime.now(timezone.utc)
        data = {
            "vid": "V-123456",
            "filename": "test.txt",
            "imported": now.isoformat(),
            "hash": "hash123",
            "size": 100,
            "description": "Test",
            "category": "config",
            "who": "admin",
        }

        meta = EvidenceMeta.from_dict(data)

        self.assertEqual(meta.vid, "V-123456")
        self.assertEqual(meta.filename, "test.txt")
        self.assertEqual(meta.file_hash, "hash123")
        self.assertEqual(meta.file_size, 100)
        self.assertEqual(meta.description, "Test")
        self.assertEqual(meta.category, "config")
        self.assertEqual(meta.who, "admin")

    def test_from_dict_minimal(self):
        """Test creating from minimal dictionary."""
        data = {
            "vid": "V-789012",
            "filename": "minimal.txt",
        }

        meta = EvidenceMeta.from_dict(data)

        self.assertEqual(meta.vid, "V-789012")
        self.assertEqual(meta.filename, "minimal.txt")
        self.assertEqual(meta.file_hash, "")
        self.assertEqual(meta.file_size, 0)
        self.assertEqual(meta.description, "")
        self.assertEqual(meta.category, "general")
        self.assertEqual(meta.who, "System")

    def test_from_dict_invalid_type(self):
        """Test from_dict with invalid type."""
        # When dependencies aren't available, should still raise error
        # but error type depends on whether ValidationError is imported
        with self.assertRaises(Exception):
            EvidenceMeta.from_dict("not a dict")

    def test_from_dict_with_z_suffix(self):
        """Test parsing timestamp with Z suffix."""
        data = {
            "vid": "V-123456",
            "filename": "test.txt",
            "imported": "2025-01-01T12:00:00.000000Z",
            "hash": "hash123",
            "size": 100,
        }

        meta = EvidenceMeta.from_dict(data)

        # Should parse successfully and have timezone info
        self.assertIsNotNone(meta.imported.tzinfo)

    def test_from_dict_without_timezone(self):
        """Test parsing timestamp without timezone."""
        data = {
            "vid": "V-123456",
            "filename": "test.txt",
            "imported": "2025-01-01T12:00:00",
            "hash": "hash123",
            "size": 100,
        }

        meta = EvidenceMeta.from_dict(data)

        # Should add UTC timezone
        self.assertIsNotNone(meta.imported.tzinfo)
        self.assertEqual(meta.imported.tzinfo, timezone.utc)

    def test_roundtrip(self):
        """Test converting to dict and back."""
        now = datetime.now(timezone.utc)
        original = EvidenceMeta(
            vid="V-123456",
            filename="test.txt",
            imported=now,
            file_hash="hash123",
            file_size=100,
            description="Test",
            category="config",
            who="admin",
        )

        # Convert to dict and back
        data = original.as_dict()
        restored = EvidenceMeta.from_dict(data)

        # Should have same values (timestamps may differ slightly)
        self.assertEqual(restored.vid, original.vid)
        self.assertEqual(restored.filename, original.filename)
        self.assertEqual(restored.file_hash, original.file_hash)
        self.assertEqual(restored.file_size, original.file_size)
        self.assertEqual(restored.description, original.description)
        self.assertEqual(restored.category, original.category)
        self.assertEqual(restored.who, original.who)


if __name__ == "__main__":
    unittest.main()

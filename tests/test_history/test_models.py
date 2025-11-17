"""
Unit tests for history.models module.

Tests the Hist dataclass including:
- Dataclass ordering by timestamp
- Status and severity normalization
- Timezone handling
- Serialization (as_dict, from_dict)
- Content hashing for deduplication
"""

import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from stig_assessor.history.models import Hist


class TestHistDataclass(unittest.TestCase):
    """Test Hist dataclass basic functionality."""

    def test_dataclass_creation(self):
        """Test creating a Hist instance with all fields."""
        ts = datetime.now(timezone.utc)
        entry = Hist(
            ts=ts,
            stat="Open",
            find="Security issue found",
            comm="Needs remediation",
            src="manual",
            chk="abc123",
            sev="high",
            who="analyst1"
        )

        self.assertEqual(entry.ts, ts)
        self.assertEqual(entry.stat, "Open")
        self.assertEqual(entry.find, "Security issue found")
        self.assertEqual(entry.comm, "Needs remediation")
        self.assertEqual(entry.src, "manual")
        self.assertEqual(entry.chk, "abc123")
        self.assertEqual(entry.sev, "high")
        self.assertEqual(entry.who, "analyst1")

    def test_ordering_by_timestamp(self):
        """Test that Hist entries are ordered by timestamp."""
        now = datetime.now(timezone.utc)
        earlier = now - timedelta(hours=1)
        later = now + timedelta(hours=1)

        entry1 = Hist(ts=now, stat="Open", find="", comm="", src="test", chk="1")
        entry2 = Hist(ts=earlier, stat="Open", find="", comm="", src="test", chk="2")
        entry3 = Hist(ts=later, stat="Open", find="", comm="", src="test", chk="3")

        # Test comparison operators
        self.assertTrue(entry2 < entry1)
        self.assertTrue(entry1 < entry3)
        self.assertTrue(entry2 < entry3)

        # Test sorting
        entries = [entry1, entry3, entry2]
        sorted_entries = sorted(entries)
        self.assertEqual(sorted_entries, [entry2, entry1, entry3])


class TestHistPostInit(unittest.TestCase):
    """Test Hist __post_init__ validation and normalization."""

    def test_timezone_aware_conversion(self):
        """Test that naive timestamps are converted to UTC."""
        naive_ts = datetime(2025, 1, 1, 12, 0, 0)
        entry = Hist(
            ts=naive_ts,
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="123"
        )

        # Should be converted to UTC
        self.assertIsNotNone(entry.ts.tzinfo)
        self.assertEqual(entry.ts.tzinfo, timezone.utc)

    def test_status_normalization(self):
        """Test that status values are normalized."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="123"
        )

        # Status should be normalized (exact behavior depends on San.status)
        self.assertIsInstance(entry.stat, str)

    def test_invalid_status_fallback(self):
        """Test that invalid status falls back to Not_Reviewed."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="InvalidStatus",
            find="",
            comm="",
            src="test",
            chk="123"
        )

        # Should fall back to Not_Reviewed
        self.assertEqual(entry.stat, "Not_Reviewed")

    def test_severity_normalization(self):
        """Test that severity values are normalized."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="123",
            sev="high"
        )

        # Severity should be normalized
        self.assertIsInstance(entry.sev, str)

    def test_invalid_severity_fallback(self):
        """Test that invalid severity falls back to medium."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="123",
            sev="InvalidSeverity"
        )

        # Should fall back to medium
        self.assertEqual(entry.sev, "medium")

    def test_default_username_from_env(self):
        """Test that username defaults to environment variable."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="123",
            who=""  # Empty username
        )

        # Should have a default username from environment or "System"
        self.assertIsInstance(entry.who, str)
        self.assertTrue(len(entry.who) > 0)


class TestHistSerialization(unittest.TestCase):
    """Test Hist serialization methods."""

    def test_as_dict(self):
        """Test serialization to dictionary."""
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        entry = Hist(
            ts=ts,
            stat="Open",
            find="Finding details",
            comm="Comments here",
            src="manual",
            chk="abc123",
            sev="high",
            who="analyst1"
        )

        result = entry.as_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["ts"], ts.isoformat())
        self.assertEqual(result["stat"], "Open")
        self.assertEqual(result["find"], "Finding details")
        self.assertEqual(result["comm"], "Comments here")
        self.assertEqual(result["src"], "manual")
        self.assertEqual(result["chk"], "abc123")
        self.assertEqual(result["sev"], "high")
        self.assertEqual(result["who"], "analyst1")

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "ts": "2025-01-01T12:00:00+00:00",
            "stat": "Open",
            "find": "Finding details",
            "comm": "Comments here",
            "src": "manual",
            "chk": "abc123",
            "sev": "high",
            "who": "analyst1"
        }

        entry = Hist.from_dict(data)

        self.assertIsInstance(entry, Hist)
        self.assertEqual(entry.stat, "Open")
        self.assertEqual(entry.find, "Finding details")
        self.assertEqual(entry.comm, "Comments here")
        self.assertEqual(entry.src, "manual")
        self.assertEqual(entry.chk, "abc123")
        self.assertEqual(entry.sev, "high")
        self.assertEqual(entry.who, "analyst1")

    def test_from_dict_with_missing_fields(self):
        """Test deserialization with missing optional fields."""
        data = {
            "stat": "Open"
        }

        entry = Hist.from_dict(data)

        self.assertIsInstance(entry, Hist)
        self.assertEqual(entry.stat, "Open")
        # Other fields should have defaults
        self.assertIsInstance(entry.ts, datetime)
        self.assertEqual(entry.find, "")
        self.assertEqual(entry.comm, "")

    def test_from_dict_with_invalid_timestamp(self):
        """Test deserialization with invalid timestamp uses current time."""
        data = {
            "ts": "invalid-timestamp",
            "stat": "Open",
            "find": "",
            "comm": "",
            "src": "test",
            "chk": "123"
        }

        entry = Hist.from_dict(data)

        # Should use current time as fallback
        self.assertIsInstance(entry.ts, datetime)
        self.assertIsNotNone(entry.ts.tzinfo)

    def test_from_dict_with_z_suffix(self):
        """Test deserialization handles ISO format with Z suffix."""
        data = {
            "ts": "2025-01-01T12:00:00Z",
            "stat": "Open",
            "find": "",
            "comm": "",
            "src": "test",
            "chk": "123"
        }

        entry = Hist.from_dict(data)

        # Should parse successfully
        self.assertIsInstance(entry.ts, datetime)

    def test_roundtrip_serialization(self):
        """Test that as_dict -> from_dict preserves data."""
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        original = Hist(
            ts=ts,
            stat="Open",
            find="Finding",
            comm="Comment",
            src="manual",
            chk="abc",
            sev="high",
            who="analyst"
        )

        # Convert to dict and back
        data = original.as_dict()
        restored = Hist.from_dict(data)

        # Compare key fields (some may be normalized)
        self.assertEqual(original.find, restored.find)
        self.assertEqual(original.comm, restored.comm)
        self.assertEqual(original.src, restored.src)
        self.assertEqual(original.chk, restored.chk)


class TestHistContentHash(unittest.TestCase):
    """Test Hist content hashing for deduplication."""

    def test_content_hash_generation(self):
        """Test that content hash is generated."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="Finding details",
            comm="Comments",
            src="test",
            chk="123",
            sev="high",
            who="analyst"
        )

        hash_val = entry.content_hash()

        self.assertIsInstance(hash_val, str)
        self.assertTrue(len(hash_val) > 0)

    def test_content_hash_consistency(self):
        """Test that same content produces same hash."""
        ts = datetime.now(timezone.utc)
        entry1 = Hist(
            ts=ts,
            stat="Open",
            find="Finding",
            comm="Comment",
            src="test",
            chk="abc",
            sev="high",
            who="analyst"
        )
        entry2 = Hist(
            ts=ts,
            stat="Open",
            find="Finding",
            comm="Comment",
            src="test",
            chk="xyz",  # Different chk
            sev="high",
            who="analyst"
        )

        # Hash should be based on content (stat, find, comm, sev, who)
        # not on chk field
        hash1 = entry1.content_hash()
        hash2 = entry2.content_hash()

        self.assertEqual(hash1, hash2)

    def test_content_hash_different_for_different_content(self):
        """Test that different content produces different hash."""
        ts = datetime.now(timezone.utc)
        entry1 = Hist(
            ts=ts,
            stat="Open",
            find="Finding 1",
            comm="Comment",
            src="test",
            chk="abc",
            sev="high",
            who="analyst"
        )
        entry2 = Hist(
            ts=ts,
            stat="Open",
            find="Finding 2",
            comm="Comment",
            src="test",
            chk="abc",
            sev="high",
            who="analyst"
        )

        hash1 = entry1.content_hash()
        hash2 = entry2.content_hash()

        self.assertNotEqual(hash1, hash2)


class TestHistEdgeCases(unittest.TestCase):
    """Test Hist edge cases and error handling."""

    def test_from_dict_with_non_dict(self):
        """Test that from_dict raises error for non-dict input."""
        from STIG_Script import ValidationError

        with self.assertRaises(ValidationError):
            Hist.from_dict("not a dict")

    def test_from_dict_with_none(self):
        """Test that from_dict raises error for None."""
        from STIG_Script import ValidationError

        with self.assertRaises(ValidationError):
            Hist.from_dict(None)

    def test_empty_strings(self):
        """Test handling of empty strings."""
        entry = Hist(
            ts=datetime.now(timezone.utc),
            stat="Open",
            find="",
            comm="",
            src="test",
            chk="",
            sev="medium",
            who=""
        )

        # Should handle empty strings gracefully
        self.assertEqual(entry.find, "")
        self.assertEqual(entry.comm, "")
        self.assertIsInstance(entry.who, str)  # May be set to default


if __name__ == "__main__":
    unittest.main()

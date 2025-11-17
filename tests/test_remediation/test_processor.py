"""Tests for remediation results processor.

This module tests the FixResPro class for loading remediation results
and applying them to CKL files.
"""

import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from stig_assessor.remediation.models import FixResult
from stig_assessor.remediation.processor import FixResPro


class TestFixResult(unittest.TestCase):
    """Tests for FixResult dataclass."""

    def test_as_dict(self):
        """Test converting FixResult to dictionary."""
        ts = datetime(2025, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        result = FixResult(
            vid="V-123456",
            ts=ts,
            ok=True,
            message="Test message",
            output="Test output",
            error=""
        )

        result_dict = result.as_dict()

        self.assertEqual(result_dict["vid"], "V-123456")
        self.assertEqual(result_dict["ok"], True)
        self.assertEqual(result_dict["msg"], "Test message")
        self.assertEqual(result_dict["out"], "Test output")
        self.assertEqual(result_dict["err"], "")
        self.assertIn("2025-11-16", result_dict["ts"])

    def test_from_dict_success(self):
        """Test creating FixResult from valid dictionary."""
        data = {
            "vid": "V-123456",
            "ts": "2025-11-16T12:00:00Z",
            "ok": True,
            "msg": "Remediation successful",
            "out": "Command executed",
            "err": ""
        }

        result = FixResult.from_dict(data)

        self.assertEqual(result.vid, "V-123456")
        self.assertTrue(result.ok)
        self.assertEqual(result.message, "Remediation successful")
        self.assertEqual(result.output, "Command executed")
        self.assertEqual(result.error, "")
        self.assertIsNotNone(result.ts.tzinfo)

    def test_from_dict_minimal(self):
        """Test creating FixResult from minimal dictionary."""
        data = {
            "vid": "V-789012",
            "ok": False
        }

        result = FixResult.from_dict(data)

        self.assertEqual(result.vid, "V-789012")
        self.assertFalse(result.ok)
        self.assertEqual(result.message, "")
        self.assertEqual(result.output, "")
        self.assertEqual(result.error, "")

    def test_from_dict_invalid(self):
        """Test that invalid data raises ValidationError."""
        from STIG_Script import ValidationError

        with self.assertRaises(ValidationError):
            FixResult.from_dict("not a dict")

        with self.assertRaises(ValidationError):
            FixResult.from_dict([1, 2, 3])


class TestFixResPro(unittest.TestCase):
    """Tests for FixResPro class."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = FixResPro()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test processor initialization."""
        self.assertIsInstance(self.processor.results, dict)
        self.assertIsInstance(self.processor.meta, dict)
        self.assertEqual(len(self.processor.results), 0)

    def test_load_array_format(self):
        """Test loading JSON in array format."""
        test_data = [
            {
                "vid": "V-111111",
                "ok": True,
                "msg": "Fixed",
                "ts": "2025-11-16T10:00:00Z"
            },
            {
                "vid": "V-222222",
                "ok": False,
                "msg": "Failed",
                "ts": "2025-11-16T10:01:00Z"
            }
        ]

        # Write test file
        test_file = Path(self.temp_dir) / "results_array.json"
        test_file.write_text(json.dumps(test_data))

        # Load results
        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 2)
        self.assertEqual(skipped, 0)
        self.assertIn("V-111111", self.processor.results)
        self.assertIn("V-222222", self.processor.results)
        self.assertTrue(self.processor.results["V-111111"].ok)
        self.assertFalse(self.processor.results["V-222222"].ok)

    def test_load_object_format_with_results_key(self):
        """Test loading JSON with 'results' key."""
        test_data = {
            "meta": {"tool": "test", "version": "1.0"},
            "results": [
                {"vid": "V-333333", "ok": True, "msg": "Success"}
            ]
        }

        test_file = Path(self.temp_dir) / "results_object.json"
        test_file.write_text(json.dumps(test_data))

        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 1)
        self.assertEqual(skipped, 0)
        self.assertIn("V-333333", self.processor.results)
        self.assertEqual(self.processor.meta.get("tool"), "test")

    def test_load_multi_system_format(self):
        """Test loading JSON in multi-system format."""
        test_data = {
            "systems": {
                "server1": [
                    {"vid": "V-444444", "ok": True, "msg": "Fixed on server1"}
                ],
                "server2": [
                    {"vid": "V-555555", "ok": True, "msg": "Fixed on server2"}
                ]
            }
        }

        test_file = Path(self.temp_dir) / "results_multisystem.json"
        test_file.write_text(json.dumps(test_data))

        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 2)
        self.assertIn("V-444444", self.processor.results)
        self.assertIn("V-555555", self.processor.results)

    def test_load_alternative_keys(self):
        """Test loading JSON with alternative keys."""
        test_formats = [
            {"vulnerabilities": [{"vid": "V-666666", "ok": True}]},
            {"entries": [{"vid": "V-777777", "ok": True}]},
            {"findings": [{"vid": "V-888888", "ok": True}]},
        ]

        for idx, test_data in enumerate(test_formats):
            processor = FixResPro()
            test_file = Path(self.temp_dir) / f"results_alt_{idx}.json"
            test_file.write_text(json.dumps(test_data))

            unique, skipped = processor.load(test_file)

            self.assertEqual(unique, 1)
            self.assertEqual(len(processor.results), 1)

    def test_load_single_result_object(self):
        """Test loading single result object."""
        test_data = {"vid": "V-999999", "ok": True, "msg": "Single result"}

        test_file = Path(self.temp_dir) / "results_single.json"
        test_file.write_text(json.dumps(test_data))

        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 1)
        self.assertIn("V-999999", self.processor.results)

    def test_load_deduplication(self):
        """Test that duplicate VIDs are deduplicated (keeps most recent)."""
        ts1 = "2025-11-16T10:00:00Z"
        ts2 = "2025-11-16T11:00:00Z"  # Newer

        test_data = [
            {"vid": "V-100000", "ok": False, "msg": "Older", "ts": ts1},
            {"vid": "V-100000", "ok": True, "msg": "Newer", "ts": ts2}
        ]

        test_file = Path(self.temp_dir) / "results_dedup.json"
        test_file.write_text(json.dumps(test_data))

        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 1)
        self.assertEqual(skipped, 0)
        # Should keep the newer result
        self.assertTrue(self.processor.results["V-100000"].ok)
        self.assertEqual(self.processor.results["V-100000"].message, "Newer")

    def test_load_empty_results(self):
        """Test loading empty results."""
        test_data = []

        test_file = Path(self.temp_dir) / "results_empty.json"
        test_file.write_text(json.dumps(test_data))

        unique, skipped = self.processor.load(test_file)

        self.assertEqual(unique, 0)
        self.assertEqual(skipped, 0)

    def test_load_invalid_json(self):
        """Test that invalid JSON raises ParseError."""
        from STIG_Script import ParseError

        test_file = Path(self.temp_dir) / "invalid.json"
        test_file.write_text("{ invalid json }")

        with self.assertRaises(ParseError):
            self.processor.load(test_file)

    def test_load_unrecognized_format(self):
        """Test that unrecognized format raises ParseError."""
        from STIG_Script import ParseError

        test_data = {"unknown_key": "value"}

        test_file = Path(self.temp_dir) / "unrecognized.json"
        test_file.write_text(json.dumps(test_data))

        with self.assertRaises(ParseError):
            self.processor.load(test_file)

    def test_generate_report_text(self):
        """Test generating text report."""
        self.processor.results = {
            "V-111111": FixResult(
                vid="V-111111",
                ts=datetime.now(timezone.utc),
                ok=True,
                message="Success"
            ),
            "V-222222": FixResult(
                vid="V-222222",
                ts=datetime.now(timezone.utc),
                ok=False,
                message="Failed"
            )
        }

        report = self.processor.generate_report(format="text")

        self.assertIn("Remediation Results Report", report)
        self.assertIn("V-111111", report)
        self.assertIn("V-222222", report)
        self.assertIn("SUCCESS", report)
        self.assertIn("FAILED", report)

    def test_generate_report_json(self):
        """Test generating JSON report."""
        self.processor.results = {
            "V-111111": FixResult(
                vid="V-111111",
                ts=datetime.now(timezone.utc),
                ok=True,
                message="Success"
            )
        }

        report = self.processor.generate_report(format="json")
        report_data = json.loads(report)

        self.assertIsInstance(report_data, list)
        self.assertEqual(len(report_data), 1)
        self.assertEqual(report_data[0]["vid"], "V-111111")

    def test_generate_report_csv(self):
        """Test generating CSV report."""
        self.processor.results = {
            "V-111111": FixResult(
                vid="V-111111",
                ts=datetime.now(timezone.utc),
                ok=True,
                message="Success"
            )
        }

        report = self.processor.generate_report(format="csv")

        self.assertIn("vid,timestamp,success,message", report)
        self.assertIn("V-111111", report)
        self.assertIn("True", report)


class TestFixResProIntegration(unittest.TestCase):
    """Integration tests for FixResPro with realistic scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.processor = FixResPro()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_batch_load_multiple_files(self):
        """Test loading results from multiple files."""
        # Create multiple result files
        file1_data = [{"vid": "V-111111", "ok": True, "ts": "2025-11-16T10:00:00Z"}]
        file2_data = [{"vid": "V-222222", "ok": True, "ts": "2025-11-16T11:00:00Z"}]

        file1 = Path(self.temp_dir) / "batch1.json"
        file2 = Path(self.temp_dir) / "batch2.json"

        file1.write_text(json.dumps(file1_data))
        file2.write_text(json.dumps(file2_data))

        # Load both files
        self.processor.load(file1)
        self.processor.load(file2)

        # Should have results from both files
        self.assertEqual(len(self.processor.results), 2)
        self.assertIn("V-111111", self.processor.results)
        self.assertIn("V-222222", self.processor.results)

    def test_load_and_merge_with_deduplication_across_files(self):
        """Test that loading multiple files deduplicates across batches."""
        # First file with older timestamp
        file1_data = [{"vid": "V-333333", "ok": False, "msg": "Old", "ts": "2025-11-16T10:00:00Z"}]
        # Second file with newer timestamp for same VID
        file2_data = [{"vid": "V-333333", "ok": True, "msg": "New", "ts": "2025-11-16T12:00:00Z"}]

        file1 = Path(self.temp_dir) / "old.json"
        file2 = Path(self.temp_dir) / "new.json"

        file1.write_text(json.dumps(file1_data))
        file2.write_text(json.dumps(file2_data))

        # Load older first, then newer
        self.processor.load(file1)
        self.processor.load(file2)

        # Should keep the newer result
        self.assertEqual(len(self.processor.results), 1)
        self.assertTrue(self.processor.results["V-333333"].ok)
        self.assertEqual(self.processor.results["V-333333"].message, "New")


if __name__ == "__main__":
    unittest.main()

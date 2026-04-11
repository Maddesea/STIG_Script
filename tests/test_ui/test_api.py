"""Unit tests for the Web API handlers."""

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from stig_assessor.ui.web.api import (_decode_to_temp, handle_ping,
                                      route_request)


class TestWebAPI(unittest.TestCase):

    def setUp(self):
        self.b64_empty_ckl = base64.b64encode(b"<CHECKLIST></CHECKLIST>").decode(
            "utf-8"
        )

    def test_handle_ping(self):
        res = handle_ping({})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["message"], "pong")

    def test_route_request_ping(self):
        res = route_request("/api/v1/ping", {})
        self.assertEqual(res["status"], "success")

    def test_route_request_404(self):
        res = route_request("/api/v1/invalid", {})
        self.assertEqual(res["status"], "error")
        self.assertIn("not found", res["message"].lower())

    def test_decode_to_temp_malformed(self):
        with self.assertRaises(ValueError):
            _decode_to_temp("NOT A BASE64 !!!", ".txt")

    def test_decode_to_temp_empty(self):
        with self.assertRaises(ValueError):
            _decode_to_temp("", ".txt")

    def test_decode_to_temp_valid(self):
        b64 = base64.b64encode(b"hello world").decode("utf-8")
        path = _decode_to_temp(b64, ".txt")
        self.assertTrue(path.exists())
        self.assertEqual(path.read_text(), "hello world")
        path.unlink()

    @patch("stig_assessor.processor.processor.Proc.generate_stats")
    def test_handle_stats(self, mock_generate_stats):
        mock_generate_stats.return_value = {"by_status": {"Open": 1}}
        payload = {"ckl_b64": self.b64_empty_ckl}

        res = route_request("/api/v1/stats", payload)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["stats_data"]["status_counts"]["Open"], 1)
        self.assertEqual(mock_generate_stats.call_count, 2)

    @patch("stig_assessor.history.sqlite_store.SQLiteStore")
    def test_route_request_error_handling(self, mock_db):
        res = route_request("/api/v1/xccdf_to_ckl", {"content_b64": "BAD STRING..."})
        self.assertEqual(res["status"], "error")
        self.assertIn("Validation Error", res["message"])

    @patch("stig_assessor.ui.web.api._encode_from_temp")
    @patch("shutil.make_archive")
    @patch("stig_assessor.ui.web.api.FixExt")
    def test_handle_extract_fixes(self, mock_Extractor, mock_make_archive, mock_encode):
        mock_ext = MagicMock()
        mock_ext.stats_summary.return_value = {"bash_scripts": 1, "ps_scripts": 1}
        mock_Extractor.return_value = mock_ext
        mock_make_archive.return_value = str(
            Path(tempfile.gettempdir()) / "test_archive.zip"
        )
        mock_encode.return_value = "BASE64_ZIP_DATA"

        payload = {
            "content_b64": self.b64_empty_ckl,
            "filename": "test.ckl",
            "enable_rollbacks": True,
        }
        res = route_request("/api/v1/extract", payload)
        if res["status"] != "success":
            print("ERROR:", res)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["package_b64"], "BASE64_ZIP_DATA")

        mock_Extractor.assert_called_once()
        mock_ext.extract.assert_called_once()
        mock_ext.to_powershell.assert_called_once_with(
            mock_ext.to_powershell.call_args[0][0], dry_run=False, enable_rollbacks=True
        )

    @patch("stig_assessor.ui.web.api.Proc")
    def test_handle_track_ckl(self, mock_Proc_class):
        mock_proc = MagicMock()
        mock_Proc_class.return_value = mock_proc

        mock_db = MagicMock()
        mock_db.save_assessment.return_value = 1
        mock_proc.history.db = mock_db

        mock_root = MagicMock()
        mock_proc._load_file_as_xml.return_value = mock_root
        mock_root.getroot.return_value = mock_root

        mock_asset_node = MagicMock()
        mock_asset_node.text = "TEST_SERVER"
        mock_root.find.return_value = mock_asset_node

        mock_proc._extract_vuln_data.return_value = {
            "V-12345": {
                "status": "Open",
                "severity": "high",
                "finding_details": "Failed",
                "comments": "Fix",
            }
        }

        payload = {"ckl_b64": self.b64_empty_ckl}
        res = route_request("/api/v1/track_ckl", payload)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["asset_name"], "TEST_SERVER")
        self.assertEqual(res["data"]["assessment_id"], 1)
        mock_db.save_assessment.assert_called_once()

    @patch("stig_assessor.ui.web.api.Proc")
    def test_handle_show_drift(self, mock_Proc_class):
        mock_proc = MagicMock()
        mock_Proc_class.return_value = mock_proc

        mock_db = MagicMock()

        # Mock cursor and connection
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = [1]
        mock_conn.cursor.return_value = mock_cursor
        mock_db._get_conn.return_value.__enter__.return_value = mock_conn

        mock_db.get_drift.return_value = {
            "fixed": ["V-100"],
            "regressed": ["V-200"],
            "changed": [],
            "new": [],
            "removed": [],
        }
        mock_proc.history.db = mock_db

        payload = {"asset_name": "TEST_SERVER"}
        res = route_request("/api/v1/show_drift", payload)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["fixed"], ["V-100"])
        mock_db.get_drift.assert_called_once_with("TEST_SERVER", 1)

    @patch("stig_assessor.ui.web.api._encode_from_temp")
    @patch("stig_assessor.ui.web.api.FixResPro")
    def test_handle_apply_results(self, mock_FixResPro_class, mock_encode):
        mock_proc = MagicMock()
        mock_proc.load.return_value = (5, 0)
        mock_proc.update_ckl.return_value = {
            "imported": 5,
            "updated": 0,
            "not_found": 0,
        }
        mock_FixResPro_class.return_value = mock_proc
        mock_encode.return_value = "BASE64"

        payload = {
            "ckl_b64": self.b64_empty_ckl,
            "json_b64": base64.b64encode(b"{}").decode("utf-8"),
            "filename": "test.ckl",
        }
        res = route_request("/api/v1/apply_results", payload)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["imported"], 5)
        self.assertTrue("ckl_b64" in res["data"])
        self.assertEqual(res["data"]["filename"], "test.ckl")


if __name__ == "__main__":
    unittest.main()

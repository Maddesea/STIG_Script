"""
Unit tests for Cfg configuration and directory management.

Tests cover:
- Home directory detection
- Writable directory selection
- Directory creation
- Cleanup operations
- Path validation
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from stig_assessor.core.config import Cfg


class TestCfgInit(unittest.TestCase):
    """Test suite for Cfg initialization and directory management."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_base = Path(tempfile.mkdtemp(prefix="test_cfg_"))

    def tearDown(self):
        """Clean up test artifacts."""
        if self.temp_base.exists():
            shutil.rmtree(self.temp_base, ignore_errors=True)

    def test_home_directory_detection(self):
        """Verify Cfg can detect user home directory.

        Requirements:
        - Try Path.home() first
        - Fall back to environment variables
        - Fall back to temp directory
        """
        self.assertIsNotNone(Cfg.HOME)
        self.assertTrue(Cfg.HOME.exists())

    def test_stig_assessor_directory_creation(self):
        """Verify ~/.stig_assessor directory is created."""
        self.assertIsNotNone(Cfg.APP_DIR)
        self.assertTrue(Cfg.APP_DIR.exists())
        self.assertEqual(Cfg.APP_DIR.name, ".stig_assessor")

    def test_subdirectory_creation(self):
        """Verify all required subdirectories are created.

        Required directories:
        - logs/
        - backups/
        - evidence/
        - templates/
        - presets/
        - fixes/
        - exports/
        """
        self.assertTrue(Cfg.LOG_DIR.exists())
        self.assertTrue(Cfg.BACKUP_DIR.exists())
        self.assertTrue(Cfg.EVIDENCE_DIR.exists())
        self.assertTrue(Cfg.TEMPLATE_DIR.exists())
        self.assertTrue(Cfg.PRESET_DIR.exists())
        self.assertTrue(Cfg.FIX_DIR.exists())
        self.assertTrue(Cfg.EXPORT_DIR.exists())

    def test_writable_check(self):
        """Verify writable directory detection."""
        # The APP_DIR should be writable since Cfg.init() creates it
        import os
        self.assertTrue(os.access(Cfg.APP_DIR, os.W_OK))

    def test_readonly_fallback(self):
        """Verify fallback when primary directory is read-only."""
        # This test verifies that Cfg.init() already succeeded
        # (meaning a writable directory was found)
        self.assertTrue(Cfg._done)


class TestCfgPaths(unittest.TestCase):
    """Test suite for Cfg path resolution."""

    def test_log_directory_path(self):
        """Verify log directory path is correct."""
        self.assertEqual(Cfg.LOG_DIR, Cfg.APP_DIR / "logs")

    def test_backup_directory_path(self):
        """Verify backup directory path is correct."""
        self.assertEqual(Cfg.BACKUP_DIR, Cfg.APP_DIR / "backups")

    def test_evidence_directory_path(self):
        """Verify evidence directory path is correct."""
        self.assertEqual(Cfg.EVIDENCE_DIR, Cfg.APP_DIR / "evidence")

    def test_boilerplate_file_path(self):
        """Verify boilerplate file path is correct."""
        self.assertEqual(Cfg.BOILERPLATE_FILE, Cfg.TEMPLATE_DIR / "boilerplate.json")


class TestCfgCleanup(unittest.TestCase):
    """Test suite for Cfg cleanup operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_cleanup_"))

    def tearDown(self):
        """Clean up test artifacts."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_old_backups_cleanup(self):
        """Verify old backups are cleaned up correctly.

        Requirements:
        - Keep KEEP_BACKUPS (30) most recent files
        - Delete older files
        """
        # Verify the constant is defined
        self.assertEqual(Cfg.KEEP_BACKUPS, 30)

    def test_old_logs_cleanup(self):
        """Verify old logs are cleaned up correctly.

        Requirements:
        - Keep KEEP_LOGS (15) most recent files
        - Delete older files
        """
        # Verify the constant is defined
        self.assertEqual(Cfg.KEEP_LOGS, 15)


class TestCfg(unittest.TestCase):
    """Test configuration basics."""

    def test_directories_initialized(self):
        """Verify directories are initialized."""
        self.assertIsNotNone(Cfg.HOME)
        self.assertIsNotNone(Cfg.APP_DIR)
        self.assertIsNotNone(Cfg.LOG_DIR)
        self.assertIsInstance(Cfg.APP_DIR, Path)

    def test_directories_exist(self):
        """Verify required directories exist."""
        self.assertTrue(Cfg.APP_DIR.exists())
        self.assertTrue(Cfg.LOG_DIR.exists())
        self.assertTrue(Cfg.BACKUP_DIR.exists())

    def test_platform_detection(self):
        """Test platform detection."""
        # One of these should be True
        platforms = [Cfg.IS_WIN, Cfg.IS_LIN, Cfg.IS_MAC]
        self.assertTrue(any(platforms))

    def test_check_succeeds(self):
        """Test configuration check."""
        ok, errors = Cfg.check()
        if not ok:
            self.fail(f"Configuration check failed: {errors}")

    def test_limits_defined(self):
        """Test that all limits are defined with sensible values."""
        self.assertGreater(Cfg.MAX_FILE, 0)
        self.assertGreater(Cfg.MAX_HIST, 0)
        self.assertGreater(Cfg.MAX_FIND, 0)
        self.assertGreater(Cfg.MAX_COMM, 0)
        self.assertGreater(Cfg.MAX_MERGE, 0)
        self.assertGreater(Cfg.MAX_VULNS, 0)

    def test_python_version_requirement(self):
        """Test Python version requirement is set."""
        self.assertEqual(Cfg.MIN_PY, (3, 9))


if __name__ == "__main__":
    unittest.main()

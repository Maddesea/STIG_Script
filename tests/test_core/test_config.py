"""Tests for configuration module."""

import unittest
from pathlib import Path
from stig_assessor.core.config import Cfg


class TestCfg(unittest.TestCase):
    """Test configuration."""

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


if __name__ == "__main__":
    unittest.main()

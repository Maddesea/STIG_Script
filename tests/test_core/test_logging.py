"""Tests for logging module."""

import unittest
from stig_assessor.core.logging import Log


class TestLog(unittest.TestCase):
    """Test logging system."""

    def test_logger_creation(self):
        """Test logger instance creation."""
        logger = Log("test")
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "test")

    def test_singleton_per_name(self):
        """Verify singleton behavior per logger name."""
        logger1 = Log("test1")
        logger2 = Log("test1")
        logger3 = Log("test2")

        self.assertIs(logger1, logger2)
        self.assertIsNot(logger1, logger3)

    def test_logging_methods(self):
        """Test logging methods don't raise exceptions."""
        logger = Log("test")

        # These should not raise exceptions
        logger.d("Debug message")
        logger.i("Info message")
        logger.w("Warning message")
        logger.e("Error message")
        logger.c("Critical message")

    def test_context(self):
        """Test contextual logging."""
        logger = Log("test")
        logger.ctx(operation="test", vid="V-12345")
        logger.clear()
        # Should not raise exception


if __name__ == "__main__":
    unittest.main()

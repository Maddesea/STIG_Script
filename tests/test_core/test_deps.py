"""Tests for dependency detection."""

import unittest
from stig_assessor.core.deps import Deps


class TestDeps(unittest.TestCase):
    """Test dependency detection."""

    def test_check_runs(self):
        """Verify dependency check runs without errors."""
        # Should not raise exception
        Deps.check()

    def test_xml_parser_available(self):
        """Test that XML parser is available."""
        ET, XMLParseError = Deps.get_xml()
        self.assertIsNotNone(ET)
        self.assertIsNotNone(XMLParseError)

        # Test basic XML parsing
        elem = ET.Element("test")
        self.assertEqual(elem.tag, "test")

    def test_has_flags_are_bool(self):
        """Verify dependency flags are boolean."""
        self.assertIsInstance(Deps.HAS_DEFUSEDXML, bool)
        self.assertIsInstance(Deps.HAS_TKINTER, bool)
        self.assertIsInstance(Deps.HAS_FCNTL, bool)
        self.assertIsInstance(Deps.HAS_MSVCRT, bool)


if __name__ == "__main__":
    unittest.main()

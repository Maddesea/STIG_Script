"""
Unit tests for stig_assessor.xml.utils module.

Tests the XmlUtils class including:
- XML element indentation
- Vulnerability ID (VID) extraction
- Text content collection
- Enhanced text extraction from complex XML structures
"""

import unittest
import xml.etree.ElementTree as ET
from stig_assessor.xml.utils import XmlUtils


class TestXmlUtils(unittest.TestCase):
    """Test suite for XmlUtils class."""

    def test_indent_xml_simple(self):
        """Test XML indentation with simple structure."""
        root = ET.Element("root")
        child1 = ET.SubElement(root, "child1")
        child2 = ET.SubElement(root, "child2")

        XmlUtils.indent_xml(root)

        # Check that text and tail are set appropriately
        self.assertIn("\t", root.text)  # Should have indentation
        self.assertIn("\n", child1.tail)  # Should have newline
        self.assertIn("\n", child2.tail)  # Should have newline

    def test_indent_xml_nested(self):
        """Test XML indentation with nested structure."""
        root = ET.Element("root")
        child = ET.SubElement(root, "child")
        grandchild = ET.SubElement(child, "grandchild")
        grandchild.text = "content"

        XmlUtils.indent_xml(root)

        # Verify structure is indented
        xml_str = ET.tostring(root, encoding='unicode')
        self.assertIn("\t", xml_str)
        self.assertIn("\n", xml_str)

    def test_indent_xml_empty(self):
        """Test XML indentation with empty element."""
        root = ET.Element("root")

        XmlUtils.indent_xml(root)

        # Should not crash on empty element
        self.assertIsInstance(root, ET.Element)

    def test_get_vid_valid(self):
        """Test VID extraction from valid VULN element."""
        vuln = ET.Element("VULN")

        # Create STIG_DATA with Vuln_Num
        stig_data = ET.SubElement(vuln, "STIG_DATA")
        vuln_attr = ET.SubElement(stig_data, "VULN_ATTRIBUTE")
        vuln_attr.text = "Vuln_Num"
        attr_data = ET.SubElement(stig_data, "ATTRIBUTE_DATA")
        attr_data.text = "V-12345"

        vid = XmlUtils.get_vid(vuln)

        self.assertEqual(vid, "V-12345")

    def test_get_vid_with_whitespace(self):
        """Test VID extraction with whitespace in value."""
        vuln = ET.Element("VULN")

        stig_data = ET.SubElement(vuln, "STIG_DATA")
        vuln_attr = ET.SubElement(stig_data, "VULN_ATTRIBUTE")
        vuln_attr.text = "Vuln_Num"
        attr_data = ET.SubElement(stig_data, "ATTRIBUTE_DATA")
        attr_data.text = "  V-67890  "

        vid = XmlUtils.get_vid(vuln)

        self.assertEqual(vid, "V-67890")

    def test_get_vid_not_found(self):
        """Test VID extraction when Vuln_Num not present."""
        vuln = ET.Element("VULN")

        # Add different STIG_DATA elements but not Vuln_Num
        stig_data = ET.SubElement(vuln, "STIG_DATA")
        vuln_attr = ET.SubElement(stig_data, "VULN_ATTRIBUTE")
        vuln_attr.text = "Severity"
        attr_data = ET.SubElement(stig_data, "ATTRIBUTE_DATA")
        attr_data.text = "high"

        vid = XmlUtils.get_vid(vuln)

        self.assertIsNone(vid)

    def test_get_vid_invalid_format(self):
        """Test VID extraction with invalid VID format."""
        vuln = ET.Element("VULN")

        stig_data = ET.SubElement(vuln, "STIG_DATA")
        vuln_attr = ET.SubElement(stig_data, "VULN_ATTRIBUTE")
        vuln_attr.text = "Vuln_Num"
        attr_data = ET.SubElement(stig_data, "ATTRIBUTE_DATA")
        attr_data.text = "INVALID-12345"  # Invalid format

        # Should return None for invalid format (after logging)
        vid = XmlUtils.get_vid(vuln)

        self.assertIsNone(vid)

    def test_get_vid_empty(self):
        """Test VID extraction from empty VULN element."""
        vuln = ET.Element("VULN")

        vid = XmlUtils.get_vid(vuln)

        self.assertIsNone(vid)

    def test_collect_text_single(self):
        """Test text collection from single matching element."""
        root = ET.Element("root")
        child = ET.SubElement(root, "description")
        child.text = "Test description"

        result = XmlUtils.collect_text(root, ".//description")

        self.assertEqual(result, "Test description")

    def test_collect_text_multiple(self):
        """Test text collection from multiple matching elements."""
        root = ET.Element("root")
        child1 = ET.SubElement(root, "item")
        child1.text = "First"
        child2 = ET.SubElement(root, "item")
        child2.text = "Second"
        child3 = ET.SubElement(root, "item")
        child3.text = "Third"

        result = XmlUtils.collect_text(root, ".//item")

        self.assertEqual(result, "First\nSecond\nThird")

    def test_collect_text_custom_join(self):
        """Test text collection with custom join separator."""
        root = ET.Element("root")
        child1 = ET.SubElement(root, "item")
        child1.text = "A"
        child2 = ET.SubElement(root, "item")
        child2.text = "B"

        result = XmlUtils.collect_text(root, ".//item", join_with=", ")

        self.assertEqual(result, "A, B")

    def test_collect_text_default(self):
        """Test text collection returns default when no matches."""
        root = ET.Element("root")

        result = XmlUtils.collect_text(root, ".//missing", default="Not found")

        self.assertEqual(result, "Not found")

    def test_collect_text_empty_elements(self):
        """Test text collection with empty elements."""
        root = ET.Element("root")
        child1 = ET.SubElement(root, "item")
        child1.text = "  "  # Whitespace only
        child2 = ET.SubElement(root, "item")
        child2.text = ""  # Empty

        result = XmlUtils.collect_text(root, ".//item", default="Empty")

        self.assertEqual(result, "Empty")

    def test_extract_text_content_simple(self):
        """Test text extraction from simple element."""
        elem = ET.Element("test")
        elem.text = "Simple text content"

        result = XmlUtils.extract_text_content(elem)

        self.assertEqual(result, "Simple text content")

    def test_extract_text_content_mixed(self):
        """Test text extraction from mixed content element."""
        root = ET.fromstring("<fix>Run <code>systemctl restart</code> to apply</fix>")

        result = XmlUtils.extract_text_content(root)

        # Should extract all text including from nested elements
        self.assertIn("Run", result)
        self.assertIn("systemctl restart", result)
        self.assertIn("to apply", result)

    def test_extract_text_content_nested(self):
        """Test text extraction from deeply nested elements."""
        xml_str = """
        <root>
            <level1>
                <level2>Deep content</level2>
            </level1>
        </root>
        """
        root = ET.fromstring(xml_str)

        result = XmlUtils.extract_text_content(root)

        self.assertIn("Deep content", result)

    def test_extract_text_content_multiline(self):
        """Test text extraction preserves structure."""
        xml_str = """
        <commands>
            <cmd>First command</cmd>
            <cmd>Second command</cmd>
        </commands>
        """
        root = ET.fromstring(xml_str)

        result = XmlUtils.extract_text_content(root)

        # Should contain both commands
        self.assertIn("First command", result)
        self.assertIn("Second command", result)

    def test_extract_text_content_none(self):
        """Test text extraction from None element."""
        result = XmlUtils.extract_text_content(None)

        self.assertEqual(result, "")

    def test_extract_text_content_empty(self):
        """Test text extraction from empty element."""
        elem = ET.Element("empty")

        result = XmlUtils.extract_text_content(elem)

        self.assertEqual(result, "")

    def test_extract_text_content_whitespace_only(self):
        """Test text extraction from element with whitespace only."""
        elem = ET.Element("whitespace")
        elem.text = "   \n\t   "

        result = XmlUtils.extract_text_content(elem)

        self.assertEqual(result, "")

    def test_extract_text_content_excessive_newlines(self):
        """Test that excessive newlines are cleaned up."""
        xml_str = """
        <root>
            Line 1


            Line 2




            Line 3
        </root>
        """
        root = ET.fromstring(xml_str)

        result = XmlUtils.extract_text_content(root)

        # Should not have more than 2 consecutive newlines
        self.assertNotIn("\n\n\n", result)

    def test_extract_text_content_with_tail(self):
        """Test text extraction includes tail text."""
        root = ET.fromstring("<p>Before <em>emphasis</em> after</p>")

        result = XmlUtils.extract_text_content(root)

        self.assertIn("Before", result)
        self.assertIn("emphasis", result)
        self.assertIn("after", result)


class TestXmlUtilsIntegration(unittest.TestCase):
    """Integration tests for XmlUtils with realistic STIG data."""

    def test_realistic_vuln_element(self):
        """Test with realistic VULN element structure."""
        vuln_xml = """
        <VULN>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>V-204392</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>Test Rule</ATTRIBUTE_DATA>
            </STIG_DATA>
        </VULN>
        """
        vuln = ET.fromstring(vuln_xml)

        vid = XmlUtils.get_vid(vuln)

        self.assertEqual(vid, "V-204392")

    def test_realistic_fixtext_extraction(self):
        """Test extraction from realistic fix text with commands."""
        fixtext_xml = """
        <Fixtext>
            To remediate this finding, run the following commands:
            <code>sudo systemctl stop service</code>
            Then verify with:
            <code>systemctl status service</code>
        </Fixtext>
        """
        elem = ET.fromstring(fixtext_xml)

        result = XmlUtils.extract_text_content(elem)

        self.assertIn("remediate", result)
        self.assertIn("sudo systemctl stop service", result)
        self.assertIn("systemctl status service", result)


if __name__ == "__main__":
    unittest.main()

"""
STIG Assessor XML Utility Functions.

Provides common XML processing utilities for STIG/CKL file operations.
"""

from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Optional, List

from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.schema import Sch
from stig_assessor.core.logging import LOG
from stig_assessor.exceptions import ValidationError


class XmlUtils:
    """
    Shared XML processing utilities to eliminate code duplication.

    Provides:
    - XML element indentation for pretty printing
    - Vulnerability ID (VID) extraction from VULN elements
    - Text content collection and extraction from XML elements
    - Mixed content handling for complex XCCDF structures

    Thread-safe: Yes (stateless utility class)
    """

    @staticmethod
    def indent_xml(elem: ET.Element, level: int = 0) -> None:
        """
        Recursively indent XML element tree for pretty printing.

        Modifies the element tree in-place to add appropriate whitespace
        for human-readable XML output.

        Args:
            elem: XML element to indent
            level: Current indentation level (default: 0)

        Returns:
            None (modifies elem in-place)
        """
        indent = "\n" + "\t" * level
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "\t"
            for i, child in enumerate(elem):
                XmlUtils.indent_xml(child, level + 1)
                if not child.tail or not child.tail.strip():
                    # Last child gets dedented, others get full indent
                    child.tail = indent if i == len(elem) - 1 else indent + "\t"
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

    @staticmethod
    def get_vid(vuln: ET.Element) -> Optional[str]:
        """
        Extract Vulnerability ID (VID) from VULN element.

        Searches through STIG_DATA children to find the VULN_ATTRIBUTE
        element with value "Vuln_Num" and extracts the corresponding
        ATTRIBUTE_DATA value.

        Args:
            vuln: VULN XML element

        Returns:
            Vulnerability ID (e.g., "V-123456") or None if not found

        Example:
            >>> vuln_elem = ...  # ET.Element containing VULN data
            >>> vid = XmlUtils.get_vid(vuln_elem)
            >>> print(vid)
            V-123456
        """
        for sd in vuln.findall("STIG_DATA"):
            attr = sd.findtext("VULN_ATTRIBUTE")
            if attr == "Vuln_Num":
                vid = sd.findtext("ATTRIBUTE_DATA")
                if vid:
                    try:
                        return San.vuln(vid.strip())
                    except ValidationError as exc:
                        LOG.d(f"Invalid VID format: {vid.strip()}: {exc}")
        return None

    @staticmethod
    def collect_text(elem: ET.Element, xpath: str, default: str = "", join_with: str = "\n") -> str:
        """
        Collect and join text content from multiple XML elements.

        Finds all elements matching the XPath expression and joins their
        text content with the specified separator.

        Args:
            elem: Parent XML element
            xpath: XPath expression to find child elements
            default: Default value if no elements found
            join_with: String to join multiple results (default: newline)

        Returns:
            Joined text content or default value

        Example:
            >>> root = ...  # ET.Element
            >>> text = XmlUtils.collect_text(root, ".//description", default="No description")
            >>> print(text)
            First description
            Second description
        """
        results = []
        for child in elem.findall(xpath):
            if child.text and child.text.strip():
                results.append(child.text.strip())
        return join_with.join(results) if results else default

    @staticmethod
    def extract_text_content(elem: Optional[ET.Element]) -> str:
        """
        Enhanced text extraction with proper mixed content handling.

        This method handles XCCDF elements that contain plain text, nested elements,
        and preserves command formatting. Uses multiple fallback strategies to handle
        complex XML structures.

        Strategies:
            1. itertext() with newline preservation for mixed content
            2. Recursive manual traversal for complex nested structures
            3. Direct text attribute access for simple elements

        Args:
            elem: XML element to extract text from

        Returns:
            Extracted and normalized text content, or empty string if no content

        Example:
            >>> elem = ET.fromstring("<fix><code>cmd1</code><code>cmd2</code></fix>")
            >>> text = XmlUtils.extract_text_content(elem)
            >>> print(text)
            cmd1
            cmd2
        """
        if elem is None:
            return ""

        # Method 1: itertext() with proper newline preservation
        try:
            parts: List[str] = []
            # Collect all text including from nested elements
            for text_fragment in elem.itertext():
                if text_fragment:
                    # Only strip leading/trailing whitespace, preserve internal structure
                    cleaned = text_fragment.strip()
                    if cleaned:
                        parts.append(cleaned)

            if parts:
                # Join with newlines to preserve command structure
                result = '\n'.join(parts)
                # Clean up excessive blank lines but keep structure
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"itertext() extraction failed: {exc}")

        # Method 2: Manual traversal for complex mixed content
        try:
            def extract_text_recursive(element: ET.Element) -> List[str]:
                texts = []
                if element.text:
                    txt = element.text.strip()
                    if txt:
                        texts.append(txt)
                for child in element:
                    # Recursively get text from children
                    texts.extend(extract_text_recursive(child))
                    # Get tail text (text after child element)
                    if child.tail:
                        tail = child.tail.strip()
                        if tail:
                            texts.append(tail)
                return texts

            parts = extract_text_recursive(elem)
            if parts:
                result = '\n'.join(parts)
                result = re.sub(r'\n\s*\n\s*\n+', '\n\n', result)
                return result.strip()
        except Exception as exc:
            LOG.d(f"Recursive extraction failed: {exc}")

        # Method 3: Direct text attribute (simple elements only)
        if elem.text and elem.text.strip():
            return elem.text.strip()

        return ""
XML utilities.

NOTE: This is a minimal stub for Team 7 testing.
Full implementation will be provided by TEAM 4.
"""

from typing import Optional
from xml.etree.ElementTree import Element


class XmlUtils:
    """XML utilities stub."""

    @staticmethod
    def get_text(elem: Element) -> str:
        """Get element text safely."""
        return elem.text or ""

    @staticmethod
    def set_text(elem: Element, text: str) -> None:
        """Set element text safely."""
        elem.text = text

"""
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

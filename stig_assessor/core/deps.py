"""Optional dependency detection and XML parser management."""

from __future__ import annotations
from contextlib import suppress
import sys
import gc


class Deps:
    """Optional dependency detection."""

    HAS_DEFUSEDXML = False
    HAS_TKINTER = False
    HAS_FCNTL = False
    HAS_MSVCRT = False

    @classmethod
    def check(cls) -> None:
        """Check for available optional dependencies."""
        with suppress(ImportError):
            from defusedxml import ElementTree as DET
            from io import StringIO

            DET.parse(StringIO("<test/>"))
            cls.HAS_DEFUSEDXML = True

        with suppress(ImportError, Exception):
            import tkinter

            r = tkinter.Tk()
            r.withdraw()
            r.destroy()
            del r
            gc.collect()
            cls.HAS_TKINTER = True

        with suppress(ImportError):
            import fcntl  # noqa: F401

            cls.HAS_FCNTL = True

        with suppress(ImportError):
            import msvcrt  # noqa: F401

            cls.HAS_MSVCRT = True

    @classmethod
    def get_xml(cls):
        """Get XML parser (preferring defusedxml for security)."""
        import xml.etree.ElementTree as ET  # noqa: N813
        from xml.etree.ElementTree import ParseError as XMLParseError

        if cls.HAS_DEFUSEDXML:
            import defusedxml.ElementTree as DET

            # Patch parsing methods to secure implementations while keeping ET builders
            ET.parse = DET.parse
            ET.fromstring = DET.fromstring
            ET.XMLParser = DET.XMLParser

        return ET, XMLParseError

    @classmethod
    def warn_if_unsafe(cls) -> None:
        """Warn if defusedxml is not available (security risk)."""
        if not cls.HAS_DEFUSEDXML:
            warning_msg = """
╔════════════════════════════════════════════════════════════╗
║ SECURITY WARNING: defusedxml not installed                ║
║                                                            ║
║ Using unsafe XML parser vulnerable to XXE/billion laughs  ║
║ attacks. This is NOT recommended for DoD production use.  ║
║                                                            ║
║ Install with: pip install defusedxml                      ║
║                                                            ║
║ DoD systems MUST NOT use unsafe parser with untrusted     ║
║ XCCDF/CKL files from external sources.                    ║
╚════════════════════════════════════════════════════════════╝
"""
            print(warning_msg, file=sys.stderr)


# Automatically check dependencies on import
Deps.check()

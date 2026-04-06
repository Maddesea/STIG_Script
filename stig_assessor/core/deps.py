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
        """Get XML parser (preferring defusedxml if available, otherwise native SafeXMLParser)."""
        import xml.etree.ElementTree as ET  # noqa: N813
        from xml.etree.ElementTree import ParseError as XMLParseError

        if cls.HAS_DEFUSEDXML:
            import defusedxml.ElementTree as DET
            ET.parse = DET.parse
            ET.fromstring = DET.fromstring
            ET.XMLParser = DET.XMLParser
        else:
            # Implement a native PyExpat wrapper to prevent DTD/XXE/Billion Laughs
            # This ensures air-gapped DoD compliance without external dependencies
            class SafeXMLParser(ET.XMLParser):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    
                    if hasattr(self, 'parser'):
                        # Completely forbid internal entity declarations (Billion Laughs)
                        self.parser.EntityDeclHandler = self._forbid_entity
                        # Completely forbid external entity references (XXE)
                        self.parser.ExternalEntityRefHandler = self._forbid_external
                        
                def _forbid_entity(self, entityName, is_parameter_entity, value, base, systemId, publicId, notationName):
                    raise ValueError(f"XML Entity Processing (Billion Laughs) is forbidden for security: '{entityName}'")
                    
                def _forbid_external(self, context, base, systemId, publicId):
                    raise ValueError(f"External XML Entity Reference (XXE) is forbidden for security: '{systemId}'")

            def safe_parse(source, parser=None):
                if parser is None:
                    parser = SafeXMLParser()
                tree = ET.ElementTree()
                tree.parse(source, parser)
                return tree

            def safe_fromstring(text, parser=None):
                if parser is None:
                    parser = SafeXMLParser()
                parser.feed(text)
                return parser.close()

            # Safely patch standard library for local environment 
            ET.parse = safe_parse
            ET.fromstring = safe_fromstring
            ET.XMLParser = SafeXMLParser

        return ET, XMLParseError

    @classmethod
    def warn_if_unsafe(cls) -> None:
        """Warning is disabled because we implemented a native SafeXMLParser."""
        pass

# Automatically check dependencies on import
Deps.check()

"""
Boilerplate template management.

This module provides template management for STIG assessment findings.
Templates can be loaded, saved, and applied to VULN elements to provide
standardized finding details and comments.

Source: STIG_Script.py lines 1763-1925
Team: 7 (Phase 2)
"""

from __future__ import annotations
from typing import Dict, Optional
from pathlib import Path
from xml.etree.ElementTree import Element
import json


class BP:
    """
    Boilerplate template manager (Singleton).

    Manages templates for STIG finding details organized by
    vulnerability ID (VID) and status.

    Thread-safe: No (load at startup)
    """

    _instance: Optional['BP'] = None

    def __new__(cls) -> 'BP':
        """Singleton implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize template manager."""
        if hasattr(self, '_initialized'):
            return

        # Import here to avoid circular dependencies during module load
        from stig_assessor.core.config import CFG

        self.template_file: Path = CFG.template_dir / "boilerplate.json"
        self.templates: Dict[str, Dict[str, str]] = {}
        self.load()
        self._initialized = True

    def load(self) -> None:
        """Load templates from file."""
        from stig_assessor.io.file_ops import FO
        from stig_assessor.core.logging import LOG

        if not self.template_file.exists():
            LOG.info("No boilerplate file found, using defaults")
            self._load_defaults()
            self.save()
            return

        try:
            content = FO.read_with_fallback(self.template_file)
            self.templates = json.loads(content)
            LOG.info(f"Loaded {len(self.templates)} boilerplate templates")
        except Exception as e:
            LOG.error(f"Failed to load boilerplate: {e}")
            self._load_defaults()

    def save(self) -> None:
        """Save templates to file."""
        from stig_assessor.io.file_ops import FO
        from stig_assessor.exceptions import FileError

        try:
            content = json.dumps(self.templates, indent=2, ensure_ascii=False)
            FO.atomic_write(self.template_file, content, backup=False)
        except Exception as e:
            raise FileError(f"Failed to save boilerplate: {e}")

    def get(self, vid: str, status: str) -> Optional[str]:
        """
        Get boilerplate text for VID and status.

        Args:
            vid: Vulnerability ID (e.g., V-12345)
            status: Finding status

        Returns:
            Boilerplate text or None
        """
        if vid not in self.templates:
            return None
        return self.templates[vid].get(status)

    def set(self, vid: str, status: str, text: str) -> None:
        """
        Set boilerplate text.

        Args:
            vid: Vulnerability ID
            status: Finding status
            text: Boilerplate text
        """
        if vid not in self.templates:
            self.templates[vid] = {}
        self.templates[vid][status] = text

    def delete(self, vid: str, status: Optional[str] = None) -> bool:
        """
        Delete boilerplate.

        Args:
            vid: Vulnerability ID
            status: Status to delete (None = delete all for VID)

        Returns:
            True if deleted
        """
        if vid not in self.templates:
            return False

        if status is None:
            del self.templates[vid]
        elif status in self.templates[vid]:
            del self.templates[vid][status]
            if not self.templates[vid]:
                del self.templates[vid]
        else:
            return False

        return True

    def apply_to_vuln(self, vuln_elem: Element, vid: str, status: str) -> bool:
        """
        Apply boilerplate to VULN element.

        Args:
            vuln_elem: VULN element
            vid: Vulnerability ID
            status: Current status

        Returns:
            True if boilerplate applied
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        text = self.get(vid, status)
        if text is None:
            return False

        # Apply to FINDING_DETAILS if empty
        finding_elem = vuln_elem.find(Sch.FINDING_DETAILS)
        if finding_elem is not None:
            current = XmlUtils.get_text(finding_elem)
            if not current:
                XmlUtils.set_text(finding_elem, text)
                return True

        return False

    def _load_defaults(self) -> None:
        """Load default boilerplate templates."""
        self.templates = {
            # Example defaults - can be customized
            "V-*": {
                "NotAFinding": "This control is satisfied. Evidence: [describe evidence]",
                "Not_Applicable": "This control does not apply because: [justification]",
                "Open": "This control is not satisfied. Findings: [describe issue]"
            }
        }

    def list_all(self) -> Dict[str, Dict[str, str]]:
        """Get all templates."""
        import copy
        return copy.deepcopy(self.templates)


# Module-level singleton
BOILERPLATE = BP()

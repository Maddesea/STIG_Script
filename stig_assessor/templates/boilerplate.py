"""
Boilerplate template management.

This module provides template management for STIG assessment findings.
Templates can be loaded, saved, and applied to VULN elements to provide
standardized finding details and comments.

Source: STIG_Script.py lines 1763-1925
Team: 7 (Phase 2)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from xml.etree.ElementTree import Element

from stig_assessor.core.constants import Status


class BP:
    """
    Boilerplate template manager (Singleton).

    Manages templates for STIG finding details organized by
    vulnerability ID (VID) and status.

    Thread-safe: No (load at startup)
    """

    _instance: Optional["BP"] = None

    def __new__(cls) -> "BP":
        """Singleton implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize template manager."""
        if hasattr(self, "_initialized"):
            return

        # Import here to avoid circular dependencies during module load
        from stig_assessor.core.config import Cfg

        self.template_file: Path = Cfg.TEMPLATE_DIR / "boilerplate.json"
        self.templates: Dict[str, Dict[str, str]] = {}
        self.load()
        self._initialized = True

    def load(self) -> None:
        """Load templates from file."""
        from stig_assessor.core.logging import LOG
        from stig_assessor.io.file_ops import FO

        if not self.template_file.exists():
            LOG.i("No boilerplate file found, using defaults")
            self._load_defaults()
            self.save()
            return

        try:
            content = FO.read(self.template_file)
            if not content.strip():
                LOG.i("Boilerplate file is empty, using defaults")
                self._load_defaults()
                self.save()
                return

            raw_templates = json.loads(content)

            migrated = False
            self.templates = {}
            for vid, statuses in raw_templates.items():
                self.templates[vid] = {}
                for status, value in statuses.items():
                    if isinstance(value, str):
                        self.templates[vid][status] = {
                            "finding_details": value,
                            "comments": "Reviewed by automated script.",
                        }
                        migrated = True
                    else:
                        self.templates[vid][status] = value

            if migrated:
                LOG.i("Migrated legacy string boilerplates to dictionary format.")
                self.save()

            LOG.i(f"Loaded {len(self.templates)} boilerplate templates")
        except (OSError, ValueError, TypeError) as e:
            LOG.e(f"Failed to load boilerplate: {e}")
            self._load_defaults()

    def save(self) -> None:
        """Save templates to file."""
        self._write_to_path(self.template_file)

    def _write_to_path(self, target_path: Path) -> None:
        from stig_assessor.exceptions import FileError
        from stig_assessor.io.file_ops import FO

        try:
            content = json.dumps(self.templates, indent=2, ensure_ascii=False)
            with FO.atomic(target_path, bak=False) as f:
                f.write(content)
        except (OSError, ValueError, TypeError) as e:
            raise FileError(f"Failed to write boilerplate to {target_path}: {e}")

    def export(self, path: str) -> None:
        """Export boilerplates to a specific JSON file."""
        self._write_to_path(Path(path))

    def imp(self, path: str) -> None:
        """Import boilerplates dynamically from JSON file and merge them."""
        from stig_assessor.core.logging import LOG
        from stig_assessor.io.file_ops import FO

        try:
            p = Path(path)
            if not p.exists():
                return
            content = FO.read(p)
            incoming = json.loads(content)
            for vid, statuses in incoming.items():
                if vid not in self.templates:
                    self.templates[vid] = {}
                for status, value in statuses.items():
                    if isinstance(value, str):
                        self.templates[vid][status] = {
                            "finding_details": value,
                            "comments": "Imported comment template",
                        }
                    else:
                        self.templates[vid][status] = value
            self.save()
            LOG.i(f"Imported boilerplates from {path}")
        except (
            json.JSONDecodeError,
            OSError,
            TypeError,
            ValueError,
            KeyError,
        ) as e:
            LOG.e(f"Import boilerplate failed: {e}")

    def _resolve(self, vid: str, status: str, field: str, **kwargs) -> Optional[str]:
        vid_candidates = [vid, "V-*"] if vid else ["V-*"]
        raw_text = None
        for candidate in vid_candidates:
            if candidate in self.templates and status in self.templates[candidate]:
                entry = self.templates[candidate][status]
                raw_text = entry.get(field)
                if raw_text is not None:
                    break

        if raw_text is None:
            return None

        return raw_text.format(**kwargs) if kwargs else raw_text

    def get_finding(self, vid: str, status: str, **kwargs) -> Optional[str]:
        return self._resolve(vid, status, "finding_details", **kwargs)

    def get_comment(self, vid: str, status: str, **kwargs) -> Optional[str]:
        return self._resolve(vid, status, "comments", **kwargs)

    # Legacy shims mapped to global V-* for processor compatibility if vid wasn't passed
    def find(self, status: str, **kwargs) -> Optional[str]:
        return self.get_finding("V-*", status, **kwargs)

    def comm(self, status: str, **kwargs) -> Optional[str]:
        return self.get_comment("V-*", status, **kwargs)

    def set(self, vid: str, status: str, finding: str, comment: str) -> None:
        """Set boilerplate fields."""
        if vid not in self.templates:
            self.templates[vid] = {}
        self.templates[vid][status] = {
            "finding_details": finding,
            "comments": comment,
        }
        self.save()

    def delete(self, vid: str, status: Optional[str] = None) -> bool:
        """Delete boilerplate."""
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

        self.save()
        return True

    def apply_to_vuln(
        self, vuln_elem: Element, vid: str, status: str, **kwargs
    ) -> bool:
        """Apply boilerplate to VULN element."""
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        finding_text = self.get_finding(vid, status, **kwargs)
        comments_text = self.get_comment(vid, status, **kwargs)

        applied = False

        if finding_text:
            finding_elem = vuln_elem.find(Sch.FINDING_DETAILS)
            if finding_elem is not None:
                current_f = XmlUtils.get_text(finding_elem)
                if not current_f:
                    XmlUtils.set_text(finding_elem, finding_text)
                    applied = True

        if comments_text:
            comm_elem = vuln_elem.find(Sch.COMMENTS)
            if comm_elem is not None:
                current_c = XmlUtils.get_text(comm_elem)
                if not current_c:
                    XmlUtils.set_text(comm_elem, comments_text)
                    applied = True

        return applied

    def _load_defaults(self) -> None:
        """Load default boilerplate templates."""
        self.templates = {
            "V-*": {
                Status.NOT_A_FINDING.value: {
                    "finding_details": "This control is satisfied. Evidence: {asset}",
                    "comments": "Reviewed by automated script.",
                },
                Status.NOT_APPLICABLE.value: {
                    "finding_details": "This control does not apply because: [justification]",
                    "comments": "Not applicable to {asset} configuration.",
                },
                Status.OPEN.value: {
                    "finding_details": "This control is not satisfied. Findings: [describe issue]",
                    "comments": "Remediation pending for {asset}.",
                },
            }
        }

    def list_all(self) -> Dict[str, Dict[str, Any]]:
        """Get all templates."""
        import copy

        return copy.deepcopy(self.templates)


# Module-level singleton
BOILERPLATE = BP()

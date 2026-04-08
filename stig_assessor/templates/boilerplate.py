"""
Boilerplate template management.

This module provides template management for STIG assessment findings.
Templates can be loaded, saved, and applied to VULN elements to provide
standardized finding details and comments.

Apply Modes:
    - overwrite_empty: Only fill in empty fields (default)
    - prepend: Add boilerplate text before existing content
    - append: Add boilerplate text after existing content
    - merge: Combine boilerplate with existing, separated by a divider

Template Variables:
    Templates support Python format-string placeholders:
    - {asset}: Asset hostname or identifier
    - {severity}: Vulnerability severity level (high/medium/low)

Source: STIG_Script.py lines 1763-1925
Team: 7 (Phase 2)
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
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
        self,
        vuln_elem: Element,
        vid: str,
        status: str,
        *,
        apply_mode: str = "overwrite_empty",
        **kwargs,
    ) -> bool:
        """Apply boilerplate to VULN element.

        Args:
            vuln_elem: Target VULN XML element.
            vid: Vulnerability ID (e.g. V-12345).
            status: Finding status (e.g. NotAFinding).
            apply_mode: How to apply text. One of:
                - ``overwrite_empty``: Only fill empty fields (default).
                - ``prepend``: Add boilerplate before existing content.
                - ``append``: Add boilerplate after existing content.
                - ``merge``: Combine with existing, separated by divider.
            **kwargs: Template variable substitutions (asset, severity, etc.).

        Returns:
            True if any field was modified.
        """
        from stig_assessor.xml.schema import Sch
        from stig_assessor.xml.utils import XmlUtils

        finding_text = self.get_finding(vid, status, **kwargs)
        comments_text = self.get_comment(vid, status, **kwargs)

        applied = False

        if finding_text:
            finding_elem = vuln_elem.find(Sch.FINDING_DETAILS)
            if finding_elem is not None:
                current_f = XmlUtils.get_text(finding_elem)
                new_f = self._apply_text(
                    current_f, finding_text, apply_mode
                )
                if new_f != current_f:
                    XmlUtils.set_text(finding_elem, new_f)
                    applied = True

        if comments_text:
            comm_elem = vuln_elem.find(Sch.COMMENTS)
            if comm_elem is not None:
                current_c = XmlUtils.get_text(comm_elem)
                new_c = self._apply_text(
                    current_c, comments_text, apply_mode
                )
                if new_c != current_c:
                    XmlUtils.set_text(comm_elem, new_c)
                    applied = True

        return applied

    @staticmethod
    def _apply_text(
        current: str, boilerplate: str, mode: str
    ) -> str:
        """Combine current text with boilerplate according to mode."""
        current = current or ""
        if mode == "overwrite_empty":
            return current if current.strip() else boilerplate
        elif mode == "prepend":
            if current.strip():
                return f"{boilerplate}\n\n{current}"
            return boilerplate
        elif mode == "append":
            if current.strip():
                return f"{current}\n\n{boilerplate}"
            return boilerplate
        elif mode == "merge":
            if current.strip():
                divider = "\n--- Boilerplate ---\n"
                return f"{current}{divider}{boilerplate}"
            return boilerplate
        # Fallback to overwrite_empty
        return current if current.strip() else boilerplate

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
        """Get all templates (deep copy)."""
        return copy.deepcopy(self.templates)

    def reset_all(self) -> None:
        """Reset all boilerplates to factory defaults."""
        from stig_assessor.core.logging import LOG

        self._load_defaults()
        self.save()
        LOG.i("Boilerplate templates reset to defaults")

    def clone(self, vid_from: str, vid_to: str) -> bool:
        """Clone all status templates from one VID to another.

        Args:
            vid_from: Source vulnerability ID.
            vid_to: Destination vulnerability ID.

        Returns:
            True if clone succeeded, False if source VID not found.
        """
        if vid_from not in self.templates:
            return False
        self.templates[vid_to] = copy.deepcopy(self.templates[vid_from])
        self.save()
        return True

    @staticmethod
    def list_variables() -> List[Dict[str, str]]:
        """Return list of available template placeholder variables.

        Returns:
            List of dicts with 'name' and 'description' keys.
        """
        return [
            {
                "name": "{asset}",
                "description": "Asset hostname or identifier",
            },
            {
                "name": "{severity}",
                "description": "Vulnerability severity (high/medium/low)",
            },
        ]

    def import_b64(self, b64_str: str) -> int:
        """Import boilerplates from a base64-encoded JSON string.

        Args:
            b64_str: Base64-encoded JSON boilerplate data.

        Returns:
            Number of VIDs imported.
        """
        import base64

        raw = base64.b64decode(b64_str).decode("utf-8")
        incoming = json.loads(raw)
        count = 0
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
            count += 1
        self.save()
        return count

    def export_b64(self) -> str:
        """Export all boilerplates as a base64-encoded JSON string.

        Returns:
            Base64-encoded JSON string of all templates.
        """
        import base64

        raw = json.dumps(
            self.templates, indent=2, ensure_ascii=False
        )
        return base64.b64encode(raw.encode("utf-8")).decode("utf-8")


# Module-level singleton
BOILERPLATE = BP()

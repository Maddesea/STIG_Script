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

    def import_from_checklist(self, path: str, status_filter: Optional[List[str]] = None, overwrite: bool = True) -> Dict[str, int]:
        """
        Import boilerplates by scanning a checklist file.

        Args:
            path: Checklist file path.
            status_filter: Only import VULNs with these statuses.
            overwrite: If False, skip VIDs that already have a template.
            
        Returns:
            Dict with import statistics.
        """
        from stig_assessor.io.file_ops import FO
        from stig_assessor.processor.html_report import _parse_checklist
        
        data = _parse_checklist(FO.resolve(path))
        vulns = data.get("vulns", [])
        
        total_scanned = len(vulns)
        imported = 0
        skipped = 0
        
        for vuln in vulns:
            vid = vuln.get("vid", "")
            status = vuln.get("status", "")
            finding = vuln.get("finding", "")
            comment = vuln.get("comment", "")
            
            if not vid or (not finding.strip() and not comment.strip()):
                continue
                
            if status_filter and status not in status_filter:
                continue
                
            if not overwrite and vid in self.templates:
                skipped += 1
                continue
                
            self.set(vid, status, finding, comment)
            imported += 1
            
        return {
            "total_scanned": total_scanned,
            "imported": imported,
            "skipped": skipped
        }

    def reset_vid(self, vid: str) -> bool:
        """
        Reset a specific VID to inherit from the V-* wildcard template 
        by deleting its specific templates.
        """
        if vid in self.templates:
            del self.templates[vid]
            self.save()
            return True
        return False

    def find_duplicates(self) -> List[Dict[str, Any]]:
        """
        Analyze all loaded boilerplate templates to find identical content 
        used across multiple VIDs. This helps users consolidate to V-* wildcards.
        
        Returns:
            List of dictionaries describing duplicate groups.
        """
        # Map content hash -> { 'status': status, 'field': field, 'vids': set(), 'text': text }
        content_map = {}
        
        for vid, statuses in self.templates.items():
            if vid == "V-*": continue  # Skip the wildcard itself
            
            for status, fields in statuses.items():
                for field in ["finding_details", "comments"]:
                    text = fields.get(field, "").strip()
                    if not text or len(text) < 20: continue # Skip trivial templates
                    
                    # Create signature
                    sig = f"{status}:{field}:{hash(text)}"
                    
                    if sig not in content_map:
                        content_map[sig] = {
                            "status": status,
                            "field": field,
                            "vids": set(),
                            "text": text
                        }
                    content_map[sig]["vids"].add(vid)
                    
        # Filter to only those with >1 VID
        duplicates = []
        for sig, data in content_map.items():
            if len(data["vids"]) > 1:
                duplicates.append({
                    "status": data["status"],
                    "field": "Finding Details" if data["field"] == "finding_details" else "Comments",
                    "count": len(data["vids"]),
                    "vids": sorted(list(data["vids"])),
                    "text_preview": data["text"][:100].replace("\n", " ")
                })
                
        # Sort by count descending
        return sorted(duplicates, key=lambda x: x["count"], reverse=True)

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

    def bulk_set(
        self, vids: List[str], status: str, finding: str, comment: str
    ) -> int:
        """Set the same boilerplate across multiple VIDs at once.

        Args:
            vids: List of vulnerability IDs to update.
            status: Status key (e.g. 'NotAFinding').
            finding: Finding details text.
            comment: Comments text.

        Returns:
            Number of VIDs updated.
        """
        count = 0
        for vid in vids:
            if vid not in self.templates:
                self.templates[vid] = {}
            self.templates[vid][status] = {
                "finding_details": finding,
                "comments": comment,
            }
            count += 1
        if count:
            self.save()
        return count

    def search(self, pattern: str) -> List[str]:
        """Search for VIDs whose boilerplate text matches a pattern.

        Case-insensitive substring match against finding_details and comments.

        Args:
            pattern: Text pattern to search for.

        Returns:
            Sorted list of matching VID strings.
        """
        if not pattern:
            return sorted(self.templates.keys())
        needle = pattern.lower()
        matches = []
        for vid, statuses in self.templates.items():
            found = False
            if needle in vid.lower():
                found = True
            else:
                for _status, entry in statuses.items():
                    if isinstance(entry, dict):
                        for val in entry.values():
                            if isinstance(val, str) and needle in val.lower():
                                found = True
                                break
                    if found:
                        break
            if found:
                matches.append(vid)
        return sorted(matches)

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
            {
                "name": "{date}",
                "description": "Current date (YYYY-MM-DD)",
            },
            {
                "name": "{vid}",
                "description": "Vulnerability ID (e.g. V-12345)",
            },
            {
                "name": "{rule_title}",
                "description": "Rule title from the STIG benchmark",
            },
        ]

    def preview(
        self,
        vid: str,
        status: str,
        **kwargs,
    ) -> Dict[str, Optional[str]]:
        """Preview the expanded template for a given VID and status.

        Returns the fully expanded text without applying it to any element.
        Automatically injects {date} if not provided in kwargs.

        Args:
            vid: Vulnerability ID.
            status: Finding status.
            **kwargs: Template variable substitutions.

        Returns:
            Dict with 'finding_details' and 'comments' keys (None if no template).
        """
        from datetime import datetime, timezone

        # Auto-inject date if not provided
        if "date" not in kwargs:
            kwargs["date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        # Auto-inject vid if not provided
        if "vid" not in kwargs:
            kwargs["vid"] = vid

        return {
            "finding_details": self._resolve(vid, status, "finding_details", **kwargs),
            "comments": self._resolve(vid, status, "comments", **kwargs),
        }

    def import_from_checklist(
        self,
        ckl_path,
        *,
        status_filter: Optional[List[str]] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """Extract boilerplate templates from an existing CKL file.

        Learns from existing assessment language by importing non-empty
        finding_details and comments as VID-specific boilerplate entries.

        Args:
            ckl_path: Path to checklist file (.ckl or .cklb).
            status_filter: Only import from VULNs with these statuses.
                Defaults to all statuses if None.
            overwrite: If True, overwrite existing templates for the same
                VID/status. If False, skip VIDs that already have templates.

        Returns:
            Dict with 'imported', 'skipped', 'total_scanned' keys.
        """
        from stig_assessor.core.logging import LOG
        from stig_assessor.io.file_ops import FO
        from stig_assessor.xml.utils import XmlUtils

        ckl_path = Path(ckl_path)
        if not ckl_path.exists():
            LOG.e(f"Checklist not found: {ckl_path}")
            return {"imported": 0, "skipped": 0, "total_scanned": 0}

        try:
            if ckl_path.suffix.lower() == ".cklb":
                import json as _json
                cklb_data = _json.loads(FO.read(ckl_path))
                return self._import_from_cklb(cklb_data, status_filter, overwrite)

            tree = FO.parse_xml(ckl_path)
            root = tree.getroot()
        except (OSError, ValueError, TypeError) as e:
            LOG.e(f"Failed to parse checklist for boilerplate import: {e}")
            return {"imported": 0, "skipped": 0, "total_scanned": 0}

        status_set = {s for s in status_filter} if status_filter else None
        imported = 0
        skipped = 0
        total = 0

        stigs = root.find("STIGS")
        if stigs is None:
            return {"imported": 0, "skipped": 0, "total_scanned": 0}

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                total += 1
                vid = XmlUtils.get_vid(vuln)
                if not vid:
                    skipped += 1
                    continue

                status_node = vuln.find("STATUS")
                status = (
                    status_node.text.strip()
                    if status_node is not None and status_node.text
                    else ""
                )
                if not status:
                    skipped += 1
                    continue

                if status_set and status not in status_set:
                    skipped += 1
                    continue

                finding = vuln.findtext("FINDING_DETAILS", default="").strip()
                comment = vuln.findtext("COMMENTS", default="").strip()

                if not finding and not comment:
                    skipped += 1
                    continue

                # Check if template already exists
                if not overwrite and vid in self.templates:
                    if status in self.templates[vid]:
                        skipped += 1
                        continue

                if vid not in self.templates:
                    self.templates[vid] = {}
                self.templates[vid][status] = {
                    "finding_details": finding,
                    "comments": comment,
                }
                imported += 1

        if imported > 0:
            self.save()
            LOG.i(f"Imported {imported} boilerplate(s) from {ckl_path.name}")

        return {
            "imported": imported,
            "skipped": skipped,
            "total_scanned": total,
        }

    def _import_from_cklb(
        self, cklb_data: dict, status_filter, overwrite: bool
    ) -> Dict[str, Any]:
        """Import boilerplates from a parsed CKLB (JSON) structure."""
        status_set = set(status_filter) if status_filter else None
        imported = 0
        skipped = 0
        total = 0

        for review in cklb_data.get("reviews", []):
            total += 1
            vid = review.get("Vuln_Num", "")
            status = review.get("status", "")
            finding = (review.get("detail") or "").strip()
            comment = (review.get("comment") or "").strip()

            if not vid or not status:
                skipped += 1
                continue
            if status_set and status not in status_set:
                skipped += 1
                continue
            if not finding and not comment:
                skipped += 1
                continue
            if not overwrite and vid in self.templates:
                if status in self.templates[vid]:
                    skipped += 1
                    continue

            if vid not in self.templates:
                self.templates[vid] = {}
            self.templates[vid][status] = {
                "finding_details": finding,
                "comments": comment,
            }
            imported += 1

        if imported > 0:
            self.save()
        return {"imported": imported, "skipped": skipped, "total_scanned": total}

    def reset_vid(self, vid: str) -> bool:
        """Reset a specific VID's templates back to the V-* wildcard defaults.

        Args:
            vid: Vulnerability ID to reset.

        Returns:
            True if the VID was removed (it will now inherit from V-*).
        """
        if vid == "V-*":
            return False  # Cannot reset the wildcard itself this way
        if vid in self.templates:
            del self.templates[vid]
            self.save()
            return True
        return False

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

    # ═══ ENHANCED: Apply boilerplates to a full checklist ═══
    def apply_to_checklist(
        self,
        root: Element,
        *,
        status_filter: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None,
        vid_list: Optional[List[str]] = None,
        apply_mode: str = "overwrite_empty",
        date_override: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Apply boilerplates to an entire CKL ElementTree root.

        Args:
            root: XML root element of the checklist.
            status_filter: Only apply to VULNs matching these statuses.
            severity_filter: Only apply to VULNs matching these severities.
            vid_list: Specific VIDs to target (None means all).
            apply_mode: How to apply text (overwrite_empty, prepend, append,
                merge, overwrite_all).
            **kwargs: Template variable substitutions.

        Returns:
            Dict with 'applied', 'skipped', 'affected_vids' keys.
        """
        from stig_assessor.xml.utils import XmlUtils

        status_set = {s.lower() for s in status_filter} if status_filter else None
        sev_set = {s.lower() for s in severity_filter} if severity_filter else None
        vid_set = set(vid_list) if vid_list else None

        applied = 0
        skipped = 0
        affected: List[str] = []
        
        # Inject date into kwargs for formatting
        if "date" not in kwargs:
            if date_override:
                kwargs["date"] = date_override
            else:
                from datetime import datetime
                kwargs["date"] = datetime.now().strftime("%Y-%m-%d")

        stigs = root.find("STIGS")
        if stigs is None:
            return {"applied": 0, "skipped": 0, "affected_vids": []}

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = XmlUtils.get_vid(vuln)
                if not vid:
                    skipped += 1
                    continue

                # Filter by VID list
                if vid_set and vid not in vid_set:
                    skipped += 1
                    continue

                # Get status
                status_node = vuln.find("STATUS")
                status = (status_node.text or "").strip() if status_node is not None else ""
                if not status:
                    skipped += 1
                    continue

                # Filter by status
                if status_set and status.lower() not in status_set:
                    skipped += 1
                    continue

                # Filter by severity
                if sev_set:
                    sev_val = "medium"
                    for sd in vuln.findall("STIG_DATA"):
                        if sd.findtext("VULN_ATTRIBUTE") == "Severity":
                            sev_val = sd.findtext("ATTRIBUTE_DATA", default="medium")
                    if sev_val.lower() not in sev_set:
                        skipped += 1
                        continue

                # Handle overwrite_all mode by temporarily converting
                effective_mode = apply_mode
                if apply_mode == "overwrite_all":
                    effective_mode = "overwrite_empty"
                    # Clear existing text so overwrite_empty fills it
                    for tag in ["FINDING_DETAILS", "COMMENTS"]:
                        node = vuln.find(tag)
                        if node is not None:
                            node.text = ""

                result = self.apply_to_vuln(
                    vuln, vid, status, apply_mode=effective_mode, **kwargs
                )
                if result:
                    applied += 1
                    affected.append(vid)
                else:
                    skipped += 1

        return {"applied": applied, "skipped": skipped, "affected_vids": affected}

    def bulk_set(
        self,
        vids: List[str],
        status: str,
        finding: str,
        comment: str,
    ) -> int:
        """Set the same boilerplate template for multiple VIDs at once.

        Args:
            vids: List of vulnerability IDs.
            status: Status to set template for.
            finding: Finding details text.
            comment: Comments text.

        Returns:
            Number of VIDs updated.
        """
        count = 0
        for vid in vids:
            vid = vid.strip()
            if not vid:
                continue
            if vid not in self.templates:
                self.templates[vid] = {}
            self.templates[vid][status] = {
                "finding_details": finding,
                "comments": comment,
            }
            count += 1
        if count > 0:
            self.save()
        return count

    def search(self, query: str) -> List[Dict[str, str]]:
        """Search boilerplate text across all VIDs and statuses.

        Args:
            query: Text substring to search for (case-insensitive).

        Returns:
            List of match dicts with 'vid', 'status', 'field', 'snippet'.
        """
        query_lower = query.lower()
        results: List[Dict[str, str]] = []

        for vid, statuses in self.templates.items():
            for status, entry in statuses.items():
                if not isinstance(entry, dict):
                    continue
                for field in ["finding_details", "comments"]:
                    text = entry.get(field, "")
                    if query_lower in text.lower():
                        # Build a snippet around the match
                        idx = text.lower().index(query_lower)
                        start = max(0, idx - 40)
                        end = min(len(text), idx + len(query) + 40)
                        snippet = text[start:end]
                        if start > 0:
                            snippet = "..." + snippet
                        if end < len(text):
                            snippet = snippet + "..."
                        results.append({
                            "vid": vid,
                            "status": status,
                            "field": field,
                            "snippet": snippet,
                        })

        return results

    def find_duplicates(self) -> List[Dict[str, Any]]:
        """Identify VIDs with identical or near-identical templates.

        Useful for consolidating templates into V-* global patterns.

        Returns:
            List of duplicate groups. Each group contains 'text_hash',
            'field', 'status', and 'vids' list.
        """
        from collections import defaultdict as _dd

        # Group by (status, field, text_hash)
        groups: Dict[str, List[str]] = _dd(list)

        for vid, statuses in self.templates.items():
            if vid == "V-*":
                continue  # Skip global template
            for status, entry in statuses.items():
                if not isinstance(entry, dict):
                    continue
                for field in ["finding_details", "comments"]:
                    text = entry.get(field, "").strip()
                    if not text:
                        continue
                    # Normalize whitespace for comparison
                    normalized = " ".join(text.split()).lower()
                    key = f"{status}|{field}|{normalized[:200]}"
                    groups[key].append(vid)

        # Filter to only groups with 2+ VIDs
        duplicates: List[Dict[str, Any]] = []
        for key, vids in groups.items():
            if len(vids) >= 2:
                parts = key.split("|", 2)
                duplicates.append({
                    "status": parts[0],
                    "field": parts[1],
                    "text_preview": parts[2][:100],
                    "vids": vids,
                    "count": len(vids),
                })

        return sorted(duplicates, key=lambda d: -d["count"])


# Module-level singleton
BOILERPLATE = BP()

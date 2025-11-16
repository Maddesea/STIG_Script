"""Remediation results processor for bulk updates.

This module handles loading remediation results from JSON and applying them
to CKL (checklist) files.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Union, Tuple
import json
import xml.etree.ElementTree as ET


class FixResPro:
    """
    Bulk remediation results processor.

    Loads remediation results from JSON files in multiple formats and applies
    them to CKL checklists. Supports deduplication by VID and preserves
    existing finding details.

    Thread-safe: No

    Supported JSON formats:
        1. Array: [{"vid": "V-1", "ok": true, ...}, ...]
        2. Object: {"results": [...], "meta": {...}}
        3. Multi-system: {"systems": {"host1": [...], "host2": [...]}}
        4. Alternative keys: {"vulnerabilities": [...], "entries": [...]}
    """

    def __init__(self):
        """Initialize results processor."""
        self.results: Dict[str, "FixResult"] = {}
        self.meta: Dict[str, Any] = {}

    def load(self, path: Union[str, Path]) -> Tuple[int, int]:
        """
        Load remediation results from JSON with support for multiple formats.

        Supported formats:
            1. Array: [{"vid": "V-1", "ok": true, ...}, ...]
            2. Object: {"results": [...], "meta": {...}}
            3. Multi-system: {"systems": {"host1": [...], "host2": [...]}}
            4. Alternative keys: {"vulnerabilities": [...], "entries": [...]}

        Args:
            path: Path to JSON results file

        Returns:
            Tuple of (unique_count, skipped_count)

        Raises:
            ParseError: If JSON is invalid or unrecognized format
            FileError: If file cannot be read
        """
        from STIG_Script import San, LOG, FO, ParseError
        from stig_assessor.remediation.models import FixResult

        path = San.path(path, exist=True, file=True)
        LOG.ctx(op="load_fix_results", file=path.name)
        LOG.i("Loading remediation results JSON")

        try:
            content = FO.read(path)
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in {path.name}: {exc}") from exc
        except Exception as exc:
            raise ParseError(f"Cannot read {path.name}: {exc}") from exc

        imported = 0
        skipped = 0
        entries = []

        # ═══ FORMAT DETECTION ═══
        if isinstance(payload, list):
            # Format 1: Direct array
            LOG.d("Detected array format")
            self.meta = {"format": "array", "source": str(path)}
            entries = payload

        elif isinstance(payload, dict):
            self.meta = payload.get("meta", {})
            self.meta["source"] = str(path)

            # Format 2: Standard "results" key
            if "results" in payload:
                LOG.d("Detected standard object format with 'results' key")
                entries = payload["results"]

            # Format 3: Multi-system grouped format
            elif "systems" in payload:
                LOG.i("Detected multi-system format")
                systems_data = payload["systems"]
                if isinstance(systems_data, dict):
                    for system_name, system_results in systems_data.items():
                        if isinstance(system_results, list):
                            # Tag each result with source system
                            for entry in system_results:
                                if isinstance(entry, dict):
                                    entry['_source_system'] = system_name
                            entries.extend(system_results)
                            LOG.d(f"  Loaded {len(system_results)} from system '{system_name}'")

            # Format 4: Alternative keys
            elif "vulnerabilities" in payload:
                LOG.d("Detected 'vulnerabilities' format")
                entries = payload["vulnerabilities"]
            elif "entries" in payload:
                LOG.d("Detected 'entries' format")
                entries = payload["entries"]
            elif "res" in payload:
                LOG.d("Detected 'res' format")
                entries = payload["res"]
            elif "findings" in payload:
                LOG.d("Detected 'findings' format")
                entries = payload["findings"]
            else:
                # Maybe the payload itself is a single result entry?
                if "vid" in payload:
                    LOG.d("Detected single result object")
                    entries = [payload]
                else:
                    raise ParseError(
                        f"Unrecognized JSON format. Expected keys: 'results', 'systems', "
                        f"'vulnerabilities', 'entries', or direct array. Found: {list(payload.keys())}"
                    )
        else:
            raise ParseError(f"JSON must be object or array, got {type(payload).__name__}")

        if not isinstance(entries, list):
            raise ParseError(f"Results must be array, got {type(entries).__name__}")

        if not entries:
            LOG.w("No entries found in results file")
            return 0, 0

        # ═══ PROCESS ENTRIES WITH DEDUPLICATION ═══
        dedup: Dict[str, FixResult] = {}

        for idx, entry in enumerate(entries, 1):
            try:
                result = FixResult.from_dict(entry)

                # Deduplication: keep most recent for each VID
                if result.vid in dedup:
                    existing = dedup[result.vid]
                    if result.ts > existing.ts:
                        LOG.d(f"  {result.vid}: replacing older result")
                        dedup[result.vid] = result
                    else:
                        LOG.d(f"  {result.vid}: keeping existing (newer)")
                else:
                    dedup[result.vid] = result

                imported += 1

            except Exception as exc:
                skipped += 1
                LOG.w(f"Entry {idx}: invalid - {exc}")
                continue

        # Merge with existing results (for multi-file batch)
        for vid, result in dedup.items():
            if vid in self.results:
                # Keep newer result
                if result.ts > self.results[vid].ts:
                    self.results[vid] = result
            else:
                self.results[vid] = result

        unique_count = len(dedup)
        LOG.i(f"Loaded {unique_count} unique results from {imported} total entries (skipped {skipped})")
        LOG.clear()

        return unique_count, skipped

    def update_ckl(
        self,
        checklist: Union[str, Path],
        out: Union[str, Path],
        *,
        auto_status: bool = True,
        dry: bool = False,
    ) -> Dict[str, Any]:
        """
        Update CKL file with remediation results.

        Applies loaded remediation results to vulnerabilities in the checklist.
        Preserves existing finding details by prepending remediation evidence.
        Optionally updates status to "NotAFinding" for successful remediations.

        Args:
            checklist: Path to input CKL file
            out: Path to output CKL file
            auto_status: Auto-update status to NotAFinding on success
            dry: Dry-run mode (don't save changes)

        Returns:
            Dictionary with update statistics:
                - updated: Number of vulnerabilities updated
                - not_found: List of VIDs not found in checklist
                - dry_run: Whether this was a dry run
                - output: Output file path (if not dry run)

        Raises:
            ParseError: If CKL cannot be parsed
            ValidationError: If paths are invalid
        """
        from STIG_Script import San, LOG, FO, XmlUtils, Cfg, Sch, ParseError

        checklist = San.path(checklist, exist=True, file=True)
        out = San.path(out, mkpar=True)

        LOG.ctx(op="apply_results", file=checklist.name)
        LOG.i(f"Applying remediation results to checklist ({len(self.results)} vulns)")

        try:
            tree = FO.parse_xml(checklist)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Unable to parse checklist: {exc}") from exc

        stigs = root.find("STIGS")
        if stigs is None:
            raise ParseError("Checklist missing STIGS section")

        # Build VID index once for O(1) lookups (performance optimization)
        LOG.d("Building VID index for fast lookups")
        vid_to_vuln: Dict[str, Any] = {}
        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = XmlUtils.get_vid(vuln)
                if vid:
                    vid_to_vuln[vid] = vuln

        updated = 0
        not_found: List[str] = []

        # Use index for O(1) lookups instead of O(n) searches
        for vid, result in self.results.items():
            vuln = vid_to_vuln.get(vid)
            if not vuln:
                not_found.append(vid)
                continue

            updated += 1

            finding_node = vuln.find("FINDING_DETAILS")
            if finding_node is None:
                finding_node = ET.SubElement(vuln, "FINDING_DETAILS")

            summary = [
                "┌" + "─" * 78 + "┐",
                "│ AUTOMATED REMEDIATION".center(80) + "│",
                "└" + "─" * 78 + "┘",
                f"Timestamp: {result.ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"Result: {'✔ SUCCESS' if result.ok else '✘ FAILED'}",
                f"Mode: {self.meta.get('mode', 'unknown')}",
            ]
            if result.message:
                summary.append(f"Message: {result.message}")
            if result.output:
                summary.append("")
                summary.append("Output:")
                summary.append(result.output)
            if result.error:
                summary.append("")
                summary.append("Error:")
                summary.append(result.error)

            existing = finding_node.text or ""
            if existing.strip():
                combined = "\n".join(summary) + "\n\n" + "═" * 80 + "\n[PREVIOUS]\n" + "═" * 80 + "\n\n" + existing
            else:
                combined = "\n".join(summary)

            if len(combined) > Cfg.MAX_FIND:
                combined = combined[: Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
            finding_node.text = combined

            comment_node = vuln.find("COMMENTS")
            if comment_node is None:
                comment_node = ET.SubElement(vuln, "COMMENTS")
            comments = comment_node.text or ""
            entry = f"[Automated Remediation {result.ts.strftime('%Y-%m-%d %H:%M:%S UTC')}] {result.message or 'Refer to details'}"
            if comments.strip():
                comment_node.text = entry + "\n" + comments
            else:
                comment_node.text = entry

            if auto_status and result.ok:
                status_node = vuln.find("STATUS")
                if status_node is None:
                    status_node = ET.SubElement(vuln, "STATUS")
                status_node.text = San.status("NotAFinding")

        XmlUtils.indent_xml(root)

        if dry:
            LOG.i("Dry-run requested, checklist not written")
            LOG.clear()
            return {
                "updated": updated,
                "not_found": not_found,
                "dry_run": True,
            }

        self._write_ckl(root, out)
        LOG.i(f"Checklist updated and saved to {out}")
        LOG.clear()

        return {
            "updated": updated,
            "not_found": not_found,
            "dry_run": False,
            "output": str(out),
        }

    def generate_report(self, format: str = "text") -> str:
        """
        Generate remediation report.

        Args:
            format: Output format - 'text', 'json', or 'csv'

        Returns:
            Report content as string
        """
        if format == "json":
            return json.dumps([r.as_dict() for r in self.results.values()], indent=2)

        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=['vid', 'timestamp', 'success', 'message']
            )
            writer.writeheader()
            for r in self.results.values():
                writer.writerow({
                    'vid': r.vid,
                    'timestamp': r.ts.isoformat(),
                    'success': r.ok,
                    'message': r.message
                })
            return output.getvalue()

        else:  # text
            lines = ["Remediation Results Report", "=" * 50, ""]
            for r in self.results.values():
                lines.append(f"{r.vid}: {'✓ SUCCESS' if r.ok else '✗ FAILED'} - {r.message}")
            return "\n".join(lines)

    def _write_ckl(self, root, out: Path) -> None:
        """
        Write CKL file with proper XML formatting.

        Args:
            root: XML root element
            out: Output file path
        """
        from STIG_Script import FO, Sch

        with FO.atomic(out, mode="wb", bak=False) as handle:
            handle.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            handle.write(f"<!--{Sch.COMMENT}-->\n".encode("utf-8"))
            xml_text = ET.tostring(root, encoding="unicode", method="xml")
            handle.write(xml_text.encode("utf-8"))


__all__ = ["FixResPro"]

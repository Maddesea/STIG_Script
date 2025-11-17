"""Core processor module for XCCDF to CKL conversion and checklist operations.

This module provides the main Proc class which handles:
- XCCDF → CKL conversion
- Checklist merging with history preservation
- Checklist diff functionality
- Repair of corrupted checklists
- Batch conversion operations
- Integrity verification
- Statistics generation
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union
import hashlib
import re
import uuid
import xml.etree.ElementTree as ET

# Import from modular structure
from stig_assessor.core.config import Cfg
from stig_assessor.core.logging import LOG
from stig_assessor.exceptions import FileError, ParseError, ValidationError
from stig_assessor.history.manager import HistMgr
from stig_assessor.io.file_ops import FO
from stig_assessor.templates.boilerplate import BP
from stig_assessor.validation.validator import Val
from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.schema import Sch
from stig_assessor.xml.utils import XmlUtils
from stig_assessor.core.constants import Status

# Chunk size for file operations
CHUNK_SIZE = 8192


class Proc:
    """Checklist processor."""

    def __init__(self, history: Optional[HistMgr] = None, boiler: Optional[BP] = None):
        self.history = history or HistMgr()
        self.boiler = boiler or BP()
        self.validator = Val()

    # ---------------------------------------------------------------- xccdf->ckl
    def xccdf_to_ckl(
        self,
        xccdf: Union[str, Path],
        out: Union[str, Path],
        asset: str,
        *,
        ip: str = "",
        mac: str = "",
        role: str = "None",
        marking: str = "CUI",
        dry: bool = False,
        apply_boilerplate: bool = False,
    ) -> Dict[str, Any]:
        try:
            xccdf = San.path(xccdf, exist=True, file=True)
            out = San.path(out, mkpar=True)
            asset = San.asset(asset)
            ip = San.ip(ip) if ip else ""
            mac = San.mac(mac) if mac else ""
            role = role or "None"
            marking = marking or "CUI"
        except Exception as exc:
            raise ValidationError(f"Input validation failed: {exc}") from exc

        LOG.ctx(op="xccdf_to_ckl", asset=asset, file=xccdf.name)
        LOG.i("Converting XCCDF to CKL")

        try:
            tree = FO.parse_xml(xccdf)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Failed to parse XCCDF: {exc}") from exc

        ns = self._namespace(root)
        meta = self._extract_meta(root, ns)

        LOG.i(f"STIG title: {meta.get('title', 'unknown')}")
        LOG.i(f"STIG version: {meta.get('version', 'unknown')}")

        checklist = ET.Element(Sch.ROOT)
        self._build_asset(checklist, asset, ip, mac, role, marking, meta)

        stigs = ET.SubElement(checklist, "STIGS")
        istig = ET.SubElement(stigs, "iSTIG")
        self._build_stig_info(istig, xccdf, meta)

        groups = self._list_groups(root, ns)
        if not groups:
            raise ParseError("XCCDF contains no vulnerability groups")

        if len(groups) > Cfg.MAX_VULNS:
            LOG.w(f"Large checklist: {len(groups)} vulnerabilities")

        LOG.i(f"Processing {len(groups)} vulnerabilities")

        processed = 0
        skipped = 0
        errors: List[str] = []

        for idx, group in enumerate(groups, 1):
            try:
                vuln = self._build_vuln(group, ns, meta, apply_boilerplate, asset)
                if vuln is None:
                    skipped += 1
                else:
                    istig.append(vuln)
                    processed += 1
            except Exception as exc:
                errors.append(str(exc))
                skipped += 1
                LOG.e(f"Group {idx} failed: {exc}")

        if processed == 0:
            raise ParseError("No vulnerabilities could be processed")

        # Check error threshold - fail if too many vulnerabilities failed to process
        total = processed + skipped
        error_rate = (skipped / total) * 100 if total > 0 else 0
        if error_rate > Cfg.ERROR_RATE_WARN_THRESHOLD:
            LOG.w(f"High error rate: {error_rate:.1f}% of vulnerabilities failed to process")
            LOG.w(f"First 5 errors: {errors[:5]}")
            if error_rate > Cfg.ERROR_RATE_FAIL_THRESHOLD:
                raise ParseError(
                    f"Critical: {error_rate:.1f}% of vulnerabilities failed to process "
                    f"(threshold: {Cfg.ERROR_RATE_FAIL_THRESHOLD}%). "
                    f"This likely indicates a structural XCCDF parsing issue. "
                    f"Sample errors: {'; '.join(errors[:3])}"
                )

        LOG.i(f"Processed: {processed} | Skipped: {skipped} | Error rate: {error_rate:.1f}%")

        XmlUtils.indent_xml(checklist)

        if dry:
            LOG.i("Dry-run requested, checklist not written")
            LOG.clear()
            return {"ok": True, "processed": processed, "skipped": skipped, "errors": errors}

        self._write_ckl(checklist, out)

        try:
            ok, errs, _, _ = self.validator.validate(out)
            if not ok:
                raise ValidationError(f"Generated CKL failed validation: {errs[0] if errs else 'Unknown error'}")
        except ValidationError:
            raise
        except Exception:
            pass  # Do not block output if validator crashes

        LOG.i(f"Checklist created: {out}")
        LOG.clear()
        return {"ok": True, "output": str(out), "processed": processed, "skipped": skipped, "errors": errors}

    # ------------------------------------------------------------------- helpers
    def _namespace(self, root: Any) -> Dict[str, str]:
        if "}" in root.tag:
            uri = root.tag.split("}")[0][1:]
            return {"ns": uri}
        return {}

    def _extract_meta(self, root, ns: Dict[str, str]) -> Dict[str, str]:
        meta = {
            "title": "Unknown STIG",
            "description": "",
            "version": "1",
            "stigid": root.get("id", "Unknown_STIG"),
            "releaseinfo": f"Release: 1 Benchmark Date: {datetime.now(timezone.utc).strftime('%d %b %Y')}",
            "classification": "UNCLASSIFIED",
            "source": "STIG.DOD.MIL",
            "target_key": "2350",
        }

        def find_text(tag: str, default: str = "") -> str:
            search_tag = f"ns:{tag}" if ns else tag
            element = root.find(search_tag, ns)
            if element is not None and element.text:
                return element.text.strip()
            return default

        meta["title"] = find_text("title", meta["title"])
        meta["description"] = find_text("description", meta["title"])
        meta["version"] = find_text("version", meta["version"])

        plain = root.find('plain-text[@id="release-info"]')
        if plain is not None and plain.text:
            meta["releaseinfo"] = plain.text.strip()

        ref_search = ".//ns:reference" if ns else ".//reference"
        for reference in root.findall(ref_search, ns):
            for sub in reference:
                tag_name = sub.tag.split("}")[-1]
                if "identifier" in tag_name.lower() and sub.text:
                    meta["target_key"] = sub.text.strip()
                    break

        return meta

    def _build_asset(
        self,
        parent,
        asset: str,
        ip: str,
        mac: str,
        role: str,
        marking: str,
        meta: Dict[str, str],
    ) -> None:
        asset_node = ET.SubElement(parent, "ASSET")
        values = {
            "ROLE": role,
            "ASSET_TYPE": "Computing",
            "MARKING": marking,
            "HOST_NAME": asset,
            "HOST_IP": ip,
            "HOST_MAC": mac,
            "HOST_FQDN": asset,
            "TARGET_COMMENT": "",
            "TECH_AREA": "",
            "TARGET_KEY": meta.get("target_key", "2350"),
            "WEB_OR_DATABASE": "false",
            "WEB_DB_SITE": "",
            "WEB_DB_INSTANCE": "",
        }
        for field in Sch.ASSET:
            node = ET.SubElement(asset_node, field)
            node.text = values.get(field, "")

    def _build_stig_info(self, parent, xccdf: Path, meta: Dict[str, str]) -> None:
        stig_info = ET.SubElement(parent, "STIG_INFO")
        values = {
            "version": meta.get("version", "1"),
            "classification": meta.get("classification", "UNCLASSIFIED"),
            "customname": "",
            "stigid": meta.get("stigid", "Unknown_STIG"),
            "description": meta.get("description", ""),
            "filename": xccdf.name if hasattr(xccdf, "name") else str(xccdf),
            "releaseinfo": meta.get("releaseinfo", ""),
            "title": meta.get("title", ""),
            "uuid": str(uuid.uuid4()),
            "notice": "terms-of-use",
            "source": meta.get("source", "STIG.DOD.MIL"),
        }

        for field in Sch.STIG:
            si_data = ET.SubElement(stig_info, "SI_DATA")
            name = ET.SubElement(si_data, "SID_NAME")
            name.text = field
            data = ET.SubElement(si_data, "SID_DATA")
            value = values.get(field, "")
            if value:
                data.text = value

    def _list_groups(self, root, ns: Dict[str, str]) -> List[Any]:
        search = ".//ns:Group" if ns else ".//Group"
        groups = root.findall(search, ns)
        valid: List[Any] = []
        for group in groups:
            rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
            if rule is not None:
                valid.append(group)
        return valid

    def _build_vuln(
        self,
        group,
        ns: Dict[str, str],
        meta: Dict[str, str],
        apply_boilerplate: bool,
        asset: str,
    ):
        vid = group.get("id", "")
        if not vid:
            return None
        try:
            vid = San.vuln(vid)
        except Exception:
            return None

        rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
        if rule is None:
            return None

        rule_id = rule.get("id", "").strip()
        if not rule_id:
            return None

        severity = San.sev(rule.get("severity", "medium"))
        weight = rule.get("weight", "10.0")

        def find(tag: str):
            return rule.find(f"ns:{tag}", ns) if ns else rule.find(tag)

        def findall(tag: str):
            return rule.findall(f"ns:{tag}", ns) if ns else rule.findall(tag)

        def text(elem) -> str:
            if elem is None:
                return ""
            if elem.text and elem.text.strip():
                return elem.text.strip()
            try:
                return ET.tostring(elem, encoding="unicode", method="text").strip()
            except Exception as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag}: {exc}")
                return ""

        rule_title = text(find("title"))[:300]
        rule_ver = text(find("version"))
        discussion = text(find("description"))
        fix_elem = find("fixtext")

        fix_text = self._collect_fix_text(fix_elem) if fix_elem is not None else ""

        check_elem = find("check")
        check_text = ""
        check_ref = "M"
        if check_elem is not None:
            check_content = check_elem.find("ns:check-content", ns) if ns else check_elem.find("check-content")
            check_text = self._collect_fix_text(check_content) if check_content is not None else ""
            check_content_ref = check_elem.find("ns:check-content-ref", ns) if ns else check_elem.find("check-content-ref")
            if check_content_ref is not None:
                ref_name = check_content_ref.get("name", "M")
                if ref_name:
                    check_ref = ref_name

        group_title_elem = group.find("ns:title", ns) if ns else group.find("title")
        group_title = text(group_title_elem) if group_title_elem is not None else vid

        legacy_refs: List[str] = []
        cci_refs: List[str] = []

        for ident in findall("ident"):
            ident_text = text(ident)
            if not ident_text:
                continue
            system = (ident.get("system") or "").lower()
            if "cci" in system:
                cci_refs.append(ident_text)
            elif "legacy" in system:
                legacy_refs.append(ident_text)

        vuln_node = ET.Element("VULN")
        stig_data_map = OrderedDict(
            [
                ("Vuln_Num", vid),
                ("Severity", severity),
                ("Group_Title", group_title),
                ("Rule_ID", rule_id),
                ("Rule_Ver", rule_ver),
                ("Rule_Title", rule_title),
                ("Vuln_Discuss", discussion),
                ("IA_Controls", ""),
                ("Check_Content", check_text),
                ("Fix_Text", fix_text),
                ("False_Positives", ""),
                ("False_Negatives", ""),
                ("Documentable", "false"),
                ("Mitigations", ""),
                ("Potential_Impact", ""),
                ("Third_Party_Tools", ""),
                ("Mitigation_Control", ""),
                ("Responsibility", ""),
                ("Security_Override_Guidance", ""),
                ("Check_Content_Ref", check_ref),
                ("Weight", weight),
                ("Class", "Unclass"),
                (
                    "STIGRef",
                    f"{meta.get('title', '')} :: Version {meta.get('version', '')}, "
                    f"{meta.get('releaseinfo', '')}",
                ),
                ("TargetKey", meta.get("target_key", "2350")),
                ("STIG_UUID", str(uuid.uuid4())),
            ]
        )

        for attribute in Sch.VULN:
            value = stig_data_map.get(attribute, "")
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = attribute
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            if value:
                data.text = San.xml(value)

        for legacy in legacy_refs:
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "LEGACY_ID"
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            data.text = legacy

        for cci in cci_refs:
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "CCI_REF"
            data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            data.text = cci

        status = "Not_Reviewed"
        finding = ""
        comment = ""

        if apply_boilerplate:
            finding = self.boiler.find(status, asset=asset, severity=severity)
            comment = self.boiler.comm(status)

        status_node = ET.SubElement(vuln_node, "STATUS")
        status_node.text = status
        finding_node = ET.SubElement(vuln_node, "FINDING_DETAILS")
        if finding:
            finding_node.text = finding
        comment_node = ET.SubElement(vuln_node, "COMMENTS")
        if comment:
            comment_node.text = comment
        ET.SubElement(vuln_node, "SEVERITY_OVERRIDE")
        ET.SubElement(vuln_node, "SEVERITY_JUSTIFICATION")

        return vuln_node

    def _collect_fix_text(self, elem) -> str:
        """
        Enhanced fix text extraction with proper handling of XCCDF mixed content.

        Handles:
        - Plain text content
        - Nested HTML elements (xhtml:br, xhtml:code, etc.)
        - CDATA sections
        - Mixed content with proper whitespace preservation
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
            def extract_text_recursive(element) -> List[str]:
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

        # Method 4: Last resort - tostring
        try:
            text_content = ET.tostring(elem, encoding='unicode', method='text')
            if text_content and text_content.strip():
                # Clean up excessive whitespace
                text_content = re.sub(r'\s+', ' ', text_content)
                return text_content.strip()
        except Exception as exc:
            LOG.d(f"tostring() extraction failed: {exc}")

        return ""

    def _write_ckl(self, root, out: Path) -> None:
        try:
            with FO.atomic(out, mode="wb", bak=False) as handle:
                handle.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                handle.write(f"<!--{Sch.COMMENT}-->\n".encode("utf-8"))
                xml_text = ET.tostring(root, encoding="unicode", method="xml")
                handle.write(xml_text.encode("utf-8"))
        except Exception as exc:
            raise FileError(f"Failed to write CKL: {exc}") from exc

    # -------------------------------------------------------------------- merge
    def merge(
        self,
        base: Union[str, Path],
        histories: Iterable[Union[str, Path]],
        out: Union[str, Path],
        *,
        preserve_history: bool = True,
        apply_boilerplate: bool = True,
        dry: bool = False,
    ) -> Dict[str, Any]:
        try:
            base = San.path(base, exist=True, file=True)
            out = San.path(out, mkpar=True)
            history_paths = [San.path(p, exist=True, file=True) for p in histories]
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        if len(history_paths) > Cfg.MAX_MERGE:
            raise ValidationError(f"Too many historical files (limit {Cfg.MAX_MERGE})")

        LOG.ctx(op="merge", base=base.name, histories=len(history_paths))
        LOG.i(f"Merging {len(history_paths)} checklist(s) into base {base.name}")

        if preserve_history:
            for idx, hist_file in enumerate(history_paths, 1):
                LOG.d(f"Loading history {idx}/{len(history_paths)}: {hist_file}")
                self._ingest_history(hist_file)

        try:
            tree = FO.parse_xml(base)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Unable to parse base checklist: {exc}") from exc

        if root.tag != Sch.ROOT:
            raise ParseError("Base checklist has incorrect root element")

        stigs = root.find("STIGS")
        if stigs is None:
            raise ParseError("Base checklist missing STIGS")

        total_vulns = sum(len(istig.findall("VULN")) for istig in stigs.findall("iSTIG"))
        if total_vulns == 0:
            raise ParseError("Base checklist contains no vulnerabilities")

        updated = 0
        skipped = 0

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                result = self._merge_vuln(vuln, preserve_history, apply_boilerplate)
                if result is True:
                    updated += 1
                else:
                    skipped += 1

        LOG.i(f"Merge summary: {updated} updated, {skipped} unchanged")

        XmlUtils.indent_xml(root)

        if dry:
            LOG.i("Dry-run requested, merged checklist not written")
            LOG.clear()
            return {"updated": updated, "skipped": skipped, "dry_run": True}

        self._write_ckl(root, out)
        LOG.i(f"Merged checklist saved to {out}")
        LOG.clear()
        return {"updated": updated, "skipped": skipped, "dry_run": False, "output": str(out)}

    # ------------------------------------------------------------------ diff
    def diff(
        self,
        ckl1: Union[str, Path],
        ckl2: Union[str, Path],
        *,
        output_format: str = "summary",
    ) -> Dict[str, Any]:
        """
        Compare two checklists and identify differences.

        Args:
            ckl1: First checklist (baseline)
            ckl2: Second checklist (comparison target)
            output_format: Output format - 'summary', 'detailed', or 'json'

        Returns:
            Dictionary containing comparison results
        """
        try:
            ckl1 = San.path(ckl1, exist=True, file=True)
            ckl2 = San.path(ckl2, exist=True, file=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        LOG.ctx(op="diff", ckl1=ckl1.name, ckl2=ckl2.name)
        LOG.i(f"Comparing {ckl1.name} vs {ckl2.name}")

        # Parse both checklists
        try:
            tree1 = FO.parse_xml(ckl1)
            root1 = tree1.getroot()
            tree2 = FO.parse_xml(ckl2)
            root2 = tree2.getroot()
        except Exception as exc:
            raise ParseError(f"Failed to parse checklists: {exc}") from exc

        # Extract vulnerability data from both checklists
        vulns1 = self._extract_vuln_data(root1)
        vulns2 = self._extract_vuln_data(root2)

        # Compare
        vids1 = set(vulns1.keys())
        vids2 = set(vulns2.keys())

        only_in_1 = vids1 - vids2
        only_in_2 = vids2 - vids1
        common = vids1 & vids2

        changed = []
        unchanged = []

        for vid in sorted(common):
            v1 = vulns1[vid]
            v2 = vulns2[vid]

            differences = []
            if v1["status"] != v2["status"]:
                differences.append({
                    "field": "status",
                    "from": v1["status"],
                    "to": v2["status"],
                })
            if v1["severity"] != v2["severity"]:
                differences.append({
                    "field": "severity",
                    "from": v1["severity"],
                    "to": v2["severity"],
                })
            if v1["finding_details"] != v2["finding_details"]:
                differences.append({
                    "field": "finding_details",
                    "from_length": len(v1["finding_details"]),
                    "to_length": len(v2["finding_details"]),
                })
            if v1["comments"] != v2["comments"]:
                differences.append({
                    "field": "comments",
                    "from_length": len(v1["comments"]),
                    "to_length": len(v2["comments"]),
                })

            if differences:
                changed.append({
                    "vid": vid,
                    "rule_title": v1.get("rule_title", "Unknown"),
                    "differences": differences,
                })
            else:
                unchanged.append(vid)

        # Build results
        results = {
            "summary": {
                "total_in_baseline": len(vids1),
                "total_in_comparison": len(vids2),
                "only_in_baseline": len(only_in_1),
                "only_in_comparison": len(only_in_2),
                "common": len(common),
                "changed": len(changed),
                "unchanged": len(unchanged),
            },
            "only_in_baseline": sorted(only_in_1),
            "only_in_comparison": sorted(only_in_2),
            "changed": changed,
        }

        # Format output based on requested format
        if output_format == "summary":
            self._print_diff_summary(results, ckl1.name, ckl2.name)
        elif output_format == "detailed":
            self._print_diff_detailed(results, ckl1.name, ckl2.name)

        LOG.clear()
        return results

    def _extract_vuln_data(self, root) -> Dict[str, Dict[str, str]]:
        """Extract vulnerability data from a checklist for comparison."""
        vulns = {}
        stigs = root.find("STIGS")
        if stigs is None:
            return vulns

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = XmlUtils.get_vid(vuln)
                if not vid:
                    continue

                # Extract relevant data
                status = ""
                severity = ""
                finding_details = ""
                comments = ""
                rule_title = ""

                for sd in vuln.findall("STIG_DATA"):
                    attr = sd.findtext("VULN_ATTRIBUTE")
                    if attr == "Severity":
                        severity = sd.findtext("ATTRIBUTE_DATA", default="")
                    elif attr == "Rule_Title":
                        rule_title = sd.findtext("ATTRIBUTE_DATA", default="")

                status = vuln.findtext("STATUS", default="")
                finding_details = vuln.findtext("FINDING_DETAILS", default="")
                comments = vuln.findtext("COMMENTS", default="")

                vulns[vid] = {
                    "status": status,
                    "severity": severity,
                    "finding_details": finding_details,
                    "comments": comments,
                    "rule_title": rule_title,
                }

        return vulns

    def _print_diff_summary(self, results: Dict[str, Any], name1: str, name2: str) -> None:
        """Print a summary of the diff results."""
        s = results["summary"]
        print(f"\n{'='*80}")
        print(f"Checklist Comparison: {name1} vs {name2}")
        print(f"{'='*80}")
        print(f"\nBaseline ({name1}): {s['total_in_baseline']} vulnerabilities")
        print(f"Comparison ({name2}): {s['total_in_comparison']} vulnerabilities")
        print(f"\nCommon vulnerabilities: {s['common']}")
        print(f"  - Changed: {s['changed']}")
        print(f"  - Unchanged: {s['unchanged']}")
        print(f"\nOnly in baseline: {s['only_in_baseline']}")
        print(f"Only in comparison: {s['only_in_comparison']}")

        if results["changed"]:
            print(f"\n{'-'*80}")
            print("Changed Vulnerabilities:")
            print(f"{'-'*80}")
            for item in results["changed"][:10]:  # Show first 10
                print(f"\n{item['vid']}: {item['rule_title'][:60]}")
                for diff in item["differences"]:
                    if diff["field"] == "status":
                        print(f"  Status: {diff['from']} → {diff['to']}")
                    elif diff["field"] == "severity":
                        print(f"  Severity: {diff['from']} → {diff['to']}")
                    else:
                        print(f"  {diff['field']} changed ({diff.get('from_length', 0)} → {diff.get('to_length', 0)} chars)")
            if len(results["changed"]) > 10:
                print(f"\n... and {len(results['changed']) - 10} more changed vulnerabilities")

    def _print_diff_detailed(self, results: Dict[str, Any], name1: str, name2: str) -> None:
        """Print detailed diff results."""
        self._print_diff_summary(results, name1, name2)

        if results["only_in_baseline"]:
            print(f"\n{'-'*80}")
            print(f"Vulnerabilities only in {name1}:")
            print(f"{'-'*80}")
            for vid in results["only_in_baseline"][:20]:
                print(f"  {vid}")
            if len(results["only_in_baseline"]) > 20:
                print(f"  ... and {len(results['only_in_baseline']) - 20} more")

        if results["only_in_comparison"]:
            print(f"\n{'-'*80}")
            print(f"Vulnerabilities only in {name2}:")
            print(f"{'-'*80}")
            for vid in results["only_in_comparison"][:20]:
                print(f"  {vid}")
            if len(results["only_in_comparison"]) > 20:
                print(f"  ... and {len(results['only_in_comparison']) - 20} more")

    # ----------------------------------------------------------------- helpers
    def _ingest_history(self, path: Path) -> None:
        try:
            tree = FO.parse_xml(path)
            root = tree.getroot()
        except Exception:
            return

        stigs = root.find("STIGS")
        if stigs is None:
            return

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = XmlUtils.get_vid(vuln)
                if not vid:
                    continue

                status = vuln.findtext("STATUS", default="Not_Reviewed")
                finding = vuln.findtext("FINDING_DETAILS", default="")
                comment = vuln.findtext("COMMENTS", default="")
                severity = "medium"

                for sd in vuln.findall("STIG_DATA"):
                    attr = sd.findtext("VULN_ATTRIBUTE")
                    if attr == "Severity":
                        severity = San.sev(sd.findtext("ATTRIBUTE_DATA", default="medium"))

                if finding.strip() or comment.strip():
                    self.history.add(
                        vid,
                        status,
                        finding,
                        comment,
                        src=path.name,
                        sev=severity,
                    )

    def _merge_vuln(self, vuln, preserve_history: bool, apply_boilerplate: bool) -> bool:
        vid = XmlUtils.get_vid(vuln)
        if not vid:
            return False

        status_node = vuln.find("STATUS")
        status = status_node.text.strip() if status_node is not None and status_node.text else "Not_Reviewed"
        finding_node = vuln.find("FINDING_DETAILS")
        comment_node = vuln.find("COMMENTS")

        current_finding = finding_node.text if finding_node is not None and finding_node.text else ""
        current_comment = comment_node.text if comment_node is not None and comment_node.text else ""

        merged = False

        if preserve_history and vid in self.history._h:
            merged_finding = self.history.merge_find(vid, current_finding)
            if finding_node is None:
                finding_node = ET.SubElement(vuln, "FINDING_DETAILS")
            finding_node.text = merged_finding

            merged_comment = self.history.merge_comm(vid, current_comment)
            if comment_node is None:
                comment_node = ET.SubElement(vuln, "COMMENTS")
            comment_node.text = merged_comment

            merged = True

        elif apply_boilerplate and status in Sch.STAT_VALS:
            default_finding = self.boiler.find(status)
            default_comment = self.boiler.comm(status)
            if default_finding and not current_finding.strip():
                if finding_node is None:
                    finding_node = ET.SubElement(vuln, "FINDING_DETAILS")
                finding_node.text = default_finding
                merged = True
            if default_comment and not current_comment.strip():
                if comment_node is None:
                    comment_node = ET.SubElement(vuln, "COMMENTS")
                comment_node.text = default_comment
                merged = True

        return merged

    # ------------------------------------------------------------ new features v7.2.0
    def repair(self, ckl_path: Union[str, Path], out_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Repair corrupted CKL file by fixing common issues.

        Args:
            ckl_path: Path to corrupted checklist
            out_path: Path for repaired checklist

        Returns:
            Dictionary with repair statistics
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            out_path = San.path(out_path, mkpar=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        LOG.ctx(op="repair", file=ckl_path.name)
        LOG.i(f"Repairing checklist: {ckl_path}")

        repairs = []

        try:
            tree = FO.parse_xml(ckl_path)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Failed to parse CKL (too corrupted): {exc}") from exc

        # Repair 1: Fix invalid status values
        stigs = root.find("STIGS")
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    status_node = vuln.find("STATUS")
                    if status_node is not None and status_node.text:
                        status_val = status_node.text.strip()
                        if not Status.is_valid(status_val):
                            # Try to fix common typos
                            if status_val.lower().replace(" ", "_") == "not_a_finding":
                                status_node.text = "NotAFinding"
                                repairs.append(f"Fixed status typo: '{status_val}' → 'NotAFinding'")
                            elif status_val.lower() == "open":
                                status_node.text = "Open"
                                repairs.append(f"Fixed status case: '{status_val}' → 'Open'")
                            elif "not" in status_val.lower() and "applicable" in status_val.lower():
                                status_node.text = "Not_Applicable"
                                repairs.append(f"Fixed status typo: '{status_val}' → 'Not_Applicable'")
                            else:
                                # Can't fix, set to Not_Reviewed
                                old_val = status_val
                                status_node.text = "Not_Reviewed"
                                repairs.append(f"Reset invalid status: '{old_val}' → 'Not_Reviewed'")

        # Repair 2: Add missing required elements
        asset = root.find("ASSET")
        if asset is None:
            asset = ET.SubElement(root, "ASSET")
            repairs.append("Added missing ASSET element")

        # Ensure required ASSET fields exist
        required_fields = {
            "ROLE": "None",
            "ASSET_TYPE": "Computing",
            "MARKING": "CUI",
            "HOST_NAME": "Unknown",
            "TARGET_KEY": "0",
            "WEB_OR_DATABASE": "false",
        }
        asset_children = {child.tag: child for child in asset}
        for field, default_val in required_fields.items():
            if field not in asset_children:
                elem = ET.SubElement(asset, field)
                elem.text = default_val
                repairs.append(f"Added missing ASSET/{field}")

        # Repair 3: Remove excessively long content (prevents STIG Viewer crashes)
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    finding_node = vuln.find("FINDING_DETAILS")
                    if finding_node is not None and finding_node.text:
                        if len(finding_node.text) > Cfg.MAX_FIND:
                            finding_node.text = finding_node.text[:Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
                            repairs.append(f"Truncated oversized FINDING_DETAILS")

                    comment_node = vuln.find("COMMENTS")
                    if comment_node is not None and comment_node.text:
                        if len(comment_node.text) > Cfg.MAX_COMM:
                            comment_node.text = comment_node.text[:Cfg.MAX_COMM - 15] + "\n[TRUNCATED]"
                            repairs.append(f"Truncated oversized COMMENTS")

        # Write repaired checklist
        XmlUtils.indent_xml(root)
        self._write_ckl(root, out_path)

        LOG.i(f"Repaired checklist written to {out_path}")
        LOG.i(f"Repairs applied: {len(repairs)}")
        LOG.clear()

        return {
            "ok": True,
            "input": str(ckl_path),
            "output": str(out_path),
            "repairs": len(repairs),
            "details": repairs,
        }

    def batch_convert(
        self,
        xccdf_dir: Union[str, Path],
        out_dir: Union[str, Path],
        *,
        asset_prefix: str = "ASSET",
        apply_boilerplate: bool = False,
    ) -> Dict[str, Any]:
        """
        Batch convert multiple XCCDF files to CKL format.

        Args:
            xccdf_dir: Directory containing XCCDF files
            out_dir: Output directory for CKL files
            asset_prefix: Prefix for auto-generated asset names
            apply_boilerplate: Apply boilerplate templates

        Returns:
            Dictionary with batch conversion statistics
        """
        try:
            xccdf_dir = San.path(xccdf_dir, exist=True, dir=True)
            out_dir = San.path(out_dir, mkpar=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        LOG.ctx(op="batch_convert", dir=xccdf_dir.name)
        LOG.i(f"Batch converting XCCDF files from {xccdf_dir}")

        # Find all XML files in directory
        xccdf_files = list(xccdf_dir.glob("*.xml"))
        if not xccdf_files:
            raise FileError(f"No XML files found in {xccdf_dir}")

        LOG.i(f"Found {len(xccdf_files)} XML files to convert")

        successes = []
        failures = []

        for idx, xccdf_file in enumerate(xccdf_files, 1):
            try:
                # Generate asset name from filename
                asset_name = f"{asset_prefix}_{xccdf_file.stem.replace(' ', '_').replace('-', '_')}"
                out_file = out_dir / f"{xccdf_file.stem}.ckl"

                LOG.i(f"[{idx}/{len(xccdf_files)}] Converting {xccdf_file.name} → {out_file.name}")

                result = self.xccdf_to_ckl(
                    xccdf_file,
                    out_file,
                    asset_name,
                    apply_boilerplate=apply_boilerplate,
                )

                successes.append({
                    "file": xccdf_file.name,
                    "output": out_file.name,
                    "processed": result.get("processed", 0),
                })

            except Exception as exc:
                LOG.e(f"Failed to convert {xccdf_file.name}: {exc}")
                failures.append({
                    "file": xccdf_file.name,
                    "error": str(exc),
                })

        LOG.i(f"Batch conversion complete: {len(successes)} successes, {len(failures)} failures")
        LOG.clear()

        return {
            "ok": len(failures) == 0,
            "total": len(xccdf_files),
            "successes": len(successes),
            "failures": len(failures),
            "details": successes,
            "errors": failures,
        }

    def verify_integrity(self, ckl_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Verify checklist integrity using checksums and validation.

        Args:
            ckl_path: Path to checklist to verify

        Returns:
            Dictionary with integrity check results
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        LOG.ctx(op="verify_integrity", file=ckl_path.name)
        LOG.i(f"Verifying integrity of {ckl_path}")

        # Compute checksum
        checksum = hashlib.sha256()
        with open(ckl_path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                checksum.update(chunk)
        checksum_value = checksum.hexdigest()

        # Run validation
        ok, errors, warnings, info = self.validator.validate(ckl_path)

        # Check file size
        file_size = ckl_path.stat().st_size

        LOG.clear()

        return {
            "valid": ok,
            "file": str(ckl_path),
            "size": file_size,
            "checksum": checksum_value,
            "checksum_type": "SHA256",
            "validation_errors": len(errors),
            "validation_warnings": len(warnings),
            "errors": errors if errors else None,
            "warnings": warnings if warnings else None,
            "info": info if info else None,
        }

    def compute_checksum(self, file_path: Union[str, Path]) -> str:
        """
        Compute SHA256 checksum for a file.

        Args:
            file_path: Path to file

        Returns:
            Hex digest of SHA256 checksum
        """
        try:
            file_path = San.path(file_path, exist=True, file=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        checksum = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                checksum.update(chunk)

        return checksum.hexdigest()

    def generate_stats(self, ckl_path: Union[str, Path], *, output_format: str = "text") -> Union[str, Dict[str, Any]]:
        """
        Generate compliance statistics for a checklist.

        Args:
            ckl_path: Path to checklist
            output_format: Output format - 'text', 'json', or 'csv'

        Returns:
            Formatted statistics (string for text/csv, dict for json)
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
        except Exception as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        LOG.ctx(op="generate_stats", file=ckl_path.name)
        LOG.i(f"Generating statistics for {ckl_path}")

        try:
            tree = FO.parse_xml(ckl_path)
            root = tree.getroot()
        except Exception as exc:
            raise ParseError(f"Failed to parse checklist: {exc}") from exc

        # Extract statistics
        stats = {
            "file": str(ckl_path),
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_vulns": 0,
            "by_status": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_status_and_severity": defaultdict(lambda: defaultdict(int)),
        }

        stigs = root.find("STIGS")
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    stats["total_vulns"] += 1

                    # Get status
                    status_node = vuln.find("STATUS")
                    status = status_node.text.strip() if status_node is not None and status_node.text else "Not_Reviewed"
                    stats["by_status"][status] += 1

                    # Get severity
                    severity = "medium"  # default
                    for sd in vuln.findall("STIG_DATA"):
                        attr = sd.findtext("VULN_ATTRIBUTE")
                        if attr == "Severity":
                            severity = sd.findtext("ATTRIBUTE_DATA", default="medium")
                            break

                    stats["by_severity"][severity] += 1
                    stats["by_status_and_severity"][severity][status] += 1

        # Calculate completion percentage
        reviewed = sum(stats["by_status"][s] for s in stats["by_status"] if s != "Not_Reviewed")
        stats["reviewed"] = reviewed
        stats["completion_pct"] = (reviewed / stats["total_vulns"] * 100) if stats["total_vulns"] > 0 else 0

        # Calculate compliance percentage (NotAFinding / total reviewed)
        not_a_finding = stats["by_status"].get("NotAFinding", 0)
        stats["compliant"] = not_a_finding
        stats["compliance_pct"] = (not_a_finding / reviewed * 100) if reviewed > 0 else 0

        LOG.clear()

        # Format output
        if output_format == "json":
            return dict(stats)
        elif output_format == "csv":
            return self._format_stats_csv(stats)
        else:  # text
            return self._format_stats_text(stats)

    def _format_stats_text(self, stats: Dict[str, Any]) -> str:
        """Format statistics as human-readable text."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"STIG Compliance Statistics")
        lines.append("=" * 80)
        lines.append(f"File: {stats['file']}")
        lines.append(f"Generated: {stats['generated']}")
        lines.append("")
        lines.append(f"Total Vulnerabilities: {stats['total_vulns']}")
        lines.append(f"Reviewed: {stats['reviewed']} ({stats['completion_pct']:.1f}%)")
        lines.append(f"Compliant: {stats['compliant']} ({stats['compliance_pct']:.1f}% of reviewed)")
        lines.append("")
        lines.append("Status Breakdown:")
        lines.append("-" * 40)
        for status in sorted(stats['by_status'].keys()):
            count = stats['by_status'][status]
            pct = (count / stats['total_vulns'] * 100) if stats['total_vulns'] > 0 else 0
            lines.append(f"  {status:20} {count:6} ({pct:5.1f}%)")
        lines.append("")
        lines.append("Severity Breakdown:")
        lines.append("-" * 40)
        for severity in ["high", "medium", "low"]:
            if severity in stats['by_severity']:
                count = stats['by_severity'][severity]
                pct = (count / stats['total_vulns'] * 100) if stats['total_vulns'] > 0 else 0
                lines.append(f"  CAT {['I', 'II', 'III'][['high', 'medium', 'low'].index(severity)]:3} ({severity:6}) {count:6} ({pct:5.1f}%)")
        lines.append("=" * 80)
        return "\n".join(lines)

    def _format_stats_csv(self, stats: Dict[str, Any]) -> str:
        """Format statistics as CSV."""
        lines = []
        lines.append("Metric,Value")
        lines.append(f"File,{stats['file']}")
        lines.append(f"Generated,{stats['generated']}")
        lines.append(f"Total Vulnerabilities,{stats['total_vulns']}")
        lines.append(f"Reviewed,{stats['reviewed']}")
        lines.append(f"Completion %,{stats['completion_pct']:.1f}")
        lines.append(f"Compliant,{stats['compliant']}")
        lines.append(f"Compliance %,{stats['compliance_pct']:.1f}")
        lines.append("")
        lines.append("Status,Count")
        for status in sorted(stats['by_status'].keys()):
            lines.append(f"{status},{stats['by_status'][status]}")
        lines.append("")
        lines.append("Severity,Count")
        for severity in ["high", "medium", "low"]:
            if severity in stats['by_severity']:
                lines.append(f"{severity},{stats['by_severity'][severity]}")
        return "\n".join(lines)

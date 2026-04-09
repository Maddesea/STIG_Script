"""Core processor module for XCCDF to CKL conversion and merging."""

from __future__ import annotations

import hashlib
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Union
import html as _html_module

if TYPE_CHECKING:
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import ParseError as XMLParseError
else:
    # Import required modules
    from stig_assessor.core.deps import Deps

    # Get specific XML parsers (defusedxml if available) for runtime
    ET, XMLParseError = Deps.get_xml()

from stig_assessor.core.config import CFG as Cfg
from stig_assessor.core.constants import CHUNK_SIZE, TITLE_MAX_LONG, Status
from stig_assessor.core.deps import Deps
from stig_assessor.core.logging import Log
from stig_assessor.exceptions import FileError, ParseError, ValidationError
from stig_assessor.history.manager import HistMgr
from stig_assessor.io.file_ops import FO
from stig_assessor.templates.boilerplate import BP
from stig_assessor.validation.validator import Val
from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.schema import Sch
from stig_assessor.xml.utils import XmlUtils

LOG = Log("Processor")


class Proc:
    """
    Main STIG checklist processor for XCCDF to CKL conversion and merging.

    Provides core functionality for:
    - Converting XCCDF benchmark files to CKL checklist format
    - Merging multiple checklists with history preservation
    - Comparing checklists for differences
    - Generating statistics and reports

    Thread Safety:
        Instance methods are thread-safe through use of HistMgr's locking.
    """

    def __init__(self, history: Optional[HistMgr] = None, boiler: Optional[BP] = None):
        """
        Initialize processor with optional history and boilerplate managers.

        Args:
            history: History manager instance (creates new if None)
            boiler: Boilerplate manager instance (creates new if None)
        """
        self.history = history or HistMgr()
        self.boiler = boiler or BP()
        self.validator = Val()

        from stig_assessor.core.plugins import PluginManager

        self.plugins = PluginManager()
        self.plugins.load_plugins()

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
        """
        Convert XCCDF benchmark to STIG Viewer CKL format.

        Parses an XCCDF benchmark file and generates a compatible CKL checklist
        with all vulnerabilities, metadata, and optional boilerplate text.

        Args:
            xccdf: Path to source XCCDF benchmark file
            out: Path for output CKL file
            asset: Asset hostname for checklist
            ip: Asset IP address (optional)
            mac: Asset MAC address (optional)
            role: Asset role (default: "None")
            marking: Classification marking (default: "CUI")
            dry: If True, don't write output file
            apply_boilerplate: If True, apply boilerplate templates

        Returns:
            Dict with keys: ok, output, processed, skipped, errors

        Raises:
            ValidationError: If input validation fails
            ParseError: If XCCDF parsing fails or no vulnerabilities found
        """
        try:
            xccdf = San.path(xccdf, exist=True, file=True)
            out = San.path(out, mkpar=True)
            asset = San.asset(asset)
            ip = San.ip(ip) if ip else ""
            mac = San.mac(mac) if mac else ""
            role = role or "None"
            marking = marking or "CUI"
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Input validation failed: {exc}") from exc

        with LOG.context(op="xccdf_to_ckl", asset=asset, file=xccdf.name):
            LOG.i("Converting XCCDF to CKL")

            try:
                tree = FO.parse_xml(xccdf)
                root = tree.getroot()
            except (ParseError, OSError, ValueError) as exc:
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
                    vuln_data = self._parse_vuln_data(group, ns, meta, apply_boilerplate, asset)
                    vuln = self._serialize_vuln(vuln_data)
                    istig.append(vuln)
                    processed += 1
                except ParseError as exc:
                    errors.append(str(exc))
                    skipped += 1
                    LOG.e(f"Group {idx} skipped: {exc}")
                except (ValueError, TypeError, AttributeError, KeyError) as exc:
                    errors.append(str(exc))
                    skipped += 1
                    LOG.e(f"Group {idx} failed unexpectedly: {exc}")

            if processed == 0:
                raise ParseError("No vulnerabilities could be processed")

            # Check error threshold - fail if too many vulnerabilities failed to process
            total = processed + skipped
            error_rate = (skipped / total) * 100 if total > 0 else 0
            if error_rate > Cfg.ERROR_RATE_WARN_THRESHOLD:
                LOG.w(
                    f"High error rate: {error_rate:.1f}% of vulnerabilities failed to process"
                )
                LOG.w(f"First 5 errors: {errors[:5]}")
                if error_rate > Cfg.ERROR_RATE_FAIL_THRESHOLD:
                    raise ParseError(
                        f"Critical: {error_rate:.1f}% of vulnerabilities failed to process "
                        f"(threshold: {Cfg.ERROR_RATE_FAIL_THRESHOLD}%). "
                        f"This likely indicates a structural XCCDF parsing issue. "
                        f"Sample errors: {'; '.join(errors[:3])}"
                    )

            LOG.i(
                f"Processed: {processed} | Skipped: {skipped} | Error rate: {error_rate:.1f}%"
            )

            XmlUtils.indent_xml(checklist)

            # Hook: Plugins can modify the final xml ElementTree of the checklist
            checklist = self.plugins.run_hooks(
                "post_ckl_create",
                payload=checklist,
                xccdf_path=xccdf,
                out_path=out,
            )

            if dry:
                LOG.i("Dry-run requested, checklist not written")
                return {
                    "ok": True,
                    "processed": processed,
                    "skipped": skipped,
                    "errors": errors,
                }

            if out.suffix.lower() == ".cklb":
                cklb_data = self._checklist_to_json(checklist)
                FO.write_cklb(cklb_data, out, backup=False)
            else:
                self._export_xml_to_file(checklist, out)

            try:
                ok, errs, _, _ = self.validator.validate(out)
                if not ok:
                    raise ValidationError(
                        f"Generated CKL failed validation: {errs[0] if errs else 'Unknown error'}"
                    )
            except ValidationError:
                raise
            except (OSError, ParseError, ValueError) as exc:
                LOG.w(f"Validator encountered an error (output may still be valid): {exc}")

            LOG.i(f"Checklist created: {out}")
            return {
                "ok": True,
                "output": str(out),
                "processed": processed,
                "skipped": skipped,
                "errors": errors,
            }

    # ------------------------------------------------------------------- helpers
    def _namespace(self, root: ET.Element) -> Dict[str, str]:
        """Extract namespace dictionary from root element tag."""
        return XmlUtils.extract_namespace(root)

    def _extract_meta(self, root: ET.Element, ns: Dict[str, str]) -> Dict[str, str]:
        """
        Extract metadata from an XCCDF root element for STIG checklist population.

        Args:
            root: Root element of the parsed XCCDF.
            ns: XML namespace mapping for XPath queries.

        Returns:
            Dictionary containing metadata parameters such as title, version, etc.
        """
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
        parent: ET.Element,
        asset: str,
        ip: str,
        mac: str,
        role: str,
        marking: str,
        meta: Dict[str, str],
    ) -> None:
        """
        Build and append the ASSET node for the target CKL.

        Args:
            parent: Parent XML element to append to.
            asset: Asset identifier or hostname.
            ip: Target IP address.
            mac: Target MAC address.
            role: Target IT role.
            marking: Classification marking.
            meta: Metadata dictionary to draw target keys from.
        """
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
        for fld in Sch.ASSET:
            node = ET.SubElement(asset_node, fld)
            node.text = str(values.get(fld) or "")

    def _build_stig_info(
        self, parent: ET.Element, xccdf: Path, meta: Dict[str, str]
    ) -> None:
        """
        Build and append the STIG_INFO configuration node for the target CKL.

        Args:
            parent: Parent XML element to append to.
            xccdf: Source XCCDF benchmark file path.
            meta: Parsed metadata mapping.
        """
        stig_info = ET.SubElement(parent, "STIG_INFO")
        values = {
            "version": str(meta.get("version") or "1"),
            "classification": str(meta.get("classification") or "UNCLASSIFIED"),
            "customname": "",
            "stigid": str(meta.get("stigid") or "Unknown_STIG"),
            "description": str(meta.get("description") or ""),
            "filename": xccdf.name if hasattr(xccdf, "name") else str(xccdf),
            "releaseinfo": str(meta.get("releaseinfo") or ""),
            "title": str(meta.get("title") or ""),
            "uuid": str(uuid.uuid4()),
            "notice": "terms-of-use",
            "source": str(meta.get("source") or "STIG.DOD.MIL"),
        }

        for fld in Sch.STIG:
            si_data = ET.SubElement(stig_info, "SI_DATA")
            name = ET.SubElement(si_data, "SID_NAME")
            name.text = fld
            data = ET.SubElement(si_data, "SID_DATA")
            value = str(values.get(fld) or "")
            if value:
                data.text = value

    def _list_groups(self, root: ET.Element, ns: Dict[str, str]) -> List[ET.Element]:
        """
        Extract valid STIG vulnerability groups from the parsed XCCDF document.

        Args:
            root: Root element of the parsed XCCDF.
            ns: XML namespace mapping for XPath queries.

        Returns:
            List of valid vulnerability Group XML elements.
        """
        search = ".//ns:Group" if ns else ".//Group"
        groups = root.findall(search, ns)

        valid: List[ET.Element] = []
        for group in groups:
            rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
            if rule is not None:
                valid.append(group)
        return valid

    def _parse_vuln_data(
        self,
        group: ET.Element,
        ns: Dict[str, str],
        meta: Dict[str, str],
        apply_boilerplate: bool,
        asset: str,
    ) -> Dict[str, Any]:
        """
        Parse an XCCDF vulnerability group into a data dictionary.

        Args:
            group: Parsed group element from the XCCDF benchmark.
            ns: XML namespace mapping.
            meta: Target STIG metadata parameters.
            apply_boilerplate: Flag indicating whether default textual responses should be applied.
            asset: Contextual asset identifier string.

        Returns:
            Dictionary containing the structured vulnerability data.

        Raises:
            ParseError: If critical parsing fails.
        """
        if group is None:
            raise ParseError("Group element is None")

        vid = group.get("id", "")
        if not vid:
            raise ParseError("Missing ID attribute in group")
        try:
            vid = San.vuln(vid)
        except ValidationError:
            raise ParseError(f"Invalid VID format in group: {vid}")

        rule = group.find("ns:Rule", ns) if ns else group.find("Rule")
        if rule is None:
            raise ParseError(f"Missing Rule in group {vid}")

        rule_id = rule.get("id", "")
        if rule_id is not None:
            rule_id = rule_id.strip()
        else:
            rule_id = ""

        if not rule_id:
            raise ParseError(f"Missing id attribute in Rule for group {vid}")

        severity = San.sev(rule.get("severity", "medium") or "medium")
        weight = rule.get("weight", "10.0") or "10.0"

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
                txt = ET.tostring(elem, encoding="unicode", method="text")
                return txt.strip() if txt else ""
            except (TypeError, ValueError, AttributeError) as exc:
                LOG.w(f"Failed to extract text from XML element {elem.tag if hasattr(elem, 'tag') else 'unknown'}: {exc}")
                return ""

        rule_title = text(find("title"))[:TITLE_MAX_LONG]
        rule_ver = text(find("version"))
        discussion = text(find("description"))
        fix_elem = find("fixtext")

        fix_text = self._collect_fix_text(fix_elem) if fix_elem is not None else ""

        check_elem = find("check")
        check_text = ""
        check_ref = "M"
        if check_elem is not None:
            check_content = (
                check_elem.find("ns:check-content", ns)
                if ns
                else check_elem.find("check-content")
            )
            check_text = (
                self._collect_fix_text(check_content)
                if check_content is not None
                else ""
            )
            check_content_ref = (
                check_elem.find("ns:check-content-ref", ns)
                if ns
                else check_elem.find("check-content-ref")
            )
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

        status = Status.NOT_REVIEWED
        finding = ""
        comment = ""

        if apply_boilerplate:
            finding = self.boiler.get_finding(
                vid, status, asset=asset, severity=severity
            )
            comment = self.boiler.get_comment(
                vid, status, asset=asset, severity=severity
            )

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

        return {
            "vid": vid,
            "stig_data_map": stig_data_map,
            "legacy_refs": legacy_refs,
            "cci_refs": cci_refs,
            "status": status,
            "finding": finding,
            "comment": comment
        }

    def _serialize_vuln(self, data: Dict[str, Any]) -> ET.Element:
        """
        Serialize parsed vulnerability data into a CKL VULN Element.

        Args:
            data: The parsed vulnerability data mapping generated by _parse_vuln_data.

        Returns:
            Fully populuated VULN ElementTree element.
        """
        vuln_node = ET.Element("VULN")
        stig_data_map = data["stig_data_map"]
        
        for attribute in Sch.VULN:
            value = stig_data_map.get(attribute, "")
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = attribute
            attr_data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            if value:
                attr_data.text = San.xml(value)

        for legacy in data.get("legacy_refs", []):
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "LEGACY_ID"
            attr_data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            attr_data.text = legacy

        for cci in data.get("cci_refs", []):
            sd = ET.SubElement(vuln_node, "STIG_DATA")
            attr = ET.SubElement(sd, "VULN_ATTRIBUTE")
            attr.text = "CCI_REF"
            attr_data = ET.SubElement(sd, "ATTRIBUTE_DATA")
            attr_data.text = cci

        status_node = ET.SubElement(vuln_node, "STATUS")
        status_node.text = data["status"]
        finding_node = ET.SubElement(vuln_node, "FINDING_DETAILS")
        if data["finding"]:
            finding_node.text = data["finding"]
        comment_node = ET.SubElement(vuln_node, "COMMENTS")
        if data["comment"]:
            comment_node.text = data["comment"]
        ET.SubElement(vuln_node, "SEVERITY_OVERRIDE")
        ET.SubElement(vuln_node, "SEVERITY_JUSTIFICATION")

        return vuln_node

    def _collect_fix_text(self, elem: Optional[ET.Element]) -> str:
        """
        Enhanced fix text extraction with proper handling of XCCDF mixed content.

        Handles:
        - Plain text content
        - Nested HTML elements (xhtml:br, xhtml:code, etc.)
        - CDATA sections
        - Mixed content with proper whitespace preservation

        Delegates to XmlUtils.extract_text_content for consistent text extraction.
        """
        return XmlUtils.extract_text_content(elem)

    def _write_ckl(self, root: ET.Element, out: Path) -> None:
        """Write CKL using shared FO.write_ckl implementation."""
        if hasattr(FO, "write_ckl"):
            FO.write_ckl(root, out, backup=False)
        else:
            with FO.atomic(out, mode="w", enc="utf-8", bak=False) as fh:
                xml_str = ET.tostring(root, encoding="unicode", method="xml")
                fh.write(
                    '<?xml version="1.0" encoding="UTF-8"?>\n<!-- STIG Assessor Generated -->\n'
                    + xml_str
                )

    # ---------------------------------------------------------------- JSON Mapping
    def _checklist_to_json(self, root: ET.Element):
        """Convert internal XML checklist element to STIG Viewer 3 CKLB JSON structure."""
        cklb = {"target_data": {}, "stig_data": {}, "reviews": []}

        asset = root.find("ASSET")
        if asset is not None:
            for child in asset:
                cklb["target_data"][child.tag] = child.text or ""

        stigs = root.find("STIGS")
        if stigs is not None:
            istig = stigs.find("iSTIG")
            if istig is not None:
                stig_info = istig.find("STIG_INFO")
                if stig_info is not None:
                    for si_data in stig_info.findall("SI_DATA"):
                        name = si_data.findtext("SID_NAME", "")
                        data = si_data.findtext("SID_DATA", "")
                        if name:
                            cklb["stig_data"][name] = data

            for i in stigs.findall("iSTIG"):
                for vuln in i.findall("VULN"):
                    review = {
                        "status": vuln.findtext("STATUS", Status.NOT_REVIEWED),
                        "detail": vuln.findtext("FINDING_DETAILS", ""),
                        "comment": vuln.findtext("COMMENTS", ""),
                    }
                    for sd in vuln.findall("STIG_DATA"):
                        attr = sd.findtext("VULN_ATTRIBUTE")
                        val = sd.findtext("ATTRIBUTE_DATA", "")
                        if attr:
                            review[attr] = val
                    cklb["reviews"].append(review)

        return cklb

    def _json_to_checklist(self, cklb) -> ET.ElementTree:
        """Convert a CKLB JSON structure to the internal XML ElementTree for processing."""
        root = ET.Element(Sch.ROOT)

        target_data = cklb.get("target_data", {})
        asset = ET.SubElement(root, "ASSET")
        for k, v in target_data.items():
            child = ET.SubElement(asset, k)
            child.text = str(v)

        stigs = ET.SubElement(root, "STIGS")
        istig = ET.SubElement(stigs, "iSTIG")

        stig_data = cklb.get("stig_data", {})
        stig_info = ET.SubElement(istig, "STIG_INFO")
        for k, v in stig_data.items():
            si = ET.SubElement(stig_info, "SI_DATA")
            ET.SubElement(si, "SID_NAME").text = k
            ET.SubElement(si, "SID_DATA").text = str(v)

        reviews = cklb.get("reviews", [])
        for review in reviews:
            vuln = ET.SubElement(istig, "VULN")
            ET.SubElement(vuln, "STATUS").text = str(
                review.get("status", Status.NOT_REVIEWED)
            )
            ET.SubElement(vuln, "FINDING_DETAILS").text = str(review.get("detail", ""))
            ET.SubElement(vuln, "COMMENTS").text = str(review.get("comment", ""))

            for k, v in review.items():
                if k not in ("status", "detail", "comment"):
                    sd = ET.SubElement(vuln, "STIG_DATA")
                    ET.SubElement(sd, "VULN_ATTRIBUTE").text = k
                    ET.SubElement(sd, "ATTRIBUTE_DATA").text = str(v)

        return ET.ElementTree(root)

    def _load_file_as_xml(self, path: Path) -> ET.ElementTree:
        if path.suffix.lower() == ".cklb":
            data = FO.parse_cklb(path)
            return self._json_to_checklist(data)
        return FO.parse_xml(path)

    def _export_xml_to_file(self, root: ET.Element, out: Path) -> None:
        if out.suffix.lower() == ".cklb":
            data = self._checklist_to_json(root)
            FO.write_cklb(data, out, backup=False)
        else:
            self._write_ckl(root, out)

    # -------------------------------------------------------------------- merge
    def merge(
        self,
        base: Union[str, Path],
        histories: Iterable[Union[str, Path]],
        out: Union[str, Path],
        *,
        preserve_history: bool = True,
        apply_boilerplate: bool = True,
        auto_status: bool = True,
        dry: bool = False,
    ) -> Dict[str, Union[bool, int, List[str], str]]:
        """
        Merge multiple checklists into a single output with history preservation.

        Ingests assessment history from multiple source checklists and merges
        it into the base checklist's finding details and comments.

        Args:
            base: Base checklist to merge into
            histories: Iterable of historical checklist paths to ingest
            out: Output path for merged checklist
            preserve_history: If True, include formatted history in output
            apply_boilerplate: If True, apply boilerplate templates
            auto_status: If True, automatically update status based on history

        Returns:
            Dict with keys: updated, skipped, dry_run, output (if not dry)

        Raises:
            ValidationError: If path validation or limits exceeded
            ParseError: If checklist parsing fails
        """
        try:
            base = San.path(base, exist=True, file=True)
            out = San.path(out, mkpar=True)
            history_paths = [San.path(p, exist=True, file=True) for p in histories]
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        if len(history_paths) > Cfg.MAX_MERGE:
            raise ValidationError(f"Too many historical files (limit {Cfg.MAX_MERGE})")

        with LOG.context(op="merge", base=base.name, histories=len(history_paths)):
            LOG.i(f"Merging {len(history_paths)} checklist(s) into base {base.name}")

            if preserve_history:
                for idx, hist_file in enumerate(history_paths, 1):
                    LOG.d(f"Loading history {idx}/{len(history_paths)}: {hist_file}")
                    self._ingest_history(hist_file)

            try:
                tree = self._load_file_as_xml(base)
                root = tree.getroot()
            except (ParseError, OSError, ValueError, KeyError) as exc:
                raise ParseError(f"Unable to parse base checklist: {exc}") from exc

            if root.tag != Sch.ROOT:
                raise ParseError("Base checklist has incorrect root element")

            stigs = root.find("STIGS")
            if stigs is None:
                raise ParseError("Base checklist missing STIGS")

            total_vulns = sum(
                len(istig.findall("VULN")) for istig in stigs.findall("iSTIG")
            )
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
                return {"updated": updated, "skipped": skipped, "dry_run": True}

            self._export_xml_to_file(root, out)
            LOG.i(f"Merged checklist saved to {out}")
            return {
                "updated": updated,
                "skipped": skipped,
                "dry_run": False,
                "output": str(out),
            }

    # ------------------------------------------------------------------ diff
    def diff(
        self,
        ckl1: Union[str, Path],
        ckl2: Union[str, Path],
        *,
        output_format: str = "text",
    ) -> Dict[str, Union[str, int, List[str]]]:
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
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        with LOG.context(op="diff", ckl1=ckl1.name, ckl2=ckl2.name):
            LOG.i(f"Comparing {ckl1.name} vs {ckl2.name}")

            # Parse both checklists
            try:
                tree1 = self._load_file_as_xml(ckl1)
                root1 = tree1.getroot()
                tree2 = self._load_file_as_xml(ckl2)
                root2 = tree2.getroot()
            except (ParseError, OSError, ValueError) as exc:
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
                    differences.append(
                        {
                            "field": "status",
                            "from": v1["status"],
                            "to": v2["status"],
                        }
                    )
                if v1["severity"] != v2["severity"]:
                    differences.append(
                        {
                            "field": "severity",
                            "from": v1["severity"],
                            "to": v2["severity"],
                        }
                    )
                if v1["finding_details"] != v2["finding_details"]:
                    differences.append(
                        {
                            "field": "finding_details",
                            "from_length": len(v1["finding_details"]),
                            "to_length": len(v2["finding_details"]),
                        }
                    )
                if v1["comments"] != v2["comments"]:
                    differences.append(
                        {
                            "field": "comments",
                            "from_length": len(v1["comments"]),
                            "to_length": len(v2["comments"]),
                        }
                    )

                if differences:
                    changed.append(
                        {
                            "vid": vid,
                            "rule_title": v1.get("rule_title", "Unknown"),
                            "differences": differences,
                        }
                    )
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
                results["formatted_text"] = self._format_diff_summary(
                    results, ckl1.name, ckl2.name
                )
            elif output_format == "detailed":
                results["formatted_text"] = self._format_diff_detailed(
                    results, ckl1.name, ckl2.name
                )

            return results

    def _extract_vuln_data(self, root: ET.Element) -> Dict[str, Dict[str, str]]:
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

    def _format_diff_summary(
        self,
        results: Dict[str, Union[str, int, List[str]]],
        name1: str,
        name2: str,
    ) -> str:
        """Format a summary of the diff results into a string."""
        s = results["summary"]
        lines = []
        lines.append(f"\n{'='*80}")
        lines.append(f"Checklist Comparison: {name1} vs {name2}")
        lines.append(f"{'='*80}")
        lines.append(f"\nBaseline ({name1}): {s['total_in_baseline']} vulnerabilities")
        lines.append(
            f"Comparison ({name2}): {s['total_in_comparison']} vulnerabilities"
        )
        lines.append(f"\nCommon vulnerabilities: {s['common']}")
        lines.append(f"  - Changed: {s['changed']}")
        lines.append(f"  - Unchanged: {s['unchanged']}")
        lines.append(f"\nOnly in baseline: {s['only_in_baseline']}")
        lines.append(f"Only in comparison: {s['only_in_comparison']}")

        if results["changed"]:
            lines.append(f"\n{'-'*80}")
            lines.append("Changed Vulnerabilities:")
            lines.append(f"{'-'*80}")
            for item in results["changed"][:10]:  # Show first 10
                lines.append(f"\n{item['vid']}: {item['rule_title'][:60]}")
                for diff in item["differences"]:
                    if diff["field"] == "status":
                        lines.append(f"  Status: {diff['from']} → {diff['to']}")
                    elif diff["field"] == "severity":
                        lines.append(f"  Severity: {diff['from']} → {diff['to']}")
                    else:
                        lines.append(
                            f"  {diff['field']} changed ({diff.get('from_length', 0)} → {diff.get('to_length', 0)} chars)"
                        )
            if len(results["changed"]) > 10:
                lines.append(
                    f"\n... and {len(results['changed']) - 10} more changed vulnerabilities"
                )
        return "\n".join(lines)

    def _format_diff_detailed(
        self,
        results: Dict[str, Union[str, int, List[str]]],
        name1: str,
        name2: str,
    ) -> str:
        """Format detailed diff results into a string."""
        lines = [self._format_diff_summary(results, name1, name2)]

        if results["only_in_baseline"]:
            lines.append(f"\n{'-'*80}")
            lines.append(f"Vulnerabilities only in {name1}:")
            lines.append(f"{'-'*80}")
            for vid in results["only_in_baseline"][:20]:
                lines.append(f"  {vid}")
            if len(results["only_in_baseline"]) > 20:
                lines.append(f"  ... and {len(results['only_in_baseline']) - 20} more")

        if results["only_in_comparison"]:
            lines.append(f"\n{'-'*80}")
            lines.append(f"Vulnerabilities only in {name2}:")
            lines.append(f"{'-'*80}")
            for vid in results["only_in_comparison"][:20]:
                lines.append(f"  {vid}")
            if len(results["only_in_comparison"]) > 20:
                lines.append(
                    f"  ... and {len(results['only_in_comparison']) - 20} more"
                )
        return "\n".join(lines)

    # ----------------------------------------------------------------- helpers
    def _ingest_history(self, path: Path) -> None:
        """Ingest history entries from an existing CKL file."""
        try:
            tree = self._load_file_as_xml(path)
            root = tree.getroot()
        except (FileError, ParseError, ValidationError) as exc:
            LOG.d(f"Could not parse history from {path}: {exc}")
            return
        except (OSError, RuntimeError) as exc:
            LOG.w(f"Unexpected error parsing history from {path}: {exc}")
            return

        stigs = root.find("STIGS")
        if stigs is None:
            return

        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vid = XmlUtils.get_vid(vuln)
                if not vid:
                    continue

                status = vuln.findtext("STATUS", default=Status.NOT_REVIEWED)
                finding = vuln.findtext("FINDING_DETAILS", default="")
                comment = vuln.findtext("COMMENTS", default="")
                severity = "medium"

                for sd in vuln.findall("STIG_DATA"):
                    attr = sd.findtext("VULN_ATTRIBUTE")
                    if attr == "Severity":
                        severity = San.sev(
                            sd.findtext("ATTRIBUTE_DATA", default="medium")
                        )

                if finding.strip() or comment.strip():
                    self.history.add(
                        vid,
                        status,
                        finding,
                        comment,
                        src=path.name,
                        sev=severity,
                    )

    def _merge_vuln(
        self, vuln: ET.Element, preserve_history: bool, apply_boilerplate: bool
    ) -> bool:
        """
        Integrate historical data into an existing STIG vulnerability node.

        Updates the finding details, comments, and status of a given vulnerability element
        by pulling from accumulated historical configurations, seamlessly managing backfilled text
        and boilerplate formatting requirements.

        Args:
            vuln: Target ElementTree element to update.
            preserve_history: Flag to dictate whether raw historical logs are explicitly injected.
            apply_boilerplate: Flag to append missing details with standard configured templates.

        Returns:
            True if modifications occurred resulting in updates to the VULN element, False otherwise.
        """
        vid = XmlUtils.get_vid(vuln)
        if not vid:
            return False

        status_node = vuln.find("STATUS")
        status = (
            status_node.text.strip()
            if status_node is not None and status_node.text
            else Status.NOT_REVIEWED
        )
        finding_node = vuln.find("FINDING_DETAILS")
        comment_node = vuln.find("COMMENTS")

        current_finding = (
            finding_node.text if finding_node is not None and finding_node.text else ""
        )
        current_comment = (
            comment_node.text if comment_node is not None and comment_node.text else ""
        )

        merged = False

        if preserve_history and self.history.has(vid):
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
            default_finding = self.boiler.get_finding(vid, status)
            default_comment = self.boiler.get_comment(vid, status)
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
    def repair(
        self,
        ckl_path: Union[str, Path],
        out_path: Optional[Union[str, Path]] = None,
        *,
        backup: bool = False,
    ) -> Dict[str, Union[bool, str, int, List[str]]]:
        """
        Repair corrupted CKL file by fixing common issues.

        Args:
            ckl_path: Path to corrupted checklist
            out_path: Path for repaired checklist (auto-generated if None)
            backup: If True and out_path is None, create a backup of the
                    original and write the repaired file in-place.

        Returns:
            Dictionary with repair statistics
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            if out_path is None:
                if backup:
                    import shutil
                    backup_path = ckl_path.with_suffix(".ckl.bak")
                    shutil.copy2(ckl_path, backup_path)
                    LOG.i(f"Backup created: {backup_path}")
                out_path = ckl_path  # repair in-place
            out_path = San.path(out_path, mkpar=True)
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        with LOG.context(op="repair", file=ckl_path.name):
            LOG.i(f"Repairing checklist: {ckl_path}")

            repairs = []

            try:
                tree = self._load_file_as_xml(ckl_path)
                root = tree.getroot()
            except (ParseError, OSError, ValueError) as exc:
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
                                    status_node.text = Status.NOT_A_FINDING
                                    repairs.append(
                                        f"Fixed status typo: '{status_val}' → '{Status.NOT_A_FINDING}'"
                                    )
                                elif status_val.lower() == "open":
                                    status_node.text = Status.OPEN
                                    repairs.append(
                                        f"Fixed status case: '{status_val}' → '{Status.OPEN}'"
                                    )
                                elif (
                                    "not" in status_val.lower()
                                    and "applicable" in status_val.lower()
                                ):
                                    status_node.text = Status.NOT_APPLICABLE
                                    repairs.append(
                                        f"Fixed status typo: '{status_val}' → '{Status.NOT_APPLICABLE}'"
                                    )
                                else:
                                    # Can't fix, set to Status.NOT_REVIEWED
                                    old_val = status_val
                                    status_node.text = Status.NOT_REVIEWED
                                    repairs.append(
                                        f"Reset invalid status: '{old_val}' → '{Status.NOT_REVIEWED}'"
                                    )

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
                    vid = XmlUtils.get_vid(vuln) or "unknown"

                    finding_node = vuln.find("FINDING_DETAILS")
                    if finding_node is not None and finding_node.text:
                        if len(finding_node.text) > Cfg.MAX_FIND:
                            finding_node.text = (
                                finding_node.text[: Cfg.MAX_FIND - 15] + "\n[TRUNCATED]"
                            )
                            repairs.append(
                                f"Truncated oversized FINDING_DETAILS for {vid}"
                            )

                    comment_node = vuln.find("COMMENTS")
                    if comment_node is not None and comment_node.text:
                        if len(comment_node.text) > Cfg.MAX_COMM:
                            comment_node.text = (
                                comment_node.text[: Cfg.MAX_COMM - 15] + "\n[TRUNCATED]"
                            )
                            repairs.append(f"Truncated oversized COMMENTS for {vid}")

        # Write repaired checklist
        XmlUtils.indent_xml(root)
        self._export_xml_to_file(root, out_path)

        LOG.i(f"Repaired checklist written to {out_path}")
        LOG.i(f"Repairs applied: {len(repairs)}")

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
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        with LOG.context(op="batch_convert", dir=xccdf_dir.name):
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

                    LOG.i(
                        f"[{idx}/{len(xccdf_files)}] Converting {xccdf_file.name} → {out_file.name}"
                    )

                    result = self.xccdf_to_ckl(
                        xccdf_file,
                        out_file,
                        asset_name,
                        apply_boilerplate=apply_boilerplate,
                    )

                    successes.append(
                        {
                            "file": xccdf_file.name,
                            "output": out_file.name,
                            "processed": result.get("processed", 0),
                        }
                    )

                except (
                    ParseError,
                    ValidationError,
                    FileError,
                    OSError,
                    ValueError,
                ) as exc:
                    LOG.e(f"Failed to convert {xccdf_file.name}: {exc}")
                    failures.append(
                        {
                            "file": xccdf_file.name,
                            "error": str(exc),
                        }
                    )

            LOG.i(
                f"Batch conversion complete: {len(successes)} successes, {len(failures)} failures"
            )

            return {
                "ok": len(failures) == 0,
                "total": len(xccdf_files),
                "successes": len(successes),
                "failures": len(failures),
                "details": successes,
                "errors": failures,
            }

    def verify_integrity(
        self, ckl_path: Union[str, Path]
    ) -> Dict[str, Union[bool, int, List[str], str]]:
        """
        Verify checklist integrity using checksums and validation.

        Args:
            ckl_path: Path to checklist to verify

        Returns:
            Dictionary with integrity check results
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        with LOG.context(op="verify_integrity", file=ckl_path.name):
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
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        checksum = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                checksum.update(chunk)

        return checksum.hexdigest()

    def generate_stats(
        self, ckl_path: Union[str, Path], *, output_format: str = "text"
    ) -> Union[str, Dict[str, Union[str, int, float, Dict[str, int], List[str]]]]:
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
        except (ValidationError, OSError, ValueError, TypeError) as exc:
            raise ValidationError(f"Path validation failed: {exc}") from exc

        with LOG.context(op="generate_stats", file=ckl_path.name):
            LOG.i(f"Generating statistics for {ckl_path}")

            try:
                tree = self._load_file_as_xml(ckl_path)
                root = tree.getroot()
            except (ParseError, OSError, ValueError) as exc:
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
                        status = (
                            status_node.text.strip()
                            if status_node is not None and status_node.text
                            else Status.NOT_REVIEWED
                        )
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
            reviewed = sum(
                stats["by_status"][s]
                for s in stats["by_status"]
                if s != Status.NOT_REVIEWED
            )
            stats["reviewed"] = reviewed
            stats["completion_pct"] = (
                (reviewed / stats["total_vulns"] * 100) if stats["total_vulns"] > 0 else 0
            )

            # Calculate compliance percentage (NotAFinding / total reviewed)
            not_a_finding = stats["by_status"].get(Status.NOT_A_FINDING, 0)
            stats["compliant"] = not_a_finding
            stats["compliance_pct"] = (
                (not_a_finding / reviewed * 100) if reviewed > 0 else 0
            )

        # Hook: Plugins can modify or inject custom computed stats metrics
        stats = self.plugins.run_hooks(
            "post_stats_generate", payload=stats, ckl_path=ckl_path
        )

        # Format output
        if output_format == "json":
            # Convert defaultdicts to regular dicts for JSON serialization
            result = dict(stats)
            result["by_status"] = dict(stats["by_status"])
            result["by_severity"] = dict(stats["by_severity"])
            result["by_status_and_severity"] = {
                sev: dict(statuses)
                for sev, statuses in stats["by_status_and_severity"].items()
            }
            return result
        elif output_format == "csv":
            return self._format_stats_csv(stats)
        elif output_format == "html":
            return self._format_stats_html(stats)
        else:  # text
            return self._format_stats_text(stats)

    def _format_stats_text(
        self,
        stats: Dict[str, Union[str, int, float, Dict[str, int], List[str]]],
    ) -> str:
        """Format statistics as human-readable text."""
        lines = []
        lines.append("=" * 80)
        lines.append("STIG Compliance Statistics")
        lines.append("=" * 80)
        lines.append(f"File: {stats['file']}")
        lines.append(f"Generated: {stats['generated']}")
        lines.append("")
        lines.append(f"Total Vulnerabilities: {stats['total_vulns']}")
        lines.append(f"Reviewed: {stats['reviewed']} ({stats['completion_pct']:.1f}%)")
        lines.append(
            f"Compliant: {stats['compliant']} ({stats['compliance_pct']:.1f}% of reviewed)"
        )
        lines.append("")
        lines.append("Status Breakdown:")
        lines.append("-" * 40)
        for status in sorted(stats["by_status"].keys()):
            count = stats["by_status"][status]
            pct = (
                (count / stats["total_vulns"] * 100) if stats["total_vulns"] > 0 else 0
            )
            lines.append(f"  {status:20} {count:6} ({pct:5.1f}%)")
        lines.append("")
        lines.append("Severity Breakdown:")
        lines.append("-" * 40)
        for severity in ["high", "medium", "low"]:
            if severity in stats["by_severity"]:
                count = stats["by_severity"][severity]
                pct = (
                    (count / stats["total_vulns"] * 100)
                    if stats["total_vulns"] > 0
                    else 0
                )
                lines.append(
                    f"  CAT {['I', 'II', 'III'][['high', 'medium', 'low'].index(severity)]:3} ({severity:6}) {count:6} ({pct:5.1f}%)"
                )
        lines.append("=" * 80)
        return "\n".join(lines)

    def _format_stats_html(
        self,
        stats: Dict[str, Union[str, int, float, Dict[str, int], List[str]]],
    ) -> str:
        """Format statistics as a self-contained HTML report (printable to PDF)."""
        import string

        # Calculate percentages for donut
        total = stats["total_vulns"]
        not_a_finding = stats["by_status"].get(Status.NOT_A_FINDING, 0)
        open_count = stats["by_status"].get(Status.OPEN, 0)
        not_reviewed = stats["by_status"].get(Status.NOT_REVIEWED, 0)
        not_applicable = stats["by_status"].get(Status.NOT_APPLICABLE, 0)

        # Basic donut math (radius 15.915 = circ 100)
        p_naf = (not_a_finding / total * 100) if total else 0
        p_open = (open_count / total * 100) if total else 0
        p_na = (not_applicable / total * 100) if total else 0
        p_nr = (not_reviewed / total * 100) if total else 0

        o_naf = 0
        o_open = o_naf + p_naf
        o_na = o_open + p_open
        o_nr = o_na + p_na

        html_template = string.Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>STIG Compliance Report - $file</title>
    <style>
        :root {
            --bg: #ffffff; --tx: #1e293b; --tx-dim: #64748b;
            --pass: #10b981; --fail: #ef4444; --na: #94a3b8; --nr: #f59e0b;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--tx); line-height: 1.5; padding: 40px; max-width: 1000px; margin: 0 auto; }
        .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { margin: 0 0 10px 0; color: #0f172a; }
        .meta { color: var(--tx-dim); font-size: 0.9em; display: flex; gap: 20px; }
        
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 40px; }
        .card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .card h2 { margin-top: 0; font-size: 1.1em; color: #334155; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; margin-bottom: 20px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
        .stat-box { background: #f8fafc; padding: 15px; border-radius: 6px; text-align: center; }
        .stat-val { font-size: 2em; font-weight: bold; line-height: 1; }
        .stat-lbl { font-size: 0.75em; text-transform: uppercase; color: var(--tx-dim); font-weight: 600; margin-top: 5px; }
        
        .donut-container { display: flex; align-items: center; justify-content: center; position: relative; width: 220px; height: 220px; margin: 0 auto; }
        .donut-svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .donut-segment { fill: transparent; stroke-width: 4; }
        .center-label { position: absolute; text-align: center; }
        .center-lbl-val { font-size: 2.2em; font-weight: bold; line-height: 1; color: var(--pass); }
        .center-lbl-txt { font-size: 0.8em; color: var(--tx-dim); }
        
        .legend { margin-top: 20px; display: flex; justify-content: space-between; font-size: 0.85em; }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .dot { width: 10px; height: 10px; border-radius: 50%; }
        
        .table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .table th, .table td { text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f8fafc; color: #475569; font-weight: 600; text-transform: uppercase; font-size: 0.8em; }
        
        .badge { display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 0.75em; font-weight: 600; }
        .bg-pass { background: rgba(16, 185, 129, 0.1); color: #059669; }
        .bg-fail { background: rgba(239, 68, 68, 0.1); color: #dc2626; }
        .bg-na { background: rgba(148, 163, 184, 0.1); color: #475569; }
        .bg-nr { background: rgba(245, 158, 11, 0.1); color: #d97706; }
        
        .c-pass { color: var(--pass); } .c-fail { color: var(--fail); } .c-na { color: var(--na); } .c-nr { color: var(--nr); }
        .stroke-pass { stroke: var(--pass); } .stroke-fail { stroke: var(--fail); } .stroke-na { stroke: var(--na); } .stroke-nr { stroke: var(--nr); }
        
        @media print { body { padding: 0; } .card { box-shadow: none; break-inside: avoid; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>STIG Compliance Report</h1>
        <div class="meta">
            <div><strong>File:</strong> $file</div>
            <div><strong>Generated:</strong> $date</div>
        </div>
    </div>
    
    <div class="grid">
        <div class="card">
            <h2>Compliance Overview</h2>
            <div class="donut-container">
                <svg class="donut-svg" viewBox="0 0 42 42">
                    <!-- Background ring -->
                    <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#f1f5f9" stroke-width="4"></circle>
                    <!-- Segments (Dasharray: length, 100-length | Dashoffset: -start) -->
                    <circle class="donut-segment stroke-pass" cx="21" cy="21" r="15.915" stroke-dasharray="$p_naf ${rem_naf}" stroke-dashoffset="-$o_naf"></circle>
                    <circle class="donut-segment stroke-fail" cx="21" cy="21" r="15.915" stroke-dasharray="$p_open ${rem_open}" stroke-dashoffset="-$o_open"></circle>
                    <circle class="donut-segment stroke-na" cx="21" cy="21" r="15.915" stroke-dasharray="$p_na ${rem_na}" stroke-dashoffset="-$o_na"></circle>
                    <circle class="donut-segment stroke-nr" cx="21" cy="21" r="15.915" stroke-dasharray="$p_nr ${rem_nr}" stroke-dashoffset="-$o_nr"></circle>
                </svg>
                <div class="center-label">
                    <div class="center-lbl-val">$compliance_pct%</div>
                    <div class="center-lbl-txt">Compliant</div>
                </div>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="dot" style="background:var(--pass)"></div> Not a Finding ($naf)</div>
                <div class="legend-item"><div class="dot" style="background:var(--fail)"></div> Open ($open)</div>
                <div class="legend-item"><div class="dot" style="background:var(--na)"></div> N/A ($na)</div>
                <div class="legend-item"><div class="dot" style="background:var(--nr)"></div> Not Reviewed ($nr)</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Key Metrics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-val">$total</div>
                    <div class="stat-lbl">Total Checks</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val c-pass">$naf</div>
                    <div class="stat-lbl">Compliant</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val">$reviewed</div>
                    <div class="stat-lbl">Reviewed ($completion_pct%)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val c-fail">$open</div>
                    <div class="stat-lbl">Open Finds</div>
                </div>
            </div>
            
            <h2 style="margin-top:25px;">Severity Breakdown</h2>
            <table class="table" style="margin-top:0;">
                <thead><tr><th>Severity</th><th>Count</th><th>%</th></tr></thead>
                <tbody>
                    $sev_rows
                </tbody>
            </table>
        </div>
    </div>
    
    <div style="text-align:center;color:var(--tx-dim);font-size:0.8em;margin-top:40px;padding-top:20px;border-top:1px solid #e2e8f0;">
        Generated by STIG Assessor v$version &middot; Zero-Dependency Offline Reporter
    </div>
</body>
</html>""")

        # Build severity rows
        sev_rows = ""
        for sev in ["high", "medium", "low"]:
            if sev in stats["by_severity"]:
                count = stats["by_severity"][sev]
                pct = (count / total * 100) if total else 0
                bg_class = (
                    "bg-fail"
                    if sev == "high"
                    else "bg-nr" if sev == "medium" else "bg-pass"
                )
                sev_rows += f"<tr><td><span class='badge {bg_class}'>{sev.upper()}</span></td><td>{count}</td><td>{pct:.1f}%</td></tr>"

        from stig_assessor.core.constants import VERSION as _ver
        return html_template.substitute(
            file=stats["file"],
            date=stats["generated"],
            version=_ver,
            total=total,
            reviewed=stats["reviewed"],
            completion_pct=f"{stats['completion_pct']:.1f}",
            compliance_pct=f"{stats['compliance_pct']:.1f}",
            naf=not_a_finding,
            open=open_count,
            na=not_applicable,
            nr=not_reviewed,
            p_naf=p_naf,
            rem_naf=100 - p_naf,
            o_naf=o_naf,
            p_open=p_open,
            rem_open=100 - p_open,
            o_open=o_open,
            p_na=p_na,
            rem_na=100 - p_na,
            o_na=o_na,
            p_nr=p_nr,
            rem_nr=100 - p_nr,
            o_nr=o_nr,
            sev_rows=sev_rows,
        )

    def _format_stats_csv(
        self,
        stats: Dict[str, Union[str, int, float, Dict[str, int], List[str]]],
    ) -> str:
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
        for status in sorted(stats["by_status"].keys()):
            lines.append(f"{status},{stats['by_status'][status]}")
        lines.append("")
        lines.append("Severity,Count")
        for severity in ["high", "medium", "low"]:
            if severity in stats["by_severity"]:
                lines.append(f"{severity},{stats['by_severity'][severity]}")
        return "\n".join(lines)

    def export_html_report(self, ckl_path: Union[str, Path], out_path: Union[str, Path]) -> str:
        """
        Generate a standalone HTML compliance report from a checklist.
        
        Args:
            ckl_path: Path to checklist.
            out_path: Path to save the HTML file.
            
        Returns:
            The path to the generated HTML report.
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            out_path = San.path(out_path, mkpar=True)
            tree = self._load_file_as_xml(ckl_path)
            root = tree.getroot()
        except (ParseError, OSError, ValueError) as exc:
            raise ParseError(f"Failed to parse checklist: {exc}") from exc

        vulns = self._extract_vuln_data(root)
        asset_node = root.find(".//HOST_NAME")
        asset_name = asset_node.text if asset_node is not None else "Unknown Asset"
        
        # Stats — separate Pass and N/A for accurate reporting
        total = len(vulns)
        naf_count = sum(1 for v in vulns.values() if v.get("status") == Status.NOT_A_FINDING)
        open_count = sum(1 for v in vulns.values() if v.get("status") == Status.OPEN)
        na_count = sum(1 for v in vulns.values() if v.get("status") == Status.NOT_APPLICABLE)
        nr_count = sum(1 for v in vulns.values() if v.get("status") == Status.NOT_REVIEWED)

        from stig_assessor.core.constants import VERSION as _ver

        html_content = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='utf-8'>",
            f"<title>STIG Compliance Report - {_html_module.escape(asset_name)}</title>",
            "<style>",
            "*,*::before,*::after{box-sizing:border-box}",
            "body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }",
            ".container { max-width: 1400px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }",
            "h1 { border-bottom: 2px solid #0056b3; padding-bottom: 10px; color: #0056b3; margin-top:0; }",
            ".stats { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }",
            ".stat-box { flex: 1; min-width: 140px; padding: 15px; border-radius: 6px; color: #fff; text-align: center; }",
            ".stat-box h3 { margin: 0 0 5px 0; font-size: .85em; opacity: .9; }",
            ".stat-box h2 { margin: 0; font-size: 1.8em; }",
            ".bg-blue { background: #0056b3; }",
            ".bg-red { background: #dc3545; }",
            ".bg-green { background: #28a745; }",
            ".bg-teal { background: #6c757d; }",
            ".bg-yellow { background: #ffc107; color: #333; }",
            
            "/* Toolbar */",
            ".toolbar { display: flex; gap: 10px; margin: 20px 0 10px; align-items: center; flex-wrap: wrap; }",
            ".toolbar input[type=text] { flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }",
            ".toolbar input[type=text]:focus { outline: none; border-color: #0056b3; box-shadow: 0 0 0 2px rgba(0,86,179,.15); }",
            ".filter-btns { display: flex; gap: 4px; }",
            ".filter-btns button { padding: 6px 12px; border: 1px solid #ccc; border-radius: 4px; background: #f8f9fa; cursor: pointer; font-size: 13px; transition: all .15s; }",
            ".filter-btns button:hover { background: #e9ecef; }",
            ".filter-btns button.active { background: #0056b3; color: #fff; border-color: #0056b3; }",
            ".match-count { font-size: 13px; color: #6c757d; margin-left: 8px; white-space: nowrap; }",
            
            "/* Table */",
            "table { width: 100%; border-collapse: collapse; margin-top: 0; font-size: 14px; }",
            "th, td { border: 1px solid #ddd; padding: 10px 12px; text-align: left; }",
            "th { background-color: #f8f9fa; font-weight: bold; cursor: pointer; user-select: none; position: relative; white-space: nowrap; }",
            "th:hover { background: #e9ecef; }",
            "th .sort-arrow { margin-left: 4px; font-size: .7em; opacity: .4; }",
            "th.sorted .sort-arrow { opacity: 1; }",
            ".status-Open { color: #dc3545; font-weight: bold; }",
            ".status-NotAFinding { color: #28a745; font-weight: bold; }",
            ".status-Not_Applicable { color: #6c757d; }",
            ".status-Not_Reviewed { color: #d89e00; font-weight: bold; }",
            "tr.hidden { display: none; }",
            
            "/* Footer */",
            ".footer { text-align: center; color: #6c757d; font-size: .8em; margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; }",
            
            "@media print { .toolbar { display: none; } th { cursor: default; } }",
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            f"<h1>STIG Compliance Report: {_html_module.escape(asset_name)}</h1>",
            "<div class='stats'>",
            f"<div class='stat-box bg-blue'><h3>Total</h3><h2>{total}</h2></div>",
            f"<div class='stat-box bg-green'><h3>Not a Finding</h3><h2>{naf_count}</h2></div>",
            f"<div class='stat-box bg-red'><h3>Open</h3><h2>{open_count}</h2></div>",
            f"<div class='stat-box bg-teal'><h3>Not Applicable</h3><h2>{na_count}</h2></div>",
            f"<div class='stat-box bg-yellow'><h3>Not Reviewed</h3><h2>{nr_count}</h2></div>",
            "</div>",
            
            "<!-- Search / Filter toolbar -->",
            "<div class='toolbar'>",
            "<input type='text' id='searchInput' placeholder='Search by Vuln ID, severity, or details…' />",
            "<div class='filter-btns'>",
            "<button class='active' data-filter='all'>All</button>",
            "<button data-filter='Open'>Open</button>",
            "<button data-filter='NotAFinding'>Pass</button>",
            "<button data-filter='Not_Applicable'>N/A</button>",
            "<button data-filter='Not_Reviewed'>Not Reviewed</button>",
            "</div>",
            "<span class='match-count' id='matchCount'></span>",
            "</div>",
            
            "<table id='vulnTable'>",
            "<thead>",
            "<tr>",
            "<th data-col='0'>Vuln ID <span class='sort-arrow'>▲▼</span></th>",
            "<th data-col='1'>Severity <span class='sort-arrow'>▲▼</span></th>",
            "<th data-col='2'>Status <span class='sort-arrow'>▲▼</span></th>",
            "<th data-col='3'>Finding Details <span class='sort-arrow'>▲▼</span></th>",
            "</tr>",
            "</thead>",
            "<tbody id='vulnBody'>",
        ]

        for vid, vdata in vulns.items():
            status = vdata.get("status", "Not_Reviewed")
            severity = vdata.get("severity", "medium").upper()
            details = vdata.get("finding_details", "")
            if len(details) > 200:
                details = details[:200] + "..."
            details = _html_module.escape(details)

            html_content.append(f"<tr data-status='{_html_module.escape(status)}'>")
            html_content.append(f"<td><strong>{_html_module.escape(vid)}</strong></td>")
            html_content.append(f"<td>{_html_module.escape(severity)}</td>")
            html_content.append(f"<td class='status-{_html_module.escape(status)}'>{status.replace('_', ' ')}</td>")
            html_content.append(f"<td>{details}</td>")
            html_content.append("</tr>")

        html_content.append("</tbody>")
        html_content.append("</table>")

        # Client-side search, filter, and sort (self-contained, no dependencies)
        html_content.append("""<script>
(function(){
  var table = document.getElementById('vulnTable');
  var tbody = document.getElementById('vulnBody');
  var searchInput = document.getElementById('searchInput');
  var matchCount = document.getElementById('matchCount');
  var filterBtns = document.querySelectorAll('.filter-btns button');
  var currentFilter = 'all';
  var sortCol = -1, sortAsc = true;

  /* ── Filter + Search ── */
  function applyFilters() {
    var query = searchInput.value.toLowerCase();
    var rows = tbody.getElementsByTagName('tr');
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var status = row.getAttribute('data-status') || '';
      var text = row.textContent.toLowerCase();
      var matchFilter = (currentFilter === 'all' || status === currentFilter);
      var matchSearch = (!query || text.indexOf(query) !== -1);
      if (matchFilter && matchSearch) {
        row.classList.remove('hidden');
        shown++;
      } else {
        row.classList.add('hidden');
      }
    }
    matchCount.textContent = shown + ' of ' + rows.length + ' shown';
  }

  searchInput.addEventListener('input', applyFilters);

  filterBtns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      filterBtns.forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter');
      applyFilters();
    });
  });

  /* ── Column Sort ── */
  var headers = table.querySelectorAll('th[data-col]');
  headers.forEach(function(th) {
    th.addEventListener('click', function() {
      var col = parseInt(th.getAttribute('data-col'));
      if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
      headers.forEach(function(h) { h.classList.remove('sorted'); });
      th.classList.add('sorted');
      th.querySelector('.sort-arrow').textContent = sortAsc ? '▲' : '▼';

      var rows = Array.prototype.slice.call(tbody.getElementsByTagName('tr'));
      rows.sort(function(a, b) {
        var aVal = (a.children[col] || {}).textContent || '';
        var bVal = (b.children[col] || {}).textContent || '';
        return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      });
      rows.forEach(function(row) { tbody.appendChild(row); });
    });
  });

  applyFilters();
})();
</script>""")

        html_content.append(f"<div class='footer'>Generated by STIG Assessor v{_ver} &middot; Zero-Dependency Offline Reporter</div>")
        html_content.append("</div></body></html>")

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(html_content))

        LOG.i(f"Exported HTML report to {out_path}")
        return str(out_path)

    # ------------------------------------------------------------ POAM & Bulk Operations
    def export_poam(self, ckl_path: Union[str, Path]) -> str:
        """
        Generate an eMASS-compatible POAM export (CSV).
        Only exports Open and Not_Reviewed vulnerabilities.

        Args:
            ckl_path: Path to checklist.

        Returns:
            CSV formatted string with POAM data.
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            tree = self._load_file_as_xml(ckl_path)
            root = tree.getroot()
        except (ParseError, OSError, ValueError) as exc:
            raise ParseError(f"Failed to parse checklist: {exc}")

        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # eMASS POAM Header
        writer.writerow([
            "Control Number", "Vulnerability Description", "Severity",
            "Status", "Comments", "Checklist Name"
        ])

        stigs = root.find("STIGS")
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    status_node = vuln.find("STATUS")
                    status = status_node.text.strip(
                    ) if status_node is not None and status_node.text else Status.NOT_REVIEWED

                    if status not in [Status.OPEN, Status.NOT_REVIEWED]:
                        continue

                    vid = XmlUtils.get_vid(vuln) or "Unknown_VID"
                    title = ""
                    severity = "medium"

                    for sd in vuln.findall("STIG_DATA"):
                        attr = sd.findtext("VULN_ATTRIBUTE")
                        if attr == "Rule_Title":
                            title = sd.findtext("ATTRIBUTE_DATA", default="")
                        elif attr == "Severity":
                            severity = sd.findtext("ATTRIBUTE_DATA", default="medium")

                    comment_node = vuln.find("COMMENTS")
                    comment = comment_node.text.strip() if comment_node is not None and comment_node.text else ""

                    writer.writerow([
                        vid, title, severity.upper(), status, comment, ckl_path.name
                    ])

        return output.getvalue()

    def bulk_edit(
        self,
        ckl_path: Union[str, Path],
        out_path: Union[str, Path],
        *,
        severity: Optional[str] = None,
        regex_vid: Optional[str] = None,
        new_status: str,
        new_comment: str,
        append_comment: bool = False
    ) -> Dict[str, Any]:
        """
        Bulk update vulnerabilities matching specific selectors.

        Args:
            ckl_path: Path to checklist.
            out_path: Where to save the updated checklist.
            severity: Filter string (high/medium/low).
            regex_vid: Regex pattern to match VIDs.
            new_status: The status to enforce (e.g. 'Not_Applicable').
            new_comment: The comment to apply.
            append_comment: If True, appends to existing comments instead of replacing.

        Returns:
            Dictionary with batch update result statistics.
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            out_path = San.path(out_path, mkpar=True)
            tree = self._load_file_as_xml(ckl_path)
            root = tree.getroot()
        except (ParseError, OSError, ValueError) as exc:
            raise ParseError(f"Failed to load checklist: {exc}")

        if not Status.is_valid(new_status):
            raise ValidationError(f"Invalid status value: {new_status}")

        import re
        vid_pattern = re.compile(regex_vid) if regex_vid else None

        count = 0
        stigs = root.find("STIGS")
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    vid = XmlUtils.get_vid(vuln) or ""

                    # Evaluate Selectors
                    match = True
                    if vid_pattern and not vid_pattern.search(vid):
                        match = False

                    if severity:
                        sev_val = "medium"
                        for sd in vuln.findall("STIG_DATA"):
                            if sd.findtext("VULN_ATTRIBUTE") == "Severity":
                                sev_val = sd.findtext(
                                    "ATTRIBUTE_DATA", default="medium")
                        if sev_val.lower() != severity.lower():
                            match = False

                    # Apply if passed selectors
                    if match:
                        status_node = vuln.find("STATUS")
                        if status_node is None:
                            status_node = ET.SubElement(vuln, "STATUS")
                        status_node.text = new_status

                        comment_node = vuln.find("COMMENTS")
                        if comment_node is None:
                            comment_node = ET.SubElement(vuln, "COMMENTS")

                        if append_comment and comment_node.text and comment_node.text.strip():
                            comment_node.text = f"{comment_node.text.strip()}\n{new_comment}"
                        else:
                            comment_node.text = new_comment

                        count += 1

        XmlUtils.indent_xml(root)
        self._export_xml_to_file(root, out_path)

        LOG.i(f"Bulk edited {count} vulnerabilities")
        return {
            "ok": True,
            "updates": count,
            "output": str(out_path)
        }

    def apply_waivers(
        self,
        ckl_path: Union[str, Path],
        out_path: Union[str, Path],
        vids: List[str],
        approver: str,
        reason: str,
        valid_until: str
    ) -> Dict[str, Any]:
        """
        Automated Waiver Engine pipeline.

        Args:
            ckl_path: Path to checklist.
            out_path: Where to save the updated checklist.
            vids: List of vulnerability IDs to apply the waiver to.
            approver: Name of the approval authority.
            reason: Waiver rationale/justification.
            valid_until: Expiration date.

        Returns:
            Dictionary with waiver batch statistics.
        """
        try:
            ckl_path = San.path(ckl_path, exist=True, file=True)
            out_path = San.path(out_path, mkpar=True)
            tree = self._load_file_as_xml(ckl_path)
            root = tree.getroot()
        except (ParseError, OSError, ValueError) as exc:
            raise ParseError(f"Failed to load checklist: {exc}")

        count = 0
        waiver_block = (
            "═" * 40 + "\n"
            f"[WAIVER APPROVED: {approver}]\n"
            f"Valid Until: {valid_until}\n"
            f"Reason: {reason}\n"
            + "═" * 40
        )

        stigs = root.find("STIGS")
        if stigs is not None:
            for istig in stigs.findall("iSTIG"):
                for vuln in istig.findall("VULN"):
                    vid = XmlUtils.get_vid(vuln) or ""
                    
                    if vid in vids:
                        status_node = vuln.find("STATUS")
                        if status_node is None:
                            status_node = ET.SubElement(vuln, "STATUS")
                        status_node.text = Status.NOT_APPLICABLE

                        comment_node = vuln.find("COMMENTS")
                        if comment_node is None:
                            comment_node = ET.SubElement(vuln, "COMMENTS")

                        if comment_node.text and comment_node.text.strip():
                            comment_node.text = f"{waiver_block}\n\n{comment_node.text.strip()}"
                        else:
                            comment_node.text = waiver_block

                        count += 1

        XmlUtils.indent_xml(root)
        self._export_xml_to_file(root, out_path)

        LOG.i(f"Applied waivers to {count} vulnerabilities")
        return {
            "ok": True,
            "updates": count,
            "output": str(out_path)
        }

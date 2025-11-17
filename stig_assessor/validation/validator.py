"""
STIG Viewer compatibility validator.

Validates CKL files for STIG Viewer 2.18 compatibility.
"""

from __future__ import annotations
from typing import List, Tuple, Union
from pathlib import Path
from collections import defaultdict

from stig_assessor.xml.schema import Sch
from stig_assessor.xml.sanitizer import San
from stig_assessor.io.file_ops import FO
from stig_assessor.core.constants import Status, Severity


class Val:
    """Checklist validator for STIG Viewer compatibility."""

    def validate(self, path: Union[str, Path]) -> Tuple[bool, List[str], List[str], List[str]]:
        """
        Validate a CKL file for STIG Viewer 2.18 compatibility.

        Args:
            path: Path to CKL file

        Returns:
            Tuple of (is_valid, errors, warnings, info)
        """
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        try:
            path = San.path(path, exist=True, file=True)
        except Exception as exc:
            return False, [str(exc)], [], []

        try:
            tree = FO.parse_xml(path)
            root = tree.getroot()
        except Exception as exc:
            return False, [f"Unable to parse XML: {exc}"], [], []

        if root.tag != Sch.ROOT:
            errors.append(f"Root element must be '{Sch.ROOT}', found '{root.tag}'")

        asset = root.find("ASSET")
        if asset is None:
            errors.append("Missing ASSET element")
        else:
            self._validate_asset(asset, errors, warnings_)

        stigs = root.find("STIGS")
        if stigs is None:
            errors.append("Missing STIGS element")
        else:
            e, w, i = self._validate_stigs(stigs)
            errors.extend(e)
            warnings_.extend(w)
            info.extend(i)

        return len(errors) == 0, errors, warnings_, info

    def _validate_asset(self, asset, errors: List[str], warnings_: List[str]) -> None:
        """Validate ASSET element."""
        values = {child.tag: (child.text or "") for child in asset}
        required = ["ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "TARGET_KEY", "WEB_OR_DATABASE"]
        for field in required:
            if field not in values:
                errors.append(f"Missing ASSET field: {field}")

        marking = values.get("MARKING", "")
        if marking and marking not in Sch.MARKS:
            warnings_.append(f"Non-standard MARKING: {marking}")

        web = values.get("WEB_OR_DATABASE", "")
        if web and web not in ("true", "false"):
            errors.append("WEB_OR_DATABASE must be 'true' or 'false'")

    def _validate_stigs(self, stigs) -> Tuple[List[str], List[str], List[str]]:
        """Validate STIGS element and all vulnerabilities."""
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        istigs = stigs.findall("iSTIG")
        if not istigs:
            errors.append("No iSTIG elements present")
            return errors, warnings_, info

        total_vulns = 0
        status_counts = defaultdict(int)

        for idx, istig in enumerate(istigs, 1):
            stig_info = istig.find("STIG_INFO")
            if stig_info is None:
                errors.append(f"iSTIG #{idx}: Missing STIG_INFO")
                continue

            vulns = istig.findall("VULN")
            total_vulns += len(vulns)

            for vuln_idx, vuln in enumerate(vulns, 1):
                # Validate required VULN elements
                vuln_num = None
                stig_data_elem = vuln.findall("STIG_DATA")
                for data in stig_data_elem:
                    attr_elem = data.find("VULN_ATTRIBUTE")
                    if attr_elem is not None and attr_elem.text == "Vuln_Num":
                        val_elem = data.find("ATTRIBUTE_DATA")
                        if val_elem is not None:
                            vuln_num = val_elem.text

                # Check status value is valid
                status = vuln.find("STATUS")
                if status is not None and status.text:
                    status_val = status.text.strip()
                    status_counts[status_val] += 1

                    # Validate status is one of the allowed values
                    if not Status.is_valid(status_val):
                        errors.append(
                            f"iSTIG #{idx}, VULN {vuln_num or vuln_idx}: "
                            f"Invalid STATUS value '{status_val}'. "
                            f"Must be one of: {', '.join(Status.all_values())}"
                        )

                # Warn if severity is not set
                severity_found = False
                for data in stig_data_elem:
                    attr_elem = data.find("VULN_ATTRIBUTE")
                    if attr_elem is not None and attr_elem.text == "Severity":
                        val_elem = data.find("ATTRIBUTE_DATA")
                        if val_elem is not None and val_elem.text:
                            severity_val = val_elem.text.strip()
                            severity_found = True
                            if not Severity.is_valid(severity_val):
                                warnings_.append(
                                    f"iSTIG #{idx}, VULN {vuln_num or vuln_idx}: "
                                    f"Invalid Severity '{severity_val}'. "
                                    f"Should be one of: {', '.join(Severity.all_values())}"
                                )

                if not severity_found:
                    warnings_.append(f"iSTIG #{idx}, VULN {vuln_num or vuln_idx}: Missing Severity")

        info.append(f"Total vulnerabilities: {total_vulns}")
        if total_vulns:
            reviewed = sum(
                status_counts[s]
                for s in status_counts
                if s not in ("Not_Reviewed", "")
            )
            pct = reviewed * 100 / total_vulns
            info.append(f"Reviewed: {reviewed}/{total_vulns} ({pct:.1f}%)")
            for status, count in sorted(status_counts.items()):
                info.append(f"  {status or '[empty]'}: {count}")

        return errors, warnings_, info

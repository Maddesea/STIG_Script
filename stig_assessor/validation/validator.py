"""STIG Viewer 2.18 compatibility validator.

Provides comprehensive validation of CKL files against STIG Viewer schema,
checking required elements, valid status/severity values, and proper formatting.

Team 5 Deliverable - Complete implementation of the Val class.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Import from our package
from stig_assessor.exceptions import ValidationError
from stig_assessor.core.constants import Status, Severity
from stig_assessor.xml.schema import Sch
from stig_assessor.xml.sanitizer import San
from stig_assessor.io.file_ops import FO


class Val:
    """
    STIG Viewer 2.18 compatibility validator for CKL files.

    Validates checklist structure and content against STIG Viewer schema,
    checking for required elements, valid status values, and proper formatting.

    Thread-safe: Yes (stateless validation methods)

    Example:
        >>> validator = Val()
        >>> is_valid, errors, warnings, info = validator.validate("checklist.ckl")
        >>> if not is_valid:
        ...     for error in errors:
        ...         print(f"ERROR: {error}")
    """

    # Required ASSET fields per STIG Viewer 2.18 schema
    REQUIRED_ASSET_FIELDS = frozenset([
        "ROLE",
        "ASSET_TYPE",
        "MARKING",
        "HOST_NAME",
        "TARGET_KEY",
        "WEB_OR_DATABASE",
    ])

    def validate(self, path: Union[str, Path]) -> Tuple[bool, List[str], List[str], List[str]]:
        """
        Validate a CKL file for STIG Viewer 2.18 compatibility.

        Performs comprehensive validation including:
        - XML structure and parsing
        - Required elements (ASSET, STIGS, iSTIG, VULN)
        - Status value validation
        - Severity value validation
        - Asset field validation

        Args:
            path: Path to CKL file to validate

        Returns:
            Tuple of (is_valid, errors, warnings, info):
            - is_valid: True if no critical errors found
            - errors: List of critical issues preventing use
            - warnings: List of non-critical issues
            - info: Summary statistics
        """
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        # Validate path exists and is a file
        try:
            path = San.path(path, exist=True, file=True)
        except (ValidationError, FileNotFoundError, ValueError) as exc:
            return False, [str(exc)], [], []

        # Parse XML
        try:
            tree = FO.parse_xml(path)
            root = tree.getroot()
        except Exception as exc:
            return False, [f"Unable to parse XML: {exc}"], [], []

        # Validate root element
        if root.tag != Sch.ROOT:
            errors.append(f"Root element must be '{Sch.ROOT}', found '{root.tag}'")

        # Validate ASSET section
        asset = root.find("ASSET")
        if asset is None:
            errors.append("Missing ASSET element")
        else:
            self._validate_asset(asset, errors, warnings_)

        # Validate STIGS section
        stigs = root.find("STIGS")
        if stigs is None:
            errors.append("Missing STIGS element")
        else:
            e, w, i = self._validate_stigs(stigs)
            errors.extend(e)
            warnings_.extend(w)
            info.extend(i)

        return len(errors) == 0, errors, warnings_, info

    def _validate_asset(
        self,
        asset,
        errors: List[str],
        warnings_: List[str]
    ) -> None:
        """
        Validate ASSET element for required fields and valid values.

        Checks for:
        - Required fields present (ROLE, ASSET_TYPE, MARKING, HOST_NAME, etc.)
        - MARKING value is a recognized security classification
        - WEB_OR_DATABASE has valid boolean value

        Args:
            asset: XML Element for ASSET section
            errors: List to append critical errors
            warnings_: List to append non-critical warnings
        """
        values: Dict[str, str] = {
            child.tag: (child.text or "") for child in asset
        }

        # Check required fields
        for field in self.REQUIRED_ASSET_FIELDS:
            if field not in values:
                errors.append(f"Missing ASSET field: {field}")

        # Validate MARKING
        marking = values.get("MARKING", "")
        if marking and marking not in Sch.MARKS:
            warnings_.append(f"Non-standard MARKING: {marking}")

        # Validate WEB_OR_DATABASE
        web = values.get("WEB_OR_DATABASE", "")
        if web and web not in ("true", "false"):
            errors.append("WEB_OR_DATABASE must be 'true' or 'false'")

        # Validate ROLE if present
        role = values.get("ROLE", "")
        valid_roles = {"None", "Workstation", "Member Server", "Domain Controller"}
        if role and role not in valid_roles:
            warnings_.append(f"Non-standard ROLE: {role}")

        # Validate ASSET_TYPE if present
        asset_type = values.get("ASSET_TYPE", "")
        valid_types = {"Computing", "Non-Computing"}
        if asset_type and asset_type not in valid_types:
            warnings_.append(f"Non-standard ASSET_TYPE: {asset_type}")

    def _validate_stigs(
        self,
        stigs
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Validate STIGS element and all contained vulnerabilities.

        Checks each iSTIG and VULN element for proper structure,
        valid status/severity values, and collects statistics.

        Args:
            stigs: XML Element for STIGS section

        Returns:
            Tuple of (errors, warnings, info) lists
        """
        errors: List[str] = []
        warnings_: List[str] = []
        info: List[str] = []

        istigs = stigs.findall("iSTIG")
        if not istigs:
            errors.append("No iSTIG elements present")
            return errors, warnings_, info

        total_vulns = 0
        status_counts: Dict[str, int] = defaultdict(int)

        for idx, istig in enumerate(istigs, 1):
            # Check for required STIG_INFO
            stig_info = istig.find("STIG_INFO")
            if stig_info is None:
                errors.append(f"iSTIG #{idx}: Missing STIG_INFO")
                continue

            vulns = istig.findall("VULN")
            total_vulns += len(vulns)

            for vuln_idx, vuln in enumerate(vulns, 1):
                self._validate_vuln(
                    vuln, idx, vuln_idx, errors, warnings_, status_counts
                )

        # Generate info statistics
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

    def _validate_vuln(
        self,
        vuln,
        istig_idx: int,
        vuln_idx: int,
        errors: List[str],
        warnings_: List[str],
        status_counts: Dict[str, int]
    ) -> None:
        """
        Validate a single VULN element.

        Checks for:
        - Valid STATUS value
        - Valid Severity value
        - Presence of required STIG_DATA elements

        Args:
            vuln: XML Element for VULN
            istig_idx: Index of parent iSTIG element
            vuln_idx: Index of this VULN element
            errors: List to append critical errors
            warnings_: List to append warnings
            status_counts: Dictionary to track status distribution
        """
        # Get vulnerability number for better error messages
        vuln_num = self._get_vuln_attribute(vuln, "Vuln_Num")
        vuln_id = vuln_num or str(vuln_idx)

        # Validate STATUS
        status_elem = vuln.find("STATUS")
        if status_elem is not None and status_elem.text:
            status_val = status_elem.text.strip()
            status_counts[status_val] += 1

            if not Status.is_valid(status_val):
                errors.append(
                    f"iSTIG #{istig_idx}, VULN {vuln_id}: "
                    f"Invalid STATUS value '{status_val}'. "
                    f"Must be one of: {', '.join(sorted(Status.all_values()))}"
                )
        else:
            status_counts[""] += 1

        # Validate Severity
        severity_val = self._get_vuln_attribute(vuln, "Severity")
        if severity_val:
            if not Severity.is_valid(severity_val):
                warnings_.append(
                    f"iSTIG #{istig_idx}, VULN {vuln_id}: "
                    f"Invalid Severity '{severity_val}'. "
                    f"Should be one of: {', '.join(sorted(Severity.all_values()))}"
                )
        else:
            warnings_.append(
                f"iSTIG #{istig_idx}, VULN {vuln_id}: Missing Severity"
            )

    def _get_vuln_attribute(self, vuln, attr_name: str) -> Optional[str]:
        """
        Get a VULN attribute value from STIG_DATA elements.

        Searches through STIG_DATA elements to find the specified
        VULN_ATTRIBUTE and returns its ATTRIBUTE_DATA value.

        Args:
            vuln: XML Element for VULN
            attr_name: Name of the attribute to find (e.g., "Vuln_Num", "Severity")

        Returns:
            The attribute value if found, None otherwise
        """
        for data in vuln.findall("STIG_DATA"):
            attr_elem = data.find("VULN_ATTRIBUTE")
            if attr_elem is not None and attr_elem.text == attr_name:
                val_elem = data.find("ATTRIBUTE_DATA")
                if val_elem is not None:
                    return val_elem.text
        return None

    def validate_strict(
        self,
        path: Union[str, Path]
    ) -> None:
        """
        Validate a CKL file strictly, raising an exception on any error.

        This is a convenience wrapper around validate() that raises
        ValidationError if any errors are found.

        Args:
            path: Path to CKL file to validate

        Raises:
            ValidationError: If any validation errors are found
        """
        is_valid, errors, warnings_, info = self.validate(path)
        if not is_valid:
            raise ValidationError(
                f"Validation failed with {len(errors)} error(s): {'; '.join(errors)}",
                ctx={"path": str(path), "errors": errors, "warnings": warnings_}
            )

    def validate_xml_structure(self, root) -> Tuple[bool, List[str]]:
        """
        Validate basic XML structure without file operations.

        Useful for validating in-memory XML trees without writing to disk.

        Args:
            root: XML root Element to validate

        Returns:
            Tuple of (is_valid, errors)
        """
        errors: List[str] = []

        if root.tag != Sch.ROOT:
            errors.append(f"Root element must be '{Sch.ROOT}', found '{root.tag}'")

        if root.find("ASSET") is None:
            errors.append("Missing ASSET element")

        if root.find("STIGS") is None:
            errors.append("Missing STIGS element")

        stigs = root.find("STIGS")
        if stigs is not None:
            if not stigs.findall("iSTIG"):
                errors.append("No iSTIG elements present")

        return len(errors) == 0, errors


# Create a singleton instance for convenient import
validator = Val()

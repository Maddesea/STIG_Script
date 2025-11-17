"""
STIG Viewer 2.18 compatibility validation.

Provides validation functions for CKL and XCCDF files to ensure
compatibility with STIG Viewer 2.18.
"""

from __future__ import annotations
from typing import Dict, Any, List
from xml.etree.ElementTree import ElementTree, Element

from stig_assessor.core.constants import Status, Severity, ERROR_THRESHOLD
from stig_assessor.core.logging import LOG
from stig_assessor.xml.schema import Sch
from stig_assessor.xml.utils import XmlUtils
from stig_assessor.exceptions import ValidationError


class Val:
    """
    STIG Viewer 2.18 compatibility validation.

    Provides methods to validate CKL and XCCDF file structures
    and content for compliance with STIG Viewer requirements.

    Thread-safe: Yes (stateless)
    """

    # Required VULN_ATTRIBUTE names for CKL validation
    REQUIRED_ATTRS = frozenset([
        "Vuln_Num",
        "Severity",
        "Group_Title",
        "Rule_ID",
        "Rule_Ver",
        "Rule_Title",
        "Vuln_Discuss",
        "Check_Content",
        "Fix_Text",
    ])

    @staticmethod
    def validate_ckl(tree: ElementTree, strict: bool = True) -> Dict[str, Any]:
        """
        Validate CKL file structure and content.

        Checks for:
        - Valid root element (CHECKLIST)
        - Required ASSET element
        - Required STIGS/iSTIG structure
        - Valid vulnerability elements (VULN)
        - Valid status and severity values
        - Required VULN_ATTRIBUTE fields

        Args:
            tree: CKL ElementTree to validate
            strict: If True, raise ValidationError on validation failures
                   If False, return validation report without raising

        Returns:
            Validation report dict with:
                - valid: bool - True if no errors found
                - errors: List[str] - List of error messages
                - warnings: List[str] - List of warning messages
                - vuln_count: int - Number of vulnerabilities found

        Raises:
            ValidationError: If strict=True and validation fails

        Example:
            >>> from stig_assessor.io.file_ops import FO
            >>> tree = FO.load_xml(Path("checklist.ckl"))
            >>> report = Val.validate_ckl(tree, strict=False)
            >>> print(f"Valid: {report['valid']}")
            Valid: True
        """
        errors: List[str] = []
        warnings: List[str] = []
        root = tree.getroot()

        # Check root element
        if root.tag != "CHECKLIST":
            errors.append(f"Invalid root element: {root.tag}, expected CHECKLIST")

        # Check ASSET element
        asset = root.find("ASSET")
        if asset is None:
            errors.append("Missing required ASSET element")
        else:
            # Validate ASSET has required children
            if asset.find("ROLE") is None:
                warnings.append("Missing ROLE element in ASSET")
            if asset.find("ASSET_TYPE") is None:
                warnings.append("Missing ASSET_TYPE element in ASSET")
            if asset.find("HOST_NAME") is None:
                warnings.append("Missing HOST_NAME element in ASSET")

        # Check STIGS structure
        stigs = root.find("STIGS")
        if stigs is None:
            errors.append("Missing required STIGS element")
        else:
            istig = stigs.find("iSTIG")
            if istig is None:
                errors.append("Missing required iSTIG element")
            else:
                # Check STIG_INFO
                stig_info = istig.find("STIG_INFO")
                if stig_info is None:
                    warnings.append("Missing STIG_INFO element in iSTIG")

        # Validate vulnerabilities
        vulns = root.findall(".//VULN")
        vuln_count = len(vulns)

        if vuln_count == 0:
            warnings.append("No vulnerabilities found in checklist")
        elif vuln_count > 15000:
            warnings.append(f"Large checklist: {vuln_count} vulnerabilities (may impact performance)")

        LOG.d(f"Validating {vuln_count} vulnerabilities")

        for i, vuln in enumerate(vulns):
            vuln_errors = Val._validate_vuln(vuln)
            if vuln_errors:
                # Prefix errors with VULN index for debugging
                errors.extend([f"VULN[{i}]: {e}" for e in vuln_errors])

        # Build validation report
        report = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "vuln_count": vuln_count
        }

        # If strict mode and errors found, raise exception
        if strict and errors:
            # Show first 10 errors in exception message
            error_summary = "\n".join(errors[:10])
            if len(errors) > 10:
                error_summary += f"\n... and {len(errors) - 10} more errors"
            raise ValidationError(
                f"CKL validation failed with {len(errors)} error(s):\n{error_summary}"
            )

        LOG.d(f"Validation complete: {len(errors)} errors, {len(warnings)} warnings")
        return report

    @staticmethod
    def _validate_vuln(vuln: Element) -> List[str]:
        """
        Validate single VULN element.

        Checks for:
        - Required STIG_DATA attributes
        - Valid STATUS value
        - Valid Severity value
        - Vuln_Num (VID) present

        Args:
            vuln: VULN XML element to validate

        Returns:
            List of error messages (empty if valid)
        """
        errors: List[str] = []

        # Check required STIG_DATA attributes
        found_attrs = set()
        for sdata in vuln.findall("STIG_DATA"):
            vattr = sdata.find("VULN_ATTRIBUTE")
            if vattr is not None and vattr.text:
                found_attrs.add(vattr.text)

        # Check for missing required attributes
        missing = Val.REQUIRED_ATTRS - found_attrs
        if missing:
            errors.append(f"Missing required attributes: {sorted(missing)}")

        # Check STATUS element
        status_elem = vuln.find("STATUS")
        if status_elem is None:
            errors.append("Missing STATUS element")
        elif status_elem.text:
            if not Status.is_valid(status_elem.text):
                errors.append(
                    f"Invalid status: '{status_elem.text}' "
                    f"(valid: {', '.join(Status.all_values())})"
                )
        else:
            warnings_msg = "STATUS element is empty"
            # This is technically an error, but some tools create empty STATUS
            errors.append(warnings_msg)

        # Check Severity value (from STIG_DATA)
        severity = Val._find_stig_data(vuln, "Severity")
        if severity:
            if not Severity.is_valid(severity):
                errors.append(
                    f"Invalid severity: '{severity}' "
                    f"(valid: {', '.join(Severity.all_values())})"
                )
        else:
            errors.append("Missing Severity in STIG_DATA")

        # Check Vuln_Num (VID) - critical for identifying vulnerability
        vid = XmlUtils.get_vid(vuln)
        if not vid:
            errors.append("Missing or invalid Vuln_Num (VID)")

        return errors

    @staticmethod
    def _find_stig_data(vuln: Element, attr_name: str) -> str | None:
        """
        Find STIG_DATA value by VULN_ATTRIBUTE name.

        Helper method to extract attribute values from VULN element's
        STIG_DATA children.

        Args:
            vuln: VULN element
            attr_name: VULN_ATTRIBUTE name to search for

        Returns:
            ATTRIBUTE_DATA value if found, None otherwise

        Example:
            >>> severity = Val._find_stig_data(vuln_elem, "Severity")
            >>> print(severity)
            high
        """
        for sdata in vuln.findall("STIG_DATA"):
            vattr = sdata.find("VULN_ATTRIBUTE")
            if vattr is not None and vattr.text == attr_name:
                adata = sdata.find("ATTRIBUTE_DATA")
                if adata is not None and adata.text:
                    return adata.text.strip()
        return None

    @staticmethod
    def validate_xccdf(tree: ElementTree) -> Dict[str, Any]:
        """
        Validate XCCDF benchmark file.

        Checks for:
        - Valid Benchmark root element (with namespace)
        - Presence of Group elements
        - Presence of Rule elements

        Args:
            tree: XCCDF ElementTree to validate

        Returns:
            Validation report dict with:
                - valid: bool - True if no errors found
                - errors: List[str] - List of error messages
                - warnings: List[str] - List of warning messages
                - rule_count: int - Number of rules found
                - group_count: int - Number of groups found

        Example:
            >>> tree = FO.load_xml(Path("benchmark.xml"))
            >>> report = Val.validate_xccdf(tree)
            >>> print(f"Rules found: {report['rule_count']}")
            Rules found: 245
        """
        errors: List[str] = []
        warnings: List[str] = []
        root = tree.getroot()

        # Check Benchmark root - XCCDF uses namespace
        # Root tag should be like: {http://checklists.nist.gov/xccdf/1.2}Benchmark
        if "Benchmark" not in root.tag:
            errors.append(
                f"Invalid root element: {root.tag}, expected Benchmark "
                "(with or without namespace)"
            )

        # Define namespace for XCCDF (try to extract from root or use default)
        ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}
        if root.tag.startswith("{"):
            # Extract namespace from tag
            ns_uri = root.tag[1:].split("}")[0]
            ns = {"xccdf": ns_uri}

        # Find Groups (may be namespaced)
        groups = root.findall(".//xccdf:Group", ns)
        if not groups:
            # Try without namespace
            groups = root.findall(".//Group")
        if not groups:
            warnings.append("No Group elements found in benchmark")

        # Find Rules (may be namespaced)
        rules = root.findall(".//xccdf:Rule", ns)
        if not rules:
            # Try without namespace
            rules = root.findall(".//Rule")
        if not rules:
            warnings.append("No Rule elements found in benchmark")

        rule_count = len(rules)
        group_count = len(groups)

        LOG.d(f"XCCDF validation: {group_count} groups, {rule_count} rules")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "rule_count": rule_count,
            "group_count": group_count
        }

    @staticmethod
    def check_error_threshold(total: int, errors: int) -> None:
        """
        Check if error rate exceeds acceptable threshold.

        Used during bulk processing to fail fast if too many errors occur.
        Default threshold is 25% (ERROR_THRESHOLD constant).

        Args:
            total: Total number of items processed
            errors: Number of items that failed/had errors

        Raises:
            ValidationError: If error rate exceeds ERROR_THRESHOLD

        Example:
            >>> Val.check_error_threshold(total=100, errors=30)
            ValidationError: Error rate 30.0% exceeds threshold 25.0% (30/100 failed)

            >>> Val.check_error_threshold(total=100, errors=10)
            # No exception - under threshold
        """
        if total == 0:
            LOG.d("No items to validate (total=0)")
            return

        error_rate = errors / total

        if error_rate > ERROR_THRESHOLD:
            raise ValidationError(
                f"Error rate {error_rate:.1%} exceeds threshold "
                f"{ERROR_THRESHOLD:.1%} ({errors}/{total} failed)"
            )

        LOG.d(f"Error threshold check passed: {error_rate:.1%} ({errors}/{total})")

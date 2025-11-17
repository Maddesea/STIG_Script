"""
STIG Assessor XML Schema Definitions.

Defines XML namespaces, element names, and schema constants
for STIG/CKL file processing.

This module provides:
- XML namespace constants for XCCDF and related standards
- Element name constants for CHECKLIST, ASSET, STIG_INFO, VULN sections
- Default values for mandatory fields
- Valid value sets for status and severity enumerations
- Namespace resolution and tag manipulation utilities
"""

from __future__ import annotations
from typing import Dict, FrozenSet, Tuple

from stig_assessor.core.constants import STIG_VIEWER_VERSION


class Sch:
    """
    XML schema definitions for STIG/CKL processing.

    Provides:
    - Element names and structure constants
    - Default values for required fields
    - Valid value sets for status, severity, and markings
    - Namespace handling for XCCDF processing
    - STIG Viewer 2.18 compatibility

    Thread-safe: Yes (immutable class constants)
    """

    # Root element and version comment
    ROOT = "CHECKLIST"
    COMMENT = f"DISA STIG Viewer :: {STIG_VIEWER_VERSION}"

    # XML Namespaces
    NS: Dict[str, str] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
        "cdf": "http://checklists.nist.gov/xccdf/1.1",
    }

    # Asset metadata elements (in ASSET section)
    ASSET: Tuple[str, ...] = (
        "ROLE",
        "ASSET_TYPE",
        "MARKING",
        "HOST_NAME",
        "HOST_IP",
        "HOST_MAC",
        "HOST_FQDN",
        "TARGET_COMMENT",
        "TECH_AREA",
        "TARGET_KEY",
        "WEB_OR_DATABASE",
        "WEB_DB_SITE",
        "WEB_DB_INSTANCE",
    )

    # STIG metadata elements (in STIG_INFO section)
    STIG: Tuple[str, ...] = (
        "version",
        "classification",
        "customname",
        "stigid",
        "description",
        "filename",
        "releaseinfo",
        "title",
        "uuid",
        "notice",
        "source",
    )

    # Vulnerability metadata elements (in STIG_DATA within VULN)
    VULN: Tuple[str, ...] = (
        "Vuln_Num",
        "Severity",
        "Group_Title",
        "Rule_ID",
        "Rule_Ver",
        "Rule_Title",
        "Vuln_Discuss",
        "IA_Controls",
        "Check_Content",
        "Fix_Text",
        "False_Positives",
        "False_Negatives",
        "Documentable",
        "Mitigations",
        "Potential_Impact",
        "Third_Party_Tools",
        "Mitigation_Control",
        "Responsibility",
        "Security_Override_Guidance",
        "Check_Content_Ref",
        "Weight",
        "Class",
        "STIGRef",
        "TargetKey",
        "STIG_UUID",
        "CCI_REF",
    )

    # Status tracking elements (in VULN section)
    STATUS: Tuple[str, ...] = (
        "STATUS",
        "FINDING_DETAILS",
        "COMMENTS",
        "SEVERITY_OVERRIDE",
        "SEVERITY_JUSTIFICATION",
    )

    # CKL Element names (direct access without tuple lookup)
    FINDING_DETAILS = "FINDING_DETAILS"
    COMMENTS = "COMMENTS"
    STIG_DATA = "STIG_DATA"
    VULN_ATTRIBUTE = "VULN_ATTRIBUTE"
    ATTRIBUTE_DATA = "ATTRIBUTE_DATA"
    SI_DATA = "SI_DATA"
    SID_NAME = "SID_NAME"
    SID_DATA = "SID_DATA"

    # XCCDF element names (used with namespace)
    XCCDF_BENCHMARK = "Benchmark"
    XCCDF_GROUP = "Group"
    XCCDF_RULE = "Rule"
    XCCDF_VERSION = "version"
    XCCDF_TITLE = "title"
    XCCDF_DESCRIPTION = "description"
    XCCDF_REFERENCE = "reference"
    XCCDF_FIXTEXT = "fixtext"
    XCCDF_FIX = "fix"
    XCCDF_CHECK = "check"
    XCCDF_CHECK_CONTENT = "check-content"
    XCCDF_CHECK_CONTENT_REF = "check-content-ref"
    XCCDF_IDENT = "ident"
    XCCDF_PROFILE = "Profile"
    XCCDF_SELECT = "select"

    # Valid values for status (STIG Viewer compatible)
    STAT_VALS: FrozenSet[str] = frozenset([
        "NotAFinding",
        "Open",
        "Not_Reviewed",
        "Not_Applicable"
    ])

    # Valid values for severity
    SEV_VALS: FrozenSet[str] = frozenset(["high", "medium", "low"])

    # Valid security markings
    MARKS: FrozenSet[str] = frozenset([
        "CUI",
        "UNCLASSIFIED",
        "SECRET",
        "TOP SECRET",
        "TS",
        "S",
        "U"
    ])

    # Default values for optional/mandatory elements
    DEFS: Dict[str, str] = {
        # VULN defaults
        "Check_Content_Ref": "M",
        "Weight": "10.0",
        "Class": "Unclass",
        "Documentable": "false",
        # ASSET defaults
        "MARKING": "CUI",
        "ROLE": "None",
        "ASSET_TYPE": "Computing",
        "WEB_OR_DATABASE": "false",
        # STIG_DATA optional fields (empty defaults)
        "IA_Controls": "",
        "False_Positives": "",
        "False_Negatives": "",
        "Mitigations": "",
        "Potential_Impact": "",
        "Third_Party_Tools": "",
        "Mitigation_Control": "",
        "Responsibility": "",
        "Security_Override_Guidance": "",
        "TECH_AREA": "",
        "TARGET_COMMENT": "",
        "WEB_DB_SITE": "",
        "WEB_DB_INSTANCE": "",
        # STIG_INFO defaults
        "customname": "",
        "notice": "terms-of-use",
        "source": "STIG.DOD.MIL",
        "classification": "UNCLASSIFIED",
    }

    @staticmethod
    def ns(tag: str, namespace: str = "xccdf") -> str:
        """
        Get namespaced tag for XML element.

        Converts a tag name to its fully qualified namespace form
        for use with ElementTree find/findall operations.

        Args:
            tag: Element tag name (e.g., "Benchmark", "Rule")
            namespace: Namespace prefix (default: "xccdf")

        Returns:
            Fully qualified tag name (e.g., "{http://...}Benchmark")

        Example:
            >>> Sch.ns("Benchmark")
            '{http://checklists.nist.gov/xccdf/1.2}Benchmark'
            >>> root.find(Sch.ns("Benchmark"))
        """
        if namespace in Sch.NS:
            return f"{{{Sch.NS[namespace]}}}{tag}"
        return tag

    @staticmethod
    def strip_ns(tag: str) -> str:
        """
        Remove namespace prefix from tag.

        Extracts the tag name from a fully qualified namespace tag.

        Args:
            tag: Potentially namespaced tag (e.g., "{http://...}Rule")

        Returns:
            Tag without namespace (e.g., "Rule")

        Example:
            >>> Sch.strip_ns("{http://checklists.nist.gov/xccdf/1.2}Rule")
            'Rule'
            >>> Sch.strip_ns("VULN")
            'VULN'
        """
        if '}' in tag:
            return tag.split('}', 1)[1]
        return tag

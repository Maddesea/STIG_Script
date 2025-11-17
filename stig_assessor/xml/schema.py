"""
STIG Assessor XML Schema Definitions.

Defines XML namespaces, element names, and schema constants
for STIG/CKL file processing.
"""

from __future__ import annotations
from typing import FrozenSet, Dict
"""XML schema definitions and namespace handling.

This module defines XML element names, default values, and valid value sets
for STIG Viewer CKL format and XCCDF processing.

The Sch class provides:
- Element name constants for CHECKLIST, ASSET, STIG_INFO, VULN sections
- Default values for mandatory fields
- Valid value sets for status and severity enumerations
- Marking/classification constants
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
    - STIG Viewer 2.18 compatibility

    Thread-safe: Yes (immutable class constants)
    """

    ROOT = "CHECKLIST"
    COMMENT = f"DISA STIG Viewer :: {STIG_VIEWER_VERSION}"

    # Asset-level elements
    ASSET = (
    """XML schema definitions for STIG Viewer CKL format.

    This class defines the structure and valid values for CKL (Checklist) files
    as used by STIG Viewer. All element names and values are defined here to
    ensure consistency across the application.

    Attributes:
        ROOT: Root element name for CKL files
        COMMENT: XML comment identifying STIG Viewer version
        ASSET: Asset metadata element names
        STIG: STIG metadata element names
        VULN: Vulnerability element names
        STATUS: Status tracking element names
        STAT_VALS: Valid status values (frozen set)
        SEV_VALS: Valid severity values (frozen set)
        MARKS: Valid security marking values (frozen set)
        DEFS: Default values for optional elements
    """

    # Root element and version comment
    ROOT = "CHECKLIST"
    COMMENT = f"DISA STIG Viewer :: {STIG_VIEWER_VERSION}"

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

    # STIG information elements
    STIG = (
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

    # Vulnerability (STIG_DATA) elements
    VULN = (
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
    )

    # Assessment status elements
    STATUS = (
    # Status tracking elements (in VULN section)
    STATUS: Tuple[str, ...] = (
        "STATUS",
        "FINDING_DETAILS",
        "COMMENTS",
        "SEVERITY_OVERRIDE",
        "SEVERITY_JUSTIFICATION",
    )

    # Valid values
    STAT_VALS: FrozenSet[str] = frozenset(["NotAFinding", "Open", "Not_Reviewed", "Not_Applicable"])
    SEV_VALS: FrozenSet[str] = frozenset(["high", "medium", "low"])
    MARKS: FrozenSet[str] = frozenset(["CUI", "UNCLASSIFIED", "SECRET", "TOP SECRET", "TS", "S", "U"])

    # Default values for various fields
    DEFS: Dict[str, str] = {
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

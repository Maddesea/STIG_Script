"""
STIG Assessor XML Schema Definitions.

Defines XML namespaces, element names, and schema constants
for STIG/CKL file processing.
"""

from __future__ import annotations
from typing import FrozenSet, Dict

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
        "Check_Content_Ref": "M",
        "Weight": "10.0",
        "Class": "Unclass",
        "Documentable": "false",
        "MARKING": "CUI",
        "ROLE": "None",
        "ASSET_TYPE": "Computing",
        "WEB_OR_DATABASE": "false",
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
        "customname": "",
        "notice": "terms-of-use",
        "source": "STIG.DOD.MIL",
        "classification": "UNCLASSIFIED",
    }

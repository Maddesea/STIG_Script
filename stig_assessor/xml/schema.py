"""XML schema definitions.

Defines XML namespaces, element names, and schema constants for STIG/CKL file processing.

NOTE: This is a minimal stub for Team 7 testing.
Full implementation will be provided by TEAM 2.
"""


class Sch:
    """XML schema stub."""

    # Element names
    FINDING_DETAILS = "FINDING_DETAILS"
    COMMENTS = "COMMENTS"
    STATUS = "STATUS"

    # Status values
    STAT_VALS = ["NotAFinding", "Open", "Not_Reviewed", "Not_Applicable"]

"""
Exception classes for STIG Assessor.

NOTE: This is a minimal stub for Team 7 testing.
Full implementation will be provided by TEAM 0.
"""


class STIGError(Exception):
    """Base exception for STIG operations."""
    pass


class ValidationError(STIGError):
    """Validation error."""
    pass


class FileError(STIGError):
    """File operation error."""
    pass


class ParseError(STIGError):
    """XML parsing error."""
    pass

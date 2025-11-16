"""STIG Assessor - Modular security compliance assessment tool.

A production-ready, zero-dependency, air-gap certified security compliance tool
for Department of Defense (DoD) Security Technical Implementation Guide (STIG)
assessments.

Version: 7.3.0
Build Date: 2025-11-16
STIG Viewer Compatibility: 2.18
"""

from stig_assessor.exceptions import STIGError, ValidationError, FileError, ParseError
from stig_assessor.core.constants import VERSION, BUILD_DATE, APP_NAME, STIG_VIEWER_VERSION

__version__ = VERSION
__all__ = [
    "STIGError",
    "ValidationError",
    "FileError",
    "ParseError",
    "VERSION",
    "BUILD_DATE",
    "APP_NAME",
    "STIG_VIEWER_VERSION",
]

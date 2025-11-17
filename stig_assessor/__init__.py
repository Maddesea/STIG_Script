"""STIG Assessor - Department of Defense STIG compliance assessment tool.

A production-ready, zero-dependency, air-gap certified security compliance tool
for Security Technical Implementation Guide (STIG) assessments.

Version: 8.0.0
Build Date: 2025-11-16
STIG Viewer Compatibility: 2.18
"""

from __future__ import annotations

from stig_assessor.core.constants import VERSION, BUILD_DATE, APP_NAME, STIG_VIEWER_VERSION
from stig_assessor.exceptions import STIGError, ValidationError, FileError, ParseError

__version__ = VERSION
__build_date__ = BUILD_DATE
__app_name__ = APP_NAME
__stig_viewer_version__ = STIG_VIEWER_VERSION

__all__ = [
    "VERSION",
    "BUILD_DATE",
    "APP_NAME",
    "STIG_VIEWER_VERSION",
    "STIGError",
    "ValidationError",
    "FileError",
    "ParseError",
]

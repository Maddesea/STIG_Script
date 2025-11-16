"""STIG Assessor - Department of Defense STIG compliance assessment tool.

A production-ready, zero-dependency, air-gap certified security compliance tool
for Security Technical Implementation Guide (STIG) assessments.
"""

from __future__ import annotations

from stig_assessor.core.constants import VERSION, BUILD_DATE, APP_NAME, STIG_VIEWER_VERSION

__version__ = VERSION
__build_date__ = BUILD_DATE
__app_name__ = APP_NAME

__all__ = [
    "VERSION",
    "BUILD_DATE",
    "APP_NAME",
    "STIG_VIEWER_VERSION",
]

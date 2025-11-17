"""
STIG Assessor - Modular Package

Team 12 - User Interface Modules (Phase 4)

This package contains the modularized STIG Assessor codebase.
The UI modules have been extracted to enable parallel development.

Note: This is a work-in-progress modularization. Team 12 (UI) modules are complete
and currently import dependencies from the monolithic STIG_Script.py file.
As other teams (0-11) complete their modules, the imports will be updated to use
the modular package structure.
"""

__version__ = "7.3.0"
__author__ = "STIG Assessor Development Team"

# UI components are the primary exports for now
from stig_assessor.ui import main, PresetMgr

# Try to export GUI if available
try:
    from stig_assessor.ui import GUI
    __all__ = ["main", "PresetMgr", "GUI"]
except ImportError:
    __all__ = ["main", "PresetMgr"]
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
"""STIG Assessor Complete - Modular Package.

A production-ready, zero-dependency, air-gap certified security compliance tool for
Department of Defense (DoD) Security Technical Implementation Guide (STIG) assessments.

Version: 8.0.0
Build Date: 2025-11-16
STIG Viewer Compatibility: 2.18
"""STIG Assessor - Department of Defense STIG compliance assessment tool.

A production-ready, zero-dependency, air-gap certified security compliance tool
for Security Technical Implementation Guide (STIG) assessments.
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

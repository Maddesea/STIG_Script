"""
STIG Assessor - Modularized Security Compliance Tool
"""STIG Assessor - Modular security compliance assessment tool.

A production-ready, zero-dependency, air-gap certified security compliance tool
for Department of Defense (DoD) Security Technical Implementation Guide (STIG)
assessments.

This is the modularized version of STIG Assessor, broken down into logical
components for parallel development and easier maintenance.

Package Structure:
    core/           - Core infrastructure (config, logging, state management)
    xml/            - XML processing (schema, sanitizer, utilities)
    io/             - File operations (atomic writes, encoding detection)
    validation/     - STIG Viewer compatibility validation
    history/        - History tracking and management
    templates/      - Boilerplate template system
    remediation/    - Fix extraction and remediation processing
    evidence/       - Evidence lifecycle management
    processor/      - Main XCCDF→CKL conversion engine
    ui/             - User interfaces (CLI and GUI)

Version: 7.3.0 (Modular)
"""

__version__ = "7.3.0"
__author__ = "STIG Assessor Development Team"
__license__ = "MIT"
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

"""
STIG Assessor - Modularized Security Compliance Tool

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

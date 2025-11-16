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

"""User interface modules (CLI and GUI).

This package contains the command-line interface and graphical user interface
for the STIG Assessor application.
"""

from __future__ import annotations

# Import CLI components (always available)
from stig_assessor.ui.cli import main, ensure_default_boilerplates
from stig_assessor.ui.presets import PresetMgr

__all__ = [
    "main",
    "ensure_default_boilerplates",
    "PresetMgr",
]

# Try to import GUI - it will only be available if tkinter is installed
try:
    from stig_assessor.ui.gui import GUI
    __all__.append("GUI")
except ImportError:
    # GUI not available (tkinter not installed)
    GUI = None

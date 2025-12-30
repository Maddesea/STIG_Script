"""User interface modules (CLI and GUI).

This package contains the command-line interface and graphical user interface
for the STIG Assessor application.

Public API:
    - main: CLI entry point function
    - ensure_default_boilerplates: Initialize default templates
    - PresetMgr: GUI preset management class
    - GUI: Graphical user interface (only available if tkinter is installed)
"""

from __future__ import annotations

# Import CLI components (always available)
from stig_assessor.ui.cli import main, ensure_default_boilerplates
from stig_assessor.ui.presets import PresetMgr

# Import GUI conditionally (only if tkinter is available)
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

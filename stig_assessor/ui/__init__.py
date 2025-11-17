"""User interface modules."""

from __future__ import annotations

# Placeholder for Team 12 deliverables
# Will contain cli.py, gui.py, and presets.py modules
"""User interface modules (CLI and GUI)."""

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
"""User interface module.

Provides CLI and GUI interfaces.
"""

# Exports will be added when UI modules are created
"""User interface modules.

This package contains CLI and GUI interfaces.
"""
"""User interface modules (CLI and GUI)."""

from __future__ import annotations

__all__ = []

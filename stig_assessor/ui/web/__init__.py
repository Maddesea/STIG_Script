"""Web interface module for STIG Assessor.

Provides a native, zero-dependency REST API and Web GUI.
"""

from stig_assessor.ui.web.server import start_server

__all__ = ["start_server"]

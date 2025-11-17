"""Configuration management.

Application configuration and directory management stub for testing.

NOTE: This is a minimal stub for Team 7 testing.
Full implementation will be provided by TEAM 1.
"""

from pathlib import Path
import tempfile


class Cfg:
    """Configuration singleton stub."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        # Use temp directory for testing
        self.base_dir = Path(tempfile.gettempdir()) / ".stig_assessor_test"
        self.template_dir = self.base_dir / "templates"
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self._initialized = True


# Module-level singleton
CFG = Cfg()

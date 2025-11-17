"""Preset management for CLI/GUI configurations."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from contextlib import suppress
import json
import re

# Temporary imports from monolithic file - will be replaced when other teams complete their modules
# This allows Team 12 to work in parallel while Teams 0-11 modularize their components
import sys
from pathlib import Path

# Add parent directory to path to import from monolithic STIG_Script.py
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from STIG_Script import (
        Cfg,          # Configuration (Team 1 - core/config.py)
        FO,           # File Operations (Team 3 - io/file_ops.py)
        LOG,          # Logging (Team 1 - core/logging.py)
        VERSION,      # Constants (Team 0 - core/constants.py)
        ValidationError,  # Exceptions (Team 0 - exceptions.py)
    )
except ImportError:
    # If running as part of the full modular package, import from proper modules
    from stig_assessor.core.config import Cfg
    from stig_assessor.io.file_ops import FO
    from stig_assessor.core.logging import LOG
    from stig_assessor.core.constants import VERSION
    from stig_assessor.exceptions import ValidationError


class PresetMgr:
    """CLI/GUI presets."""

    def __init__(self):
        self.base = Cfg.PRESET_DIR
        self.presets: Dict[str, Dict[str, Any]] = {}
        self._load_all()

    def _load_all(self) -> None:
        if not self.base.exists():
            return
        for file in self.base.glob("*.json"):
            with suppress(Exception):
                data = json.loads(FO.read(file))
                if isinstance(data, dict):
                    self.presets[file.stem] = data

    def save(self, name: str, payload: Dict[str, Any]) -> None:
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", name).strip("_")
        if not name:
            raise ValidationError("Invalid preset name")
        path = self.base / f"{name}.json"
        payload = dict(payload)
        payload["_version"] = VERSION
        payload["_saved_at"] = datetime.now(timezone.utc).isoformat()
        with FO.atomic(path) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        self.presets[name] = payload
        LOG.i(f"Preset saved: {name}")

    def load(self, name: str) -> Optional[Dict[str, Any]]:
        return self.presets.get(name)

    def list(self) -> List[str]:
        return sorted(self.presets.keys())

    def delete(self, name: str) -> bool:
        if name not in self.presets:
            return False
        path = self.base / f"{name}.json"
        with suppress(Exception):
            path.unlink()
        del self.presets[name]
        LOG.i(f"Preset deleted: {name}")
        return True

"""Preset management for CLI/GUI configurations."""

from __future__ import annotations

import json
import re
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import VERSION
from stig_assessor.core.logging import LOG
from stig_assessor.exceptions import ValidationError
from stig_assessor.io.file_ops import FO

SAFE_PRESET_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")


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
            with suppress(OSError, json.JSONDecodeError, ValueError):
                data = json.loads(FO.read(file))
                if isinstance(data, dict):
                    self.presets[file.stem] = data

    def save(self, name: str, payload: Dict[str, Any]) -> None:
        name = SAFE_PRESET_NAME_RE.sub("_", name).strip("_")
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
        with suppress(OSError):
            path.unlink()
        del self.presets[name]
        LOG.i(f"Preset deleted: {name}")
        return True

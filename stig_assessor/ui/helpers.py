"""Shared UI helper classes — tooltips, settings persistence, context menus.

All stdlib-only. No external dependencies.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
# SETTINGS PERSISTENCE
# ──────────────────────────────────────────────────────────────────────────────


class SettingsManager:
    """Persist user preferences (theme, recent dirs, etc.) to JSON."""

    _DEFAULTS: Dict[str, Any] = {
        "theme": "light",
        "recent_dirs": [],
        "recent_files": [],
        "last_browse_dir": "",
        "wizard_mode": False,
        "backup_retention": 30,
        "log_retention": 15,
        "default_marking": "CUI",
        "default_boilerplate": False,
    }
    _MAX_RECENT = 10

    def __init__(self, settings_dir: Path):
        self._path = settings_dir / "settings.json"
        self._data: Dict[str, Any] = dict(self._DEFAULTS)
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path.exists():
            with suppress(OSError, json.JSONDecodeError, ValueError):
                raw = self._path.read_text(encoding="utf-8")
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    self._data.update(loaded)

    def save(self) -> None:
        """Flush current settings to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False)

    # ── getters / setters ────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    # ── theme ────────────────────────────────────────────────────────────────

    @property
    def theme(self) -> str:
        return self._data.get("theme", "light")

    @theme.setter
    def theme(self, mode: str) -> None:
        self._data["theme"] = mode
        self.save()

    # ── recent files / dirs ──────────────────────────────────────────────────

    def add_recent_dir(self, directory: str) -> None:
        dirs = self._data.setdefault("recent_dirs", [])
        if directory in dirs:
            dirs.remove(directory)
        dirs.insert(0, directory)
        self._data["recent_dirs"] = dirs[: self._MAX_RECENT]
        self._data["last_browse_dir"] = directory
        self.save()

    def add_recent_file(self, filepath: str) -> None:
        files = self._data.setdefault("recent_files", [])
        if filepath in files:
            files.remove(filepath)
        files.insert(0, filepath)
        self._data["recent_files"] = files[: self._MAX_RECENT]
        # Also remember directory
        parent = str(Path(filepath).parent)
        self._data["last_browse_dir"] = parent
        self.save()

    @property
    def recent_files(self) -> List[str]:
        return list(self._data.get("recent_files", []))

    @property
    def last_browse_dir(self) -> str:
        d = self._data.get("last_browse_dir", "")
        if d and Path(d).is_dir():
            return d
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# TOOLTIP CLASS
# ──────────────────────────────────────────────────────────────────────────────

# Only define if tkinter is available
try:
    import tkinter as tk

    class ToolTip:
        """Hover tooltip for any tkinter widget.

        Usage::

            ToolTip(my_button, "This button does something useful")
        """

        _DELAY_MS = 400
        _WRAP_PX = 320

        def __init__(self, widget: tk.Widget, text: str):
            self.widget = widget
            self.text = text
            self._tip_window: Optional[tk.Toplevel] = None
            self._after_id: Optional[str] = None
            widget.bind("<Enter>", self._schedule, add="+")
            widget.bind("<Leave>", self._cancel, add="+")
            widget.bind("<ButtonPress>", self._cancel, add="+")

        def _schedule(self, event=None) -> None:
            self._cancel()
            self._after_id = self.widget.after(self._DELAY_MS, self._show)

        def _cancel(self, event=None) -> None:
            if self._after_id:
                self.widget.after_cancel(self._after_id)
                self._after_id = None
            self._hide()

        def _show(self) -> None:
            if self._tip_window:
                return
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
            self._tip_window = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            tw.attributes("-topmost", True)
            label = tk.Label(
                tw,
                text=self.text,
                justify=tk.LEFT,
                wraplength=self._WRAP_PX,
                background="#2d2d30",
                foreground="#cccccc",
                relief=tk.SOLID,
                borderwidth=1,
                padx=8,
                pady=5,
                font=("Segoe UI", 9),
            )
            label.pack()

        def _hide(self) -> None:
            if self._tip_window:
                self._tip_window.destroy()
                self._tip_window = None

    # ──────────────────────────────────────────────────────────────
    # DEBOUNCER / THROTTLING
    # ──────────────────────────────────────────────────────────────

    class Debouncer:
        """Throttle/debounce rapid UI events (e.g. keypresses)."""

        def __init__(self, widget: tk.Widget, delay_ms: int, callback):
            self.widget = widget
            self.delay_ms = delay_ms
            self.callback = callback
            self._after_id = None

        def __call__(self, *args, **kwargs):
            if self._after_id:
                self.widget.after_cancel(self._after_id)
            self._after_id = self.widget.after(
                self.delay_ms, self._execute, args, kwargs
            )

        def _execute(self, args, kwargs):
            self._after_id = None
            self.callback(*args, **kwargs)

    # ──────────────────────────────────────────────────────────────
    # CONTEXT MENU BUILDER
    # ──────────────────────────────────────────────────────────────

    class ContextMenu:
        """Right-click context menu for Listbox widgets."""

        def __init__(self, widget: tk.Listbox, items: List[Dict[str, Any]]):
            """
            Args:
                widget: The Listbox to bind to.
                items:  List of dicts like ``{"label": "Remove", "command": callable}``.
                        Use ``{"separator": True}`` for dividers.
            """
            self.widget = widget
            self.menu = tk.Menu(widget, tearoff=0)
            for item in items:
                if item.get("separator"):
                    self.menu.add_separator()
                else:
                    self.menu.add_command(
                        label=item["label"],
                        command=item["command"],
                    )
            widget.bind("<Button-2>", self._show)  # macOS right-click
            widget.bind("<Button-3>", self._show)  # Windows/Linux right-click

        def _show(self, event) -> None:
            # Select the item under cursor
            index = self.widget.nearest(event.y)
            if index >= 0:
                self.widget.selection_clear(0, tk.END)
                self.widget.selection_set(index)
                self.widget.activate(index)
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    class TextContextMenu:
        """Right-click context menu for Text/ScrolledText widgets providing native clipboard actions."""

        def __init__(self, widget: tk.Text):
            self.widget = widget
            self.menu = tk.Menu(widget, tearoff=0)
            self.menu.add_command(
                label="Cut", command=lambda: widget.event_generate("<<Cut>>")
            )
            self.menu.add_command(
                label="Copy", command=lambda: widget.event_generate("<<Copy>>")
            )
            self.menu.add_command(
                label="Paste", command=lambda: widget.event_generate("<<Paste>>")
            )
            self.menu.add_separator()
            self.menu.add_command(label="Select All", command=self._select_all)
            self.menu.add_command(
                label="Clear", command=lambda: widget.delete("1.0", tk.END)
            )

            widget.bind("<Button-2>", self._show)
            widget.bind("<Button-3>", self._show)

        def _select_all(self):
            self.widget.tag_add("sel", "1.0", "end-1c")
            return "break"

        def _show(self, event) -> None:
            if self.widget.tag_ranges("sel"):
                self.menu.entryconfig("Cut", state="normal")
                self.menu.entryconfig("Copy", state="normal")
            else:
                self.menu.entryconfig("Cut", state="disabled")
                self.menu.entryconfig("Copy", state="disabled")

            # Check clipboard for Paste enablement
            try:
                if self.widget.clipboard_get():
                    self.menu.entryconfig("Paste", state="normal")
                else:
                    self.menu.entryconfig("Paste", state="disabled")
            except tk.TclError:
                self.menu.entryconfig("Paste", state="disabled")

            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    # ──────────────────────────────────────────────────────────────
    # PREMIUM VISUALS (CANVAS)
    # ──────────────────────────────────────────────────────────────

    class PremiumChart:
        """Helper for drawing modern, high-quality charts on a tk.Canvas."""

        @staticmethod
        def draw_bar(
            canvas: tk.Canvas,
            x,
            y_bottom,
            width,
            height,
            color,
            label,
            count,
            font_normal,
            font_bold,
            fg_color,
            text_color,
        ):
            """Draw a single 'premium' bar with rounded top and subtle shadow."""
            # Shadow effect
            shadow_offset = 3
            canvas.create_rectangle(
                x + shadow_offset,
                y_bottom - height + shadow_offset,
                x + width + shadow_offset,
                y_bottom + shadow_offset,
                fill="#000000",
                stipple="gray25",  # Faux transparency
                outline="",
            )

            # Main bar body
            canvas.create_rectangle(
                x, y_bottom - height, x + width, y_bottom, fill=color, outline=color
            )

            # Subtle "shine" gradient (lighter top edge)
            canvas.create_line(
                x,
                y_bottom - height,
                x + width,
                y_bottom - height,
                fill="#ffffff",
                width=1,
                dash=(2, 2),
            )

            # Bar label (the count)
            canvas.create_text(
                x + width / 2,
                y_bottom - height - 12,
                text=str(count),
                fill=fg_color,
                font=(font_bold[0], font_bold[1], "bold"),
            )

            # Category Label
            canvas.create_text(
                x + width / 2,
                y_bottom + 15,
                text=label,
                fill=text_color,
                font=font_normal,
            )

    def open_file_location(filepath: str) -> None:
        """Open the containing folder of a file in the system file manager."""
        path = Path(filepath)
        folder = str(path.parent) if path.is_file() else str(path)
        system = platform.system()
        with suppress(Exception):
            if system == "Windows":
                os.startfile(folder)  # type: ignore[attr-defined]
            elif system == "Darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])

except ImportError:
    # tkinter not available — helpers are a no-op
    pass

"""Graphical user interface (tkinter-based)."""

from __future__ import annotations

import json
import os
import platform
import queue
import re
import subprocess
import sys
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import (APP_NAME, BUILD_DATE,
                                          GUI_BUTTON_WIDTH,
                                          GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH,
                                          GUI_ENTRY_WIDTH_MEDIUM,
                                          GUI_ENTRY_WIDTH_SMALL,
                                          GUI_FONT_HEADING, GUI_FONT_MONO,
                                          GUI_FONT_NORMAL, GUI_FONT_SMALL,
                                          GUI_LISTBOX_HEIGHT,
                                          GUI_LISTBOX_WIDTH, GUI_PADDING,
                                          GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION, GUI_TEXT_HEIGHT,
                                          GUI_TEXT_WIDTH, GUI_WRAP_LENGTH,
                                          STIG_VIEWER_VERSION, VERSION, Status)
from stig_assessor.core.deps import Deps
from stig_assessor.core.logging import LOG
from stig_assessor.evidence.manager import EvidenceMgr
from stig_assessor.exceptions import ValidationError
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.ui.gui.tabs.analytics import build_analytics_tab
from stig_assessor.ui.gui.tabs.batch import build_batch_tab
from stig_assessor.ui.gui.tabs.boilerplates import build_boilerplates_tab
from stig_assessor.ui.gui.tabs.compare import build_compare_tab
from stig_assessor.ui.gui.tabs.create import build_create_tab
from stig_assessor.ui.gui.tabs.dashboard import build_dashboard_tab
from stig_assessor.ui.gui.tabs.drift import build_drift_tab
from stig_assessor.ui.gui.tabs.editor import build_editor_tab
from stig_assessor.ui.gui.tabs.evidence import build_evidence_tab
from stig_assessor.ui.gui.tabs.extract import build_extract_tab
from stig_assessor.ui.gui.tabs.log_viewer import build_log_viewer_tab
from stig_assessor.ui.gui.tabs.merge import build_merge_tab
from stig_assessor.ui.gui.tabs.repair import build_repair_tab
from stig_assessor.ui.gui.tabs.results import build_results_tab
from stig_assessor.ui.gui.tabs.validate import build_validate_tab
from stig_assessor.ui.helpers import Debouncer
from stig_assessor.ui.presets import PresetMgr
from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.schema import Sch

# ──────────────────────────────────────────────────────────────────────────────
# GUI CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# Status icons
ICON_SUCCESS = "\u2714"  # ✔
ICON_FAILURE = "\u2718"  # ✘
ICON_WARNING = "\u26a0"  # ⚠
ICON_INFO = "\u2139"  # ℹ
ICON_PENDING = "\u23f3"  # ⏳

# Vuln-ID validation pattern (#16)
VULN_ID_PATTERN = re.compile(r"^V-\d+$")

# ── Theme color palettes (#1/#2) ─────────────────────────────────────────────
_LIGHT_COLORS: Dict[str, str] = {
    "bg": "#F8F9FC",
    "fg": "#1B1F2A",
    "accent": "#2563EB",
    "accent_hover": "#1D4ED8",
    "accent_fg": "#FFFFFF",
    "entry_bg": "#FFFFFF",
    "entry_fg": "#1B1F2A",
    "frame_bg": "#F0F2F8",
    "card_bg": "#FFFFFF",
    "select_bg": "#DBEAFE",
    "status_bg": "#E8ECF4",
    "border": "#D1D5DB",
    "muted": "#6B7280",
    "tooltip_bg": "#1F2937",
    "tooltip_fg": "#F9FAFB",
    "error": "#DC2626",
    "warn": "#D97706",
    "ok": "#059669",
    "info": "#2563EB",
    "treeview_bg": "#FFFFFF",
    "treeview_fg": "#1B1F2A",
}
_DARK_COLORS: Dict[str, str] = {
    "bg": "#0D1117",
    "fg": "#E6EDF3",
    "accent": "#58A6FF",
    "accent_hover": "#79C0FF",
    "accent_fg": "#0D1117",
    "entry_bg": "#161B22",
    "entry_fg": "#E6EDF3",
    "frame_bg": "#161B22",
    "card_bg": "#1C2333",
    "select_bg": "#1F3A5F",
    "status_bg": "#161B22",
    "border": "#30363D",
    "muted": "#8B949E",
    "tooltip_bg": "#58A6FF",
    "tooltip_fg": "#0D1117",
    "error": "#F85149",
    "warn": "#D29922",
    "ok": "#3FB950",
    "info": "#58A6FF",
    "treeview_bg": "#161B22",
    "treeview_fg": "#E6EDF3",
}

# Try to detect premium theme library
_HAS_SV_TTK = False
try:
    import sv_ttk as _sv_ttk  # type: ignore

    _HAS_SV_TTK = True
except ImportError:
    _sv_ttk = None  # type: ignore


def _settings_path() -> Path:
    """Resolve settings.json path inside ~/.stig_assessor/."""
    try:
        return Cfg.APP_DIR / "settings.json"
    except Exception:
        return Path.home() / ".stig_assessor" / "settings.json"


def _load_settings() -> Dict[str, Any]:
    p = _settings_path()
    if p.exists():
        with suppress(Exception):
            return json.loads(p.read_text("utf-8"))
    return {}


def _save_settings(data: Dict[str, Any]) -> None:
    p = _settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


# Tkinter imports - only if available
if Deps.HAS_TKINTER:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter.scrolledtext import ScrolledText

    # ToolTip is defined in stig_assessor.ui.helpers — no duplicate here.

    class GUI:
        """Graphical interface."""

        editor_ckl_var: tk.StringVar
        _editor_load: Callable[[], None]
        evid_tree: ttk.Treeview

        def __init__(self):
            self.root = tk.Tk()
            self.root.title(f"{APP_NAME} v{VERSION}")
            # Dynamic min size
            self.root.minsize(1100, 750)
            self.root.geometry("1280x800")
            if sys.platform == "win32":
                with suppress(tk.TclError):
                    self.root.iconbitmap(default="")

            self.proc = Proc()
            self.evidence = EvidenceMgr()
            self.presets = PresetMgr()
            self.queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
            self._action_buttons: List[ttk.Button] = []
            self._settings = _load_settings()
            self._inline_labels: List[Tuple[ttk.Label, Optional[str]]] = []  # (#9)
            self.notebook: Optional[ttk.Notebook] = None  # reference for shortcuts

            self._logo_img: Optional[tk.PhotoImage] = None

            self._apply_theme(self._settings.get("theme", "dark"))

            # Header frame for logo/graphics
            self._header_frame = ttk.Frame(self.root)
            self._header_frame.pack(fill="x", padx=10, pady=(10, 0))
            self._header_label = ttk.Label(self._header_frame)
            self._header_label.pack(anchor="center")

            self._load_logo()

            self._build_menus()
            self._create_status_bar()
            self._build_tabs()
            self._bind_shortcuts()
            self.root.protocol("WM_DELETE_WINDOW", self._close)
            self.root.after(200, self._process_queue)

        # ── #11 Keyboard shortcuts ───────────────────────────────────────────
        def _bind_shortcuts(self) -> None:
            """Bind keyboard shortcuts."""
            self.root.bind_all("<Control-s>", lambda e: self._save_preset())
            self.root.bind_all("<Control-o>", lambda e: self._load_preset())
            self.root.bind_all("<Control-q>", lambda e: self._close())
            self.root.bind_all("<Escape>", lambda e: self._close())
            self.root.bind_all("<Control-comma>", lambda e: self._show_settings())

            # Setup advanced Phase 2 shortcuts (Tab jumping 1-9 and Ctrl+F)
            self._setup_global_shortcuts()

            # Ctrl+Return — execute current tab action
            self.root.bind_all("<Control-Return>", lambda e: self._exec_current_tab())

            # Navigate tabs
            def cycle_tabs(event):
                if getattr(self, "notebook", None):
                    current = self.notebook.index(self.notebook.select())
                    next_idx = (current + 1) % self.notebook.index("end")
                    self._switch_tab(next_idx)
                return "break"

            def cycle_tabs_reverse(event):
                if getattr(self, "notebook", None):
                    current = self.notebook.index(self.notebook.select())
                    prev_idx = (current - 1) % self.notebook.index("end")
                    self._switch_tab(prev_idx)
                return "break"

            self.root.bind_all("<Control-Tab>", cycle_tabs)
            self.root.bind_all("<Control-Shift-Tab>", cycle_tabs_reverse)

        def _switch_tab(self, idx: int) -> None:
            if self.notebook and idx < self.notebook.index("end"):
                self.notebook.select(idx)

        def _exec_current_tab(self) -> None:
            """Run the primary action for the currently visible tab."""
            if not self.notebook:
                return
            tab_actions = [
                getattr(self, "action_create", lambda: None),
                getattr(
                    self, "action_editor", lambda: None
                ),  # Editor has no mass execution, but keeps index aligned
                getattr(self, "action_merge", lambda: None),
                getattr(self, "action_extract", lambda: None),
                getattr(self, "action_results", lambda: None),
                getattr(self, "action_evidence", lambda: None),
                getattr(self, "action_validate", lambda: None),
                getattr(self, "action_repair", lambda: None),
                getattr(self, "action_batch", lambda: None),
                getattr(self, "action_boilerplates", lambda: None),
                getattr(self, "action_compare", lambda: None),
                getattr(self, "action_analytics", lambda: None),
                getattr(self, "action_drift", lambda: None),
            ]
            idx = self.notebook.index(self.notebook.select())
            if 0 <= idx < len(tab_actions):
                tab_actions[idx]()

        # ── Graphics / Logo Integration ──────────────────────────────────────
        def _load_logo(self) -> None:
            """Load the configured logo graphic and set window icon on Windows 11."""
            path = self._settings.get("logo_path", "")
            if not path or not Path(path).exists():
                self._header_label.config(image="")
                if hasattr(self, "_logo_img") and self._logo_img is not None:
                    self._logo_img = None
                return

            try:
                # tk.PhotoImage natively supports PNG (Tk 8.6+). Wraps in try..except for 100% reliability.
                self._logo_img = tk.PhotoImage(file=path)
                self._header_label.config(image=self._logo_img)

                # Apply as window taskbar icon on Windows (works natively for PNGs)
                if sys.platform == "win32" and self._logo_img:
                    with suppress(tk.TclError):
                        self.root.iconphoto(False, self._logo_img)
            except Exception as e:
                LOG.e(f"Failed to load graphic/logo from {path}: {e}")
                self._header_label.config(image="")
                self._logo_img = None

        # ── #1/#2 Theming engine ─────────────────────────────────────────────
        def _apply_theme(self, mode: str = "dark") -> None:
            """Apply light or dark theme. Uses sv_ttk if available, else custom clam."""
            self._current_theme = mode
            colors = _DARK_COLORS if mode == "dark" else _LIGHT_COLORS
            self._colors = colors

            if _HAS_SV_TTK:
                _sv_ttk.set_theme(mode)
            else:
                style = ttk.Style()
                with suppress(tk.TclError):
                    style.theme_use("clam")

                # ── Base styles ──
                style.configure(
                    ".",
                    background=colors["bg"],
                    foreground=colors["fg"],
                    fieldbackground=colors["entry_bg"],
                    borderwidth=0,
                    focuscolor=colors["accent"],
                )
                style.configure("TFrame", background=colors["bg"])
                style.configure(
                    "TLabelframe",
                    background=colors["bg"],
                    borderwidth=1,
                    relief="flat",
                )
                style.configure(
                    "TLabelframe.Label",
                    background=colors["bg"],
                    foreground=colors["accent"],
                    font=GUI_FONT_HEADING,
                )
                style.configure(
                    "TLabel",
                    background=colors["bg"],
                    foreground=colors["fg"],
                    font=GUI_FONT_NORMAL,
                )

                # ── Card frame (elevated surface) ──
                style.configure(
                    "Card.TFrame",
                    background=colors["card_bg"],
                    relief="flat",
                    borderwidth=0,
                )
                style.configure(
                    "Card.TLabel",
                    background=colors["card_bg"],
                    foreground=colors["fg"],
                    font=GUI_FONT_NORMAL,
                )

                # ── Muted label ──
                style.configure(
                    "Muted.TLabel",
                    background=colors["bg"],
                    foreground=colors["muted"],
                    font=GUI_FONT_SMALL,
                )

                # ── Separator ──
                style.configure(
                    "TSeparator",
                    background=colors.get("border", "#30363D"),
                )

                # ── Notebook (tab bar) ──
                style.configure(
                    "TNotebook",
                    background=colors["bg"],
                    borderwidth=0,
                    tabmargins=[0, 0, 0, 0],
                )
                style.configure(
                    "TNotebook.Tab",
                    padding=[12, 6],
                    font=GUI_FONT_NORMAL,
                    borderwidth=0,
                )
                style.map(
                    "TNotebook.Tab",
                    background=[
                        ("selected", colors["accent"]),
                        ("!selected", colors["frame_bg"]),
                    ],
                    foreground=[
                        ("selected", colors["accent_fg"]),
                        ("!selected", colors.get("muted", colors["fg"])),
                    ],
                )

                # ── Entry / Combobox ──
                style.configure(
                    "TEntry",
                    fieldbackground=colors["entry_bg"],
                    foreground=colors["entry_fg"],
                    padding=[6, 4],
                    borderwidth=1,
                    insertcolor=colors["fg"],
                )
                style.configure(
                    "TCombobox",
                    fieldbackground=colors["entry_bg"],
                    foreground=colors["entry_fg"],
                    padding=[6, 4],
                )

                # ── Buttons ──
                style.configure(
                    "TButton",
                    padding=[10, 5],
                    font=GUI_FONT_NORMAL,
                    borderwidth=1,
                )
                style.map(
                    "TButton",
                    background=[
                        ("active", colors["select_bg"]),
                        ("!disabled", colors["frame_bg"]),
                    ],
                    foreground=[("!disabled", colors["fg"])],
                )

                # ── Treeview ──
                style.configure(
                    "Treeview",
                    background=colors["treeview_bg"],
                    foreground=colors["treeview_fg"],
                    fieldbackground=colors["treeview_bg"],
                    rowheight=26,
                    font=GUI_FONT_NORMAL,
                    borderwidth=0,
                )
                style.configure(
                    "Treeview.Heading",
                    font=(GUI_FONT_NORMAL[0], GUI_FONT_NORMAL[1], "bold"),
                    padding=[6, 5],
                    background=colors["frame_bg"],
                    foreground=colors["fg"],
                )
                style.map(
                    "Treeview",
                    background=[("selected", colors["select_bg"])],
                    foreground=[("selected", colors["fg"])],
                )

                # ── LabelFrame ──
                style.configure(
                    "TLabelframe",
                    background=colors["bg"],
                    borderwidth=1,
                    relief="groove",
                )
                style.configure(
                    "TLabelframe.Label",
                    background=colors["bg"],
                    foreground=colors["accent"],
                    font=(GUI_FONT_NORMAL[0], GUI_FONT_NORMAL[1], "bold"),
                )

                # ── Separator ──
                style.configure(
                    "TSeparator",
                    background=colors["border"],
                )

                # ── Progressbar ──
                style.configure(
                    "TProgressbar",
                    background=colors["accent"],
                    troughcolor=colors["frame_bg"],
                    thickness=6,
                )

                # ── Scrollbar ──
                style.configure(
                    "TScrollbar",
                    background=colors["frame_bg"],
                    troughcolor=colors["bg"],
                    borderwidth=0,
                )

                # ── Checkbutton / Radiobutton ──
                style.configure(
                    "TCheckbutton",
                    background=colors["bg"],
                    foreground=colors["fg"],
                )
                style.configure(
                    "TRadiobutton",
                    background=colors["bg"],
                    foreground=colors["fg"],
                )

            # Accent button style (#3)
            style = ttk.Style()
            style.configure(
                "Accent.TButton",
                font=GUI_FONT_HEADING,
                padding=[18, 10],
                borderwidth=0,
            )
            with suppress(tk.TclError):
                style.map(
                    "Accent.TButton",
                    background=[
                        ("active", colors["accent_hover"]),
                        ("!disabled", colors["accent"]),
                    ],
                    foreground=[("!disabled", colors["accent_fg"])],
                )

            # Text.TButton — borderless link-style button
            style.configure(
                "Text.TButton",
                font=GUI_FONT_SMALL,
                padding=[4, 2],
                borderwidth=0,
                relief="flat",
            )
            with suppress(tk.TclError):
                style.map(
                    "Text.TButton",
                    foreground=[("!disabled", colors["accent"])],
                )

            # Apply bg to root
            with suppress(tk.TclError):
                self.root.configure(bg=colors["bg"])

        def _toggle_theme(self) -> None:
            """Toggle between light and dark mode."""
            new = "dark" if self._current_theme == "light" else "light"
            self._apply_theme(new)
            self._settings["theme"] = new
            _save_settings(self._settings)
            self.status_var.set(f"Theme switched to {new} mode")

        def _save_settings(self) -> None:
            """Convenience method for tab modules to persist settings."""
            _save_settings(self._settings)

        # --------------------------------------------------------------- UI setup
        def _build_menus(self) -> None:
            menu = tk.Menu(self.root)
            self.root.config(menu=menu)

            # ── File menu ──
            file_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(
                label="Save Preset…",
                command=self._save_preset,
                accelerator="Ctrl+S",
            )
            file_menu.add_command(
                label="Load Preset…",
                command=self._load_preset,
                accelerator="Ctrl+O",
            )
            file_menu.add_command(label="Delete Preset…", command=self._delete_preset)
            file_menu.add_separator()
            # #8 Recent files submenu
            self._recent_menu = tk.Menu(file_menu, tearoff=0)
            file_menu.add_cascade(label="Recent Files", menu=self._recent_menu)
            self._refresh_recent_menu()
            file_menu.add_separator()
            file_menu.add_command(
                label="Exit", command=self._close, accelerator="Ctrl+Q"
            )

            # ── View menu (#2 theme toggle, #13 wizard) ──
            view_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="View", menu=view_menu)
            view_menu.add_command(
                label="Toggle Dark/Light Mode", command=self._toggle_theme
            )
            self._wizard_var = tk.BooleanVar(
                value=self._settings.get("wizard_mode", False)
            )
            view_menu.add_checkbutton(
                label="Wizard Mode",
                variable=self._wizard_var,
                command=self._toggle_wizard,
            )

            # ── Tools menu ──
            tools_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Tools", menu=tools_menu)
            tools_menu.add_command(
                label="Export History…", command=self._export_history
            )
            tools_menu.add_command(
                label="Import History…", command=self._import_history
            )
            tools_menu.add_separator()
            tools_menu.add_command(
                label="Export Boilerplates…", command=self._export_boiler
            )
            tools_menu.add_command(
                label="Import Boilerplates…", command=self._import_boiler
            )
            tools_menu.add_separator()
            tools_menu.add_command(
                label="Export eMASS POAM…", command=self._export_poam
            )
            tools_menu.add_separator()
            tools_menu.add_command(label="Cleanup Old Files", command=self._cleanup_old)
            tools_menu.add_separator()
            tools_menu.add_command(
                label="Checklist Statistics…", command=self._show_stats
            )
            tools_menu.add_command(label="Compare Checklists…", command=self._show_diff)
            tools_menu.add_separator()
            tools_menu.add_command(
                label="Settings…",
                command=self._show_settings,
                accelerator="Ctrl+,",
            )

            # ── Help menu ──
            help_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="Quick-Start Guide", command=self._show_help)
            help_menu.add_command(
                label="Keyboard Shortcuts", command=self._show_shortcuts
            )
            help_menu.add_separator()
            help_menu.add_command(label="About", command=self._about)

        def _refresh_recent_menu(self) -> None:
            """Refresh the Recent Files cascade menu."""
            self._recent_menu.delete(0, tk.END)
            recent_files = self._settings.get("recent_files", [])
            if not recent_files:
                self._recent_menu.add_command(label="No recent files", state="disabled")
                return

            for f in recent_files:
                # Truncate long paths for display
                display_name = f
                if len(f) > 50:
                    display_name = f"...{f[-47:]}"

                # Pass variable securely
                def make_cmd(path=f):
                    return lambda: self._open_recent_file(path)

                self._recent_menu.add_command(label=display_name, command=make_cmd())

            self._recent_menu.add_separator()
            self._recent_menu.add_command(
                label="Clear Recent Files", command=self._clear_recent_files
            )

        def _add_recent_file(self, path: str) -> None:
            """Add a file to the recent history."""
            if not path or not os.path.exists(path):
                return

            recent = self._settings.get("recent_files", [])
            path = os.path.abspath(path)
            if path in recent:
                recent.remove(path)
            recent.insert(0, path)
            recent = recent[:10]  # Keep max 10
            self._settings["recent_files"] = recent
            _save_settings(self._settings)

            # Refresh if defined
            if hasattr(self, "_recent_menu"):
                self._refresh_recent_menu()

        def _clear_recent_files(self) -> None:
            self._settings["recent_files"] = []
            _save_settings(self._settings)
            self._refresh_recent_menu()

        def _open_recent_file(self, path: str) -> None:
            if not os.path.exists(path):
                messagebox.showerror("Error", f"File not found:\n{path}")
                self._settings["recent_files"] = [
                    f for f in self._settings.get("recent_files", []) if f != path
                ]
                self._refresh_recent_menu()
                return

            # If it's a checklist, we can load it into the native Editor Tab!
            if (
                path.lower().endswith(".ckl")
                and hasattr(self, "editor_ckl_var")
                and hasattr(self, "_editor_load")
            ):
                self.editor_ckl_var.set(path)
                try:
                    self._switch_tab(1)  # Editor Tab is index 1
                except Exception:
                    pass
                self._editor_load()
                return

            # Fallback to operating system shell execution for unsupported specific types
            import subprocess

            if os.name == "nt":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.call(["open", path])
            else:
                subprocess.call(["xdg-open", path])

        def _build_tabs(self) -> None:
            # #13 Wizard mode frame (hidden by default)
            self._wizard_frame = ttk.Frame(self.root)
            self._wizard_steps = [
                "① Create",
                "② Extract",
                "③ Remediate",
                "④ Merge",
                "⑤ Compare",
                "⑥ Analytics",
                "⑦ Validate",
            ]
            self._wizard_idx = 0
            if self._wizard_var.get():
                self._build_wizard_bar()

            notebook = ttk.Notebook(self.root)
            self.notebook = notebook
            notebook.pack(fill="both", expand=True, padx=GUI_PADDING, pady=GUI_PADDING)

            tabs = [
                ("🏠 Dashboard", lambda f: build_dashboard_tab(self, f)),
                ("\U0001f4cb Create CKL", lambda f: build_create_tab(self, f)),
                ("📝 Assessment Editor", lambda f: build_editor_tab(self, f)),
                ("\U0001f500 Merge Checklists", lambda f: build_merge_tab(self, f)),
                ("\U0001f527 Extract Fixes", lambda f: build_extract_tab(self, f)),
                ("\U0001f4e5 Import Results", lambda f: build_results_tab(self, f)),
                ("\U0001f4ce Evidence", lambda f: build_evidence_tab(self, f)),
                ("\u2705 Validate", lambda f: build_validate_tab(self, f)),
                ("🔧 Repair CKL", lambda f: build_repair_tab(self, f)),
                ("🏭 Batch Convert", lambda f: build_batch_tab(self, f)),
                ("📝 Boilerplates", lambda f: build_boilerplates_tab(self, f)),
                ("🔍 Compare", lambda f: build_compare_tab(self, f)),
                ("📊 Analytics", lambda f: build_analytics_tab(self, f)),
                ("📈 History/Drift", lambda f: build_drift_tab(self, f)),
                ("📋 App Logs", lambda f: build_log_viewer_tab(self, f)),
            ]

            for title, builder in tabs:
                frame = ttk.Frame(notebook, padding=GUI_PADDING_LARGE)
                notebook.add(frame, text=title)
                builder(frame)

        def _create_status_bar(self) -> None:
            """Create global status bar with progress indicator at the bottom."""
            colors = self._colors
            status_frame = ttk.Frame(self.root)
            status_frame.pack(side=tk.BOTTOM, fill=tk.X)

            # Thin separator above status bar
            ttk.Separator(status_frame, orient="horizontal").pack(
                side=tk.TOP, fill=tk.X
            )

            inner = ttk.Frame(status_frame)
            inner.pack(fill=tk.X, padx=8, pady=4)

            self.status_var = tk.StringVar()
            self.status_bar = ttk.Label(
                inner,
                textvariable=self.status_var,
                anchor=tk.W,
                font=GUI_FONT_SMALL,
                padding=(4, 2),
            )
            self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.status_var.set("Ready")

            self.progress_bar = ttk.Progressbar(
                inner, mode="indeterminate", length=100
            )
            self.progress_bar.pack(side=tk.RIGHT, padx=(8, 4))

            # Version badge
            ttk.Label(
                inner,
                text=f"v{VERSION}",
                font=GUI_FONT_SMALL,
                foreground=colors.get("muted", "#8B949E"),
            ).pack(side=tk.RIGHT, padx=(4, 0))

        def _async(
            self, func: Callable[[], Any], callback: Callable[[Any], None]
        ) -> None:
            """Run work in thread, process result via queue."""
            for btn in self._action_buttons:
                if btn.winfo_exists():
                    btn.state(["disabled"])

            self.progress_bar.start(10)

            def thread_target():
                try:
                    res = func()
                    self.queue.put(("success", callback, res))
                except Exception as e:
                    self.queue.put(("error", callback, e))
                finally:
                    self.queue.put(("done", None, None))

            threading.Thread(target=thread_target, daemon=True).start()

        def _process_queue(self) -> None:
            while not self.queue.empty():
                msg, cb, payload = self.queue.get()
                if msg == "done":
                    for btn in self._action_buttons:
                        if btn.winfo_exists():
                            btn.state(["!disabled"])
                    self.progress_bar.stop()
                    # Revert to Ready if we just finished normally without overriding
                    if self.status_var.get() == "Processing…":
                        self.status_var.set("Ready")
                elif msg in ("success", "error") and cb:
                    cb(payload)

            self.root.after(200, self._process_queue)

        # ------------------------------------------------------------ menu actions
        def _save_preset(self):
            name = simpledialog.askstring("Save Preset", "Preset name:")
            if not name:
                return
            preset = {
                "xccdf": (
                    self.create_xccdf.get() if hasattr(self, "create_xccdf") else ""
                ),
                "asset": (
                    self.create_asset.get() if hasattr(self, "create_asset") else ""
                ),
                "ip": self.create_ip.get() if hasattr(self, "create_ip") else "",
                "mac": self.create_mac.get() if hasattr(self, "create_mac") else "",
                "mark": self.create_mark.get() if hasattr(self, "create_mark") else "",
                "apply_boilerplate": (
                    self.create_bp.get() if hasattr(self, "create_bp") else False
                ),
            }
            try:
                self.presets.save(name, preset)
                messagebox.showinfo("Preset saved", f"Preset '{name}' saved.")
            except Exception as exc:
                messagebox.showerror("Preset error", str(exc))

        def _load_preset(self):
            name = self._show_preset_picker()
            if not name:
                return
            preset = self.presets.load(name)
            if not preset:
                messagebox.showerror("Preset error", f"Preset '{name}' not found.")
                return
            if hasattr(self, "create_xccdf"):
                self.create_xccdf.set(preset.get("xccdf", ""))
            if hasattr(self, "create_asset"):
                self.create_asset.set(preset.get("asset", ""))
            if hasattr(self, "create_ip"):
                self.create_ip.set(preset.get("ip", ""))
            if hasattr(self, "create_mac"):
                self.create_mac.set(preset.get("mac", ""))
            if hasattr(self, "create_mark"):
                self.create_mark.set(preset.get("mark", "CUI"))
            if hasattr(self, "create_bp"):
                self.create_bp.set(bool(preset.get("apply_boilerplate", False)))
            self.status_var.set(f"Preset '{name}' loaded")

        def _delete_preset(self):
            """Delete a saved preset visually (delegates to picker loop)."""
            self._show_preset_picker()

        def _export_history(self):
            path = filedialog.asksaveasfilename(
                title="Export history",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return

            def work():
                self.proc.history.export(path)
                return path

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo(
                        "History export", f"History exported to {result}"
                    )

            self._async(work, done)

        def _import_history(self):
            path = filedialog.askopenfilename(
                title="Import history", filetypes=[("JSON Files", "*.json")]
            )
            if not path:
                return

            def work():
                return self.proc.history.imp(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo(
                        "History import", f"Imported {result} history entries."
                    )

            self._async(work, done)

        def _export_boiler(self):
            path = filedialog.asksaveasfilename(
                title="Export boilerplates",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return
            try:
                self.proc.boiler.export(path)
                messagebox.showinfo("Boilerplates", f"Boilerplates exported to {path}")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _import_boiler(self):
            path = filedialog.askopenfilename(
                title="Import boilerplates",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return
            try:
                self.proc.boiler.imp(path)
                messagebox.showinfo("Boilerplates", "Custom boilerplates imported.")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _export_poam(self):
            ckl_path = filedialog.askopenfilename(
                title="Select CKL for POAM Export",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if not ckl_path:
                return
            out_path = filedialog.asksaveasfilename(
                title="Save eMASS POAM As",
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv")],
            )
            if not out_path:
                return
            try:
                poam_str = self.proc.export_poam(ckl_path)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(poam_str)
                messagebox.showinfo(
                    "Export Successful", f"Successfully exported POAM to:\n{out_path}"
                )
            except Exception as exc:
                messagebox.showerror("Export Error", str(exc))

        def _cleanup_old(self):
            try:
                backups, logs = Cfg.cleanup_old()
                messagebox.showinfo(
                    "Cleanup",
                    f"Removed {backups} backup(s) and {logs} log(s).",
                )
            except Exception as exc:
                messagebox.showerror("Cleanup error", str(exc))

        def _about(self):
            messagebox.showinfo(
                "About",
                f"{APP_NAME}\nVersion: {VERSION}\nBuild: {BUILD_DATE}\n"
                f"STIG Viewer: {STIG_VIEWER_VERSION}\n"
                f"Python: {platform.python_version()}\n"
                f"Platform: {platform.system()} {platform.release()}",
            )

        def _refresh_evidence_summary(self):
            if not hasattr(self, "evid_tree"):
                return
            for item in self.evid_tree.get_children():
                self.evid_tree.delete(item)
            try:
                manifest = getattr(self.evidence, "metadata", {})
                if not manifest:
                    manifest = getattr(self.evidence, "_manifest", {})

                # Check for private dictionary _meta
                if not manifest and hasattr(self.evidence, "_meta"):
                    manifest = self.evidence._meta

                for vid, items in manifest.items():
                    for ev in items:
                        # Handle new domain models
                        filename = (
                            ev.filename
                            if hasattr(ev, "filename")
                            else ev.get("orig_name", ev.get("filename", ""))
                        )
                        category = (
                            ev.category
                            if hasattr(ev, "category")
                            else ev.get("category", "")
                        )
                        timestamp = (
                            str(ev.imported)
                            if hasattr(ev, "imported")
                            else ev.get("timestamp", "")
                        )
                        self.evid_tree.insert(
                            "",
                            "end",
                            values=(
                                vid,
                                filename,
                                category,
                                timestamp,
                            ),
                        )
                # Update stats label
                if hasattr(self, "evid_stats_label"):
                    s = self.evidence.summary()
                    text = f"Storage: {s['size_mb']:.1f} MB  |  Files: {s['files']}  |  Mapped VIDs: {s['vulnerabilities']}"
                    self.evid_stats_label.config(text=text)
            except Exception:
                import traceback

                traceback.print_exc()

            summary = self.evidence.summary()
            if hasattr(self, "evid_status"):
                self.evid_status.set(
                    f"Vulnerabilities: {summary['vulnerabilities']} | Files: {summary['files']} | Size: {summary['size_mb']:.2f} MB"
                )

        def _show_stats(self):
            path = filedialog.askopenfilename(
                title="Select CKL for Stats",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if not path:
                return
            try:
                s = self.proc.generate_stats(path, output_format="text")
                win = tk.Toplevel(self.root)
                win.title(f"Statistics - {Path(path).name}")
                win.geometry("500x400")
                txt = ScrolledText(win, font=GUI_FONT_MONO)
                txt.pack(fill="both", expand=True, padx=10, pady=10)
                txt.insert(tk.END, str(s))
                txt.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", f"Could not generate stats: {e}")

        def _show_diff(self):
            path1 = filedialog.askopenfilename(
                title="Select First CKL", filetypes=[("CKL Files", "*.ckl")]
            )
            if not path1:
                return
            path2 = filedialog.askopenfilename(
                title="Select Second CKL", filetypes=[("CKL Files", "*.ckl")]
            )
            if not path2:
                return
            try:
                d = self.proc.diff(path1, path2, output_format="text")
                win = tk.Toplevel(self.root)
                win.title("Diff Analysis")
                win.geometry("700x500")
                txt = ScrolledText(win, font=GUI_FONT_MONO, wrap=tk.NONE)
                txt.pack(fill="both", expand=True, padx=10, pady=10)

                hbar = ttk.Scrollbar(win, orient="horizontal", command=txt.xview)
                hbar.pack(fill="x", side="bottom")
                txt.configure(xscrollcommand=hbar.set)

                # Format diff dict back to string safely if dict is returned
                if isinstance(d, dict):
                    output = [f"Comparison: {Path(path1).name} vs {Path(path2).name}"]
                    for k, v in d.items():
                        output.append(f"\n[{str(k).upper()}]")
                        if isinstance(v, list):
                            for ln in v:
                                output.append(str(ln))
                        else:
                            output.append(str(v))
                    txt.insert(tk.END, "\n".join(output))
                else:
                    txt.insert(tk.END, str(d))
                txt.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", f"Could not compare checklists: {e}")

        def _show_help(self):
            win = tk.Toplevel(self.root)
            win.title("Quick-Start Guide")
            win.geometry("600x500")
            txt = ScrolledText(win, font=("TkDefaultFont", 10), wrap="word")
            txt.pack(fill="both", expand=True, padx=10, pady=10)
            help_text = """STIG Assessor Quick-Start Guide

1. Create a New Checklist
   - Go to 'Create CKL' tab.
   - Select STIG XCCDF file.
   - Provide Asset Name. Output CKL will automatically populate.
   - Tip: Check 'Apply Boilerplate' to auto-fill empty finding details!

2. Merge Older Results
   - Go to 'Merge Checklists' tab.
   - Select your new 'Base Checklist' created in Step 1.
   - Add previous checklist files to 'History Files'.
   - This carries forward statuses and comments to your new file.

3. Import Automation Results
   - Go to 'Import Results' tab.
   - Add JSON output from STIG Assessor automated scripts.
   - Set the Target CKL and hit Apply.

4. Extract Remediation Scripts
   - Go to 'Extract Fixes' tab.
   - Select an XCCDF file and an Output Directory.
   - Select your desired formats (JSON, CLI, PowerShell).

Shortcuts:
  Ctrl+S: Save current configuration as a Preset
  Ctrl+O: Load a Preset
  Ctrl+1-6: Switch tabs
  Ctrl+Enter: Run the action in the current tab
"""
            txt.insert(tk.END, help_text)
            txt.configure(state="disabled")
            ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

        def _show_shortcuts(self):
            win = tk.Toplevel(self.root)
            win.title("Keyboard Shortcuts Reference")
            win.geometry("500x420")
            txt = ScrolledText(win, font=("TkDefaultFont", 10), wrap="word")
            txt.pack(fill="both", expand=True, padx=10, pady=10)
            st = """STIG Assessor Productivity Shortcuts

Global Navigation:
  Ctrl + 1..9 : Jump directly to specific tabs
  Ctrl + Tab  : Next Tab
  Ctrl + Shift + Tab : Previous Tab
  Ctrl + Enter : Execute primary action on current tab
  Ctrl + Q : Exit Application
  Esc : Close current dialog / tool

Assessment Editor:
  Up / Down : Navigate findings
  Ctrl + S : Save current finding and move to next
  Ctrl + C : Copy finding details
  Ctrl + V : Paste into comment/finding

Presets & Settings:
  Ctrl + S : Save current tab configuration as a Preset
  Ctrl + O : Load a Preset
  Ctrl + , : Open Settings
"""
            txt.insert(tk.END, st)
            txt.configure(state="disabled")
            ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

        # ────────────────────────────────────────────────────────────────
        # #9  Inline Validation Feedback
        # ────────────────────────────────────────────────────────────────
        def _show_inline_error(self, widget: tk.Widget, message: str) -> None:
            """Show an inline error message below a widget (#9)."""
            self._clear_inline_errors()
            lbl = ttk.Label(
                widget.master,
                text=message,
                foreground=self._colors.get("error", "red"),
                font=("TkDefaultFont", 8),
            )
            info = widget.grid_info()
            if info:
                lbl.grid(
                    row=int(info.get("row", 0)) + 1,
                    column=int(info.get("column", 0)),
                    columnspan=2,
                    sticky="w",
                    padx=int(info.get("padx", 0)),
                )
            else:
                lbl.pack(anchor="w")
            # Auto-clear after 8 seconds
            after_id = self.root.after(8000, self._clear_inline_errors)
            self._inline_labels.append((lbl, after_id))

        def _clear_inline_errors(self, *args) -> None:
            for lbl, after_id in self._inline_labels:
                if after_id:
                    self.root.after_cancel(after_id)
                with suppress(tk.TclError):
                    lbl.destroy()
            self._inline_labels.clear()

        # ────────────────────────────────────────────────────────────────
        # #6  Drag and Drop
        # ────────────────────────────────────────────────────────────────
        def _enable_dnd(self, widget: tk.Widget, var: tk.StringVar) -> None:
            """Enable Drag and Drop #6 and clipboard paste fallback."""

            # Fallback for clipboard paste
            def on_paste(event=None):
                try:
                    text = self.root.clipboard_get()
                    if text and Path(text.strip("'\"")).exists():
                        var.set(text.strip("'\""))
                        # Flash green
                        with suppress(Exception):
                            orig = widget.cget("background")
                            widget.configure(background="#e6ffe6")
                            self.root.after(
                                500, lambda: widget.configure(background=orig)
                            )
                except Exception:
                    # Ignore widget blink failures on window close/destroy
                    pass

            # Bind right click / button release for quick paste
            widget.bind("<ButtonRelease-3>", on_paste)
            if platform.system() == "Darwin":
                widget.bind("<ButtonRelease-2>", on_paste)

        # ────────────────────────────────────────────────────────────────
        # #8  Recent files Integration
        # ────────────────────────────────────────────────────────────────
        def _remember_file(self, filepath: str) -> None:
            """Add file to recent list and update browse dir."""
            if hasattr(self, "_add_recent_file"):
                self._add_recent_file(filepath)
            self._settings["last_browse_dir"] = str(Path(filepath).parent)
            _save_settings(self._settings)

        def _last_dir(self) -> str:
            """Return last browse directory if it exists."""
            d = self._settings.get("last_browse_dir", "")
            if d and Path(d).is_dir():
                return d
            return ""

        # ────────────────────────────────────────────────────────────────
        # #13  Wizard mode
        # ────────────────────────────────────────────────────────────────
        def _build_wizard_bar(self) -> None:
            """Build the step-indicator bar for wizard mode."""
            self._wizard_frame.pack(fill="x", padx=GUI_PADDING, pady=(GUI_PADDING, 0))
            for widget in self._wizard_frame.winfo_children():
                widget.destroy()
            ttk.Button(
                self._wizard_frame,
                text="◂ Back",
                width=8,
                command=self._wizard_back,
            ).pack(side="left", padx=2)
            for i, step in enumerate(self._wizard_steps):
                style = "Accent.TButton" if i == self._wizard_idx else "TButton"
                ttk.Button(
                    self._wizard_frame,
                    text=step,
                    style=style,
                    command=lambda idx=i: self._wizard_go(idx),
                ).pack(side="left", padx=2)
            ttk.Button(
                self._wizard_frame,
                text="Next ▸",
                width=8,
                command=self._wizard_next,
            ).pack(side="right", padx=2)

        def _toggle_wizard(self) -> None:
            if self._wizard_var.get():
                self._build_wizard_bar()
            else:
                self._wizard_frame.pack_forget()
            self._settings["wizard_mode"] = self._wizard_var.get()
            _save_settings(self._settings)

        def _wizard_go(self, idx: int) -> None:
            tab_map = {
                0: 0,  # Create
                1: 2,  # Extract
                2: 3,  # Remediate/Results
                3: 1,  # Merge
                4: 9,  # Compare
                5: 10,  # Analytics
                6: 5,  # Validate
            }
            self._wizard_idx = idx
            self._switch_tab(tab_map.get(idx, 0))
            self._build_wizard_bar()

        def _wizard_back(self) -> None:
            if self._wizard_idx > 0:
                self._wizard_go(self._wizard_idx - 1)

        def _wizard_next(self) -> None:
            if self._wizard_idx < len(self._wizard_steps) - 1:
                self._wizard_go(self._wizard_idx + 1)

        # ────────────────────────────────────────────────────────────────
        # #14  Settings pane
        # ────────────────────────────────────────────────────────────────
        def _show_settings(self) -> None:
            """Open centralized settings modal."""
            win = tk.Toplevel(self.root)
            win.title("Settings")
            win.geometry("460x380")
            win.transient(self.root)
            win.grab_set()

            nb = ttk.Notebook(win)
            nb.pack(fill="both", expand=True, padx=8, pady=8)

            # General tab
            g = ttk.Frame(nb, padding=10)
            nb.add(g, text="General")
            ttk.Label(g, text="Backup retention (count):").grid(
                row=0, column=0, sticky="w", pady=4
            )
            bk_var = tk.IntVar(value=self._settings.get("backup_retention", 30))
            ttk.Spinbox(g, from_=1, to=999, textvariable=bk_var, width=6).grid(
                row=0, column=1, padx=8
            )
            ttk.Label(g, text="Log retention (count):").grid(
                row=1, column=0, sticky="w", pady=4
            )
            lg_var = tk.IntVar(value=self._settings.get("log_retention", 15))
            ttk.Spinbox(g, from_=1, to=999, textvariable=lg_var, width=6).grid(
                row=1, column=1, padx=8
            )

            # Theme tab
            t = ttk.Frame(nb, padding=10)
            nb.add(t, text="Theme")
            theme_var = tk.StringVar(value=self._current_theme)
            ttk.Radiobutton(
                t, text="Light Mode", variable=theme_var, value="light"
            ).pack(anchor="w", pady=4)
            ttk.Radiobutton(t, text="Dark Mode", variable=theme_var, value="dark").pack(
                anchor="w", pady=4
            )

            # --- Appearance / Graphic ---
            ttk.Separator(t, orient="horizontal").pack(fill="x", pady=10)
            ttk.Label(t, text="Custom Header Graphic (PNG/GIF):").pack(
                anchor="w", pady=4
            )
            logo_frame = ttk.Frame(t)
            logo_frame.pack(fill="x")
            logo_var = tk.StringVar(value=self._settings.get("logo_path", ""))

            ent_logo = ttk.Entry(logo_frame, textvariable=logo_var, width=28)
            ent_logo.pack(side="left", padx=2)

            def browse_logo():
                path = filedialog.askopenfilename(
                    title="Select Graphic",
                    filetypes=[
                        ("Image Files", "*.png;*.gif"),
                        ("All Files", "*.*"),
                    ],
                )
                if path:
                    logo_var.set(path)

            ttk.Button(logo_frame, text="Browse…", command=browse_logo).pack(
                side="left", padx=2
            )

            def clear_logo():
                logo_var.set("")

            ttk.Button(logo_frame, text="Clear", command=clear_logo).pack(
                side="left", padx=2
            )

            # Defaults tab
            d = ttk.Frame(nb, padding=10)
            nb.add(d, text="Defaults")
            ttk.Label(d, text="Default marking:").grid(
                row=0, column=0, sticky="w", pady=4
            )
            mark_var = tk.StringVar(value=self._settings.get("default_marking", "CUI"))
            ttk.Entry(d, textvariable=mark_var, width=20).grid(row=0, column=1, padx=8)
            bp_var = tk.BooleanVar(
                value=self._settings.get("default_boilerplate", False)
            )
            ttk.Checkbutton(
                d, text="Apply boilerplate by default", variable=bp_var
            ).grid(row=1, column=0, columnspan=2, sticky="w", pady=4)

            def save_and_close():
                self._settings["backup_retention"] = bk_var.get()
                self._settings["log_retention"] = lg_var.get()
                self._settings["default_marking"] = mark_var.get()
                self._settings["default_boilerplate"] = bp_var.get()
                self._settings["logo_path"] = logo_var.get()

                self._load_logo()

                if theme_var.get() != self._current_theme:
                    self._apply_theme(theme_var.get())
                    self._settings["theme"] = theme_var.get()
                _save_settings(self._settings)
                self.status_var.set("Settings saved")
                win.destroy()

            ttk.Button(
                win,
                text="Save",
                command=save_and_close,
                style="Accent.TButton",
            ).pack(pady=8)

        # ────────────────────────────────────────────────────────────────
        # #15  Visual Preset Manager (replaces simpledialog in _load_preset)
        # ────────────────────────────────────────────────────────────────
        def _show_preset_picker(self) -> Optional[str]:
            """Show a list-based preset picker dialog. Returns selected name or None."""
            names = self.presets.list()
            if not names:
                messagebox.showinfo("No presets", "No presets available.")
                return None
            result: List[Optional[str]] = [None]

            win = tk.Toplevel(self.root)
            win.title("Select Preset")
            win.geometry("380x320")
            win.transient(self.root)
            win.grab_set()

            ttk.Label(win, text="Available Presets:", font=GUI_FONT_HEADING).pack(
                anchor="w", padx=10, pady=(10, 4)
            )
            lb = tk.Listbox(win, height=10)
            lb.pack(fill="both", expand=True, padx=10, pady=4)
            for name in names:
                preset = self.presets.load(name) or {}
                saved = preset.get("_saved_at", "")[:10]
                asset = preset.get("asset", "")
                detail = f"{name}  —  asset: {asset}  ({saved})" if asset else name
                lb.insert(tk.END, detail)

            info_var = tk.StringVar()
            ttk.Label(win, textvariable=info_var, wraplength=340).pack(padx=10, pady=2)

            def on_select(event=None):
                sel = lb.curselection()
                if sel:
                    name = names[sel[0]]
                    p = self.presets.load(name) or {}
                    info_var.set(f"XCCDF: {p.get('xccdf', 'N/A')}")

            lb.bind("<<ListboxSelect>>", on_select)

            btn_frame = ttk.Frame(win)
            btn_frame.pack(pady=8)

            def confirm():
                sel = lb.curselection()
                if sel:
                    result[0] = names[sel[0]]
                win.destroy()

            def delete_selected():
                sel = lb.curselection()
                if not sel:
                    return
                name = names[sel[0]]
                if messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
                    self.presets.delete(name)
                    lb.delete(sel[0])
                    names.pop(sel[0])

            ttk.Button(
                btn_frame, text="Load", command=confirm, style="Accent.TButton"
            ).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Delete", command=delete_selected).pack(
                side="left", padx=4
            )
            ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(
                side="left", padx=4
            )

            lb.bind("<Double-Button-1>", lambda e: confirm())
            win.wait_window()
            return result[0]

        def run(self):
            self.root.mainloop()

        def _close(self, event=None):
            if hasattr(self, "create_asset"):
                self._settings["create_asset"] = self.create_asset.get()
                self._settings["create_ip"] = self.create_ip.get()
                self._settings["create_mac"] = self.create_mac.get()
                self._settings["create_mark"] = self.create_mark.get()
                self._settings["create_bp"] = self.create_bp.get()
            _save_settings(self._settings)

            self.root.destroy()

        def _attach_listbox_context_menu(
            self,
            listbox: "tk.Listbox",
            file_list: List[str],
            remove_cb: Callable,
        ) -> None:
            """Attach a right-click context menu to a listbox."""
            menu = tk.Menu(listbox, tearoff=0)

            def move_up():
                selections = listbox.curselection()
                if not selections:
                    return
                for pos in selections:
                    if pos == 0:
                        continue
                    text = listbox.get(pos)
                    val = file_list.pop(pos)
                    listbox.delete(pos)
                    listbox.insert(pos - 1, text)
                    file_list.insert(pos - 1, val)
                    listbox.selection_set(pos - 1)

            def move_down():
                selections = listbox.curselection()
                if not selections:
                    return
                for pos in reversed(selections):
                    if pos == listbox.size() - 1:
                        continue
                    text = listbox.get(pos)
                    val = file_list.pop(pos)
                    listbox.delete(pos)
                    listbox.insert(pos + 1, text)
                    file_list.insert(pos + 1, val)
                    listbox.selection_set(pos + 1)

            def open_location():
                selections = listbox.curselection()
                if not selections:
                    return
                path = file_list[selections[0]]
                if os.name == "nt":
                    subprocess.run(["explorer", "/select,", os.path.normpath(path)])
                elif sys.platform == "darwin":
                    subprocess.run(["open", "-R", path])
                else:
                    subprocess.run(["xdg-open", os.path.dirname(path)])

            menu.add_command(label="Open file location", command=open_location)
            menu.add_separator()
            menu.add_command(label="Move up", command=move_up)
            menu.add_command(label="Move down", command=move_down)
            menu.add_separator()
            menu.add_command(label="Remove", command=remove_cb)

            def show_menu(event):
                try:
                    clicked = listbox.nearest(event.y)
                    if clicked >= 0:
                        if clicked not in listbox.curselection():
                            listbox.selection_clear(0, tk.END)
                            listbox.selection_set(clicked)
                            listbox.activate(clicked)
                    menu.tk_popup(event.x_root, event.y_root)
                except Exception:
                    # Gracefully skip popup triggering failures on invalid selections
                    pass

            listbox.bind("<Button-3>", show_menu)
            if sys.platform == "darwin":
                listbox.bind("<Button-2>", show_menu)
                listbox.bind("<Control-Button-1>", show_menu)

        def _attach_tree_context_menu(self, tree: ttk.Treeview) -> None:
            """Generic right-click context menu for TreeViews to copy cell content."""
            menu = tk.Menu(tree, tearoff=0)

            def copy_cell():
                sel = tree.selection()
                if not sel:
                    return
                # Identify which column was clicked
                # We use the stored x,y from the post event
                col = tree.identify_column(self._last_x)
                if not col:
                    return
                col_idx = int(col.replace("#", "")) - 1
                vals = tree.item(sel[0])["values"]
                if 0 <= col_idx < len(vals):
                    self.root.clipboard_clear()
                    self.root.clipboard_append(str(vals[col_idx]))

            menu.add_command(label="Copy Cell", command=copy_cell)

            def show_menu(event):
                item = tree.identify_row(event.y)
                if item:
                    tree.selection_set(item)
                    self._last_x = event.x
                    menu.tk_popup(event.x_root, event.y_root)

            tree.bind("<Button-3>", show_menu)
            if sys.platform == "darwin":
                tree.bind("<Button-2>", show_menu)
                tree.bind("<Control-Button-1>", show_menu)

        # ────────────────────────────────────────────────────────────────
        # Column sorting for TreeView widgets
        # ────────────────────────────────────────────────────────────────
        def _sort_tree(self, col: str, tree: "ttk.Treeview | None" = None, reverse: bool = False) -> None:
            """Sort a treeview by the given column header.

            Called from column-header command callbacks in tabs (e.g. Validate).
            If *tree* is None the validate_tree is used as default.
            """
            if tree is None:
                tree = getattr(self, "validate_tree", None)
            if tree is None:
                return

            data = [
                (tree.set(child, col), child) for child in tree.get_children("")
            ]
            try:
                # Attempt numeric sort first
                data.sort(key=lambda t: float(t[0]), reverse=reverse)
            except (ValueError, TypeError):
                data.sort(key=lambda t: str(t[0]).lower(), reverse=reverse)

            for idx, (_, child) in enumerate(data):
                tree.move(child, "", idx)

            # Toggle direction on next click
            tree.heading(col, command=lambda: self._sort_tree(col, tree, not reverse))

        # ────────────────────────────────────────────────────────────────
        # UI state helpers (used by batch tab, extract tab, etc.)
        # ────────────────────────────────────────────────────────────────
        def _disable_ui(self) -> None:
            """Disable all action buttons during long-running operations."""
            for btn in self._action_buttons:
                if btn.winfo_exists():
                    btn.state(["disabled"])

        def _enable_ui(self) -> None:
            """Re-enable all action buttons after an operation completes."""
            for btn in self._action_buttons:
                if btn.winfo_exists():
                    btn.state(["!disabled"])

        def _save_settings(self) -> None:
            """Instance-method wrapper so tabs can call ``app._save_settings()``."""
            _save_settings(self._settings)

        def _setup_global_shortcuts(self):
            """Setup app-wide hotkeys."""
            # Tab jumping
            for i in range(1, 10):
                self.root.bind(
                    f"<Control-Key-{i}>", lambda e, idx=i - 1: self._switch_tab(idx)
                )

            # Global Search Shortcut
            def _focus_search(e=None):
                self._switch_tab(1)  # Editor
                if hasattr(self, "_editor_search_ent"):
                    self._editor_search_ent.focus_set()
                return "break"

            self.root.bind("<Control-f>", _focus_search)
            self.root.bind("<Control-F>", _focus_search)


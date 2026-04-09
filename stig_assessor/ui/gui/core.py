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
                                          STIG_VIEWER_VERSION, VERSION, Status)
from stig_assessor.core.deps import Deps
from stig_assessor.core.logging import LOG
from stig_assessor.evidence.manager import EvidenceMgr
from stig_assessor.exceptions import ValidationError
from stig_assessor.processor.processor import Proc
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.ui.helpers import Debouncer
from stig_assessor.ui.presets import PresetMgr
from stig_assessor.xml.sanitizer import San
from stig_assessor.xml.schema import Sch

from stig_assessor.ui.gui.tabs.create import build_create_tab
from stig_assessor.ui.gui.tabs.merge import build_merge_tab
from stig_assessor.ui.gui.tabs.extract import build_extract_tab
from stig_assessor.ui.gui.tabs.results import build_results_tab
from stig_assessor.ui.gui.tabs.evidence import build_evidence_tab
from stig_assessor.ui.gui.tabs.validate import build_validate_tab
from stig_assessor.ui.gui.tabs.repair import build_repair_tab
from stig_assessor.ui.gui.tabs.batch import build_batch_tab
from stig_assessor.ui.gui.tabs.boilerplates import build_boilerplates_tab
from stig_assessor.ui.gui.tabs.compare import build_compare_tab
from stig_assessor.ui.gui.tabs.analytics import build_analytics_tab
from stig_assessor.ui.gui.tabs.drift import build_drift_tab

# ──────────────────────────────────────────────────────────────────────────────
# GUI CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# Status icons
ICON_SUCCESS = "\u2714"  # ✔
ICON_FAILURE = "\u2718"  # ✘
ICON_WARNING = "\u26a0"  # ⚠
ICON_INFO = "\u2139"  # ℹ
ICON_PENDING = "\u23f3"  # ⏳

# Widget sizing
GUI_ENTRY_WIDTH = 70
GUI_ENTRY_WIDTH_SMALL = 25
GUI_ENTRY_WIDTH_MEDIUM = 40
GUI_BUTTON_WIDTH = 15
GUI_BUTTON_WIDTH_WIDE = 25
GUI_LISTBOX_HEIGHT = 6
GUI_LISTBOX_WIDTH = 60
GUI_TEXT_WIDTH = 120
GUI_TEXT_HEIGHT = 25
GUI_WRAP_LENGTH = 860

# Layout spacing
GUI_PADDING = 5
GUI_PADDING_LARGE = 10
GUI_PADDING_SECTION = 15

# Font settings
GUI_FONT_MONO = ("Courier New", 10)
GUI_FONT_NORMAL = ("TkDefaultFont", 10)
GUI_FONT_HEADING = ("TkDefaultFont", 12, "bold")

# Vuln-ID validation pattern (#16)
VULN_ID_PATTERN = re.compile(r"^V-\d+$")

# ── Theme color palettes (#1/#2) ─────────────────────────────────────────────
_LIGHT_COLORS: Dict[str, str] = {
    "bg": "#f5f5f5",
    "fg": "#1e1e1e",
    "accent": "#0078D4",
    "accent_hover": "#106EBE",
    "accent_fg": "#ffffff",
    "entry_bg": "#ffffff",
    "entry_fg": "#1e1e1e",
    "frame_bg": "#ececec",
    "select_bg": "#cce4f7",
    "status_bg": "#e0e0e0",
    "tooltip_bg": "#2d2d30",
    "tooltip_fg": "#cccccc",
    "error": "#CC0000",
    "warn": "#CC8800",
    "ok": "#008800",
    "info": "#0055AA",
    "treeview_bg": "#ffffff",
    "treeview_fg": "#1e1e1e",
}
_DARK_COLORS: Dict[str, str] = {
    "bg": "#1e1e1e",
    "fg": "#d4d4d4",
    "accent": "#3794ff",
    "accent_hover": "#2070c0",
    "accent_fg": "#ffffff",
    "entry_bg": "#2d2d30",
    "entry_fg": "#d4d4d4",
    "frame_bg": "#252526",
    "select_bg": "#264f78",
    "status_bg": "#007acc",
    "tooltip_bg": "#3c3c3c",
    "tooltip_fg": "#e0e0e0",
    "error": "#f44747",
    "warn": "#cca700",
    "ok": "#6a9955",
    "info": "#569cd6",
    "treeview_bg": "#1e1e1e",
    "treeview_fg": "#d4d4d4",
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

    class ToolTip:
        """Lightweight tooltip for tkinter widgets (zero external dependencies)."""

        def __init__(self, widget: tk.Widget, text: str, delay: int = 600):
            self.widget = widget
            self.text = text
            self.delay = delay
            self._tip: tk.Toplevel | None = None
            self._after_id: str | None = None
            widget.bind("<Enter>", self._schedule)
            widget.bind("<Leave>", self._cancel)
            # Fetch root app via widget master chain to check theme colors
            self._app = None
            root = widget.winfo_toplevel()
            if hasattr(root, "children"):
                for child in root.winfo_children():
                    if hasattr(child, "_colors"):
                        self._app = child
                        break

        def _schedule(self, event=None):
            self._cancel()
            self._after_id = self.widget.after(self.delay, self._show)

        def _cancel(self, event=None):
            if self._after_id:
                self.widget.after_cancel(self._after_id)
                self._after_id = None
            self._hide()

        def _show(self):
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
            self._tip = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            
            # Adopt proper theme colors
            bg_color = "#FFFFDD"
            fg_color = "#333333"
            if self._app and self._app.get("_current_theme", "light") == "dark":
                bg_color = "#2d2d30"
                fg_color = "#e6edf3"
            
            label = tk.Label(
                tw,
                text=self.text,
                justify="left",
                background=bg_color,
                foreground=fg_color,
                relief="flat",
                borderwidth=1,
                highlightbackground="#58a6ff" if bg_color == "#2d2d30" else "#2563eb",
                highlightthickness=1,
                font=("TkDefaultFont", 9),
                wraplength=350,
                padx=10,
                pady=8,
            )
            label.pack()

        def _hide(self):
            if self._tip:
                self._tip.destroy()
                self._tip = None

    class GUI:
        """Graphical interface."""

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

            self._apply_theme(self._settings.get("theme", "light"))

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
            # Tab switching Ctrl+1..6
            for i in range(6):
                self.root.bind_all(
                    f"<Control-Key-{i+1}>",
                    lambda e, idx=i: self._switch_tab(idx),
                )
            # Ctrl+Return — execute current tab action
            self.root.bind_all("<Control-Return>", lambda e: self._exec_current_tab())

        def _switch_tab(self, idx: int) -> None:
            if self.notebook and idx < self.notebook.index("end"):
                self.notebook.select(idx)

        def _exec_current_tab(self) -> None:
            """Run the primary action for the currently visible tab."""
            if not self.notebook:
                return
            tab_actions = [
                self._do_create,
                self._do_merge,
                self._do_extract,
                self._do_results,
                lambda: None,
                self._do_validate,
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
        def _apply_theme(self, mode: str = "light") -> None:
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
                style.configure(
                    ".",
                    background=colors["bg"],
                    foreground=colors["fg"],
                    fieldbackground=colors["entry_bg"],
                    borderwidth=1,
                )
                style.configure("TFrame", background=colors["bg"])
                style.configure("TLabelframe", background=colors["bg"])
                style.configure(
                    "TLabelframe.Label",
                    background=colors["bg"],
                    foreground=colors["fg"],
                )
                style.configure(
                    "TLabel", background=colors["bg"], foreground=colors["fg"]
                )
                style.configure("TNotebook", background=colors["bg"])
                style.configure("TNotebook.Tab", padding=[10, 4])
                style.map(
                    "TNotebook.Tab",
                    background=[
                        ("selected", colors["accent"]),
                        ("!selected", colors["frame_bg"]),
                    ],
                    foreground=[
                        ("selected", colors["accent_fg"]),
                        ("!selected", colors["fg"]),
                    ],
                )
                style.configure(
                    "TEntry",
                    fieldbackground=colors["entry_bg"],
                    foreground=colors["entry_fg"],
                )
                style.configure(
                    "TCombobox",
                    fieldbackground=colors["entry_bg"],
                    foreground=colors["entry_fg"],
                )
                style.configure("TButton", padding=4)
                style.map(
                    "TButton",
                    background=[
                        ("active", colors["select_bg"]),
                        ("!disabled", colors["frame_bg"]),
                    ],
                    foreground=[("!disabled", colors["fg"])],
                )
                style.configure(
                    "Treeview",
                    background=colors["treeview_bg"],
                    foreground=colors["treeview_fg"],
                    fieldbackground=colors["treeview_bg"],
                )
                style.map("Treeview", background=[("selected", colors["select_bg"])])

            # Accent button style (#3)
            style = ttk.Style()
            style.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))
            with suppress(tk.TclError):
                style.map(
                    "Accent.TButton",
                    background=[
                        ("active", colors["accent_hover"]),
                        ("!disabled", colors["accent"]),
                    ],
                    foreground=[("!disabled", colors["accent_fg"])],
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
            help_menu.add_separator()
            help_menu.add_command(label="About", command=self._about)

        def _build_tabs(self) -> None:
            # #13 Wizard mode frame (hidden by default)
            self._wizard_frame = ttk.Frame(self.root)
            self._wizard_steps = [
                "① Create",
                "② Remediate",
                "③ Merge",
                "④ Validate",
            ]
            self._wizard_idx = 0
            if self._wizard_var.get():
                self._build_wizard_bar()

            notebook = ttk.Notebook(self.root)
            self.notebook = notebook
            notebook.pack(fill="both", expand=True, padx=GUI_PADDING, pady=GUI_PADDING)

            tabs = [
                ("\U0001f4cb Create CKL", lambda f: build_create_tab(self, f)),
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
            ]

            for title, builder in tabs:
                frame = ttk.Frame(notebook, padding=GUI_PADDING_LARGE)
                notebook.add(frame, text=title)
                builder(frame)

        def _create_status_bar(self) -> None:
            """Create global status bar with progress indicator at the bottom."""
            status_frame = ttk.Frame(self.root)
            status_frame.pack(side=tk.BOTTOM, fill=tk.X)

            self.progress_bar = ttk.Progressbar(
                status_frame, mode="indeterminate", length=120
            )
            self.progress_bar.pack(side=tk.RIGHT, padx=(0, 5), pady=2)

            self.status_var = tk.StringVar()
            self.status_bar = ttk.Label(
                status_frame,
                textvariable=self.status_var,
                relief=tk.SUNKEN,
                anchor=tk.W,
                padding=(5, 2),
            )
            self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.status_var.set("Ready")

        # --------------------------------------------------------------- tabs

        def _tab_merge(self, frame):
            # Input Frame
            input_frame = ttk.LabelFrame(
                frame, text="Input Checklists", padding=GUI_PADDING_LARGE
            )
            input_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            input_frame.columnconfigure(1, weight=1)

            ttk.Label(input_frame, text="Base Checklist: *").grid(
                row=0, column=0, sticky="w"
            )
            self.merge_base = tk.StringVar()
            ent_mb = ttk.Entry(
                input_frame,
                textvariable=self.merge_base,
                width=GUI_ENTRY_WIDTH,
            )
            ent_mb.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                input_frame, text="📂 Browse…", command=self._browse_merge_base
            ).grid(row=0, column=2)
            self._enable_dnd(ent_mb, self.merge_base)

            self._merge_base_err = ttk.Label(
                input_frame,
                text="",
                foreground=self._colors.get("error", "red"),
            )
            self._merge_base_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

            def _validate_merge_form(*args):
                self._merge_base_err.config(
                    text=("* Required" if not self.merge_base.get().strip() else "")
                )

            self.merge_base.trace_add("write", _validate_merge_form)
            self.root.after(100, _validate_merge_form)

            ttk.Label(input_frame, text="History Files:").grid(
                row=1, column=0, sticky="nw", pady=GUI_PADDING
            )

            list_container = ttk.Frame(input_frame)
            list_container.grid(
                row=1,
                column=1,
                padx=GUI_PADDING,
                pady=GUI_PADDING,
                sticky="ew",
            )

            self.merge_list = tk.Listbox(
                list_container,
                height=GUI_LISTBOX_HEIGHT,
                width=GUI_LISTBOX_WIDTH,
            )
            self.merge_list.pack(side="left", fill="both", expand=True)
            scrollbar = ttk.Scrollbar(
                list_container,
                orient="vertical",
                command=self.merge_list.yview,
            )
            scrollbar.pack(side="right", fill="y")
            self.merge_list.config(yscrollcommand=scrollbar.set)

            btn_frame = ttk.Frame(input_frame)
            btn_frame.grid(row=1, column=2, sticky="n", pady=GUI_PADDING)
            ttk.Button(btn_frame, text="Add…", command=self._add_merge_hist).pack(
                fill="x", pady=2
            )
            ttk.Button(btn_frame, text="Remove", command=self._remove_merge_hist).pack(
                fill="x", pady=2
            )
            ttk.Button(btn_frame, text="Clear", command=self._clear_merge_hist).pack(
                fill="x", pady=2
            )
            self.merge_histories: List[str] = []

            self._attach_listbox_context_menu(
                self.merge_list, self.merge_histories, self._remove_merge_hist
            )

            # Output Frame
            out_frame = ttk.LabelFrame(frame, text="Output", padding=GUI_PADDING_LARGE)
            out_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            ttk.Label(out_frame, text="Merged CKL:").grid(row=0, column=0, sticky="w")
            self.merge_out = tk.StringVar()
            ttk.Entry(
                out_frame, textvariable=self.merge_out, width=GUI_ENTRY_WIDTH
            ).grid(row=0, column=1, padx=GUI_PADDING)
            ttk.Button(
                out_frame, text="📂 Browse…", command=self._browse_merge_out
            ).grid(row=0, column=2)

            # Options
            options = ttk.LabelFrame(frame, text="Options", padding=GUI_PADDING_LARGE)
            options.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            self.merge_preserve = tk.BooleanVar(value=True)
            cb_preserve = ttk.Checkbutton(
                options,
                text="Preserve full history",
                variable=self.merge_preserve,
            )
            cb_preserve.pack(anchor="w")
            ToolTip(
                cb_preserve,
                "Include formatted history of previous assessments\nin the merged checklist's finding details.",
            )
            self.merge_bp = tk.BooleanVar(value=True)
            cb_merge_bp = ttk.Checkbutton(
                options,
                text="Apply boilerplates when missing",
                variable=self.merge_bp,
            )
            cb_merge_bp.pack(anchor="w")
            ToolTip(
                cb_merge_bp,
                "Fill empty finding details and comments with\ndefault boilerplate text based on the vulnerability status.",
            )

            btn_merge = ttk.Button(
                frame,
                text="🔀 Merge Checklists",
                command=self._do_merge,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn_merge.pack(pady=GUI_PADDING_SECTION)
            self._action_buttons.append(btn_merge)


        def _tab_results(self, frame):
            # Batch Import
            batch_frame = ttk.LabelFrame(
                frame,
                text="Batch Import (Multiple JSON Files)",
                padding=GUI_PADDING_LARGE,
            )
            batch_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

            ttk.Label(batch_frame, text="Results Files:").grid(
                row=0,
                column=0,
                sticky="nw",
                padx=GUI_PADDING,
                pady=GUI_PADDING,
            )

            list_container = ttk.Frame(batch_frame)
            list_container.grid(row=0, column=1, padx=GUI_PADDING, sticky="ew")

            self.results_list = tk.Listbox(
                list_container, height=5, width=65, selectmode=tk.EXTENDED
            )
            self.results_list.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(
                list_container,
                orient="vertical",
                command=self.results_list.yview,
            )
            scrollbar.pack(side="right", fill="y")
            self.results_list.config(yscrollcommand=scrollbar.set)

            self.results_files: List[str] = []

            self._attach_listbox_context_menu(
                self.results_list,
                self.results_files,
                self._remove_results_file,
            )

            btn_container = ttk.Frame(batch_frame)
            btn_container.grid(row=0, column=2, sticky="n", padx=GUI_PADDING)
            ttk.Button(
                btn_container,
                text="Add Files…",
                command=self._add_results_files,
                width=15,
            ).pack(fill="x", pady=2)
            ttk.Button(
                btn_container,
                text="Paste Files",
                command=self._paste_results_files,
                width=15,
            ).pack(fill="x", pady=2)
            ttk.Button(
                btn_container,
                text="Remove",
                command=self._remove_results_file,
                width=15,
            ).pack(fill="x", pady=2)
            ttk.Button(
                btn_container,
                text="Clear All",
                command=self._clear_results_files,
                width=15,
            ).pack(fill="x", pady=2)

            batch_frame.columnconfigure(1, weight=1)

            # Single File Import
            single_frame = ttk.LabelFrame(
                frame, text="Single File Import", padding=GUI_PADDING_LARGE
            )
            single_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            single_frame.columnconfigure(1, weight=1)

            ttk.Label(single_frame, text="Results JSON:").grid(
                row=0, column=0, sticky="w", padx=GUI_PADDING
            )
            self.results_json = tk.StringVar()
            ent_rj = ttk.Entry(
                single_frame,
                textvariable=self.results_json,
                width=GUI_ENTRY_WIDTH,
            )
            ent_rj.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                single_frame,
                text="📂 Browse…",
                command=self._browse_results_json,
            ).grid(row=0, column=2, padx=GUI_PADDING)
            self._enable_dnd(ent_rj, self.results_json)

            # Target & Output
            target_frame = ttk.LabelFrame(
                frame, text="Target & Output", padding=GUI_PADDING_LARGE
            )
            target_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            target_frame.columnconfigure(1, weight=1)

            ttk.Label(target_frame, text="Target CKL: *").grid(
                row=0, column=0, sticky="w"
            )
            self.results_ckl = tk.StringVar()
            ent_rc = ttk.Entry(
                target_frame,
                textvariable=self.results_ckl,
                width=GUI_ENTRY_WIDTH,
            )
            ent_rc.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                target_frame,
                text="📂 Browse…",
                command=self._browse_results_ckl,
            ).grid(row=0, column=2)
            self._enable_dnd(ent_rc, self.results_ckl)
            self._results_ckl_err = ttk.Label(
                target_frame,
                text="",
                foreground=self._colors.get("error", "red"),
            )
            self._results_ckl_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

            ttk.Label(target_frame, text="Output CKL: *").grid(
                row=1, column=0, sticky="w"
            )
            self.results_out = tk.StringVar()
            ent_out = ttk.Entry(
                target_frame,
                textvariable=self.results_out,
                width=GUI_ENTRY_WIDTH,
            )
            ent_out.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                target_frame,
                text="📂 Browse…",
                command=self._browse_results_out,
            ).grid(row=1, column=2)
            self._results_out_err = ttk.Label(
                target_frame,
                text="",
                foreground=self._colors.get("error", "red"),
            )
            self._results_out_err.grid(row=1, column=3, sticky="w", padx=GUI_PADDING)

            def _validate_results_form(*args):
                self._results_ckl_err.config(
                    text=("* Required" if not self.results_ckl.get().strip() else "")
                )
                self._results_out_err.config(
                    text=("* Required" if not self.results_out.get().strip() else "")
                )

            debounced_results = Debouncer(self.root, 300, _validate_results_form)
            self.results_ckl.trace_add("write", debounced_results)
            self.results_out.trace_add("write", debounced_results)
            self.root.after(100, debounced_results)

            # Options
            opts_frame = ttk.Frame(frame)
            opts_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

            mode_frame = ttk.Frame(opts_frame)
            mode_frame.pack(fill="x", pady=(0, 5))

            ttk.Label(mode_frame, text="Finding Details Action:").grid(
                row=0, column=0, sticky="w", padx=GUI_PADDING
            )
            self.results_details_mode = tk.StringVar(value="prepend")
            cb_details = ttk.Combobox(
                mode_frame,
                textvariable=self.results_details_mode,
                values=["prepend", "append", "overwrite"],
                state="readonly",
                width=12,
            )
            cb_details.grid(row=0, column=1, sticky="w", padx=GUI_PADDING)
            ToolTip(
                cb_details,
                "How to apply new finding details to existing ones.",
            )

            ttk.Label(mode_frame, text="Comments Action:").grid(
                row=0,
                column=2,
                sticky="w",
                padx=(GUI_PADDING_LARGE, GUI_PADDING),
            )
            self.results_comment_mode = tk.StringVar(value="prepend")
            cb_comment = ttk.Combobox(
                mode_frame,
                textvariable=self.results_comment_mode,
                values=["prepend", "append", "overwrite"],
                state="readonly",
                width=12,
            )
            cb_comment.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)
            ToolTip(cb_comment, "How to apply new comments to existing ones.")

            self.results_auto = tk.BooleanVar(value=True)
            cb_auto = ttk.Checkbutton(
                opts_frame,
                text="Auto-mark successful remediations as NotAFinding",
                variable=self.results_auto,
            )
            cb_auto.pack(anchor="center")
            ToolTip(
                cb_auto,
                "When a remediation result reports 'pass', automatically\nset the vulnerability status to NotAFinding.",
            )

            self.results_dry = tk.BooleanVar(value=False)
            cb_dry = ttk.Checkbutton(
                opts_frame,
                text="Dry run (preview only)",
                variable=self.results_dry,
            )
            cb_dry.pack(anchor="center")
            ToolTip(
                cb_dry,
                "Preview what would change without writing the output file.\nUseful for verifying results before committing.",
            )

            # Action
            btn_results = ttk.Button(
                frame,
                text="📥 Apply Remediation Results",
                command=self._do_results,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn_results.pack(pady=GUI_PADDING_SECTION)
            self._action_buttons.append(btn_results)

        # Add helper methods for batch file management:

        def _add_results_files(self):
            """Add multiple result files to batch queue."""
            paths = filedialog.askopenfilenames(
                title="Select Remediation Results (Ctrl+Click for multiple)",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            )
            added = 0
            for path in paths:
                if path and path not in self.results_files:
                    self.results_files.append(path)
                    self.results_list.insert(tk.END, Path(path).name)
                    added += 1

            if added:
                self.status_var.set(
                    f"✓ Added {added} file(s) - Total: {len(self.results_files)} queued"
                )

        def _paste_results_files(self):
            """Alternative to DND: Paste copied files from clipboard into the batch queue."""
            try:
                paths = self.root.clipboard_get().splitlines()
                added = 0
                for path in paths:
                    path = path.strip().strip('"').strip("'")
                    if os.path.exists(path) and path not in self.results_files:
                        self.results_files.append(path)
                        self.results_list.insert(tk.END, Path(path).name)
                        added += 1
                if added:
                    self.status_var.set(
                        f"✓ Pasted {added} file(s) - Total: {len(self.results_files)} queued"
                    )
                else:
                    self.status_var.set("No valid file paths found in clipboard")
            except tk.TclError:
                self.status_var.set("Clipboard is empty or inaccessible")

        def _remove_results_file(self):
            """Remove selected files from batch queue."""
            selections = self.results_list.curselection()
            if not selections:
                return

            for index in reversed(selections):
                self.results_list.delete(index)
                self.results_files.pop(index)

            self.status_var.set(f"{len(self.results_files)} file(s) remaining")

        def _clear_results_files(self):
            """Clear all files from batch queue with confirmation."""
            if not self.results_files:
                return
            if not messagebox.askyesno(
                "Confirm Clear",
                f"Remove all {len(self.results_files)} file(s) from the queue?",
            ):
                return
            self.results_files.clear()
            self.results_list.delete(0, tk.END)
            self.status_var.set("Queue cleared")

        def _do_results(self):
            """Apply remediation results with batch import support."""
            if not self.results_ckl.get() or not self.results_out.get():
                self._show_inline_error(
                    self._action_buttons[3],
                    "Missing input: Please provide checklist and output path.",
                )
                return

            # Collect files: batch list takes priority over single field
            files_to_process = []
            if self.results_files:
                files_to_process = list(self.results_files)
            elif self.results_json.get():
                files_to_process = [self.results_json.get()]
            else:
                self._show_inline_error(
                    self._action_buttons[3],
                    "Missing input: Please add result files or specify single JSON file.",
                )
                return

            dry = self.results_dry.get()
            auto = self.results_auto.get()
            in_ckl = self.results_ckl.get()
            out_ckl = self.results_out.get()
            details_mode = (
                self.results_details_mode.get()
                if hasattr(self, "results_details_mode")
                else "prepend"
            )
            comment_mode = (
                self.results_comment_mode.get()
                if hasattr(self, "results_comment_mode")
                else "prepend"
            )

            def work():
                """Background batch processor."""
                combined_processor = FixResPro()
                total_loaded = 0
                total_skipped = 0
                failed_files = []

                for idx, result_file in enumerate(files_to_process, 1):
                    try:
                        self.queue.put(
                            (
                                "status",
                                f"Loading {idx}/{len(files_to_process)}: {Path(result_file).name}",
                            )
                        )
                        self.queue.put(
                            ("progress", (idx / len(files_to_process)) * 100)
                        )
                        imported, skipped = combined_processor.load(result_file)
                        total_loaded += imported
                        total_skipped += skipped
                    except Exception as exc:
                        LOG.e(f"Failed to load {result_file}: {exc}")
                        failed_files.append((Path(result_file).name, str(exc)))
                        continue

                self.queue.put(("status", "Applying results to CKL..."))
                self.queue.put(("progress", 0))  # reset to indeterminate or 100

                if not combined_processor.results:
                    raise ValidationError("No valid results loaded from any file")

                result = combined_processor.update_ckl(
                    in_ckl,
                    out_ckl,
                    auto_status=auto,
                    dry=dry,
                    details_mode=details_mode,
                    comment_mode=comment_mode,
                )
                result["total_loaded"] = total_loaded
                result["total_skipped"] = total_skipped
                result["files_processed"] = len(files_to_process)
                result["failed_files"] = failed_files
                return result

            def done(result):
                """Completion handler."""
                if isinstance(result, Exception):
                    self.status_var.set(f"✘ Error: {result}")
                    messagebox.showerror("Import Failed", str(result))
                else:
                    nf = result.get("not_found", [])
                    nf_display = f"{len(nf)} VIDs" if nf else "None"

                    summary = (
                        f"✔ Batch import complete!\n"
                        f"Files: {result.get('files_processed', 0)} | "
                        f"Results loaded: {result.get('total_loaded', 0)} | "
                        f"Skipped: {result.get('total_skipped', 0)}\n"
                        f"Vulnerabilities updated: {result.get('updated', 0)} | "
                        f"Not found: {nf_display}\n"
                        f"Output: {result.get('output', 'dry run')}"
                    )

                    self.status_var.set(
                        f"Batch import complete: {result.get('updated', 0)} updated"
                    )
                    messagebox.showinfo("Success", summary)

            self.status_var.set("Processing batch import…")
            self._async(work, done)

        def _tab_evidence(self, frame):
            ttk.Label(frame, text="Evidence Manager", font=GUI_FONT_HEADING).pack(
                anchor="w"
            )

            import_frame = ttk.LabelFrame(
                frame, text="Import Evidence", padding=GUI_PADDING_LARGE
            )
            import_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
            ttk.Label(import_frame, text="Vuln ID:").grid(row=0, column=0, sticky="w")
            self.evid_vid = tk.StringVar()

            style = ttk.Style()
            style.configure("Invalid.TEntry", foreground="red")

            self.vid_entry = ttk.Entry(
                import_frame,
                textvariable=self.evid_vid,
                width=GUI_ENTRY_WIDTH_SMALL,
            )
            self.vid_entry.grid(row=0, column=1, padx=GUI_PADDING)
            ToolTip(self.vid_entry, "Enter Vulnerability ID (e.g. V-12345)")

            def _validate_vid(*args):
                import re

                val = self.evid_vid.get()
                if not val or re.match(r"^V-\d+$", val):
                    self.vid_entry.configure(style="TEntry")
                    if hasattr(self, "btn_import_evid"):
                        self.btn_import_evid.config(state="normal")
                else:
                    self.vid_entry.configure(style="Invalid.TEntry")
                    if hasattr(self, "btn_import_evid"):
                        self.btn_import_evid.config(state="disabled")

            debounced_vid = Debouncer(self.root, 300, _validate_vid)
            self.evid_vid.trace_add("write", debounced_vid)

            ttk.Label(import_frame, text="Description:").grid(
                row=0, column=2, sticky="w"
            )
            self.evid_desc = tk.StringVar()
            ttk.Entry(import_frame, textvariable=self.evid_desc, width=30).grid(
                row=0, column=3, padx=GUI_PADDING
            )
            ttk.Label(import_frame, text="Category:").grid(row=0, column=4, sticky="w")
            self.evid_cat = tk.StringVar(value="general")
            ttk.Entry(import_frame, textvariable=self.evid_cat, width=15).grid(
                row=0, column=5, padx=GUI_PADDING
            )
            self.btn_import_evid = ttk.Button(
                import_frame,
                text="Select & Import…",
                command=self._import_evidence,
            )
            self.btn_import_evid.grid(row=0, column=6, padx=GUI_PADDING)

            action_frame = ttk.LabelFrame(
                frame, text="Export / Package", padding=GUI_PADDING_LARGE
            )
            action_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
            ttk.Button(
                action_frame, text="Export All…", command=self._export_evidence
            ).grid(row=0, column=0, padx=GUI_PADDING, pady=GUI_PADDING)
            ttk.Button(
                action_frame,
                text="Create Package…",
                command=self._package_evidence,
            ).grid(row=0, column=1, padx=GUI_PADDING, pady=GUI_PADDING)

            self.evid_stats_label = ttk.Label(
                action_frame,
                text="",
                font=("", 9, "bold"),
                foreground=self._colors.get("text_muted", "gray"),
            )
            self.evid_stats_label.grid(
                row=0, column=3, padx=GUI_PADDING * 2, sticky="w"
            )
            ttk.Button(
                action_frame,
                text="Import Package…",
                command=self._import_evidence_package,
            ).grid(row=0, column=2, padx=GUI_PADDING, pady=GUI_PADDING)

            summary_frame = ttk.LabelFrame(
                frame, text="Summary", padding=GUI_PADDING_LARGE
            )
            summary_frame.pack(fill="both", expand=True, pady=GUI_PADDING_LARGE)

            cols = ("vid", "file", "category", "timestamp")
            self.evid_tree = ttk.Treeview(
                summary_frame, columns=cols, show="headings", height=8
            )
            self.evid_tree.heading("vid", text="V-ID")
            self.evid_tree.heading("file", text="Filename")
            self.evid_tree.heading("category", text="Category")
            self.evid_tree.heading("timestamp", text="Timestamp")
            self.evid_tree.column("vid", width=100)
            self.evid_tree.column("file", width=300)
            self.evid_tree.column("category", width=120)
            self.evid_tree.column("timestamp", width=180)

            evid_scroll = ttk.Scrollbar(
                summary_frame, orient="vertical", command=self.evid_tree.yview
            )
            self.evid_tree.configure(yscrollcommand=evid_scroll.set)
            self.evid_tree.pack(side="left", fill="both", expand=True)
            evid_scroll.pack(side="right", fill="y")

            # Context menu for copy
            self._attach_tree_context_menu(self.evid_tree)

            self.evid_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.evid_status, font=GUI_FONT_MONO).pack(
                anchor="w", pady=2
            )

            self._refresh_evidence_summary()

        def _tab_validate(self, frame):
            ttk.Label(frame, text="Validate Checklist", font=GUI_FONT_HEADING).pack(
                anchor="w"
            )

            input_frame = ttk.Frame(frame)
            input_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
            ttk.Label(input_frame, text="Checklist (CKL):").pack(side="left")
            self.validate_ckl = tk.StringVar()
            ent_vc = ttk.Entry(input_frame, textvariable=self.validate_ckl, width=60)
            ent_vc.pack(side="left", padx=GUI_PADDING)
            ttk.Button(
                input_frame,
                text="📂 Browse…",
                command=self._browse_validate_ckl,
            ).pack(side="left", padx=GUI_PADDING)
            ttk.Button(
                input_frame,
                text="✅ Validate",
                command=self._do_validate,
                style="Accent.TButton",
            ).pack(side="left")
            self._enable_dnd(ent_vc, self.validate_ckl)

            self._validate_ckl_err = ttk.Label(
                input_frame,
                text="",
                foreground=self._colors.get("error", "red"),
            )
            self._validate_ckl_err.pack(side="left", padx=GUI_PADDING)

            def _validate_validate_form(*args):
                self._validate_ckl_err.config(
                    text=("* Required" if not self.validate_ckl.get().strip() else "")
                )

            debounced_val = Debouncer(self.root, 300, _validate_validate_form)
            self.validate_ckl.trace_add("write", debounced_val)
            self.root.after(100, debounced_val)

            # #12 Validation data grid (TreeView) instead of ScrolledText
            columns = ("severity", "type", "message")
            self.validate_tree = ttk.Treeview(
                frame, columns=columns, show="headings", height=18
            )
            self.validate_tree.heading(
                "severity",
                text="Severity",
                command=lambda: self._sort_tree("severity"),
            )
            self.validate_tree.heading(
                "type", text="Type", command=lambda: self._sort_tree("type")
            )
            self.validate_tree.heading(
                "message",
                text="Message",
                command=lambda: self._sort_tree("message"),
            )
            self.validate_tree.column("severity", width=80, anchor="center")
            self.validate_tree.column("type", width=80, anchor="center")
            self.validate_tree.column("message", width=700)
            tree_scroll = ttk.Scrollbar(
                frame, orient="vertical", command=self.validate_tree.yview
            )
            self.validate_tree.configure(yscrollcommand=tree_scroll.set)
            self.validate_tree.pack(
                side="left", fill="both", expand=True, pady=GUI_PADDING
            )
            tree_scroll.pack(side="right", fill="y", pady=GUI_PADDING)
            # Color tags for tree rows
            self.validate_tree.tag_configure(
                "error", foreground=self._colors.get("error", "#CC0000")
            )
            self.validate_tree.tag_configure(
                "warn", foreground=self._colors.get("warn", "#CC8800")
            )
            self.validate_tree.tag_configure(
                "ok", foreground=self._colors.get("ok", "#008800")
            )
            self.validate_tree.tag_configure(
                "info", foreground=self._colors.get("info", "#0055AA")
            )
            # Right-click copy
            self._attach_tree_context_menu(self.validate_tree)

            # Also keep a text label for the summary line
            self.validate_summary_var = tk.StringVar()
            ttk.Label(
                frame,
                textvariable=self.validate_summary_var,
                font=GUI_FONT_MONO,
            ).pack(anchor="w", pady=2)

        def _sort_tree(self, col: str) -> None:
            """Sort treeview by column."""
            items = [
                (self.validate_tree.set(k, col), k)
                for k in self.validate_tree.get_children("")
            ]
            items.sort()
            for idx, (_, k) in enumerate(items):
                self.validate_tree.move(k, "", idx)

        def _attach_tree_context_menu(self, tree: ttk.Treeview) -> None:
            """Attach copy context menu to a Treeview."""
            menu = tk.Menu(tree, tearoff=0)

            def copy_msg():
                sel = tree.selection()
                if sel:
                    msg = tree.set(sel[0], "message")
                    self.root.clipboard_clear()
                    self.root.clipboard_append(msg)

            menu.add_command(label="Copy message", command=copy_msg)

            def show(event):
                row = tree.identify_row(event.y)
                if row:
                    tree.selection_set(row)
                    menu.tk_popup(event.x_root, event.y_root)

            tree.bind("<Button-3>", show)
            if sys.platform == "darwin":
                tree.bind("<Button-2>", show)

        # --------------------------------------------------------- action helpers
        def _set_action_buttons_state(self, state: str) -> None:
            """Enable or disable all tracked action buttons."""
            for btn in self._action_buttons:
                with suppress(tk.TclError):
                    btn.configure(state=state)

        def _async(self, work_func, callback):
            self._set_action_buttons_state("disabled")
            self.progress_bar.start(15)

            def worker():
                try:
                    result = work_func()
                except Exception as exc:
                    result = exc
                self.queue.put(("callback", callback, result))

            def wrapper_callback(result):
                self.progress_bar.stop()
                self.progress_bar.configure(mode="indeterminate")  # reset mode
                self._set_action_buttons_state("normal")
                callback(result)

            # Replace the callback so buttons are re-enabled after completion
            def guarded_worker():
                try:
                    result = work_func()
                except Exception as exc:
                    result = exc
                self.queue.put(("callback", wrapper_callback, result))

            threading.Thread(target=guarded_worker, daemon=True).start()

        def _process_queue(self):
            """Process async callback queue with status update support."""
            try:
                while True:
                    item = self.queue.get_nowait()

                    # Handle different message types with validation
                    try:
                        if not isinstance(item, tuple):
                            LOG.w(f"Invalid queue item type: {type(item)}")
                            continue

                        if len(item) == 3:
                            # Standard callback format
                            kind, func, payload = item
                            if kind == "callback" and callable(func):
                                func(payload)
                            else:
                                LOG.w(
                                    f"Invalid callback item: kind={kind}, callable={callable(func)}"
                                )
                        elif len(item) == 2:
                            # Status update format
                            kind, message = item
                            if kind == "status":
                                self.status_var.set(message)
                                self.root.update_idletasks()  # Force UI refresh
                            elif kind == "progress":
                                self.progress_bar.stop()
                                self.progress_bar.configure(mode="determinate")
                                self.progress_bar["value"] = float(message)
                                self.root.update_idletasks()
                            else:
                                LOG.w(f"Unknown queue item kind: {kind}")
                        else:
                            LOG.w(f"Invalid queue item length: {len(item)}")
                    except Exception as e:
                        LOG.e(f"Error processing queue item: {e}", exc=True)
            except queue.Empty:
                # Idle state, queue is naturally empty
                pass

            self.root.after(200, self._process_queue)

        # -------------------------------------------------------------- browse
        def _browse_create_xccdf(self):
            path = filedialog.askopenfilename(
                title="Select XCCDF",
                initialdir=self._last_dir(),
                filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")],
            )
            if path:
                self.create_xccdf.set(path)
                self._remember_file(path)
                if not self.create_out.get():
                    self.create_out.set(str(Path(path).with_suffix(".ckl")))

        def _browse_create_out(self):
            path = filedialog.asksaveasfilename(
                title="Save CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl"), ("All Files", "*.*")],
            )
            if path:
                self.create_out.set(path)

        def _browse_merge_base(self):
            path = filedialog.askopenfilename(
                title="Select base CKL",
                initialdir=self._last_dir(),
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.merge_base.set(path)
                self._remember_file(path)

        def _browse_merge_out(self):
            path = filedialog.asksaveasfilename(
                title="Save merged CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.merge_out.set(path)

        def _browse_extract_xccdf(self):
            path = filedialog.askopenfilename(
                title="Select XCCDF",
                initialdir=self._last_dir(),
                filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")],
            )
            if path:
                self.extract_xccdf.set(path)
                self._remember_file(path)

        def _browse_extract_out(self):
            path = filedialog.askdirectory(title="Select output directory")
            if path:
                self.extract_outdir.set(path)

        def _browse_results_json(self):
            path = filedialog.askopenfilename(
                title="Select results JSON",
                initialdir=self._last_dir(),
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            )
            if path:
                self.results_json.set(path)
                self._remember_file(path)

        def _browse_results_ckl(self):
            path = filedialog.askopenfilename(
                title="Select checklist",
                initialdir=self._last_dir(),
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.results_ckl.set(path)
                self._remember_file(path)
                if not self.results_out.get():
                    out_path = Path(path).with_name(Path(path).stem + "_updated.ckl")
                    self.results_out.set(str(out_path))

        def _browse_results_out(self):
            path = filedialog.asksaveasfilename(
                title="Save updated CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.results_out.set(path)

        def _browse_validate_ckl(self):
            path = filedialog.askopenfilename(
                title="Select CKL",
                initialdir=self._last_dir(),
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.validate_ckl.set(path)
                self._remember_file(path)

        def _tab_boilerplates(self, frame):
            frame.columnconfigure(1, weight=1)
            frame.rowconfigure(0, weight=1)

            left_frame = ttk.LabelFrame(
                frame, text="Vulnerability IDs", padding=GUI_PADDING_LARGE
            )
            left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, GUI_PADDING_LARGE))

            columns = ("vid", "flags")
            self._bp_vids_list = ttk.Treeview(
                left_frame,
                columns=columns,
                show="headings",
                selectmode="browse",
            )
            self._bp_vids_list.heading("vid", text="VID")
            self._bp_vids_list.heading("flags", text="Configs")
            self._bp_vids_list.column("vid", width=120)
            self._bp_vids_list.column("flags", width=80)
            self._bp_vids_list.pack(side="left", fill="both", expand=True)
            self._bp_vids_list.bind("<<TreeviewSelect>>", self._on_bp_vid_select)
            scroll_bp = ttk.Scrollbar(
                left_frame, orient="vertical", command=self._bp_vids_list.yview
            )
            scroll_bp.pack(side="right", fill="y")
            self._bp_vids_list.configure(yscrollcommand=scroll_bp.set)

            self._bp_vids_list.tag_configure(
                Status.OPEN.value, foreground=self._colors.get("error", "red")
            )
            self._bp_vids_list.tag_configure(
                Status.NOT_A_FINDING.value,
                foreground=self._colors.get("ok", "green"),
            )
            self._bp_vids_list.tag_configure(
                Status.NOT_REVIEWED.value,
                foreground=self._colors.get("warn", "orange"),
            )

            ttk.Button(left_frame, text="+ Add VID", command=self._bp_add_vid).pack(
                side="bottom", fill="x", pady=2
            )

            right_frame = ttk.LabelFrame(
                frame, text="Boilerplate Editor", padding=GUI_PADDING_LARGE
            )
            right_frame.grid(row=0, column=1, sticky="nsew")
            right_frame.rowconfigure(1, weight=1)
            right_frame.columnconfigure(0, weight=1)

            ctrl_frame = ttk.Frame(right_frame)
            ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))
            ttk.Label(ctrl_frame, text="Status:").pack(side="left", padx=5)
            self._bp_status_var = tk.StringVar(value=Status.NOT_A_FINDING.value)
            status_cb = ttk.Combobox(
                ctrl_frame,
                textvariable=self._bp_status_var,
                values=[
                    Status.NOT_A_FINDING.value,
                    Status.OPEN.value,
                    Status.NOT_APPLICABLE.value,
                    Status.NOT_REVIEWED.value,
                ],
                state="readonly",
            )
            status_cb.pack(side="left", padx=5)
            status_cb.bind("<<ComboboxSelected>>", self._on_bp_status_select)

            editors = ttk.Frame(right_frame)
            editors.grid(row=1, column=0, sticky="nsew")
            editors.columnconfigure(0, weight=1)
            editors.rowconfigure(1, weight=1)
            editors.rowconfigure(3, weight=1)

            ttk.Label(editors, text="Finding Details:").grid(
                row=0, column=0, sticky="w"
            )
            self._bp_finding_text = ScrolledText(
                editors, width=60, height=8, font=GUI_FONT_MONO
            )
            self._bp_finding_text.grid(
                row=1, column=0, sticky="nsew", pady=(0, GUI_PADDING_LARGE)
            )

            ttk.Label(editors, text="Comments:").grid(row=2, column=0, sticky="w")
            self._bp_comment_text = ScrolledText(
                editors, width=60, height=8, font=GUI_FONT_MONO
            )
            self._bp_comment_text.grid(row=3, column=0, sticky="nsew")

            actions = ttk.Frame(right_frame)
            actions.grid(row=2, column=0, sticky="ew", pady=(GUI_PADDING_LARGE, 0))
            ttk.Button(
                actions,
                text="💾 Save",
                command=self._bp_save,
                style="Accent.TButton",
            ).pack(side="right", padx=5)
            ttk.Button(actions, text="🗑 Delete", command=self._bp_delete).pack(
                side="left", padx=5
            )

            self._bp_current_vid = None
            self._bp_refresh_vids()

        def _bp_refresh_vids(self):
            for row in self._bp_vids_list.get_children():
                self._bp_vids_list.delete(row)
            bmap = self.proc.boiler.list_all()
            vids = sorted(list(bmap.keys()))
            if "V-*" not in vids:
                vids.insert(0, "V-*")
            for v in vids:
                statuses = list(bmap.get(v, {}).keys())
                flags = ",".join(statuses) if statuses else ""
                tag = ""
                if Status.OPEN.value in statuses:
                    tag = Status.OPEN.value
                elif Status.NOT_A_FINDING.value in statuses:
                    tag = Status.NOT_A_FINDING.value
                elif Status.NOT_REVIEWED.value in statuses:
                    tag = Status.NOT_REVIEWED.value

                self._bp_vids_list.insert(
                    "", tk.END, iid=v, values=(v, flags), tags=(tag,)
                )

        def _on_bp_vid_select(self, event):
            sel = self._bp_vids_list.selection()
            if not sel:
                return
            self._bp_current_vid = sel[0]
            self._load_bp_editor()

        def _on_bp_status_select(self, event):
            self._load_bp_editor()

        def _load_bp_editor(self):
            if not self._bp_current_vid:
                return
            status = self._bp_status_var.get()
            bmap = self.proc.boiler.list_all()
            entry = bmap.get(self._bp_current_vid, {}).get(status, {})
            self._bp_finding_text.delete("1.0", tk.END)
            self._bp_comment_text.delete("1.0", tk.END)
            self._bp_finding_text.insert("1.0", entry.get("finding_details", ""))
            self._bp_comment_text.insert("1.0", entry.get("comments", ""))

        def _bp_add_vid(self):
            vid = simpledialog.askstring(
                "Add VID", "Enter STIG Check ID (e.g. V-12345):"
            )
            if vid:
                vid = vid.strip()
                if not vid.startswith("V-") and vid != "V-*":
                    msg = f"'{vid}' does not look like a STIG Vuln ID (V-12345).\nForce add?"
                    if not messagebox.askyesno("Invalid VID format", msg):
                        return

                if not self._bp_vids_list.exists(vid):
                    self._bp_vids_list.insert("", tk.END, iid=vid, values=(vid, ""))

                self._bp_vids_list.selection_set(vid)
                self._bp_vids_list.focus(vid)
                self._bp_vids_list.see(vid)
                self._bp_vids_list.event_generate("<<TreeviewSelect>>")

        def _bp_save(self):
            if not self._bp_current_vid:
                return
            status = self._bp_status_var.get()
            finding = self._bp_finding_text.get("1.0", "end-1c")
            comment = self._bp_comment_text.get("1.0", "end-1c")
            self.proc.boiler.set(self._bp_current_vid, status, finding, comment)
            self.status_var.set(
                f"Saved boilerplate for {self._bp_current_vid} / {status}"
            )
            self._bp_refresh_vids()
            self._bp_vids_list.selection_set(self._bp_current_vid)

        def _bp_delete(self):
            if not self._bp_current_vid:
                return
            status = self._bp_status_var.get()
            if messagebox.askyesno(
                "Confirm Delete",
                f"Delete boilerplate for {self._bp_current_vid} / {status}?",
            ):
                if self.proc.boiler.delete(self._bp_current_vid, status):
                    self.status_var.set("Boilerplate deleted.")
                    self._bp_refresh_vids()
                    self._bp_vids_list.selection_set(self._bp_current_vid)
                    self._load_bp_editor()

        def _tab_compare(self, frame):
            io_frame = ttk.LabelFrame(
                frame, text="Input Checklists", padding=GUI_PADDING_LARGE
            )
            io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            io_frame.columnconfigure(1, weight=1)

            ttk.Label(io_frame, text="Old/Base CKL: *").grid(
                row=0, column=0, sticky="w"
            )
            self.diff_ckl1 = tk.StringVar()
            ent_1 = ttk.Entry(
                io_frame, textvariable=self.diff_ckl1, width=GUI_ENTRY_WIDTH
            )
            ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.diff_ckl1.set(
                    filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
                ),
            ).grid(row=0, column=2)
            self._enable_dnd(ent_1, self.diff_ckl1)

            ttk.Label(io_frame, text="New/Target CKL: *").grid(
                row=1, column=0, sticky="w"
            )
            self.diff_ckl2 = tk.StringVar()
            ent_2 = ttk.Entry(
                io_frame, textvariable=self.diff_ckl2, width=GUI_ENTRY_WIDTH
            )
            ent_2.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.diff_ckl2.set(
                    filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
                ),
            ).grid(row=1, column=2)
            self._enable_dnd(ent_2, self.diff_ckl2)

            btn = ttk.Button(
                frame,
                text="🔍 Compare",
                command=self._do_diff_tab,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn.pack(pady=GUI_PADDING_SECTION)

            self.diff_results_txt = ScrolledText(
                frame, font=GUI_FONT_MONO, wrap=tk.NONE, height=15
            )
            self.diff_results_txt.pack(fill="both", expand=True)

        def _tab_analytics(self, frame):
            io_frame = ttk.LabelFrame(
                frame, text="Checklist Analytics", padding=GUI_PADDING_LARGE
            )
            io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            io_frame.columnconfigure(1, weight=1)

            ttk.Label(io_frame, text="Checklist: *").grid(row=0, column=0, sticky="w")
            self.stats_ckl = tk.StringVar()
            ent_1 = ttk.Entry(
                io_frame, textvariable=self.stats_ckl, width=GUI_ENTRY_WIDTH
            )
            ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.stats_ckl.set(
                    filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
                ),
            ).grid(row=0, column=2)
            self._enable_dnd(ent_1, self.stats_ckl)

            btn = ttk.Button(
                frame,
                text="📊 Generate Vis & Stats",
                command=self._do_stats_tab,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn.pack(pady=GUI_PADDING_SECTION)

            self.stats_canvas = tk.Canvas(
                frame,
                height=220,
                bg="#ffffff",
                highlightthickness=1,
                highlightbackground="#e5e7eb",
            )
            self.stats_canvas.pack(fill="x", pady=(0, GUI_PADDING))
            self.stats_canvas.create_text(
                300,
                110,
                text="Load a checklist to view graphical compliance dashboard",
                fill="#9ca3af",
                font=GUI_FONT_NORMAL,
            )

            self.stats_results_txt = ScrolledText(frame, font=GUI_FONT_MONO, height=12)
            self.stats_results_txt.pack(fill="both", expand=True)

        def _tab_drift(self, frame):
            io_frame = ttk.LabelFrame(
                frame,
                text="Track Checklist History",
                padding=GUI_PADDING_LARGE,
            )
            io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            io_frame.columnconfigure(1, weight=1)

            ttk.Label(io_frame, text="Completed CKL: *").grid(
                row=0, column=0, sticky="w"
            )
            self.drift_track_ckl = tk.StringVar()
            ent_1 = ttk.Entry(
                io_frame,
                textvariable=self.drift_track_ckl,
                width=GUI_ENTRY_WIDTH,
            )
            ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.drift_track_ckl.set(
                    filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
                ),
            ).grid(row=0, column=2)
            self._enable_dnd(ent_1, self.drift_track_ckl)

            btn1 = ttk.Button(
                io_frame,
                text="📈 Track Checklist",
                command=self._do_track_ckl,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn1.grid(row=1, column=1, pady=GUI_PADDING, sticky="e")

            drift_frame = ttk.LabelFrame(
                frame, text="Analyze Asset Drift", padding=GUI_PADDING_LARGE
            )
            drift_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            drift_frame.columnconfigure(1, weight=1)

            ttk.Label(drift_frame, text="Asset Name: *").grid(
                row=0, column=0, sticky="w"
            )
            self.drift_asset = tk.StringVar()
            ttk.Entry(
                drift_frame,
                textvariable=self.drift_asset,
                width=GUI_ENTRY_WIDTH,
            ).grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

            btn2 = ttk.Button(
                drift_frame,
                text="🔍 Analyze Drift",
                command=self._do_show_drift,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn2.grid(row=1, column=1, pady=GUI_PADDING, sticky="e")

            self.drift_canvas = tk.Canvas(
                frame,
                height=220,
                bg="#ffffff",
                highlightthickness=1,
                highlightbackground="#e5e7eb",
            )
            self.drift_canvas.pack(
                fill="x", padx=GUI_PADDING_LARGE, pady=(0, GUI_PADDING_LARGE)
            )
            self.drift_canvas.create_text(
                300,
                110,
                text="Analyze an asset to view compliance drift",
                fill="#9ca3af",
                font=GUI_FONT_NORMAL,
            )

        def _tab_repair(self, frame):
            io_frame = ttk.LabelFrame(
                frame,
                text="Repair Corrupted Checklists",
                padding=GUI_PADDING_LARGE,
            )
            io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            io_frame.columnconfigure(1, weight=1)

            ttk.Label(io_frame, text="Target CKL: *").grid(row=0, column=0, sticky="w")
            self.repair_ckl = tk.StringVar()
            ent_1 = ttk.Entry(
                io_frame, textvariable=self.repair_ckl, width=GUI_ENTRY_WIDTH
            )
            ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.repair_ckl.set(
                    filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
                ),
            ).grid(row=0, column=2)
            self._enable_dnd(ent_1, self.repair_ckl)

            self.repair_backup = tk.BooleanVar(value=True)
            ttk.Checkbutton(
                io_frame,
                text="Create backup copy before altering file",
                variable=self.repair_backup,
            ).grid(row=1, column=1, sticky="w", pady=(GUI_PADDING, 0))

            btn_frame = ttk.Frame(frame)
            btn_frame.pack(pady=GUI_PADDING_SECTION)
            ttk.Button(
                btn_frame,
                text="🔍 Verify Integrity",
                command=self._do_verify_integrity,
                width=GUI_BUTTON_WIDTH_WIDE,
            ).pack(side="left", padx=5)
            btn_repair = ttk.Button(
                btn_frame,
                text="🔧 Repair",
                command=self._do_repair,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn_repair.pack(side="left", padx=5)
            self._action_buttons.append(btn_repair)

            self.repair_txt = ScrolledText(frame, font=GUI_FONT_MONO, height=15)
            self.repair_txt.pack(fill="both", expand=True)
            self.repair_txt.insert(
                "1.0",
                "Select a CKL file to verify its checksum or repair structural issues.",
            )
            self.repair_txt.config(state="disabled")

        def _tab_batch(self, frame):
            io_frame = ttk.LabelFrame(
                frame,
                text="Bulk Data Transformation",
                padding=GUI_PADDING_LARGE,
            )
            io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
            io_frame.columnconfigure(1, weight=1)

            ttk.Label(io_frame, text="Input Directory: *").grid(
                row=0, column=0, sticky="w"
            )
            self.batch_ind = tk.StringVar()
            ent_1 = ttk.Entry(
                io_frame, textvariable=self.batch_ind, width=GUI_ENTRY_WIDTH
            )
            ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.batch_ind.set(filedialog.askdirectory()),
            ).grid(row=0, column=2)

            ttk.Label(io_frame, text="Output Directory: *").grid(
                row=1, column=0, sticky="w", pady=GUI_PADDING
            )
            self.batch_out = tk.StringVar()
            ent_2 = ttk.Entry(
                io_frame, textvariable=self.batch_out, width=GUI_ENTRY_WIDTH
            )
            ent_2.grid(
                row=1,
                column=1,
                padx=GUI_PADDING,
                sticky="we",
                pady=GUI_PADDING,
            )
            ttk.Button(
                io_frame,
                text="📂 Browse…",
                command=lambda: self.batch_out.set(filedialog.askdirectory()),
            ).grid(row=1, column=2, pady=GUI_PADDING)

            opt_frame = ttk.LabelFrame(frame, text="Options", padding=GUI_PADDING_LARGE)
            opt_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

            ttk.Label(opt_frame, text="Format:").grid(row=0, column=0, sticky="w")
            self.batch_fmt = tk.StringVar(value="csv")
            ttk.Combobox(
                opt_frame,
                textvariable=self.batch_fmt,
                values=["csv", "json"],
                state="readonly",
                width=10,
            ).grid(row=0, column=1, padx=GUI_PADDING, sticky="w")

            self.batch_merge = tk.BooleanVar(value=True)
            ttk.Checkbutton(
                opt_frame,
                text="Merge into single file",
                variable=self.batch_merge,
            ).grid(
                row=1,
                column=0,
                columnspan=2,
                sticky="w",
                pady=(GUI_PADDING, 0),
            )

            btn_batch = ttk.Button(
                frame,
                text="🏭 Export Batch",
                command=self._do_batch_convert,
                width=GUI_BUTTON_WIDTH_WIDE,
                style="Accent.TButton",
            )
            btn_batch.pack(pady=GUI_PADDING_SECTION)
            self._action_buttons.append(btn_batch)

        # ------------------------------------------------------------ actions

        def _do_verify_integrity(self):
            ckl_path = self.repair_ckl.get().strip()
            if not ckl_path:
                messagebox.showerror(
                    "Missing input", "Please select a CKL file to verify."
                )
                return

            def work():
                return self.proc.verify_integrity(ckl_path)

            def done(result):
                self.repair_txt.config(state="normal")
                self.repair_txt.delete("1.0", tk.END)
                if isinstance(result, Exception):
                    self.repair_txt.insert(
                        tk.END, f"[ERROR] Integrity Check Failed:\n{result}"
                    )
                    messagebox.showerror("Error", str(result))
                else:
                    self.repair_txt.insert(
                        tk.END,
                        f"[SUCCESS] Integrity Verification Complete\n\nChecksum (SHA3-256):\n{result}\n\nThis checksum proves the file has not been tampered with since creation.",
                    )
                self.repair_txt.config(state="disabled")

            self.status_var.set("Verifying...")
            self._async(work, done)

        def _do_repair(self):
            ckl_path = self.repair_ckl.get().strip()
            if not ckl_path:
                messagebox.showerror(
                    "Missing input", "Please select a CKL file to repair."
                )
                return

            backup = self.repair_backup.get()

            def work():
                return self.proc.repair(ckl_path, backup=backup)

            def done(result):
                self.repair_txt.config(state="normal")
                self.repair_txt.delete("1.0", tk.END)
                if isinstance(result, Exception):
                    self.repair_txt.insert(tk.END, f"[ERROR] Repair Failed:\n{result}")
                    messagebox.showerror("Repair Failed", str(result))
                else:
                    fixed_lines = result.get("fixed", [])
                    output_file = result.get("file", ckl_path)

                    if not fixed_lines:
                        self.repair_txt.insert(
                            tk.END,
                            f"No structural issues found in {Path(ckl_path).name}.\nThe file appears normal.",
                        )
                        self.status_var.set("✔ Checklist is structurally sound.")
                    else:
                        self.repair_txt.insert(
                            tk.END,
                            f"[SUCCESS] Repaired {len(fixed_lines)} anomalies in {Path(ckl_path).name}\n\nDetails:\n",
                        )
                        for msg in fixed_lines:
                            self.repair_txt.insert(tk.END, f"- {msg}\n")
                        self.status_var.set(f"✔ Repaired checklist: {output_file}")
                        messagebox.showinfo(
                            "Repair Complete",
                            f"Successfully repaired {len(fixed_lines)} issue(s).",
                        )
                self.repair_txt.config(state="disabled")

            self.status_var.set("Repairing...")
            self._async(work, done)

        def _do_batch_convert(self):
            in_dir = self.batch_ind.get().strip()
            out_dir = self.batch_out.get().strip()
            if not in_dir or not out_dir:
                messagebox.showerror(
                    "Missing input",
                    "Please provide both input and output directories.",
                )
                return

            fmt = self.batch_fmt.get()
            merge = self.batch_merge.get()

            def work():
                return self.proc.batch_convert(
                    input_dir=in_dir,
                    output_dir=out_dir,
                    format_=fmt,
                    merge=merge,
                )

            def done(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"✘ Batch convert failed: {result}")
                    messagebox.showerror("Batch Convert Error", str(result))
                else:
                    processed = result.get("processed", 0)
                    skipped = result.get("skipped", 0)
                    errors = result.get("errors", 0)
                    out_path = result.get("output", "")

                    msg = f"Processed: {processed}\nSkipped: {skipped}\nErrors: {errors}\n\nOutput saved in: {out_path}"
                    self.status_var.set(
                        f"✔ Batch conversion complete. Output: {out_path}"
                    )
                    messagebox.showinfo("Batch Convert Complete", msg)

            self.status_var.set("Running batch conversion...")
            self._async(work, done)

        def _do_diff_tab(self):
            if not self.diff_ckl1.get() or not self.diff_ckl2.get():
                messagebox.showerror(
                    "Error",
                    "Please provide two checklists down for comparison.",
                )
                return
            try:
                d = self.proc.diff(
                    self.diff_ckl1.get(),
                    self.diff_ckl2.get(),
                    output_format="text",
                )
                self.diff_results_txt.configure(state="normal")
                self.diff_results_txt.delete("1.0", tk.END)
                if isinstance(d, dict):
                    output = [
                        f"Comparison: {Path(self.diff_ckl1.get()).name} vs {Path(self.diff_ckl2.get()).name}"
                    ]
                    for k, v in d.items():
                        output.append(f"\n[{str(k).upper()}]")
                        if isinstance(v, list):
                            for ln in v:
                                output.append(str(ln))
                        else:
                            output.append(str(v))
                    self.diff_results_txt.insert(tk.END, "\n".join(output))
                else:
                    self.diff_results_txt.insert(tk.END, str(d))
                self.diff_results_txt.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Diff Error", str(e))

        def _do_stats_tab(self):
            if not self.stats_ckl.get():
                return
            try:
                stats_dict = self.proc.generate_stats(
                    self.stats_ckl.get(), output_format="json"
                )
                s_text = self.proc.generate_stats(
                    self.stats_ckl.get(), output_format="text"
                )
                self.stats_results_txt.configure(state="normal")
                self.stats_results_txt.delete("1.0", tk.END)
                self.stats_results_txt.insert(tk.END, str(s_text))
                self.stats_results_txt.configure(state="disabled")

                # Parse counts for visual graph
                by_status = stats_dict.get("by_status", {})
                total = stats_dict.get("total_vulns", 0)

                self.stats_canvas.delete("all")
                if total == 0:
                    self.stats_canvas.create_text(
                        300,
                        110,
                        text="No vulnerabilities found.",
                        fill="#6b7280",
                        font=GUI_FONT_NORMAL,
                    )
                    return

                colors = {
                    "NotAFinding": "#10b981",
                    "Open": "#ef4444",
                    "Not_Applicable": "#6b7280",
                    "Not_Reviewed": "#f59e0b",
                }
                width = int(self.stats_canvas.winfo_width())
                if width <= 10:
                    width = 600
                height = int(self.stats_canvas.winfo_height())
                if height <= 10:
                    height = 220

                self.stats_canvas.create_text(
                    width / 2,
                    20,
                    text=f"Compliance Posture Overview ({total} Total Rules)",
                    fill="#374151",
                    font=(GUI_FONT_NORMAL[0], 12, "bold"),
                )

                bars = [
                    "NotAFinding",
                    "Open",
                    "Not_Applicable",
                    "Not_Reviewed",
                ]
                bar_labels = [
                    "Not A Finding",
                    "Open",
                    "Not Applicable",
                    "Not Reviewed",
                ]
                max_h = height - 80
                bar_w = width / (len(bars) * 2)
                gap = bar_w
                current_x = gap / 2

                for i, k in enumerate(bars):
                    count = by_status.get(k, 0)
                    h = (count / total) * max_h
                    color = colors.get(k, "#3b82f6")

                    self.stats_canvas.create_rectangle(
                        current_x,
                        height - 30 - h,
                        current_x + bar_w,
                        height - 30,
                        fill=color,
                        outline=color,
                    )
                    self.stats_canvas.create_text(
                        current_x + bar_w / 2,
                        height - 30 - h - 12,
                        text=str(count),
                        fill="#1f2937",
                        font=(GUI_FONT_NORMAL[0], 10, "bold"),
                    )
                    self.stats_canvas.create_text(
                        current_x + bar_w / 2,
                        height - 15,
                        text=bar_labels[i],
                        fill="#4b5563",
                        font=(GUI_FONT_NORMAL[0], 10),
                    )

                    current_x += bar_w + gap

            except Exception as e:
                messagebox.showerror("Stats Error", str(e))

        def _do_track_ckl(self):
            if not self.drift_track_ckl.get():
                return
            ckl_path = self.drift_track_ckl.get()
            if not self.proc.history.db:
                messagebox.showerror("Error", "SQLite History DB is not initialized.")
                return
            try:
                tree = self.proc._load_file_as_xml(Path(ckl_path))
                root = tree.getroot()
                vulns = self.proc._extract_vuln_data(root)
                asset_elem = root.find(".//HOST_NAME")
                asset_name = asset_elem.text if asset_elem is not None else "Unknown"

                results = []
                for vid, vdata in vulns.items():
                    results.append(
                        {
                            "vid": vid,
                            "status": vdata.get("status", "Not_Reviewed"),
                            "severity": vdata.get("severity", "medium"),
                            "find": vdata.get("finding_details", ""),
                            "comm": vdata.get("comments", ""),
                        }
                    )

                db_id = self.proc.history.db.save_assessment(
                    asset_name, ckl_path, "STIG", results
                )
                messagebox.showinfo(
                    "Success",
                    f"Successfully ingested {len(results)} findings into database.\nAssessment ID: {db_id}",
                )
            except Exception as e:
                messagebox.showerror("Tracking Error", str(e))

        def _do_show_drift(self):
            asset_name = self.drift_asset.get().strip()
            if not asset_name:
                return
            if not self.proc.history.db:
                messagebox.showerror("Error", "SQLite History DB is not initialized.")
                return
            try:
                with self.proc.history.db._get_conn() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT id FROM assessments WHERE asset_name = ? ORDER BY timestamp DESC LIMIT 1",
                        (asset_name,),
                    )
                    row = cursor.fetchone()
                    if not row:
                        messagebox.showwarning(
                            "No Data",
                            f"No assessments found for asset '{asset_name}'",
                        )
                        return
                    latest_id = row[0]

                drift = self.proc.history.db.get_drift(asset_name, latest_id)
                if "error" in drift:
                    messagebox.showerror("Drift Error", drift["error"])
                    return

                self.drift_canvas.delete("all")

                width = int(self.drift_canvas.winfo_width())
                if width <= 10:
                    width = 600
                height = int(self.drift_canvas.winfo_height())
                if height <= 10:
                    height = 220

                self.drift_canvas.create_text(
                    width / 2,
                    20,
                    text=f"Compliance Drift Analysis: {asset_name}",
                    fill="#374151",
                    font=(GUI_FONT_NORMAL[0], 12, "bold"),
                )

                bars = [
                    ("Fixed", len(drift["fixed"]), "#10b981"),
                    ("Regressed", len(drift["regressed"]), "#ef4444"),
                    ("Changed", len(drift["changed"]), "#f59e0b"),
                    ("New Rules", len(drift["new"]), "#3b82f6"),
                    ("Removed", len(drift["removed"]), "#6b7280"),
                ]

                max_val = max([b[1] for b in bars] + [1])
                max_h = height - 80
                bar_w = width / (len(bars) * 2)
                gap = bar_w
                current_x = gap / 2

                for label, count, color in bars:
                    h = (count / max_val) * max_h
                    if h < 2 and count > 0:
                        h = 2

                    self.drift_canvas.create_rectangle(
                        current_x,
                        height - 30 - h,
                        current_x + bar_w,
                        height - 30,
                        fill=color,
                        outline=color,
                    )
                    self.drift_canvas.create_text(
                        current_x + bar_w / 2,
                        height - 30 - h - 12,
                        text=str(count),
                        fill="#1f2937",
                        font=(GUI_FONT_NORMAL[0], 10, "bold"),
                    )
                    self.drift_canvas.create_text(
                        current_x + bar_w / 2,
                        height - 15,
                        text=label,
                        fill="#4b5563",
                        font=(GUI_FONT_NORMAL[0], 10),
                    )

                    current_x += bar_w + gap

            except Exception as e:
                messagebox.showerror("Drift Error", str(e))

        def _do_create(self):
            if (
                not self.create_xccdf.get()
                or not self.create_asset.get()
                or not self.create_out.get()
            ):
                self._show_inline_error(
                    self._action_buttons[0],
                    "Missing input: Please provide XCCDF, asset name, and output path.",
                )
                return

            # (#20) Overwrite confirmation
            out_path = Path(self.create_out.get())
            if out_path.exists():
                if not messagebox.askyesno(
                    "Overwrite?",
                    f"{out_path.name} already exists.\nOverwrite it?",
                ):
                    return

            in_xccdf = self.create_xccdf.get()
            out_file = self.create_out.get()
            asset = self.create_asset.get()
            ip = self.create_ip.get()
            mac = self.create_mac.get()
            marking = self.create_mark.get()
            bp = self.create_bp.get()

            def work():
                return self.proc.xccdf_to_ckl(
                    in_xccdf,
                    out_file,
                    asset,
                    ip=ip,
                    mac=mac,
                    marking=marking,
                    apply_boilerplate=bp,
                )

            def done(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"✘ Error: {result}")
                    messagebox.showerror("Create Failed", str(result))
                else:
                    processed = result.get("processed", 0)
                    skipped = result.get("skipped", 0)
                    errors = result.get("errors", [])
                    self.status_var.set(f"✔ Checklist created: {result.get('output')}")
                    summary = f"Checklist created successfully.\n\nProcessed: {processed}\nSkipped: {skipped}"
                    if errors:
                        summary += (
                            f"\nErrors: {len(errors)}\nFirst error: {errors[0][:120]}"
                        )
                    messagebox.showinfo("Create Complete", summary)

            self.status_var.set("Processing…")
            self._async(work, done)

        def _add_merge_hist(self):
            paths = filedialog.askopenfilenames(
                title="Select historical CKL",
                filetypes=[("CKL Files", "*.ckl")],
            )
            for path in paths:
                if path not in self.merge_histories:
                    self.merge_histories.append(path)
                    self.merge_list.insert(tk.END, Path(path).name)

        def _remove_merge_hist(self):
            selection = self.merge_list.curselection()
            if not selection:
                return
            index = selection[0]
            path = self.merge_histories.pop(index)
            self.merge_list.delete(index)
            LOG.d(f"Removed historical checklist: {path}")

        def _clear_merge_hist(self):
            """Clear merge history list with confirmation."""
            if not self.merge_histories:
                return
            if not messagebox.askyesno(
                "Confirm Clear",
                f"Remove all {len(self.merge_histories)} history file(s)?",
            ):
                return
            self.merge_histories.clear()
            self.merge_list.delete(0, tk.END)

        def _do_merge(self):
            if not self.merge_base.get() or not self.merge_out.get():
                self._show_inline_error(
                    self._action_buttons[1],
                    "Missing input: Please provide base checklist and output path.",
                )
                return

            # (#20) Overwrite confirmation
            out_path = Path(self.merge_out.get())
            if out_path.exists():
                if not messagebox.askyesno(
                    "Overwrite?",
                    f"{out_path.name} already exists.\nOverwrite it?",
                ):
                    return

            histories = list(self.merge_histories)

            in_base = self.merge_base.get()
            in_out = self.merge_out.get()
            in_preserve = self.merge_preserve.get()
            in_bp = self.merge_bp.get()

            def work():
                return self.proc.merge(
                    in_base,
                    histories,
                    in_out,
                    preserve_history=in_preserve,
                    apply_boilerplate=in_bp,
                )

            def done(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"✘ Error: {result}")
                    messagebox.showerror("Merge Failed", str(result))
                else:
                    updated = result.get("updated", 0)
                    skipped = result.get("skipped", 0)
                    self.status_var.set(f"✔ Merged checklist: {result.get('output')}")
                    messagebox.showinfo(
                        "Merge Complete",
                        f"Merge completed successfully.\n\n"
                        f"Vulnerabilities updated: {updated}\n"
                        f"Unchanged: {skipped}\n"
                        f"Output: {result.get('output', 'N/A')}",
                    )

            self.status_var.set("Processing…")
            self._async(work, done)

        def _do_extract(self):
            if not self.extract_xccdf.get() or not self.extract_outdir.get():
                self._show_inline_error(
                    self._action_buttons[2],
                    "Missing input: Please provide XCCDF file and output directory.",
                )
                return

            in_xccdf = self.extract_xccdf.get()
            outdir = Path(self.extract_outdir.get())
            outdir.mkdir(parents=True, exist_ok=True, mode=0o700)

            do_json = self.extract_json.get()
            do_csv = self.extract_csv.get()
            do_bash = self.extract_bash.get()
            do_ps = self.extract_ps.get()
            do_ansible = self.extract_ansible.get()
            dry = self.extract_dry.get()

            def work():
                extractor = FixExt(in_xccdf)
                extractor.extract()
                outpaths = []
                if do_json:
                    extractor.to_json(outdir / "fixes.json")
                    outpaths.append("JSON")
                if do_csv:
                    extractor.to_csv(outdir / "fixes.csv")
                    outpaths.append("CSV")
                if do_bash:
                    extractor.to_bash(outdir / "remediate.sh", dry_run=dry)
                    outpaths.append("Bash")
                if do_ps:
                    enable_rollbacks = self.extract_rollbacks.get()
                    extractor.to_powershell(
                        outdir / "Remediate.ps1",
                        dry_run=dry,
                        enable_rollbacks=enable_rollbacks,
                    )
                    outpaths.append("PowerShell")
                if do_ansible:
                    extractor.to_ansible(outdir / "remediate.yml", dry_run=dry)
                    outpaths.append("Ansible")
                return extractor.stats_summary(), outpaths

            def done(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"✘ Error: {result}")
                else:
                    stats, formats = result
                    self.status_var.set(
                        f"✔ Fix extraction complete. Total groups: {stats['total_groups']}"
                    )

            self.status_var.set("Processing…")
            self._async(work, done)

        def _import_evidence(self):
            vid = self.evid_vid.get()
            if not vid:
                self._show_inline_error(
                    self.vid_entry,
                    "Missing input: Please enter a vulnerability ID.",
                )
                return
            try:
                San.vuln(vid)
            except Exception as _val_err:
                self._show_inline_error(
                    self.vid_entry,
                    f"Invalid Vuln ID: Please enter a valid Vuln ID (e.g. V-12345). ({_val_err})",
                )
                return
            path = filedialog.askopenfilename(title="Select evidence file")
            if not path:
                return

            in_desc = self.evid_desc.get()
            in_cat = self.evid_cat.get()

            def work():
                return self.evidence.import_file(
                    vid,
                    path,
                    description=in_desc,
                    category=in_cat or "general",
                )

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Error importing evidence", str(result))
                else:
                    messagebox.showinfo(
                        "Evidence Imported", f"Evidence stored at:\n{result}"
                    )
                    self._refresh_evidence_summary()
                    self.evid_vid.set("")
                    self.evid_desc.set("")
                    self.evid_cat.set("general")

            self._async(work, done)

        def _export_evidence(self):
            path = filedialog.askdirectory(title="Select export directory")
            if not path:
                return

            def work():
                return self.evidence.export_all(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo(
                        "Evidence Export",
                        f"Exported {result} file(s) to {path}",
                    )

            self._async(work, done)

        def _package_evidence(self):
            path = filedialog.asksaveasfilename(
                title="Save evidence package",
                defaultextension=".zip",
                filetypes=[("ZIP Files", "*.zip")],
            )
            if not path:
                return

            def work():
                return self.evidence.package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Package error", str(result))
                else:
                    messagebox.showinfo(
                        "Evidence Package", f"Package created:\n{result}"
                    )
                    self._refresh_evidence_summary()

            self._async(work, done)

        def _import_evidence_package(self):
            path = filedialog.askopenfilename(
                title="Select evidence package",
                filetypes=[("ZIP Files", "*.zip")],
            )
            if not path:
                return

            def work():
                return self.evidence.import_package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo("Evidence import", f"Imported {result} file(s)")
                    self._refresh_evidence_summary()

            self._async(work, done)

        def _do_validate(self):
            if not self.validate_ckl.get():
                self._show_inline_error(
                    self.validate_tree,
                    "Missing input: Please select a CKL file.",
                )
                return

            in_ckl = self.validate_ckl.get()

            def work():
                return self.proc.validator.validate(in_ckl)

            def done(result):
                self.validate_tree.delete(*self.validate_tree.get_children())

                if isinstance(result, Exception):
                    self.validate_tree.insert(
                        "",
                        "end",
                        values=("Error", "System", str(result)),
                        tags=("error",),
                    )
                    self.validate_summary_var.set(
                        "✘ Validation failed due to system error."
                    )
                    return
                ok, errors, warnings_, info = result

                if errors:
                    for err in errors:
                        self.validate_tree.insert(
                            "",
                            "end",
                            values=("High", "Error", err),
                            tags=("error",),
                        )
                if warnings_:
                    for warn in warnings_:
                        self.validate_tree.insert(
                            "",
                            "end",
                            values=("Medium", "Warning", warn),
                            tags=("warn",),
                        )
                if info:
                    for msg in info:
                        self.validate_tree.insert(
                            "",
                            "end",
                            values=("Low", "Info", msg),
                            tags=("info",),
                        )

                if ok:
                    self.validate_summary_var.set(
                        "✔ Checklist is STIG Viewer compatible."
                    )
                    # Add dummy success row if nothing else
                    if not errors and not warnings_ and not info:
                        self.validate_tree.insert(
                            "",
                            "end",
                            values=(
                                "OK",
                                "Success",
                                "Validation passed successfully.",
                            ),
                            tags=("ok",),
                        )
                else:
                    self.validate_summary_var.set(
                        f"✘ Checklist has {len(errors)} error(s) that must be resolved."
                    )

            self.status_var.set("Validating…")
            self._async(work, done)

        # ------------------------------------------------------------ menu actions
        def _save_preset(self):
            name = simpledialog.askstring("Save Preset", "Preset name:")
            if not name:
                return
            preset = {
                "xccdf": self.create_xccdf.get(),
                "asset": self.create_asset.get(),
                "ip": self.create_ip.get(),
                "mac": self.create_mac.get(),
                "mark": self.create_mark.get(),
                "apply_boilerplate": self.create_bp.get(),
            }
            try:
                self.presets.save(name, preset)
                messagebox.showinfo("Preset saved", f"Preset '{name}' saved.")
            except Exception as exc:
                messagebox.showerror("Preset error", str(exc))

        def _load_preset(self):
            names = self.presets.list()
            if not names:
                messagebox.showinfo("No presets", "No presets available.")
                return

            # (#13) Listbox-based preset picker instead of text input
            picker = tk.Toplevel(self.root)
            picker.title("Load Preset")
            picker.geometry("550x350")
            picker.transient(self.root)
            picker.grab_set()

            top_frame = ttk.Frame(picker)
            top_frame.pack(
                fill="both",
                expand=True,
                padx=GUI_PADDING_LARGE,
                pady=GUI_PADDING_LARGE,
            )

            left_frame = ttk.Frame(top_frame)
            left_frame.pack(side="left", fill="both", expand=True)
            ttk.Label(left_frame, text="Select a preset:", font=GUI_FONT_HEADING).pack(
                anchor="w", pady=(0, GUI_PADDING)
            )
            listbox = tk.Listbox(left_frame, height=10, font=("TkDefaultFont", 10))
            listbox.pack(fill="both", expand=True)
            for n in names:
                listbox.insert(tk.END, n)

            right_frame = ttk.LabelFrame(top_frame, text="Details", padding=GUI_PADDING)
            right_frame.pack(
                side="right",
                fill="both",
                expand=True,
                padx=(GUI_PADDING_LARGE, 0),
            )
            details_text = tk.Text(
                right_frame,
                width=30,
                height=10,
                state="disabled",
                bg=self._colors.get("entries_bg", "white"),
                font=GUI_FONT_MONO,
            )
            details_text.pack(fill="both", expand=True)

            def _on_select(event):
                sel = listbox.curselection()
                if not sel:
                    return
                name = listbox.get(sel[0])
                data = self.presets.load(name)
                details_text.config(state="normal")
                details_text.delete("1.0", tk.END)
                if data:
                    formatted = "\n".join(
                        f"{k}:\n  {v}"
                        for k, v in data.items()
                        if getattr(data, "items", None)
                    )
                    details_text.insert(tk.END, formatted)
                details_text.config(state="disabled")

            listbox.bind("<<ListboxSelect>>", _on_select)
            if names:
                listbox.selection_set(0)
                _on_select(None)

            def on_ok():
                sel = listbox.curselection()
                if not sel:
                    return
                name = listbox.get(sel[0])
                preset = self.presets.load(name)
                if not preset:
                    messagebox.showerror("Preset error", f"Preset '{name}' not found.")
                    return
                self.create_xccdf.set(preset.get("xccdf", ""))
                self.create_asset.set(preset.get("asset", ""))
                self.create_ip.set(preset.get("ip", ""))
                self.create_mac.set(preset.get("mac", ""))
                self.create_mark.set(preset.get("mark", "CUI"))
                self.create_bp.set(bool(preset.get("apply_boilerplate", False)))
                picker.destroy()
                self.status_var.set(f"Preset '{name}' loaded")

            btn_frame = ttk.Frame(picker)
            btn_frame.pack(fill="x", padx=GUI_PADDING_LARGE, pady=GUI_PADDING_LARGE)
            ttk.Button(btn_frame, text="Load", command=on_ok).pack(
                side="left", padx=GUI_PADDING
            )
            ttk.Button(btn_frame, text="Cancel", command=picker.destroy).pack(
                side="right", padx=GUI_PADDING
            )
            listbox.bind("<Double-1>", lambda e: on_ok())

        def _delete_preset(self):
            """Delete a saved preset with confirmation."""
            names = self.presets.list()
            if not names:
                messagebox.showinfo("No presets", "No presets available to delete.")
                return
            name = simpledialog.askstring(
                "Delete Preset",
                f"Available presets:\n{', '.join(names)}\n\nEnter name to delete:",
            )
            if not name:
                return
            if name not in names:
                messagebox.showerror("Not found", f"Preset '{name}' does not exist.")
                return
            if messagebox.askyesno(
                "Confirm Delete", f"Permanently delete preset '{name}'?"
            ):
                try:
                    self.presets.delete(name)
                    self.status_var.set(f"Preset '{name}' deleted")
                except Exception as exc:
                    messagebox.showerror("Delete error", str(exc))

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
        # #8  Recent files
        # ────────────────────────────────────────────────────────────────
        def _refresh_recent_menu(self) -> None:
            """Rebuild the Recent Files submenu from settings."""
            if not hasattr(self, "_recent_menu"):
                return
            self._recent_menu.delete(0, tk.END)
            recent = self._settings.get("recent_files", [])
            if not recent:
                self._recent_menu.add_command(label="(none)", state="disabled")
                return
            for filepath in recent[:10]:
                label = Path(filepath).name
                self._recent_menu.add_command(
                    label=label,
                    command=lambda p=filepath: self._open_recent(p),
                )
            self._recent_menu.add_separator()
            self._recent_menu.add_command(
                label="Clear Recent", command=self._clear_recent
            )

        def _open_recent(self, filepath: str) -> None:
            """Populate the first matching input field with a recent file."""
            ext = Path(filepath).suffix.lower()
            if ext == ".xml":
                self.create_xccdf.set(filepath)
            elif ext == ".ckl":
                self.merge_base.set(filepath)
            elif ext == ".json":
                self.results_json.set(filepath)
            self.status_var.set(f"Loaded recent: {Path(filepath).name}")

        def _clear_recent(self) -> None:
            self._settings["recent_files"] = []
            _save_settings(self._settings)
            self._refresh_recent_menu()

        def _remember_file(self, filepath: str) -> None:
            """Add file to recent list and update browse dir."""
            recent = self._settings.setdefault("recent_files", [])
            if filepath in recent:
                recent.remove(filepath)
            recent.insert(0, filepath)
            self._settings["recent_files"] = recent[:10]
            self._settings["last_browse_dir"] = str(Path(filepath).parent)
            _save_settings(self._settings)
            self._refresh_recent_menu()

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
            tab_map = {0: 0, 1: 3, 2: 1, 3: 5}  # wizard→notebook
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

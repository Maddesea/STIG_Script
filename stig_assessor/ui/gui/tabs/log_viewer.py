"""Diagnostic Log Viewer Tab module."""

import os
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import GUI_FONT_MONO, GUI_PADDING_LARGE


def build_log_viewer_tab(app, frame):
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    colors = app._colors

    header = ttk.Frame(frame)
    header.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))

    ttk.Label(
        header,
        text="Application Events & Diagnostics",
        font=("TkDefaultFont", 11, "bold"),
    ).pack(side="left")

    def _refresh_logs():
        log_file = Cfg.LOG_DIR / "stig_assessor.log"
        txt_area.configure(state="normal")
        txt_area.delete("1.0", tk.END)

        if not log_file.exists():
            txt_area.insert(
                tk.END, "Log file not found yet. Perform some actions to generate logs."
            )
            txt_area.configure(state="disabled")
            return

        try:
            # Read last 500 lines
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                tail = lines[-500:]
                for line in tail:
                    tags = []
                    if "[ERROR]" in line or " ERROR " in line:
                        tags.append("ERROR")
                    elif "[WARNING]" in line or " WARNING " in line:
                        tags.append("WARNING")
                    elif "[INFO]" in line or " INFO " in line:
                        tags.append("INFO")
                    elif "[DEBUG]" in line or " DEBUG " in line:
                        tags.append("DEBUG")
                    txt_area.insert(tk.END, line, tags)
            txt_area.see(tk.END)
        except Exception as e:
            txt_area.insert(tk.END, f"Error reading logs: {e}")

        txt_area.configure(state="disabled")

    def _copy_all():
        log_file = Cfg.LOG_DIR / "stig_assessor.log"
        if log_file.exists():
            try:
                content = log_file.read_text(encoding="utf-8", errors="replace")
                app.root.clipboard_clear()
                app.root.clipboard_append(content)
                messagebox.showinfo(
                    "Success", "Full application logs copied to clipboard."
                )
            except Exception as e:
                messagebox.showerror("Error", f"Could not copy logs: {e}")

    btn_row = ttk.Frame(header)
    btn_row.pack(side="right")

    ttk.Button(btn_row, text="🔄 Refresh", command=_refresh_logs).pack(
        side="left", padx=2
    )
    ttk.Button(btn_row, text="📋 Copy All", command=_copy_all).pack(side="left", padx=2)

    def _open_log_folder():
        import subprocess
        import sys

        log_dir = str(Cfg.LOG_DIR)
        if os.name == "nt":
            os.startfile(log_dir)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", log_dir])
        else:
            subprocess.Popen(["xdg-open", log_dir])

    ttk.Button(
        btn_row,
        text="📂 Open Folder",
        command=_open_log_folder,
    ).pack(side="left", padx=2)

    # Use themed colors from the palette instead of hardcoded values
    log_bg = colors.get("entry_bg", "#161B22")
    log_fg = colors.get("entry_fg", "#E6EDF3")

    txt_area = ScrolledText(
        frame,
        font=GUI_FONT_MONO,
        wrap="none",
        bg=log_bg,
        fg=log_fg,
        insertbackground=log_fg,
        selectbackground=colors.get("select_bg", "#1F3A5F"),
        selectforeground=colors.get("fg", "#E6EDF3"),
        borderwidth=1,
        relief="flat",
        highlightthickness=1,
        highlightbackground=colors.get("border", "#30363D"),
    )
    txt_area.grid(row=1, column=0, sticky="nsew")

    # Color tags for log levels — use palette colors
    txt_area.tag_configure("ERROR", foreground=colors.get("error", "#F85149"))
    txt_area.tag_configure("WARNING", foreground=colors.get("warn", "#D29922"))
    txt_area.tag_configure("INFO", foreground=colors.get("info", "#58A6FF"))
    txt_area.tag_configure("DEBUG", foreground=colors.get("muted", "#8B949E"))

    # Initial load
    _refresh_logs()
    app.log_refresh = _refresh_logs

"""Diagnostic Log Viewer Tab module."""
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import os

from stig_assessor.core.config import Cfg
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_FONT_MONO


def build_log_viewer_tab(app, frame):
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    header = ttk.Frame(frame)
    header.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))
    
    ttk.Label(header, text="Application Events & Diagnostics", font=("TkDefaultFont", 11, "bold")).pack(side="left")
    
    def _refresh_logs():
        log_file = Cfg.LOG_DIR / "stig_assessor.log"
        txt_area.configure(state="normal")
        txt_area.delete("1.0", tk.END)
        
        if not log_file.exists():
            txt_area.insert(tk.END, "Log file not found yet. Perform some actions to generate logs.")
            txt_area.configure(state="disabled")
            return
            
        try:
            # Read last 500 lines
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                tail = lines[-500:]
                txt_area.insert(tk.END, "".join(tail))
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
                messagebox.showinfo("Success", "Full application logs copied to clipboard.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not copy logs: {e}")

    btn_row = ttk.Frame(header)
    btn_row.pack(side="right")
    
    ttk.Button(btn_row, text="🔄 Refresh", command=_refresh_logs).pack(side="left", padx=2)
    ttk.Button(btn_row, text="📋 Copy All", command=_copy_all).pack(side="left", padx=2)
    ttk.Button(btn_row, text="📂 Open Folder", command=lambda: os.startfile(Cfg.LOG_DIR) if os.name == 'nt' else None).pack(side="left", padx=2)

    txt_area = ScrolledText(frame, font=GUI_FONT_MONO, wrap="none", bg="#1e1e1e" if app._current_theme == "dark" else "white", fg="#d4d4d4" if app._current_theme == "dark" else "black")
    txt_area.grid(row=1, column=0, sticky="nsew")
    
    # Color tags for log levels
    txt_area.tag_configure("ERROR", foreground="#f85149")
    txt_area.tag_configure("WARNING", foreground="#d29922")
    txt_area.tag_configure("INFO", foreground="#58a6ff")

    # Initial load
    _refresh_logs()
    app.log_refresh = _refresh_logs

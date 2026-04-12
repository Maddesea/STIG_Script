"""Repair CKL Tab module."""

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import (GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH, GUI_FONT_MONO,
                                          GUI_PADDING, GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION)


def build_repair_tab(app, frame):
    io_frame = ttk.LabelFrame(
        frame,
        text="Repair Corrupted Checklists",
        padding=GUI_PADDING_LARGE,
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Target CKL: *").grid(row=0, column=0, sticky="w")
    app.repair_ckl = tk.StringVar()
    ent_1 = ttk.Entry(io_frame, textvariable=app.repair_ckl, width=GUI_ENTRY_WIDTH)
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_repair_ckl():
        path = filedialog.askopenfilename(
            initialdir=app._last_dir(), filetypes=[("CKL", "*.ckl")]
        )
        if path:
            app.repair_ckl.set(path)

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_repair_ckl,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_1, app.repair_ckl)

    app.repair_backup = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        io_frame,
        text="Create backup copy before altering file",
        variable=app.repair_backup,
    ).grid(row=1, column=1, sticky="w", pady=(GUI_PADDING, 0))

    def _clear_repair_form():
        app.repair_ckl.set("")
        app.repair_backup.set(True)
        app.repair_txt.config(state="normal")
        app.repair_txt.delete("1.0", tk.END)
        app.repair_txt.insert(
            "1.0",
            "Select a CKL file to verify its checksum or repair structural issues.",
        )
        app.repair_txt.config(state="disabled")

    ttk.Button(io_frame, text="🗑 Clear Form", command=_clear_repair_form).grid(
        row=0, column=3, rowspan=2, padx=GUI_PADDING_LARGE
    )

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(pady=GUI_PADDING_SECTION)

    def _do_verify_integrity():
        ckl_path = app.repair_ckl.get().strip()
        if not ckl_path:
            messagebox.showerror("Missing input", "Please select a CKL file to verify.")
            return

        def work():
            return app.proc.verify_integrity(ckl_path)

        def done(result):
            app.repair_txt.config(state="normal")
            app.repair_txt.delete("1.0", tk.END)
            if isinstance(result, Exception):
                app.repair_txt.insert(
                    tk.END, "[ERROR] Integrity Check Failed:\n", "ERROR"
                )
                app.repair_txt.insert(tk.END, f"{result}\n")
                messagebox.showerror("Error", str(result))
            else:
                app.repair_txt.insert(
                    tk.END, "[SUCCESS] Integrity Verification Complete\n\n", "SUCCESS"
                )
                app.repair_txt.insert(
                    tk.END,
                    f"Checksum (SHA3-256):\n{result}\n\nThis checksum proves the file has not been tampered with since creation.\n",
                )
            app.repair_txt.config(state="disabled")

        app.status_var.set("Verifying...")
        app._async(work, done)

    ttk.Button(
        btn_frame,
        text="🔍 Verify Integrity",
        command=_do_verify_integrity,
        width=GUI_BUTTON_WIDTH_WIDE,
    ).pack(side="left", padx=5)

    def _do_repair():
        ckl_path = app.repair_ckl.get().strip()
        if not ckl_path:
            messagebox.showerror("Missing input", "Please select a CKL file to repair.")
            return

        backup = app.repair_backup.get()

        def work():
            return app.proc.repair(ckl_path, backup=backup)

        def done(result):
            app.repair_txt.config(state="normal")
            app.repair_txt.delete("1.0", tk.END)
            if isinstance(result, Exception):
                app.repair_txt.insert(tk.END, "[ERROR] Repair Failed:\n", "ERROR")
                app.repair_txt.insert(tk.END, f"{result}\n")
                messagebox.showerror("Repair Failed", str(result))
            else:
                fixed_lines = result.get("details", [])
                output_file = result.get("file", ckl_path)

                if not fixed_lines:
                    app.repair_txt.insert(
                        tk.END,
                        f"No structural issues found in {Path(ckl_path).name}.\nThe file appears normal.\n",
                        "INFO",
                    )
                    app.status_var.set("✔ Checklist is structurally sound.")
                else:
                    app.repair_txt.insert(
                        tk.END,
                        f"[SUCCESS] Repaired {len(fixed_lines)} anomalies in {Path(ckl_path).name}\n\nDetails:\n",
                        "SUCCESS",
                    )
                    for msg in fixed_lines:
                        app.repair_txt.insert(tk.END, f"- {msg}\n")
                    app.status_var.set(f"✔ Repaired checklist: {output_file}")
                    messagebox.showinfo(
                        "Repair Complete",
                        f"Successfully repaired {len(fixed_lines)} issue(s).",
                    )
            app.repair_txt.config(state="disabled")

        app.status_var.set("Repairing...")
        app._async(work, done)

    btn_repair = ttk.Button(
        btn_frame,
        text="🔧 Repair",
        command=_do_repair,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_repair.pack(side="left", padx=5)
    app._action_buttons.append(btn_repair)
    app.action_repair = _do_repair

    app.repair_txt = ScrolledText(frame, font=GUI_FONT_MONO, height=15)
    app.repair_txt.pack(fill="both", expand=True)

    # Configure color tags
    app.repair_txt.tag_configure("ERROR", foreground="#f85149")
    app.repair_txt.tag_configure("SUCCESS", foreground="#3fb950")
    app.repair_txt.tag_configure("INFO", foreground="#58a6ff")

    app.repair_txt.insert(
        "1.0",
        "Select a CKL file to verify its checksum or repair structural issues.",
        "INFO",
    )
    app.repair_txt.config(state="disabled")

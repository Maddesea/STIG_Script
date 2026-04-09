"""Evidence Manager Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re

from stig_assessor.ui.helpers import Debouncer, ToolTip
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH_SMALL, GUI_FONT_MONO, GUI_FONT_HEADING
from stig_assessor.xml.sanitizer import San


def build_evidence_tab(app, frame):
    ttk.Label(frame, text="Evidence Manager", font=GUI_FONT_HEADING).pack(
        anchor="w"
    )

    import_frame = ttk.LabelFrame(
        frame, text="Import Evidence", padding=GUI_PADDING_LARGE
    )
    import_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
    ttk.Label(import_frame, text="Vuln ID:").grid(row=0, column=0, sticky="w")
    app.evid_vid = tk.StringVar()

    style = ttk.Style()
    style.configure("Invalid.TEntry", foreground="red")

    app.vid_entry = ttk.Entry(
        import_frame,
        textvariable=app.evid_vid,
        width=GUI_ENTRY_WIDTH_SMALL,
    )
    app.vid_entry.grid(row=0, column=1, padx=GUI_PADDING)
    ToolTip(app.vid_entry, "Enter Vulnerability ID (e.g. V-12345)")

    def _validate_vid(*args):
        val = app.evid_vid.get()
        if not val or re.match(r"^V-\d+$", val):
            app.vid_entry.configure(style="TEntry")
            if hasattr(app, "btn_import_evid"):
                app.btn_import_evid.config(state="normal")
        else:
            app.vid_entry.configure(style="Invalid.TEntry")
            if hasattr(app, "btn_import_evid"):
                app.btn_import_evid.config(state="disabled")

    debounced_vid = Debouncer(app.root, 300, _validate_vid)
    app.evid_vid.trace_add("write", debounced_vid)

    ttk.Label(import_frame, text="Description:").grid(
        row=0, column=2, sticky="w"
    )
    app.evid_desc = tk.StringVar()
    ttk.Entry(import_frame, textvariable=app.evid_desc, width=30).grid(
        row=0, column=3, padx=GUI_PADDING
    )
    ttk.Label(import_frame, text="Category:").grid(row=0, column=4, sticky="w")
    app.evid_cat = tk.StringVar(value="general")
    ttk.Entry(import_frame, textvariable=app.evid_cat, width=15).grid(
        row=0, column=5, padx=GUI_PADDING
    )

    def _refresh_evidence_summary():
        for item in app.evid_tree.get_children():
            app.evid_tree.delete(item)
        try:
            manifest = getattr(app.evidence, "metadata", {})
            if not manifest:
                manifest = getattr(app.evidence, "_manifest", {})

            # Check for private dictionary _meta
            if not manifest and hasattr(app.evidence, "_meta"):
                manifest = app.evidence._meta

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
                    app.evid_tree.insert(
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
            if hasattr(app, "evid_stats_label"):
                s = app.evidence.summary()
                text = f"Storage: {s['size_mb']:.1f} MB  |  Files: {s['files']}  |  Mapped VIDs: {s['vulnerabilities']}"
                app.evid_stats_label.config(text=text)
        except Exception:
            import traceback
            traceback.print_exc()

        summary = app.evidence.summary()
        app.evid_status.set(
            f"Vulnerabilities: {summary['vulnerabilities']} | Files: {summary['files']} | Size: {summary['size_mb']:.2f} MB"
        )
    
    app._refresh_evidence_summary = _refresh_evidence_summary

    def _import_evidence():
        vid = app.evid_vid.get()
        if not vid:
            app._show_inline_error(
                app.vid_entry,
                "Missing input: Please enter a vulnerability ID.",
            )
            return
        try:
            San.vuln(vid)
        except Exception as _val_err:
            app._show_inline_error(
                app.vid_entry,
                f"Invalid Vuln ID: Please enter a valid Vuln ID (e.g. V-12345). ({_val_err})",
            )
            return
        path = filedialog.askopenfilename(title="Select evidence file")
        if not path:
            return

        in_desc = app.evid_desc.get()
        in_cat = app.evid_cat.get()

        def work():
            return app.evidence.import_file(
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
                app._refresh_evidence_summary()
                app.evid_vid.set("")
                app.evid_desc.set("")
                app.evid_cat.set("general")

        app._async(work, done)

    app.btn_import_evid = ttk.Button(
        import_frame,
        text="Select & Import…",
        command=_import_evidence,
    )
    app.btn_import_evid.grid(row=0, column=6, padx=GUI_PADDING)

    action_frame = ttk.LabelFrame(
        frame, text="Export / Package", padding=GUI_PADDING_LARGE
    )
    action_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
    
    def _export_evidence():
        path = filedialog.askdirectory(title="Select export directory")
        if not path:
            return

        def work():
            return app.evidence.export_all(path)

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Export error", str(result))
            else:
                messagebox.showinfo(
                    "Evidence Export",
                    f"Exported {result} file(s) to {path}",
                )

        app._async(work, done)

    ttk.Button(
        action_frame, text="Export All…", command=_export_evidence
    ).grid(row=0, column=0, padx=GUI_PADDING, pady=GUI_PADDING)

    def _package_evidence():
        path = filedialog.asksaveasfilename(
            title="Save evidence package",
            defaultextension=".zip",
            filetypes=[("ZIP Files", "*.zip")],
        )
        if not path:
            return

        def work():
            return app.evidence.package(path)

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Package error", str(result))
            else:
                messagebox.showinfo(
                    "Evidence Package", f"Package created:\n{result}"
                )
                app._refresh_evidence_summary()

        app._async(work, done)

    ttk.Button(
        action_frame,
        text="Create Package…",
        command=_package_evidence,
    ).grid(row=0, column=1, padx=GUI_PADDING, pady=GUI_PADDING)

    app.evid_stats_label = ttk.Label(
        action_frame,
        text="",
        font=("", 9, "bold"),
        foreground=app._colors.get("text_muted", "gray"),
    )
    app.evid_stats_label.grid(
        row=0, column=3, padx=GUI_PADDING * 2, sticky="w"
    )

    def _import_evidence_package():
        path = filedialog.askopenfilename(
            title="Select evidence package",
            filetypes=[("ZIP Files", "*.zip")],
        )
        if not path:
            return

        def work():
            return app.evidence.import_package(path)

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Import error", str(result))
            else:
                messagebox.showinfo("Evidence import", f"Imported {result} file(s)")
                app._refresh_evidence_summary()

        app._async(work, done)

    ttk.Button(
        action_frame,
        text="Import Package…",
        command=_import_evidence_package,
    ).grid(row=0, column=2, padx=GUI_PADDING, pady=GUI_PADDING)

    summary_frame = ttk.LabelFrame(
        frame, text="Summary", padding=GUI_PADDING_LARGE
    )
    summary_frame.pack(fill="both", expand=True, pady=GUI_PADDING_LARGE)

    cols = ("vid", "file", "category", "timestamp")
    app.evid_tree = ttk.Treeview(
        summary_frame, columns=cols, show="headings", height=8
    )
    app.evid_tree.heading("vid", text="V-ID")
    app.evid_tree.heading("file", text="Filename")
    app.evid_tree.heading("category", text="Category")
    app.evid_tree.heading("timestamp", text="Timestamp")
    app.evid_tree.column("vid", width=100)
    app.evid_tree.column("file", width=300)
    app.evid_tree.column("category", width=120)
    app.evid_tree.column("timestamp", width=180)

    evid_scroll = ttk.Scrollbar(
        summary_frame, orient="vertical", command=app.evid_tree.yview
    )
    app.evid_tree.configure(yscrollcommand=evid_scroll.set)
    app.evid_tree.pack(side="left", fill="both", expand=True)
    evid_scroll.pack(side="right", fill="y")

    # Context menu for copy
    app._attach_tree_context_menu(app.evid_tree)

    app.evid_status = tk.StringVar()
    ttk.Label(frame, textvariable=app.evid_status, font=GUI_FONT_MONO).pack(
        anchor="w", pady=2
    )

    app._refresh_evidence_summary()

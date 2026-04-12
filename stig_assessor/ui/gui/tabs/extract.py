"""Extract Fixes Tab module."""

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from stig_assessor.core.constants import (GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH, GUI_PADDING,
                                          GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION)
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.ui.helpers import Debouncer, ToolTip


def build_extract_tab(app, frame):
    # Input/Output
    io_frame = ttk.LabelFrame(frame, text="Input & Output", padding=GUI_PADDING_LARGE)
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="XCCDF File: *").grid(row=0, column=0, sticky="w")
    app.extract_xccdf = tk.StringVar()
    ent_ex = ttk.Entry(
        io_frame,
        textvariable=app.extract_xccdf,
        width=GUI_ENTRY_WIDTH,
    )
    ent_ex.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_extract_xccdf():
        path = filedialog.askopenfilename(
            title="Select XCCDF",
            initialdir=app._last_dir(),
            filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")],
        )
        if path:
            app.extract_xccdf.set(path)
            app._remember_file(path)

    ttk.Button(io_frame, text="📂 Browse…", command=_browse_extract_xccdf).grid(
        row=0, column=2
    )
    app._enable_dnd(ent_ex, app.extract_xccdf)
    app._extract_xccdf_err = ttk.Label(
        io_frame, text="", foreground=app._colors.get("error", "red")
    )
    app._extract_xccdf_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

    ttk.Label(io_frame, text="Output Dir: *").grid(row=1, column=0, sticky="w")
    app.extract_outdir = tk.StringVar()
    ent_outdir = ttk.Entry(
        io_frame,
        textvariable=app.extract_outdir,
        width=GUI_ENTRY_WIDTH,
    )
    ent_outdir.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_extract_out():
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            app.extract_outdir.set(path)

    def _open_extract_out():
        path = app.extract_outdir.get()
        if not path or not Path(path).exists():
            messagebox.showwarning(
                "Not Found", "Output directory not set or does not exist."
            )
            return
        import os
        import subprocess
        import sys

        if os.name == "nt":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.call(["open", path])
        else:
            subprocess.call(["xdg-open", path])

    btn_out_frame = ttk.Frame(io_frame)
    btn_out_frame.grid(row=1, column=2)
    ttk.Button(btn_out_frame, text="📂 Browse…", command=_browse_extract_out).pack(
        side="left", padx=(0, 2)
    )
    ttk.Button(btn_out_frame, text="🗁 Open", command=_open_extract_out).pack(
        side="left"
    )

    app._extract_outdir_err = ttk.Label(
        io_frame, text="", foreground=app._colors.get("error", "red")
    )
    app._extract_outdir_err.grid(row=1, column=3, sticky="w", padx=GUI_PADDING)

    ttk.Label(io_frame, text="Filter by Checklist:").grid(row=2, column=0, sticky="w")
    app.extract_checklist = tk.StringVar()
    ent_ckl = ttk.Entry(
        io_frame,
        textvariable=app.extract_checklist,
        width=GUI_ENTRY_WIDTH,
    )
    ent_ckl.grid(row=2, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_extract_ckl():
        path = filedialog.askopenfilename(
            title="Select Checklist (.ckl/.cklb)",
            initialdir=app._last_dir(),
            filetypes=[("Checklist Files", "*.ckl;*.cklb"), ("All Files", "*.*")],
        )
        if path:
            app.extract_checklist.set(path)
            app._remember_file(path)

    ttk.Button(io_frame, text="📂 Browse…", command=_browse_extract_ckl).grid(
        row=2, column=2
    )
    app._enable_dnd(ent_ckl, app.extract_checklist)

    # ═══ FILTERING SECTION ═══
    filter_outer = ttk.Frame(frame)
    filter_outer.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    status_frame = ttk.LabelFrame(
        filter_outer,
        text="Compliance Status Filter (requires Checklist)",
        padding=GUI_PADDING_LARGE,
    )
    status_frame.pack(side="left", fill="x", expand=True, padx=(0, GUI_PADDING))

    app.status_all = tk.BooleanVar(value=False)
    app.status_open = tk.BooleanVar(value=True)
    app.status_not_reviewed = tk.BooleanVar(value=True)
    app.status_na = tk.BooleanVar(value=False)
    app.status_naf = tk.BooleanVar(value=False)

    def _on_status_all_toggle(*args):
        if app.status_all.get():
            # Disable individual checkboxes visually
            for cb in status_checks:
                cb.state(["disabled"])
            # Clear them so they aren't technically selected
            app.status_open.set(False)
            app.status_not_reviewed.set(False)
            app.status_na.set(False)
            app.status_naf.set(False)
        else:
            for cb in status_checks:
                cb.state(["!disabled"])

    app.status_all.trace_add("write", _on_status_all_toggle)

    cb_all = ttk.Checkbutton(status_frame, text="All Statuses", variable=app.status_all)
    cb_all.grid(row=0, column=0, padx=GUI_PADDING_LARGE)

    status_checks = []
    cb_open = ttk.Checkbutton(status_frame, text="Open", variable=app.status_open)
    cb_open.grid(row=0, column=1, padx=GUI_PADDING_LARGE)
    status_checks.append(cb_open)
    cb_nr = ttk.Checkbutton(
        status_frame, text="Not Reviewed", variable=app.status_not_reviewed
    )
    cb_nr.grid(row=0, column=2, padx=GUI_PADDING_LARGE)
    status_checks.append(cb_nr)
    cb_na = ttk.Checkbutton(status_frame, text="Not Applicable", variable=app.status_na)
    cb_na.grid(row=0, column=3, padx=GUI_PADDING_LARGE)
    status_checks.append(cb_na)
    cb_naf = ttk.Checkbutton(status_frame, text="NotAFinding", variable=app.status_naf)
    cb_naf.grid(row=0, column=4, padx=GUI_PADDING_LARGE)
    status_checks.append(cb_naf)

    # ═══ SEVERITY FILTER ═══
    sev_frame = ttk.LabelFrame(
        filter_outer, text="Severity Filter", padding=GUI_PADDING_LARGE
    )
    sev_frame.pack(side="left", fill="x")

    app.extract_sev_high = tk.BooleanVar(value=True)
    app.extract_sev_med = tk.BooleanVar(value=True)
    app.extract_sev_low = tk.BooleanVar(value=True)

    ttk.Checkbutton(sev_frame, text="CAT I", variable=app.extract_sev_high).pack(
        anchor="w"
    )
    ttk.Checkbutton(sev_frame, text="CAT II", variable=app.extract_sev_med).pack(
        anchor="w"
    )
    ttk.Checkbutton(sev_frame, text="CAT III", variable=app.extract_sev_low).pack(
        anchor="w"
    )

    def _clear_extract_form():
        app.extract_xccdf.set("")
        app.extract_outdir.set("")
        app.extract_checklist.set("")
        app.status_all.set(False)
        app.status_open.set(True)
        app.status_not_reviewed.set(True)
        app.status_na.set(False)
        app.status_naf.set(False)
        app.extract_json.set(True)
        app.extract_csv.set(True)
        app.extract_bash.set(True)
        app.extract_ps.set(True)
        app.extract_ansible.set(True)
        app.extract_html_playbook.set(True)
        app.extract_evidence.set(False)
        app.extract_dry.set(False)
        app.extract_rollbacks.set(False)
        app.extract_sev_high.set(True)
        app.extract_sev_med.set(True)
        app.extract_sev_low.set(True)
        # Clear results panel
        if hasattr(app, "_extract_results_var"):
            app._extract_results_var.set("")
        _on_status_all_toggle()

    ttk.Button(io_frame, text="🗑 Clear Form", command=_clear_extract_form).grid(
        row=1, column=4, padx=GUI_PADDING_LARGE
    )

    def _validate_extract_form(*args):
        app._extract_xccdf_err.config(
            text=("* Required" if not app.extract_xccdf.get().strip() else "")
        )
        app._extract_outdir_err.config(
            text=("* Required" if not app.extract_outdir.get().strip() else "")
        )

    debounced_extract = Debouncer(app.root, 300, _validate_extract_form)
    app.extract_xccdf.trace_add("write", debounced_extract)
    app.extract_outdir.trace_add("write", debounced_extract)
    app.root.after(100, debounced_extract)

    # ═══ EXPORT FORMATS ═══
    formats = ttk.LabelFrame(frame, text="Export Formats", padding=GUI_PADDING_LARGE)
    formats.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app.extract_json = tk.BooleanVar(value=True)
    app.extract_csv = tk.BooleanVar(value=True)
    app.extract_bash = tk.BooleanVar(value=True)
    app.extract_ps = tk.BooleanVar(value=True)
    app.extract_ansible = tk.BooleanVar(value=True)
    app.extract_html_playbook = tk.BooleanVar(value=True)

    # Grid for checkbuttons
    ttk.Checkbutton(formats, text="JSON", variable=app.extract_json).grid(
        row=0, column=0, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="CSV", variable=app.extract_csv).grid(
        row=0, column=1, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="Bash", variable=app.extract_bash).grid(
        row=0, column=2, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="PowerShell", variable=app.extract_ps).grid(
        row=0, column=3, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="Ansible", variable=app.extract_ansible).grid(
        row=0, column=4, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(
        formats, text="HTML Playbook", variable=app.extract_html_playbook
    ).grid(row=0, column=5, padx=GUI_PADDING_LARGE)

    opts_frame = ttk.Frame(frame)
    opts_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app.extract_dry = tk.BooleanVar(value=app._settings.get("ext_dry", False))
    app.extract_rollbacks = tk.BooleanVar(value=app._settings.get("ext_roll", False))
    app.extract_evidence = tk.BooleanVar(value=app._settings.get("ext_evid", False))

    def _save_ext_opts(*args):
        app._settings["ext_dry"] = app.extract_dry.get()
        app._settings["ext_roll"] = app.extract_rollbacks.get()
        app._settings["ext_evid"] = app.extract_evidence.get()
        app._save_settings()

    app.extract_dry.trace_add("write", _save_ext_opts)
    app.extract_rollbacks.trace_add("write", _save_ext_opts)
    app.extract_evidence.trace_add("write", _save_ext_opts)

    ttk.Checkbutton(
        opts_frame,
        text="Generate automated evidence gathering scripts (Bash & PowerShell)",
        variable=app.extract_evidence,
    ).pack(anchor="center")
    ttk.Checkbutton(
        opts_frame,
        text="Generate scripts in dry-run mode",
        variable=app.extract_dry,
    ).pack(anchor="center", pady=(5, 0))
    ttk.Checkbutton(
        opts_frame,
        text="Enable PowerShell Registry Rollbacks (`reg export`)",
        variable=app.extract_rollbacks,
    ).pack(anchor="center", pady=(5, 0))

    app.extract_selected_only = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        opts_frame,
        text="Extract / Export only selected vulnerabilities from the preview grid below",
        variable=app.extract_selected_only,
    ).pack(anchor="center", pady=(5, 0))

    # ═══ EXTRACTION RESULTS PANEL ═══
    results_frame = ttk.LabelFrame(
        frame, text="Extraction Results (Preview)", padding=GUI_PADDING
    )
    results_frame.pack(fill="both", expand=True, pady=(0, GUI_PADDING))

    app._extract_results_var = tk.StringVar(value="No extraction performed yet.")
    ttk.Label(
        results_frame,
        textvariable=app._extract_results_var,
        wraplength=900,
        foreground=app._colors.get("info", "blue"),
        font=("TkDefaultFont", 9),
    ).pack(side="bottom", fill="x", padx=5, pady=2)

    paned = ttk.PanedWindow(results_frame, orient=tk.VERTICAL)
    paned.pack(fill="both", expand=True)

    tree_frame = ttk.Frame(paned)
    paned.add(tree_frame, weight=1)

    tree_toolbar = ttk.Frame(tree_frame)
    tree_toolbar.pack(fill="x", pady=(0, 2))

    def _select_all_extract():
        app._extract_preview_tree.selection_set(
            app._extract_preview_tree.get_children()
        )

    def _clear_extract_selection():
        app._extract_preview_tree.selection_remove(
            app._extract_preview_tree.selection()
        )

    ttk.Button(tree_toolbar, text="Select All", command=_select_all_extract).pack(
        side="left", padx=(0, 5)
    )
    ttk.Button(
        tree_toolbar, text="Clear Selection", command=_clear_extract_selection
    ).pack(side="left")

    preview_cols = ("vid", "severity", "platform", "has_cmd")
    app._extract_preview_tree = ttk.Treeview(
        tree_frame,
        columns=preview_cols,
        show="headings",
        height=5,
        selectmode="extended",
    )
    app._extract_preview_tree.heading("vid", text="VID")
    app._extract_preview_tree.heading("severity", text="Severity")
    app._extract_preview_tree.heading("platform", text="Platform")
    app._extract_preview_tree.heading("has_cmd", text="Has Commands")

    app._extract_preview_tree.column("vid", width=120)
    app._extract_preview_tree.column("severity", width=80)
    app._extract_preview_tree.column("platform", width=120)
    app._extract_preview_tree.column("has_cmd", width=100)

    app._extract_preview_tree.pack(side="left", fill="both", expand=True)

    extract_scroll = ttk.Scrollbar(
        tree_frame, orient="vertical", command=app._extract_preview_tree.yview
    )
    extract_scroll.pack(side="right", fill="y")
    app._extract_preview_tree.config(yscrollcommand=extract_scroll.set)

    details_frame = ttk.Frame(paned)
    paned.add(details_frame, weight=1)
    details_frame.columnconfigure(0, weight=1)
    details_frame.columnconfigure(1, weight=1)
    details_frame.rowconfigure(1, weight=1)

    # ═══ EXTRACT DETAILS ═══
    def _copy_to_clip(text):
        app.root.clipboard_clear()
        app.root.clipboard_append(text)
        app.status_var.set("Copied to clipboard.")

    fix_lbl_frame = ttk.Frame(details_frame)
    fix_lbl_frame.grid(row=0, column=0, sticky="ew")
    ttk.Label(fix_lbl_frame, text="Fix Command / Text:").pack(side="left")
    btn_copy_fix = ttk.Button(
        fix_lbl_frame,
        text="📋 Copy",
        command=lambda: _copy_to_clip(app._ext_fix_txt.get("1.0", "end-1c")),
    )
    btn_copy_fix.pack(side="right")

    chk_lbl_frame = ttk.Frame(details_frame)
    chk_lbl_frame.grid(row=0, column=1, sticky="ew", padx=(GUI_PADDING, 0))
    ttk.Label(chk_lbl_frame, text="Check Command / Text:").pack(side="left")
    btn_copy_chk = ttk.Button(
        chk_lbl_frame,
        text="📋 Copy",
        command=lambda: _copy_to_clip(app._ext_chk_txt.get("1.0", "end-1c")),
    )
    btn_copy_chk.pack(side="right")

    from tkinter.scrolledtext import ScrolledText

    from stig_assessor.core.constants import GUI_FONT_MONO

    app._ext_fix_txt = ScrolledText(
        details_frame, height=6, font=GUI_FONT_MONO, wrap="word"
    )
    app._ext_fix_txt.grid(row=1, column=0, sticky="nsew", pady=(2, 0))

    app._ext_chk_txt = ScrolledText(
        details_frame, height=6, font=GUI_FONT_MONO, wrap="word"
    )
    app._ext_chk_txt.grid(
        row=1, column=1, sticky="nsew", padx=(GUI_PADDING, 0), pady=(2, 0)
    )

    app._ext_fixes_cache = {}

    def _on_extract_select(event):
        sel = app._extract_preview_tree.selection()
        app._ext_fix_txt.delete("1.0", tk.END)
        app._ext_chk_txt.delete("1.0", tk.END)
        if not sel:
            return
        vid = app._extract_preview_tree.item(sel[0], "values")[0]
        if vid in app._ext_fixes_cache:
            f = app._ext_fixes_cache[vid]
            app._ext_fix_txt.insert(
                "1.0", f.fix_command or f.fix_text or "No fix details available."
            )
            app._ext_chk_txt.insert(
                "1.0", f.check_command or f.check_text or "No check details available."
            )

    app._extract_preview_tree.bind("<<TreeviewSelect>>", _on_extract_select)

    def _build_severity_filter():
        """Build list of allowed severities from the checkboxes."""
        sevs = []
        if app.extract_sev_high.get():
            sevs.append("high")
        if app.extract_sev_med.get():
            sevs.append("medium")
        if app.extract_sev_low.get():
            sevs.append("low")
        return sevs if len(sevs) < 3 else None  # None = all

    def _do_extract():
        if not app.extract_xccdf.get() or not app.extract_outdir.get():
            app._show_inline_error(
                btn_extract,
                "Missing input: Please provide XCCDF file and output directory.",
            )
            return

        in_xccdf = app.extract_xccdf.get()
        in_ckl = app.extract_checklist.get()
        outdir = Path(app.extract_outdir.get())
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)

        do_json = app.extract_json.get()
        do_csv = app.extract_csv.get()
        do_bash = app.extract_bash.get()
        do_ps = app.extract_ps.get()
        do_ansible = app.extract_ansible.get()
        do_html = app.extract_html_playbook.get()
        do_evidence = app.extract_evidence.get()
        dry = app.extract_dry.get()
        sev_filter = _build_severity_filter()

        # Status filter
        if app.status_all.get():
            status_filter = ["ALL"]
        else:
            status_filter = []
            if app.status_open.get():
                status_filter.append("Open")
            if app.status_not_reviewed.get():
                status_filter.append("Not_Reviewed")
            if app.status_na.get():
                status_filter.append("Not_Applicable")
            if app.status_naf.get():
                status_filter.append("NotAFinding")

        # Gather selection IDs safely in the main thread
        do_selected_only = app.extract_selected_only.get()
        sel_ids = []
        if do_selected_only:
            sel_items = app._extract_preview_tree.selection()
            if not sel_items:
                app._show_inline_error(
                    btn_extract,
                    "Extract Selected Only requires at least one item selected in the preview grid.",
                )
                return
            sel_ids = [
                app._extract_preview_tree.item(item, "values")[0] for item in sel_items
            ]

        def work():
            extractor = FixExt(in_xccdf, checklist=in_ckl if in_ckl else None)
            extractor.extract(status_filter=status_filter if in_ckl else None)

            # Apply severity filter if specified
            if sev_filter:
                extractor.fixes = [
                    f for f in extractor.fixes if f.severity.lower() in sev_filter
                ]

            if do_selected_only:
                extractor.fixes = [f for f in extractor.fixes if f.vid in sel_ids]

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
                enable_rollbacks = app.extract_rollbacks.get()
                extractor.to_powershell(
                    outdir / "Remediate.ps1",
                    dry_run=dry,
                    enable_rollbacks=enable_rollbacks,
                )
                outpaths.append("PowerShell")
            if do_ansible:
                if hasattr(extractor, "to_ansible"):
                    extractor.to_ansible(outdir / "remediate.yml", dry_run=dry)
                outpaths.append("Ansible")
            if do_html:
                try:
                    from stig_assessor.remediation.html_playbook import \
                        generate_html_playbook

                    generate_html_playbook(extractor, str(outdir / "playbook.html"))
                    outpaths.append("HTML Playbook")
                except Exception:
                    pass  # Silently skip if html_playbook module has issues
            if do_evidence:
                extractor.to_evidence_bash(outdir / "gather_evidence.sh")
                extractor.to_evidence_powershell(outdir / "GatherEvidence.ps1")
                outpaths.append("Evidence")

            # Build detailed stats
            stats = extractor.stats_summary()
            with_cmd = sum(1 for f in extractor.fixes if f.fix_command)
            with_check = sum(1 for f in extractor.fixes if f.check_command)
            by_sev = {}
            by_plat = {}
            for f in extractor.fixes:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
                by_plat[f.platform] = by_plat.get(f.platform, 0) + 1

            return {
                "stats": stats,
                "formats": outpaths,
                "with_cmd": with_cmd,
                "with_check": with_check,
                "by_sev": by_sev,
                "by_plat": by_plat,
                "total_fixes": len(extractor.fixes),
                "fixes": extractor.fixes,  # Pass fixes back
            }

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
                app._extract_results_var.set(f"Error: {result}")
                messagebox.showerror("Extraction Failed", str(result))
            else:
                stats = result["stats"]
                fmt_list = ", ".join(result["formats"])
                total = result["total_fixes"]
                with_cmd = result["with_cmd"]
                with_check = result["with_check"]

                # Build severity breakdown
                sev_parts = []
                for s in ["high", "medium", "low"]:
                    cnt = result["by_sev"].get(s, 0)
                    if cnt > 0:
                        label = {
                            "high": "CAT I",
                            "medium": "CAT II",
                            "low": "CAT III",
                        }.get(s, s)
                        sev_parts.append(f"{label}: {cnt}")

                # Build platform breakdown
                plat_parts = [f"{p}: {c}" for p, c in result["by_plat"].items()]

                results_text = (
                    f"✔ Extraction complete  |  "
                    f"Total: {total} findings  |  "
                    f"With fix cmd: {with_cmd}  |  "
                    f"With check cmd: {with_check}  |  "
                    f"Formats: {fmt_list}"
                )

                # Update preview tree
                for row in app._extract_preview_tree.get_children():
                    app._extract_preview_tree.delete(row)

                app._ext_fixes_cache = {}
                extracted_fixes = result.get("fixes", [])
                for f in extracted_fixes[:500]:
                    has_cmd = (
                        "Both"
                        if f.fix_command and f.check_command
                        else (
                            "Fix"
                            if f.fix_command
                            else "Check" if f.check_command else "None"
                        )
                    )
                    app._extract_preview_tree.insert(
                        "", tk.END, values=(f.vid, f.severity, f.platform, has_cmd)
                    )
                    app._ext_fixes_cache[f.vid] = f

                if total > 500:
                    app._extract_preview_tree.insert(
                        "", tk.END, values=("...", "...", "...", f"+{total-500} more")
                    )

                app._extract_results_var.set(results_text)
                app.status_var.set(f"✔ Fix extraction complete.")

                if messagebox.askyesno(
                    "Open Directory",
                    "Extraction successful. Would you like to open the output directory now?",
                ):
                    _open_extract_out()

        app.status_var.set("Processing…")
        app._extract_results_var.set("Extracting fixes… please wait.")
        app._async(work, done)

    def _do_preview():
        """Quick preview: extract in memory and show a summary without writing files."""
        if not app.extract_xccdf.get():
            messagebox.showwarning("Missing Input", "Please provide an XCCDF file.")
            return

        in_xccdf = app.extract_xccdf.get()
        in_ckl = app.extract_checklist.get()
        sev_filter = _build_severity_filter()

        if app.status_all.get():
            status_filter = ["ALL"]
        else:
            status_filter = []
            if app.status_open.get():
                status_filter.append("Open")
            if app.status_not_reviewed.get():
                status_filter.append("Not_Reviewed")
            if app.status_na.get():
                status_filter.append("Not_Applicable")
            if app.status_naf.get():
                status_filter.append("NotAFinding")

        def work():
            extractor = FixExt(in_xccdf, checklist=in_ckl if in_ckl else None)
            extractor.extract(status_filter=status_filter if in_ckl else None)

            if sev_filter:
                extractor.fixes = [
                    f for f in extractor.fixes if f.severity.lower() in sev_filter
                ]

            # Update preview tree instead of popup
            return extractor.fixes

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Preview Error", str(result))
            else:
                fixes = result
                count = len(fixes)
                app._extract_results_var.set(f"Preview: {count} fixes found")

                for row in app._extract_preview_tree.get_children():
                    app._extract_preview_tree.delete(row)

                app._ext_fixes_cache = {}
                for f in fixes[:500]:
                    has_cmd = (
                        "Both"
                        if f.fix_command and f.check_command
                        else (
                            "Fix"
                            if f.fix_command
                            else "Check" if f.check_command else "None"
                        )
                    )
                    app._extract_preview_tree.insert(
                        "", tk.END, values=(f.vid, f.severity, f.platform, has_cmd)
                    )
                    app._ext_fixes_cache[f.vid] = f

                if count > 500:
                    app._extract_preview_tree.insert(
                        "", tk.END, values=("...", "...", "...", f"+{count-500} more")
                    )

        app.status_var.set("Previewing…")
        app._async(work, done)

    # ═══ ACTION BUTTONS ═══
    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=GUI_PADDING_SECTION)

    btn_preview = ttk.Button(
        btn_row,
        text="👁 Quick Preview",
        command=_do_preview,
        width=18,
    )
    btn_preview.pack(side="left", padx=GUI_PADDING)
    ToolTip(btn_preview, "Preview extracted fixes in a table without writing files")

    btn_extract = ttk.Button(
        btn_row,
        text="💾 Extract Fixes",
        command=_do_extract,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_extract.pack(side="left", padx=GUI_PADDING)
    app._action_buttons.append(btn_extract)
    app.action_extract = _do_extract

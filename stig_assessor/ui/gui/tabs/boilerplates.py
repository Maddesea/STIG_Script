"""Boilerplates Tab module."""

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import (GUI_FONT_MONO, GUI_PADDING,
                                          GUI_PADDING_LARGE, Status)
from stig_assessor.io.file_ops import FO
from stig_assessor.processor.html_report import _parse_checklist
from stig_assessor.ui.helpers import ToolTip


def build_boilerplates_tab(app, frame):
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(1, weight=1)

    # ═══ SEARCH / FILTER BAR ═══
    search_frame = ttk.Frame(frame)
    search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, GUI_PADDING))

    ttk.Label(search_frame, text="🔍 Filter VIDs:").pack(side="left", padx=(0, 4))
    bp_search_var = tk.StringVar()
    bp_search_ent = ttk.Entry(search_frame, textvariable=bp_search_var, width=20)
    bp_search_ent.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(search_frame, text="Status Filter:").pack(side="left", padx=(0, 4))
    bp_filter_status = tk.StringVar(value="All")
    ttk.Combobox(
        search_frame,
        textvariable=bp_filter_status,
        values=[
            "All",
            Status.NOT_A_FINDING.value,
            Status.OPEN.value,
            Status.NOT_APPLICABLE.value,
            Status.NOT_REVIEWED.value,
        ],
        state="readonly",
        width=14,
    ).pack(side="left")

    # ═══ LEFT PANEL: VID LIST ═══
    app._bp_left_frame = ttk.LabelFrame(
        frame, text="Vulnerability IDs", padding=GUI_PADDING_LARGE
    )
    left_frame = app._bp_left_frame
    left_frame.grid(row=1, column=0, sticky="nsew", padx=(0, GUI_PADDING_LARGE))

    columns = ("vid", "flags")
    app._bp_vids_list = ttk.Treeview(
        left_frame,
        columns=columns,
        show="headings",
        selectmode="extended",  # Multi-select support
    )
    app._bp_vids_list.heading("vid", text="VID")
    app._bp_vids_list.heading("flags", text="Configs")
    app._bp_vids_list.column("vid", width=120)
    app._bp_vids_list.column("flags", width=80)
    app._bp_vids_list.pack(side="left", fill="both", expand=True)

    scroll_bp = ttk.Scrollbar(
        left_frame, orient="vertical", command=app._bp_vids_list.yview
    )
    scroll_bp.pack(side="right", fill="y")
    app._bp_vids_list.configure(yscrollcommand=scroll_bp.set)

    app._bp_vids_list.tag_configure(
        Status.OPEN.value, foreground=app._colors.get("error", "red")
    )
    app._bp_vids_list.tag_configure(
        Status.NOT_A_FINDING.value,
        foreground=app._colors.get("ok", "green"),
    )
    app._bp_vids_list.tag_configure(
        Status.NOT_REVIEWED.value,
        foreground=app._colors.get("warn", "orange"),
    )

    # ═══ LEFT PANEL: Action Buttons ═══
    left_btn_frame = ttk.Frame(left_frame)
    left_btn_frame.pack(side="bottom", fill="x")

    def _bp_add_vid():
        vid = simpledialog.askstring("Add VID", "Enter STIG Check ID (e.g. V-12345):")
        if vid:
            vid = vid.strip()
            if not vid.startswith("V-") and vid != "V-*":
                msg = (
                    f"'{vid}' does not look like a STIG Vuln ID (V-12345).\nForce add?"
                )
                if not messagebox.askyesno("Invalid VID format", msg):
                    return

            if not app._bp_vids_list.exists(vid):
                app._bp_vids_list.insert("", tk.END, iid=vid, values=(vid, ""))

            app._bp_vids_list.selection_set(vid)
            app._bp_vids_list.focus(vid)
            app._bp_vids_list.see(vid)
            app._bp_vids_list.event_generate("<<TreeviewSelect>>")

    def _bp_bulk_delete():
        selected = list(app._bp_vids_list.selection())
        if not selected:
            messagebox.showinfo("No Selection", "Select VIDs to delete.")
            return
        if not messagebox.askyesno(
            "Confirm Bulk Delete",
            f"Delete ALL boilerplate templates for {len(selected)} VID(s)?\n\nThis cannot be undone.",
        ):
            return
        deleted = 0
        for vid in selected:
            for status_val in [
                Status.NOT_A_FINDING.value,
                Status.OPEN.value,
                Status.NOT_APPLICABLE.value,
                Status.NOT_REVIEWED.value,
            ]:
                if app.proc.boiler.delete(vid, status_val):
                    deleted += 1
        app.status_var.set(
            f"Deleted {deleted} boilerplate entries across {len(selected)} VIDs"
        )
        _bp_refresh_vids()

    def _bp_clone():
        selected = list(app._bp_vids_list.selection())
        if not selected:
            messagebox.showinfo("No Selection", "Select VIDs to clone.")
            return
        target = simpledialog.askstring(
            "Clone Target",
            f"Clone {len(selected)} VID(s) to a new VID.\n\n"
            "Enter a single target VID (e.g. V-99999)\n"
            "or a prefix to auto-number (e.g. V-900):",
        )
        if not target:
            return
        bmap = app.proc.boiler.list_all()
        cloned = 0
        for i, src_vid in enumerate(selected):
            dest = target if len(selected) == 1 else f"{target}{i:02d}"
            src_data = bmap.get(src_vid, {})
            for status_val, entry in src_data.items():
                app.proc.boiler.set(
                    dest,
                    status_val,
                    entry.get("finding_details", ""),
                    entry.get("comments", ""),
                )
                cloned += 1
        app.status_var.set(f"Cloned {cloned} entries")
        _bp_refresh_vids()

    def _bp_import_from_ckl():
        path = filedialog.askopenfilename(
            title="Import Boilerplates from Checklist",
            filetypes=[("Checklist Files", "*.ckl;*.cklb"), ("All Files", "*.*")],
        )
        if not path:
            return

        # Ask user for import options
        overwrite = messagebox.askyesno(
            "Import Options",
            "Overwrite existing templates for VIDs that already have boilerplates?\n\n"
            "Yes = Replace existing templates\n"
            "No = Skip VIDs that already have templates",
        )

        # Ask for status filter
        filter_choice = simpledialog.askstring(
            "Status Filter",
            "Only import from vulns with specific status?\n\n"
            "Enter a status (e.g. NotAFinding, Open) or leave blank for ALL:",
        )
        status_filter = (
            [filter_choice.strip()] if filter_choice and filter_choice.strip() else None
        )

        try:
            result = app.proc.boiler.import_from_checklist(
                path, status_filter=status_filter, overwrite=overwrite
            )
            _bp_refresh_vids()
            app.status_var.set(
                f"Imported {result['imported']} boilerplates from {path}"
            )
            messagebox.showinfo(
                "Import Complete",
                f"Scanned {result['total_scanned']} vulnerabilities.\n"
                f"Imported: {result['imported']}\n"
                f"Skipped: {result['skipped']}",
            )
        except Exception as e:
            messagebox.showerror(
                "Import Error", f"Failed to import from checklist:\n{e}"
            )

    def _bp_reset_defaults():
        if not messagebox.askyesno(
            "Reset to Defaults",
            "This will reset ALL boilerplates to factory defaults.\n\n"
            "Your current custom templates will be LOST.\n\n"
            "Are you sure?",
        ):
            return
        try:
            from stig_assessor.templates.boilerplate import BP

            fresh = BP()
            app.proc.boiler = fresh
            # Also save the fresh defaults
            from stig_assessor.core.config import Cfg

            if Cfg.BOILERPLATE_FILE:
                fresh.export(Cfg.BOILERPLATE_FILE)
            _bp_refresh_vids()
            app.status_var.set("Boilerplates reset to factory defaults.")
        except Exception as e:
            messagebox.showerror("Reset Error", str(e))

    def _bp_reset_single_vid():
        selected = list(app._bp_vids_list.selection())
        if not selected:
            messagebox.showinfo(
                "No Selection", "Select VID(s) to reset to wildcard defaults."
            )
            return
        if not messagebox.askyesno(
            "Reset VID(s)",
            f"Reset {len(selected)} VID(s) to inherit from V-* wildcard?\n\n"
            "Their custom templates will be removed.",
        ):
            return
        reset_count = 0
        for vid in selected:
            if app.proc.boiler.reset_vid(vid):
                reset_count += 1
        app.status_var.set(f"Reset {reset_count} VID(s) to wildcard defaults")
        _bp_refresh_vids()

    def _bp_find_duplicates():
        dupes = app.proc.boiler.find_duplicates()
        if not dupes:
            messagebox.showinfo(
                "No Duplicates",
                "No duplicate boilerplate templates found.\n\nConsider using the V-* wildcard for common templates.",
            )
            return
        msg_lines = [f"Found {len(dupes)} duplicate group(s):\n"]
        for d in dupes[:10]:
            vids_str = ", ".join(d["vids"][:5])
            if len(d["vids"]) > 5:
                vids_str += f" (+{len(d['vids']) - 5} more)"
            msg_lines.append(
                f"  [{d['status']}] {d['field']}: {d['count']} VIDs\n"
                f"    VIDs: {vids_str}\n"
                f"    Text: {d['text_preview'][:60]}…"
            )
        if len(dupes) > 10:
            msg_lines.append(f"\n... and {len(dupes) - 10} more groups.")
        msg_lines.append("\nConsider consolidating these into V-* wildcard templates.")
        messagebox.showinfo("Duplicate Analysis", "\n".join(msg_lines))

    ttk.Button(left_btn_frame, text="+ Add VID", command=_bp_add_vid).pack(
        fill="x", pady=1
    )
    ttk.Button(
        left_btn_frame, text="📥 Import from CKL", command=_bp_import_from_ckl
    ).pack(fill="x", pady=1)
    ttk.Button(left_btn_frame, text="📋 Clone Selected", command=_bp_clone).pack(
        fill="x", pady=1
    )
    ttk.Button(
        left_btn_frame, text="↩ Reset VID to Wildcard", command=_bp_reset_single_vid
    ).pack(fill="x", pady=1)
    ttk.Button(
        left_btn_frame, text="🔎 Find Duplicates", command=_bp_find_duplicates
    ).pack(fill="x", pady=1)
    ttk.Button(left_btn_frame, text="🗑 Bulk Delete", command=_bp_bulk_delete).pack(
        fill="x", pady=1
    )
    ttk.Button(
        left_btn_frame, text="🔄 Reset All Defaults", command=_bp_reset_defaults
    ).pack(fill="x", pady=1)

    # ═══ RIGHT PANEL: EDITOR ═══
    right_frame = ttk.LabelFrame(
        frame, text="Boilerplate Editor", padding=GUI_PADDING_LARGE
    )
    right_frame.grid(row=1, column=1, sticky="nsew")
    right_frame.rowconfigure(1, weight=1)
    right_frame.columnconfigure(0, weight=1)

    ctrl_frame = ttk.Frame(right_frame)
    ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING))

    ttk.Label(ctrl_frame, text="Status:").pack(side="left", padx=5)
    app._bp_status_var = tk.StringVar(value=Status.NOT_A_FINDING.value)
    status_cb = ttk.Combobox(
        ctrl_frame,
        textvariable=app._bp_status_var,
        values=[
            Status.NOT_A_FINDING.value,
            Status.OPEN.value,
            Status.NOT_APPLICABLE.value,
            Status.NOT_REVIEWED.value,
        ],
        state="readonly",
        width=16,
    )
    status_cb.pack(side="left", padx=5)

    apply_frame = ttk.LabelFrame(
        right_frame,
        text="Apply Boilerplates to Target Checklist",
        padding=GUI_PADDING_LARGE,
    )
    apply_frame.grid(row=3, column=0, sticky="ew", pady=(GUI_PADDING_LARGE, 0))

    apply_ctrls = ttk.Frame(apply_frame)
    apply_ctrls.pack(fill="x", pady=2)

    ttk.Label(apply_ctrls, text="Apply Mode:").pack(side="left")
    app._bp_apply_mode_var = tk.StringVar(value="overwrite_empty")
    ttk.Combobox(
        apply_ctrls,
        textvariable=app._bp_apply_mode_var,
        values=["overwrite_empty", "prepend", "append", "merge", "overwrite_all"],
        state="readonly",
        width=18,
    ).pack(side="left", padx=(5, 15))

    # Filters for Apply
    ttk.Label(apply_ctrls, text="Severity Filter:").pack(side="left")
    app._bp_apply_sev_var = tk.StringVar(value="")
    sev_ent = ttk.Entry(apply_ctrls, textvariable=app._bp_apply_sev_var, width=12)
    sev_ent.pack(side="left", padx=(5, 15))
    ToolTip(
        sev_ent, "Comma separated severities (e.g. high, medium). Leave blank for all."
    )

    ttk.Label(apply_ctrls, text="Status Filter:").pack(side="left")
    app._bp_apply_status_var = tk.StringVar(value="")
    stat_ent = ttk.Entry(apply_ctrls, textvariable=app._bp_apply_status_var, width=15)
    stat_ent.pack(side="left", padx=(5, 15))
    ToolTip(
        stat_ent,
        "Comma separated statuses (e.g. Open, NotAFinding). Leave blank for all.",
    )

    # Second Row of Filters
    apply_ctrls_2 = ttk.Frame(apply_frame)
    apply_ctrls_2.pack(fill="x", pady=2)

    ttk.Label(apply_ctrls_2, text="Target VIDs:").pack(side="left")
    app._bp_apply_vids_var = tk.StringVar(value="")
    vids_ent = ttk.Entry(apply_ctrls_2, textvariable=app._bp_apply_vids_var, width=15)
    vids_ent.pack(side="left", padx=(5, 2))
    ToolTip(
        vids_ent, "Comma separated VIDs (e.g. V-12345, V-67890). Leave blank for all."
    )

    def _pull_selected_vids():
        sel = app._bp_vids_list.selection()
        if not sel:
            messagebox.showinfo(
                "No VIDs Selected",
                "Please select one or more VIDs from the left panel list.",
            )
            return
        app._bp_apply_vids_var.set(", ".join(sel))

    ttk.Button(
        apply_ctrls_2, text="← Use Selected", command=_pull_selected_vids, width=14
    ).pack(side="left", padx=(0, 15))

    ttk.Label(apply_ctrls_2, text="Custom Date:").pack(side="left")
    from datetime import datetime

    app._bp_apply_date_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
    date_ent = ttk.Entry(apply_ctrls_2, textvariable=app._bp_apply_date_var, width=15)
    date_ent.pack(side="left", padx=(5, 5))
    ToolTip(
        date_ent,
        "Override {date} variable in templates (format: YYYY-MM-DD). Leave as current or change for retroactive assessment dates.",
    )

    def _reset_date_to_today():
        from datetime import datetime

        app._bp_apply_date_var.set(datetime.now().strftime("%Y-%m-%d"))
        app.status_var.set("Date reset to today.")

    ttk.Button(
        apply_ctrls_2, text="📅 Today", command=_reset_date_to_today, width=8
    ).pack(side="left", padx=(0, 15))

    # Apply Actions
    apply_btn_frame = ttk.Frame(apply_frame)
    apply_btn_frame.pack(fill="x", pady=5)

    def _get_apply_filters():
        sev_str = app._bp_apply_sev_var.get().strip()
        stat_str = app._bp_apply_status_var.get().strip()
        vid_str = app._bp_apply_vids_var.get().strip()

        sevs = [s.strip().lower() for s in sev_str.split(",")] if sev_str else None
        stats = [s.strip() for s in stat_str.split(",")] if stat_str else None
        vids = [v.strip().upper() for v in vid_str.split(",")] if vid_str else None
        return sevs, stats, vids

    def _bp_apply_to_ckl(dry_run=False):
        path = filedialog.askopenfilename(
            title="Select Target Checklist",
            filetypes=[("Checklist Files", "*.ckl;*.cklb")],
        )
        if not path:
            return

        save_path = ""
        if not dry_run:
            save_path = filedialog.asksaveasfilename(
                title="Save Updated Checklist As",
                defaultextension=".ckl",
                initialfile=Path(path).stem + "_bp_applied.ckl",
                filetypes=[("Checklist Files", "*.ckl;*.cklb")],
            )
            if not save_path:
                return

        apply_mode = app._bp_apply_mode_var.get()
        sevs, stats, vids = _get_apply_filters()
        date_override = app._bp_apply_date_var.get().strip() or None

        def work():
            # Set up a hook or just read affected VIDs.
            # Luckily apply_boilerplates returns affected_vids if we track them.
            if dry_run:
                # We do a mock apply to see what's affected.
                # Since apply_boilerplates saves the file, for dry run we save to temp or just rely on backend support.
                # Let's temporarily pass the same path and a dummy out path if we added a dry flag.
                pass
            return app.proc.apply_boilerplates(
                path,
                save_path if not dry_run else str(Path(path).with_suffix(".tmp.ckl")),
                apply_mode=apply_mode,
                severity_filter=sevs,
                status_filter=stats,
                vid_list=vids,
                date_override=date_override,
            )

        def done(res):
            # Clean up dummy
            if dry_run:
                try:
                    Path(path).with_suffix(".tmp.ckl").unlink(missing_ok=True)
                except Exception:
                    pass

            # Update preview grid
            for row in app._bp_apply_tree.get_children():
                app._bp_apply_tree.delete(row)

            if isinstance(res, Exception):
                messagebox.showerror(
                    "Apply Error", f"Failed to apply boilerplates:\n{res}"
                )
                return

            affected = res.get("affected_vids", [])
            for vid in affected:
                app._bp_apply_tree.insert("", tk.END, values=(vid, apply_mode))

            if dry_run:
                app.status_var.set(
                    f"Preview: {res['updated']} items would be updated in {Path(path).name}"
                )
            else:
                app.status_var.set(
                    f"Applied boilerplates to {res['updated']} items in {Path(save_path).name}"
                )
                messagebox.showinfo(
                    "Apply Complete",
                    f"Successfully applied boilerplates to checklist.\n\n"
                    f"Items Updated: {res['updated']}\n"
                    f"Items Skipped: {res['skipped']}\n"
                    f"Total Processed: {res['total_scanned']}\n\n"
                    f"Saved to: {save_path}",
                )

        action = "Previewing" if dry_run else "Applying"
        app.status_var.set(f"{action} boilerplates ({apply_mode}) to checklist...")
        app._async(work, done)

    ttk.Button(
        apply_btn_frame,
        text="👁 Preview Apply...",
        command=lambda: _bp_apply_to_ckl(dry_run=True),
        width=18,
    ).pack(side="left", padx=(0, 10))

    ttk.Button(
        apply_btn_frame,
        text="⚡ Select CKL & Apply...",
        command=lambda: _bp_apply_to_ckl(dry_run=False),
        style="Accent.TButton",
    ).pack(side="left")

    # Preview Treeview
    app._bp_apply_tree = ttk.Treeview(
        apply_frame, columns=("vid", "action"), show="headings", height=4
    )
    app._bp_apply_tree.heading("vid", text="Affected VID")
    app._bp_apply_tree.heading("action", text="Action Taken")
    app._bp_apply_tree.column("vid", width=120)
    app._bp_apply_tree.column("action", width=120)
    app._bp_apply_tree.pack(fill="both", expand=True, pady=(5, 0))

    tree_scroll = ttk.Scrollbar(
        app._bp_apply_tree, orient="vertical", command=app._bp_apply_tree.yview
    )
    app._bp_apply_tree.configure(yscrollcommand=tree_scroll.set)
    tree_scroll.pack(side="right", fill="y")

    # Template variable picker
    ttk.Label(ctrl_frame, text="  Insert:").pack(
        side="left", padx=(GUI_PADDING_LARGE, 2)
    )
    var_picker = tk.StringVar(value="")

    def _insert_variable(*args):
        var = var_picker.get()
        if not var:
            return
        # Insert into whichever text widget has focus
        try:
            focused = app.root.focus_get()
            if focused in (app._bp_finding_text, app._bp_comment_text):
                focused.insert(tk.INSERT, var)
            else:
                # Default to finding text
                app._bp_finding_text.insert(tk.INSERT, var)
        except Exception:
            app._bp_finding_text.insert(tk.INSERT, var)
        var_picker.set("")

    var_cb = ttk.Combobox(
        ctrl_frame,
        textvariable=var_picker,
        values=["{asset}", "{severity}", "{date}", "{vid}", "{rule_title}", "{status}"],
        state="readonly",
        width=12,
    )
    var_cb.pack(side="left")
    var_cb.bind("<<ComboboxSelected>>", _insert_variable)

    editors = ttk.Frame(right_frame)
    editors.grid(row=1, column=0, sticky="nsew")
    editors.columnconfigure(0, weight=1)
    editors.rowconfigure(1, weight=1)
    editors.rowconfigure(3, weight=1)

    ttk.Label(editors, text="Finding Details:").grid(row=0, column=0, sticky="w")
    app._bp_finding_text = ScrolledText(editors, width=60, height=8, font=GUI_FONT_MONO)
    app._bp_finding_text.grid(
        row=1, column=0, sticky="nsew", pady=(0, GUI_PADDING_LARGE)
    )

    ttk.Label(editors, text="Comments:").grid(row=2, column=0, sticky="w")
    app._bp_comment_text = ScrolledText(editors, width=60, height=8, font=GUI_FONT_MONO)
    app._bp_comment_text.grid(row=3, column=0, sticky="nsew")

    # Preview label
    preview_frame = ttk.LabelFrame(
        editors, text="Preview (with variables substituted)", padding=4
    )
    preview_frame.grid(row=4, column=0, sticky="ew", pady=(GUI_PADDING, 0))
    app._bp_preview_var = tk.StringVar(value="")
    ttk.Label(
        preview_frame,
        textvariable=app._bp_preview_var,
        wraplength=600,
        foreground=app._colors.get("info", "blue"),
    ).pack(fill="x")

    def _update_preview(*args):
        finding = app._bp_finding_text.get("1.0", "end-1c")[:200]
        if finding.strip():
            preview = finding.replace("{asset}", "WEBSERVER01").replace(
                "{severity}", "high"
            )
            date_val = app._bp_apply_date_var.get().strip() or datetime.now().strftime(
                "%Y-%m-%d"
            )
            preview = preview.replace("{date}", date_val)
            preview = preview.replace(
                "{timestamp}", datetime.now().strftime("%Y-%m-%d")
            )
            preview = preview.replace("{vid}", app._bp_current_vid or "V-XXXXX")
            preview = preview.replace("{status}", app._bp_status_var.get())
            app._bp_preview_var.set(
                f"Preview: {preview[:180]}…"
                if len(preview) > 180
                else f"Preview: {preview}"
            )
        else:
            app._bp_preview_var.set("")

    app._bp_finding_text.bind("<KeyRelease>", _update_preview)
    app._bp_apply_date_var.trace_add("write", _update_preview)

    app._bp_current_vid = None

    def _load_bp_editor():
        if not app._bp_current_vid:
            return
        status = app._bp_status_var.get()
        bmap = app.proc.boiler.list_all()
        entry = bmap.get(app._bp_current_vid, {}).get(status, {})
        app._bp_finding_text.delete("1.0", tk.END)
        app._bp_comment_text.delete("1.0", tk.END)
        app._bp_finding_text.insert("1.0", entry.get("finding_details", ""))
        app._bp_comment_text.insert("1.0", entry.get("comments", ""))
        _update_preview()

    def _on_bp_vid_select(event):
        sel = app._bp_vids_list.selection()
        if not sel:
            return
        # Load the first selected item when multiple are selected
        app._bp_current_vid = sel[0]
        _load_bp_editor()

    def _on_bp_status_select(event):
        _load_bp_editor()

    app._bp_vids_list.bind("<<TreeviewSelect>>", lambda e: _on_bp_vid_select(e))
    status_cb.bind("<<ComboboxSelected>>", lambda e: _on_bp_status_select(e))

    def _bp_refresh_vids():
        query = bp_search_var.get().lower().strip()
        filter_st = bp_filter_status.get()

        for row in app._bp_vids_list.get_children():
            app._bp_vids_list.delete(row)

        bmap = app.proc.boiler.list_all()

        # If there is a search query, use the backend search method
        if query:
            vids = app.proc.boiler.search(query)
            # Ensure V-* is always at top if it matches or we want to keep it
            if "V-*" in bmap and "V-*" not in vids and "v-*" in query:
                vids.insert(0, "V-*")
        else:
            vids = sorted(list(bmap.keys()))
            if "V-*" not in vids and "V-*" in bmap:
                vids.insert(0, "V-*")
            elif "V-*" in vids:
                vids.remove("V-*")
                vids.insert(0, "V-*")

        display_count = 0
        for v in vids:
            statuses = list(bmap.get(v, {}).keys())
            flags = ",".join(statuses) if statuses else ""

            # Apply status filter
            if filter_st != "All" and filter_st not in statuses:
                continue

            tag = ""
            if Status.OPEN.value in statuses:
                tag = Status.OPEN.value
            elif Status.NOT_A_FINDING.value in statuses:
                tag = Status.NOT_A_FINDING.value
            elif Status.NOT_REVIEWED.value in statuses:
                tag = Status.NOT_REVIEWED.value

            app._bp_vids_list.insert("", tk.END, iid=v, values=(v, flags), tags=(tag,))
            display_count += 1

        app._bp_left_frame.configure(
            text=f"Vulnerability IDs ({display_count} configured)"
        )

    # Wire up search/filter to refresh
    bp_search_var.trace_add("write", lambda *a: _bp_refresh_vids())
    bp_filter_status.trace_add("write", lambda *a: _bp_refresh_vids())

    def _bp_save():
        if not app._bp_current_vid:
            return
        status = app._bp_status_var.get()
        finding = app._bp_finding_text.get("1.0", "end-1c")
        comment = app._bp_comment_text.get("1.0", "end-1c")
        app.proc.boiler.set(app._bp_current_vid, status, finding, comment)
        app.status_var.set(f"Saved boilerplate for {app._bp_current_vid} / {status}")
        _bp_refresh_vids()
        if app._bp_vids_list.exists(app._bp_current_vid):
            app._bp_vids_list.selection_set(app._bp_current_vid)

    def _bp_delete():
        if not app._bp_current_vid:
            return
        status = app._bp_status_var.get()
        if messagebox.askyesno(
            "Confirm Delete",
            f"Delete boilerplate for {app._bp_current_vid} / {status}?",
        ):
            if app.proc.boiler.delete(app._bp_current_vid, status):
                app.status_var.set("Boilerplate deleted.")
                _bp_refresh_vids()
                if app._bp_vids_list.exists(app._bp_current_vid):
                    app._bp_vids_list.selection_set(app._bp_current_vid)
                _load_bp_editor()

    def _bp_clear():
        app._bp_finding_text.delete("1.0", tk.END)
        app._bp_comment_text.delete("1.0", tk.END)
        app._bp_status_var.set(Status.NOT_A_FINDING.value)
        for item in app._bp_vids_list.selection():
            app._bp_vids_list.selection_remove(item)
        app._bp_current_vid = None
        app._bp_preview_var.set("")

    def _bp_export_selection():
        selected = app._bp_vids_list.selection()
        if not selected:
            messagebox.showinfo(
                "Selection Required", "Please select one or more VIDs to export."
            )
            return

        path = filedialog.asksaveasfilename(
            title="Export Selected Boilerplates",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
        )
        if not path:
            return

        try:
            subset = {}
            for item in selected:
                vid = app._bp_vids_list.item(item)["values"][0]
                if vid in app.proc.boiler.templates:
                    subset[vid] = app.proc.boiler.templates[vid]

            import json

            with open(path, "w", encoding="utf-8") as f:
                json.dump(subset, f, indent=2, ensure_ascii=False)
            messagebox.showinfo(
                "Export Successful",
                f"Exported {len(subset)} boilerplate(s) to:\n{path}",
            )
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _bp_import_json():
        path = filedialog.askopenfilename(
            title="Import Boilerplates from JSON",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            app.proc.boiler.imp(path)
            messagebox.showinfo(
                "Import Successful", f"Imported boilerplates from:\n{path}"
            )
            _bp_refresh_vids()
        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    actions = ttk.Frame(right_frame)
    actions.grid(row=2, column=0, sticky="ew", pady=(GUI_PADDING_LARGE, 0))
    ttk.Button(
        actions,
        text="💾 Save",
        command=_bp_save,
        style="Accent.TButton",
    ).pack(side="right", padx=5)
    ttk.Button(actions, text="🗑 Delete Selected", command=_bp_delete).pack(
        side="left", padx=5
    )
    ttk.Button(actions, text="🧹 Clear Form", command=_bp_clear).pack(
        side="left", padx=5
    )
    ttk.Button(actions, text="📤 Export Selected", command=_bp_export_selection).pack(
        side="left", padx=5
    )
    ttk.Button(actions, text="📥 Import JSON", command=_bp_import_json).pack(
        side="left", padx=5
    )

    _bp_refresh_vids()
    app.action_boilerplates = _bp_save

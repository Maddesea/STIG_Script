"""Merge Checklists Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import List

from stig_assessor.ui.helpers import ToolTip
from stig_assessor.core.logging import LOG
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE, GUI_LISTBOX_HEIGHT, GUI_LISTBOX_WIDTH


def build_merge_tab(app, frame):
    # Input Frame
    input_frame = ttk.LabelFrame(
        frame, text="Input Checklists", padding=GUI_PADDING_LARGE
    )
    input_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    input_frame.columnconfigure(1, weight=1)

    ttk.Label(input_frame, text="Base Checklist: *").grid(
        row=0, column=0, sticky="w"
    )
    app.merge_base = tk.StringVar()
    ent_mb = ttk.Entry(
        input_frame,
        textvariable=app.merge_base,
        width=GUI_ENTRY_WIDTH,
    )
    ent_mb.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")
    
    def _browse_merge_base():
        path = filedialog.askopenfilename(
            title="Select base CKL",
            initialdir=app._last_dir(),
            filetypes=[("CKL Files", "*.ckl")],
        )
        if path:
            app.merge_base.set(path)
            app._remember_file(path)

    ttk.Button(
        input_frame, text="📂 Browse…", command=_browse_merge_base
    ).grid(row=0, column=2)
    app._enable_dnd(ent_mb, app.merge_base)

    app._merge_base_err = ttk.Label(
        input_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._merge_base_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

    def _validate_merge_form(*args):
        app._merge_base_err.config(
            text=("* Required" if not app.merge_base.get().strip() else "")
        )

    app.merge_base.trace_add("write", _validate_merge_form)
    app.root.after(100, _validate_merge_form)

    ttk.Label(input_frame, text="History Files:").grid(
        row=1, column=0, sticky="nw", pady=GUI_PADDING
    )
    ttk.Label(input_frame, text="(💡 Drag & drop supported)", font=("TkDefaultFont", 8), foreground="gray").grid(
        row=2, column=0, sticky="nw", padx=(0, 4)
    )

    list_container = ttk.Frame(input_frame)
    list_container.grid(
        row=1,
        column=1,
        rowspan=2,
        padx=GUI_PADDING,
        pady=GUI_PADDING,
        sticky="ew",
    )

    app.merge_list = tk.Listbox(
        list_container,
        height=GUI_LISTBOX_HEIGHT,
        width=GUI_LISTBOX_WIDTH,
    )
    app.merge_list.pack(side="left", fill="both", expand=True)
    scrollbar = ttk.Scrollbar(
        list_container,
        orient="vertical",
        command=app.merge_list.yview,
    )
    scrollbar.pack(side="right", fill="y")
    app.merge_list.config(yscrollcommand=scrollbar.set)

    def _add_merge_hist():
        paths = filedialog.askopenfilenames(
            title="Select historical CKL",
            filetypes=[("CKL Files", "*.ckl")],
        )
        for path in paths:
            if path not in app.merge_histories:
                app.merge_histories.append(path)
                app.merge_list.insert(tk.END, Path(path).name)

    def _add_merge_folder():
        directory = filedialog.askdirectory(
            title="Select Folder containing Historical Checklists",
            initialdir=app._last_dir()
        )
        if not directory:
            return
        added = 0
        for p in Path(directory).rglob("*.ckl"):
            if p.is_file():
                str_p = str(p)
                if str_p not in app.merge_histories:
                    app.merge_histories.append(str_p)
                    app.merge_list.insert(tk.END, p.name)
                    added += 1
        if added:
            LOG.i(f"Added {added} historical checklists from folder")

    def _remove_merge_hist():
        selection = app.merge_list.curselection()
        if not selection:
            return
        index = selection[0]
        path = app.merge_histories.pop(index)
        app.merge_list.delete(index)
        LOG.d(f"Removed historical checklist: {path}")

    def _clear_merge_hist():
        if not app.merge_histories:
            return
        if not messagebox.askyesno(
            "Confirm Clear",
            f"Remove all {len(app.merge_histories)} history file(s)?",
        ):
            return
        app.merge_histories.clear()
        app.merge_list.delete(0, tk.END)

    btn_frame = ttk.Frame(input_frame)
    btn_frame.grid(row=1, column=2, rowspan=2, sticky="n", pady=GUI_PADDING)
    ttk.Button(btn_frame, text="Add Files…", command=_add_merge_hist).pack(
        fill="x", pady=2
    )
    ttk.Button(btn_frame, text="Add Folder…", command=_add_merge_folder).pack(
        fill="x", pady=2
    )
    ttk.Button(btn_frame, text="Remove", command=_remove_merge_hist).pack(
        fill="x", pady=2
    )
    ttk.Button(btn_frame, text="Clear All", command=_clear_merge_hist).pack(
        fill="x", pady=2
    )
    app.merge_histories: List[str] = []

    app._attach_listbox_context_menu(
        app.merge_list, app.merge_histories, _remove_merge_hist
    )

    # Output Frame
    out_frame = ttk.LabelFrame(frame, text="Output", padding=GUI_PADDING_LARGE)
    out_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    ttk.Label(out_frame, text="Merged CKL:").grid(row=0, column=0, sticky="w")
    app.merge_out = tk.StringVar()
    ttk.Entry(
        out_frame, textvariable=app.merge_out, width=GUI_ENTRY_WIDTH
    ).grid(row=0, column=1, padx=GUI_PADDING)
    
    def _browse_merge_out():
        path = filedialog.asksaveasfilename(
            title="Save merged CKL As",
            defaultextension=".ckl",
            filetypes=[("CKL Files", "*.ckl")],
        )
        if path:
            app.merge_out.set(path)

    ttk.Button(
        out_frame, text="📂 Browse…", command=_browse_merge_out
    ).grid(row=0, column=2)

    def _clear_merge_form():
        app.merge_base.set("")
        _clear_merge_hist()
        app.merge_out.set("")
        app.merge_preserve.set(True)
        app.merge_bp.set(True)

    ttk.Button(
        out_frame, text="🗑 Clear Form", command=_clear_merge_form
    ).grid(row=0, column=3, padx=GUI_PADDING_LARGE)

    # Options
    options = ttk.LabelFrame(frame, text="Options", padding=GUI_PADDING_LARGE)
    options.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app.merge_preserve = tk.BooleanVar(value=True)
    cb_preserve = ttk.Checkbutton(
        options,
        text="Preserve full history",
        variable=app.merge_preserve,
    )
    cb_preserve.pack(anchor="w")
    ToolTip(
        cb_preserve,
        "Include formatted history of previous assessments\nin the merged checklist's finding details.",
    )
    app.merge_bp = tk.BooleanVar(value=True)
    cb_merge_bp = ttk.Checkbutton(
        options,
        text="Apply boilerplates when missing",
        variable=app.merge_bp,
    )
    cb_merge_bp.pack(anchor="w")
    ToolTip(
        cb_merge_bp,
        "Fill empty finding details and comments with\ndefault boilerplate text based on the vulnerability status.",
    )

    # ═══ Granular Merge Controls ═══
    granular_frame = ttk.LabelFrame(frame, text="Merge Strategy & Granular Control", padding=GUI_PADDING_LARGE)
    granular_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    # Row 1: Conflict and Text Modes
    strategy_row = ttk.Frame(granular_frame)
    strategy_row.pack(fill="x", pady=(0, GUI_PADDING))

    ttk.Label(strategy_row, text="Conflict Resolution:", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(0, GUI_PADDING))
    app.merge_conflict = tk.StringVar(value="prefer_history")
    conflict_cb = ttk.Combobox(
        strategy_row,
        textvariable=app.merge_conflict,
        values=["prefer_history", "prefer_base", "prefer_most_assessed"],
        state="readonly",
        width=20,
    )
    conflict_cb.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(strategy_row, text="Finding Details Mode:").pack(side="left", padx=(0, 4))
    app.merge_details_mode = tk.StringVar(value="overwrite")
    ttk.Combobox(
        strategy_row,
        textvariable=app.merge_details_mode,
        values=["overwrite", "prepend", "append", "keep_base", "keep_history"],
        state="readonly",
        width=12,
    ).pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(strategy_row, text="Comments Mode:").pack(side="left", padx=(0, 4))
    app.merge_comments_mode = tk.StringVar(value="overwrite")
    ttk.Combobox(
        strategy_row,
        textvariable=app.merge_comments_mode,
        values=["overwrite", "prepend", "append", "keep_base", "keep_history"],
        state="readonly",
        width=12,
    ).pack(side="left")

    # Row 2: Status Mode and Status Filter
    filter_row = ttk.Frame(granular_frame)
    filter_row.pack(fill="x", pady=(GUI_PADDING, 0))

    ttk.Label(filter_row, text="Status Mode:").pack(side="left", padx=(0, 4))
    app.merge_status_mode = tk.StringVar(value="overwrite")
    ttk.Combobox(
        filter_row,
        textvariable=app.merge_status_mode,
        values=["overwrite", "keep_base", "keep_history"],
        state="readonly",
        width=12,
    ).pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(filter_row, text="Filter by Status (comma-sep, optional):").pack(side="left", padx=(0, 4))
    app.merge_status_filter = tk.StringVar(value="")
    ttk.Entry(filter_row, textvariable=app.merge_status_filter, width=20).pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(filter_row, text="Filter by Severity (comma-sep, optional):").pack(side="left", padx=(0, 4))
    app.merge_severity_filter = tk.StringVar(value="")
    ttk.Entry(filter_row, textvariable=app.merge_severity_filter, width=20).pack(side="left")

    # Row 3: Profile Actions
    import json
    profile_row = ttk.Frame(granular_frame)
    profile_row.pack(fill="x", pady=(GUI_PADDING_LARGE, 0))

    def _save_merge_profile():
        path = filedialog.asksaveasfilename(
            title="Save Merge Profile",
            defaultextension=".json",
            filetypes=[("JSON Profile", "*.json")],
        )
        if not path:
            return
        
        profile = {
            "preserve_history": app.merge_preserve.get(),
            "apply_boilerplates": app.merge_bp.get(),
            "conflict": app.merge_conflict.get(),
            "details_mode": app.merge_details_mode.get(),
            "comments_mode": app.merge_comments_mode.get(),
            "status_mode": app.merge_status_mode.get(),
            "status_filter": app.merge_status_filter.get(),
            "severity_filter": app.merge_severity_filter.get(),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2)
            app.status_var.set("Merge profile saved successfully.")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _load_merge_profile():
        path = filedialog.askopenfilename(
            title="Load Merge Profile",
            filetypes=[("JSON Profile", "*.json")],
        )
        if not path:
            return
            
        try:
            with open(path, "r", encoding="utf-8") as f:
                profile = json.load(f)
            if "preserve_history" in profile: app.merge_preserve.set(profile["preserve_history"])
            if "apply_boilerplates" in profile: app.merge_bp.set(profile["apply_boilerplates"])
            if "conflict" in profile: app.merge_conflict.set(profile["conflict"])
            if "details_mode" in profile: app.merge_details_mode.set(profile["details_mode"])
            if "comments_mode" in profile: app.merge_comments_mode.set(profile["comments_mode"])
            if "status_mode" in profile: app.merge_status_mode.set(profile["status_mode"])
            if "status_filter" in profile: app.merge_status_filter.set(profile["status_filter"])
            if "severity_filter" in profile: app.merge_severity_filter.set(profile["severity_filter"])
            app.status_var.set("Merge profile loaded successfully.")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    ttk.Button(profile_row, text="💾 Save Profile", command=_save_merge_profile).pack(side="left", padx=(0, 10))
    ttk.Button(profile_row, text="📂 Load Profile", command=_load_merge_profile).pack(side="left")

    def _build_merge_kwargs():
        """Gather all granular merge parameters from the UI."""
        status_f = [s.strip() for s in app.merge_status_filter.get().split(",")] if app.merge_status_filter.get() else None
        sev_f = [s.strip() for s in app.merge_severity_filter.get().split(",")] if app.merge_severity_filter.get() else None

        return {
            "conflict_resolution": app.merge_conflict.get(),
            "details_mode": app.merge_details_mode.get(),
            "comments_mode": app.merge_comments_mode.get(),
            "status_mode": app.merge_status_mode.get(),
            "status_filter": [s for s in status_f if s] if status_f else None,
            "severity_filter": [s for s in sev_f if s] if sev_f else None,
        }

    # ═══ Merge Preview Panel ═══
    preview_frame = ttk.LabelFrame(frame, text="Affected Rules", padding=GUI_PADDING_LARGE)
    preview_frame.pack(fill="both", expand=True, pady=(0, GUI_PADDING))

    preview_cols = ("vid", "severity", "changes")
    app.merge_preview_tree = ttk.Treeview(
        preview_frame,
        columns=preview_cols,
        show="headings",
        height=5,
        selectmode="extended"
    )
    app.merge_preview_tree.heading("vid", text="VID")
    app.merge_preview_tree.heading("severity", text="Severity")
    app.merge_preview_tree.heading("changes", text="Changes / Status")
    app.merge_preview_tree.column("vid", width=120)
    app.merge_preview_tree.column("severity", width=80)
    app.merge_preview_tree.column("changes", width=500)
    app.merge_preview_tree.pack(side="left", fill="both", expand=True)

    preview_scroll = ttk.Scrollbar(preview_frame, orient="vertical", command=app.merge_preview_tree.yview)
    preview_scroll.pack(side="right", fill="y")
    app.merge_preview_tree.config(yscrollcommand=preview_scroll.set)

    tree_toolbar = ttk.Frame(preview_frame)
    tree_toolbar.pack(fill="x", pady=(5, 0))

    def _select_all_merge():
        app.merge_preview_tree.selection_set(app.merge_preview_tree.get_children())
        
    def _clear_merge_selection():
        app.merge_preview_tree.selection_remove(app.merge_preview_tree.selection())

    ttk.Button(tree_toolbar, text="Select All", command=_select_all_merge).pack(side="left", padx=(0, 5))
    ttk.Button(tree_toolbar, text="Clear Selection", command=_clear_merge_selection).pack(side="left", padx=(0, 15))

    app.merge_selected_only = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        tree_toolbar,
        text="Only merge selected vulnerabilities from preview grid above",
        variable=app.merge_selected_only,
    ).pack(side="left")

    def _do_preview():
        if not app.merge_base.get() or not app.merge_histories:
            messagebox.showinfo("Missing Input", "Base and History files are required for preview.")
            return

        kwargs = _build_merge_kwargs()

        def work():
            return app.proc.merge_preview(
                app.merge_base.get(),
                app.merge_histories,
                status_filter=kwargs.get("status_filter"),
                severity_filter=kwargs.get("severity_filter"),
            )

        def done(res):
            for row in app.merge_preview_tree.get_children():
                app.merge_preview_tree.delete(row)

            if isinstance(res, Exception):
                messagebox.showerror("Preview Failed", str(res))
                return

            preview_list = res.get("preview", [])
            for p in preview_list:
                change_strs = []
                for c in p.get("changes", []):
                    if c["field"] == "status":
                        change_strs.append(f"Status: {c['from']}->{c['to']}")
                    else:
                        change_strs.append(f"{c['field']} length: {c['from_length']}->{c['to_length']}")
                app.merge_preview_tree.insert("", tk.END, values=(
                    p.get("vid", ""),
                    p.get("severity", ""),
                    " | ".join(change_strs)
                ))
            app.status_var.set(f"Preview: {res.get('total_affected', 0)} VIDs would be affected ({res.get('filtered', 0)} filtered)")

        app.status_var.set("Generating preview...")
        app._async(work, done)

    def _do_merge(dry=False):
        if not app.merge_base.get() or not app.merge_histories:
            app._show_inline_error(btn_merge, "Missing input: base and history required.")
            return
        if not dry and not app.merge_out.get():
            app._show_inline_error(btn_merge, "Missing output path.")
            return

        out_path_str = app.merge_out.get() if not dry else app.merge_base.get().replace(".ckl", "_preview.ckl")
        if not dry and Path(out_path_str).exists():
            if not messagebox.askyesno("Overwrite?", f"{Path(out_path_str).name} already exists. Overwrite?"):
                return

        merge_kwargs = _build_merge_kwargs()
        
        # Only inject vid_list if we're actually merging (or dry run merging)
        # and the user explicitly ticked the box.
        if app.merge_selected_only.get():
            sel_items = app.merge_preview_tree.selection()
            if not sel_items:
                messagebox.showwarning("No Selection", "You checked 'Only merge selected' but selected nothing in the preview grid.")
                return
            
            vid_list = [app.merge_preview_tree.item(item, "values")[0] for item in sel_items]
            merge_kwargs["vid_list"] = vid_list

        def work():
            return app.proc.merge_advanced(
                app.merge_base.get(),
                app.merge_histories,
                out_path_str,
                preserve_history=app.merge_preserve.get(),
                apply_boilerplate=app.merge_bp.get(),
                dry=dry,
                **merge_kwargs,
            )

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
                messagebox.showerror("Merge Failed", str(result))
                return

            updated = result.get("updated", 0)
            skipped = result.get("skipped", 0)
            filtered = result.get("filtered", 0)
            
            # Populate summary frame
            app.merge_updated_var.set(f"Updated: {updated}")
            app.merge_skipped_var.set(f"Skipped: {skipped}")
            app.merge_protected_var.set(f"Protected/Filtered: {filtered}")
            
            # Show the results frame if not already packed
            if not getattr(app, '_merge_results_packed', False):
                app.merge_results_frame.pack(fill="x", pady=GUI_PADDING, after=btn_row)
                app._merge_results_packed = True
            
            if dry:
                _do_preview()
                app.status_var.set(f"Dry Run: {updated} would change, {skipped} skipped, {filtered} filtered")
            else:
                _do_preview() # Show actual changes
                out_path = result.get('output')
                app.status_var.set(f"✔ Merged checklist saved: {out_path}")
                
                # Configure open button
                def _open_out():
                    import os, sys, subprocess
                    dir_path = str(Path(out_path).parent)
                    if os.name == "nt": os.startfile(dir_path)
                    elif sys.platform == "darwin": subprocess.call(["open", dir_path])
                    else: subprocess.call(["xdg-open", dir_path])
                    
                app.merge_open_btn.configure(command=_open_out)
                
                messagebox.showinfo(
                    "Merge Complete",
                    f"Merge completed successfully.\n\n"
                    f"Updated: {updated}\n"
                    f"Skipped: {skipped}\n"
                    f"Filtered out: {filtered}",
                )

        app.status_var.set("Processing merge...")
        app._async(work, done)

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=GUI_PADDING_SECTION)

    btn_preview = ttk.Button(
        btn_row,
        text="👁 Preview Merge",
        command=lambda: _do_merge(dry=True),
        width=18,
    )
    btn_preview.pack(side="left", padx=GUI_PADDING)
    ToolTip(btn_preview, "Run a dry-run merge to preview what would change\nwithout writing any files.")

    btn_merge = ttk.Button(
        btn_row,
        text="🔀 Merge Checklists",
        command=lambda: _do_merge(dry=False),
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_merge.pack(side="left", padx=GUI_PADDING)
    app._action_buttons.append(btn_merge)
    app.action_merge = lambda: _do_merge(dry=False)

    # ═══ Merge Results Panel ═══
    app.merge_results_frame = ttk.LabelFrame(frame, text="Merge Results Summary", padding=GUI_PADDING_LARGE)
    
    stats_row = ttk.Frame(app.merge_results_frame)
    stats_row.pack(fill="x", pady=5)
    
    app.merge_updated_var = tk.StringVar(value="Updated: 0")
    app.merge_skipped_var = tk.StringVar(value="Skipped: 0")
    app.merge_protected_var = tk.StringVar(value="Protected/Filtered: 0")
    
    ttk.Label(stats_row, textvariable=app.merge_updated_var, foreground="#10b981", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(0, GUI_PADDING_LARGE))
    ttk.Label(stats_row, textvariable=app.merge_skipped_var, foreground="#6b7280", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=GUI_PADDING_LARGE)
    ttk.Label(stats_row, textvariable=app.merge_protected_var, foreground="#f59e0b", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=GUI_PADDING_LARGE)
    
    app.merge_open_btn = ttk.Button(stats_row, text="📂 Open Output Folder")
    app.merge_open_btn.pack(side="right")



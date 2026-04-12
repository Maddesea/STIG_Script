"""Interactive Assessment Editor Tab module."""

import tkinter as tk
import xml.etree.ElementTree as ET
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import (GUI_ENTRY_WIDTH_MEDIUM,
                                          GUI_FONT_HEADING, GUI_FONT_MONO,
                                          GUI_FONT_NORMAL, GUI_PADDING,
                                          GUI_PADDING_LARGE, Status)
from stig_assessor.io.file_ops import FO
from stig_assessor.processor.html_report import _parse_checklist
from stig_assessor.remediation.extractor import FixExt
from stig_assessor.ui.helpers import TextContextMenu, ToolTip


def build_editor_tab(app, frame):
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    # ── TOP BAR: File Loading ──
    top_frame = ttk.Frame(frame)
    top_frame.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))

    file_row = ttk.Frame(top_frame)
    file_row.pack(fill="x")

    ttk.Label(file_row, text="Active Checklist:").pack(side="left")
    app.editor_ckl_var = tk.StringVar()
    ent = ttk.Entry(file_row, textvariable=app.editor_ckl_var, width=60)
    ent.pack(side="left", padx=GUI_PADDING)
    app._enable_dnd(ent, app.editor_ckl_var)

    app._editor_findings_cache = []
    app._editor_current_vid = None
    app._editor_active_xml_tree = None
    app._editor_ckl_path = None

    def _load_checklist():
        path = app.editor_ckl_var.get().strip()
        if not path:
            return
        try:
            resolved_path = Path(path).resolve()
            data = _parse_checklist(resolved_path)
            app._editor_findings_cache = data.get("vulns", [])
            app._editor_ckl_path = resolved_path
            app._editor_active_xml_tree = FO.parse_xml(app._editor_ckl_path)
            _refresh_editor_list()
            app.status_var.set(
                f"Loaded {len(app._editor_findings_cache)} vulnerabilities."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load: {e}")

    app._editor_load = _load_checklist

    ttk.Button(file_row, text="📂 Load", command=_load_checklist).pack(
        side="left", padx=GUI_PADDING
    )

    # Mini Progress Dashboard
    status_summary_frame = ttk.Frame(top_frame)
    status_summary_frame.pack(fill="x", pady=(5, 0))

    app._editor_stats_open = tk.StringVar(value="Open: 0")
    app._editor_stats_naf = tk.StringVar(value="NotAFinding: 0")
    app._editor_stats_nr = tk.StringVar(value="Not Reviewed: 0")
    app._editor_stats_na = tk.StringVar(value="N/A: 0")

    ttk.Label(
        status_summary_frame,
        textvariable=app._editor_stats_open,
        foreground="#ef4444",
        font=(GUI_FONT_NORMAL[0], 9, "bold"),
    ).pack(side="left", padx=GUI_PADDING)
    ttk.Label(
        status_summary_frame,
        textvariable=app._editor_stats_naf,
        foreground="#10b981",
        font=(GUI_FONT_NORMAL[0], 9, "bold"),
    ).pack(side="left", padx=GUI_PADDING)
    ttk.Label(
        status_summary_frame,
        textvariable=app._editor_stats_nr,
        foreground="#f59e0b",
        font=(GUI_FONT_NORMAL[0], 9, "bold"),
    ).pack(side="left", padx=GUI_PADDING)
    ttk.Label(
        status_summary_frame,
        textvariable=app._editor_stats_na,
        foreground="#6b7280",
        font=(GUI_FONT_NORMAL[0], 9, "bold"),
    ).pack(side="left", padx=GUI_PADDING)

    # Progress Bar
    progress_frame = ttk.Frame(top_frame)
    progress_frame.pack(fill="x", pady=(2, 0))
    app._editor_progress_var = tk.DoubleVar()
    app._editor_progress_text = tk.StringVar(value="0/0 (0%)")
    ttk.Progressbar(
        progress_frame, variable=app._editor_progress_var, maximum=100
    ).pack(side="left", fill="x", expand=True, padx=(0, GUI_PADDING))
    ttk.Label(
        progress_frame,
        textvariable=app._editor_progress_text,
        font=(GUI_FONT_NORMAL[0], 9),
    ).pack(side="left")

    search_row = ttk.Frame(top_frame)
    search_row.pack(fill="x", pady=(5, 0))

    search_var = tk.StringVar()
    filter_status_var = tk.StringVar(value="All Statuses")

    def _on_search(*args):
        _refresh_editor_list()

    search_var.trace_add("write", _on_search)
    filter_status_var.trace_add("write", _on_search)

    ttk.Label(search_row, text="🔍").pack(side="left", padx=(0, 2))
    app._editor_search_ent = ttk.Entry(search_row, textvariable=search_var, width=20)
    app._editor_search_ent.pack(side="left")

    ttk.Label(search_row, text="Filter:").pack(side="left", padx=(GUI_PADDING_LARGE, 2))
    status_filter_cb = ttk.Combobox(
        search_row,
        textvariable=filter_status_var,
        values=[
            "All Statuses",
            Status.OPEN.value,
            Status.NOT_A_FINDING.value,
            Status.NOT_REVIEWED.value,
            Status.NOT_APPLICABLE.value,
        ],
        state="readonly",
        width=15,
    )
    status_filter_cb.pack(side="left")

    def _export_remediation():
        if not app._editor_active_xml_tree or not hasattr(app, "_editor_ckl_path"):
            messagebox.showwarning("Warning", "Please load a checklist first.")
            return

        # Simple dialog for remediation options
        dialog = tk.Toplevel(app.root)
        dialog.title("Generate Remediation Playbook")
        dialog.geometry("450x400")
        dialog.transient(app.root)
        dialog.grab_set()

        content = ttk.Frame(dialog, padding=GUI_PADDING_LARGE)
        content.pack(fill="both", expand=True)

        ttk.Label(
            content, text="Target Platform:", font=(GUI_FONT_NORMAL[0], 10, "bold")
        ).pack(anchor="w")
        platform_var = tk.StringVar(value="windows")
        ttk.Radiobutton(
            content, text="Windows (PowerShell)", variable=platform_var, value="windows"
        ).pack(anchor="w", padx=10)
        ttk.Radiobutton(
            content, text="Linux (Bash)", variable=platform_var, value="linux"
        ).pack(anchor="w", padx=10)

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(
            content, text="Filter by Status:", font=(GUI_FONT_NORMAL[0], 10, "bold")
        ).pack(anchor="w")

        status_vars = {}
        for s in [
            Status.OPEN.value,
            Status.NOT_REVIEWED.value,
            Status.NOT_A_FINDING.value,
            Status.NOT_APPLICABLE.value,
        ]:
            var = tk.BooleanVar(
                value=(s in [Status.OPEN.value, Status.NOT_REVIEWED.value])
            )
            status_vars[s] = var
            ttk.Checkbutton(content, text=s, variable=var).pack(anchor="w", padx=10)

        def _select_all_status():
            for v in status_vars.values():
                v.set(True)

        ttk.Button(
            content, text="Select All", command=_select_all_status, style="Text.TButton"
        ).pack(anchor="w", padx=10)

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(
            content, text="Filter by Severity:", font=(GUI_FONT_NORMAL[0], 10, "bold")
        ).pack(anchor="w")

        sev_vars = {}
        for sev, lbl in [
            ("high", "CAT I (High)"),
            ("medium", "CAT II (Medium)"),
            ("low", "CAT III (Low)"),
        ]:
            var = tk.BooleanVar(value=True)
            sev_vars[sev] = var
            ttk.Checkbutton(content, text=lbl, variable=var).pack(anchor="w", padx=10)

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(
            content, text="Script Options:", font=(GUI_FONT_NORMAL[0], 10, "bold")
        ).pack(anchor="w")
        dry_var = tk.BooleanVar(value=app._settings.get("ext_dry", False))
        ttk.Checkbutton(
            content, text="Dry-Run (Print Commands Without Executing)", variable=dry_var
        ).pack(anchor="w", padx=10)
        rollback_var = tk.BooleanVar(value=app._settings.get("ext_roll", False))
        ttk.Checkbutton(
            content,
            text="Enable PowerShell Registry Rollbacks (`reg export`)",
            variable=rollback_var,
        ).pack(anchor="w", padx=10)
        evidence_var = tk.BooleanVar(value=app._settings.get("ext_evid", False))
        ttk.Checkbutton(
            content, text="Generate Evidence Collection Scripts", variable=evidence_var
        ).pack(anchor="w", padx=10)

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(
            content,
            text="Target VIDs (Optional, comma-separated):",
            font=(GUI_FONT_NORMAL[0], 10, "bold"),
        ).pack(anchor="w")
        vid_filter_var = tk.StringVar()
        ttk.Entry(content, textvariable=vid_filter_var).pack(
            fill="x", padx=10, pady=(0, 5)
        )

        def _save_editor_opts(*args):
            app._settings["ext_dry"] = dry_var.get()
            app._settings["ext_roll"] = rollback_var.get()
            app._settings["ext_evid"] = evidence_var.get()
            app._save_settings()

        dry_var.trace_add("write", _save_editor_opts)
        rollback_var.trace_add("write", _save_editor_opts)
        evidence_var.trace_add("write", _save_editor_opts)

        def _generate():
            selected_statuses = [s for s, v in status_vars.items() if v.get()]
            if not selected_statuses:
                messagebox.showwarning(
                    "No Status Selected", "Please select at least one status."
                )
                return

            selected_sevs = [s for s, v in sev_vars.items() if v.get()]
            if not selected_sevs:
                messagebox.showwarning(
                    "No Severity Selected", "Please select at least one severity."
                )
                return

            xccdf_path = filedialog.askopenfilename(
                title="Select Source Benchmark (XCCDF/XML)",
                filetypes=[("XML files", "*.xml")],
            )
            if not xccdf_path:
                return

            out_dir = filedialog.askdirectory(title="Select Output Directory")
            if not out_dir:
                return

            try:
                ext = FixExt(xccdf_path, checklist=app._editor_ckl_path)

                # Fetch target VIDs from the entry
                vid_raw = vid_filter_var.get().strip()
                vids = (
                    [v.strip().upper() for v in vid_raw.split(",") if v.strip()]
                    if vid_raw
                    else None
                )

                ext.extract(status_filter=selected_statuses, vid_include=vids)

                if len(selected_sevs) < 3:
                    ext.fixes = [
                        f for f in ext.fixes if f.severity.lower() in selected_sevs
                    ]

                plat = platform_var.get()
                out_name = (
                    f"remediate_{plat}.ps1"
                    if plat == "windows"
                    else f"remediate_{plat}.sh"
                )
                out_path = Path(out_dir) / out_name

                if plat == "windows":
                    ext.to_powershell(
                        out_path,
                        dry_run=dry_var.get(),
                        enable_rollbacks=rollback_var.get(),
                    )
                else:
                    ext.to_bash(out_path, dry_run=dry_var.get())

                if evidence_var.get():
                    if plat == "windows":
                        ext.to_evidence_powershell(
                            Path(out_dir) / f"gather_evidence_{plat}.ps1"
                        )
                    else:
                        ext.to_evidence_bash(
                            Path(out_dir) / f"gather_evidence_{plat}.sh"
                        )

                dialog.destroy()
                messagebox.showinfo(
                    "Success",
                    f"Playbook generated successfully:\n{out_path}\n\nEvidence mapping logs and scripts are in the output directory.",
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate playbook: {e}")

        btn_frame = ttk.Frame(content)
        btn_frame.pack(side="bottom", fill="x", pady=(20, 0))
        ttk.Button(btn_frame, text="Generate Playbook", command=_generate).pack(
            side="right"
        )
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(
            side="right", padx=GUI_PADDING
        )

    ttk.Button(
        search_row, text="🛠 Remediation Playbook", command=_export_remediation
    ).pack(side="right", padx=(GUI_PADDING, 0))

    # Filter Persistence
    if hasattr(app, "_editor_filter_state"):
        search_var.set(app._editor_filter_state.get("query", ""))
        filter_status_var.set(app._editor_filter_state.get("status", "All Statuses"))

    def _save_filter_state():
        app._editor_filter_state = {
            "query": search_var.get(),
            "status": filter_status_var.get(),
        }

    status_filter_cb.bind("<<ComboboxSelected>>", lambda e: _save_filter_state())

    # ── MAIN SPLIT VIEW ──
    pw = ttk.PanedWindow(frame, orient="horizontal")
    pw.grid(row=1, column=0, sticky="nsew")

    # LEFT: VULN LIST
    list_frame = ttk.Frame(pw)
    pw.add(list_frame, weight=1)

    columns = ("vid", "severity", "status")
    app._editor_tree = ttk.Treeview(
        list_frame, columns=columns, show="headings", selectmode="extended"
    )
    app._editor_tree.heading("vid", text="VID")
    app._editor_tree.heading("severity", text="Severity")
    app._editor_tree.heading("status", text="Status")
    app._editor_tree.column("vid", width=100, anchor="w")
    app._editor_tree.column("severity", width=70, anchor="center")
    app._editor_tree.column("status", width=90, anchor="center")

    scroll_tree = ttk.Scrollbar(
        list_frame, orient="vertical", command=app._editor_tree.yview
    )
    app._editor_tree.configure(yscrollcommand=scroll_tree.set)
    app._editor_tree.pack(side="left", fill="both", expand=True)
    scroll_tree.pack(side="right", fill="y")

    app._editor_tree.tag_configure(
        Status.OPEN.value, foreground=app._colors.get("error", "red")
    )
    app._editor_tree.tag_configure(
        Status.NOT_A_FINDING.value, foreground=app._colors.get("ok", "green")
    )
    app._editor_tree.tag_configure(
        Status.NOT_REVIEWED.value, foreground=app._colors.get("warn", "orange")
    )
    app._editor_tree.tag_configure(
        Status.NOT_APPLICABLE.value, foreground=app._colors.get("info", "gray")
    )

    # Context Menu for Quick Status
    ctx = tk.Menu(app._editor_tree, tearoff=0)

    def _quick_set_status(new_status):
        selections = app._editor_tree.selection()
        if not selections or not app._editor_active_xml_tree:
            return
        for vid in selections:
            vuln = next(
                (v for v in app._editor_findings_cache if v.get("vid") == vid), {}
            )
            _update_xml_vuln(
                vid, new_status, vuln.get("finding", ""), vuln.get("comment", "")
            )
        FO.write_ckl(app._editor_active_xml_tree, app._editor_ckl_path)
        app.status_var.set(f"Quick-set {len(selections)} rules to {new_status}")
        _refresh_editor_list()

    ctx.add_command(
        label="✓ Mark NotAFinding",
        command=lambda: _quick_set_status(Status.NOT_A_FINDING.value),
    )
    ctx.add_command(
        label="⚠ Mark Open", command=lambda: _quick_set_status(Status.OPEN.value)
    )
    ctx.add_command(
        label="⊘ Mark NotApplicable",
        command=lambda: _quick_set_status(Status.NOT_APPLICABLE.value),
    )
    ctx.add_separator()
    ctx.add_command(
        label="📋 Apply Boilerplate", command=lambda: _execute_bulk_boilerplate()
    )

    def _show_ctx(event):
        item = app._editor_tree.identify_row(event.y)
        if item:
            if item not in app._editor_tree.selection():
                app._editor_tree.selection_set(item)
            ctx.tk_popup(event.x_root, event.y_root)

    app._editor_tree.bind("<Button-3>", _show_ctx)

    # RIGHT: EDITOR PANE
    editor_frame = ttk.LabelFrame(
        pw, text="Assessment Details", padding=GUI_PADDING_LARGE
    )
    pw.add(editor_frame, weight=3)
    editor_frame.columnconfigure(0, weight=1)
    editor_frame.rowconfigure(0, weight=1)

    single_pane = ttk.Frame(editor_frame)
    single_pane.columnconfigure(0, weight=1)

    bulk_pane = ttk.Frame(editor_frame)
    bulk_pane.columnconfigure(0, weight=1)

    single_pane.grid(row=0, column=0, sticky="nsew")

    # ==========================
    # SINGLE PANE COMPONENTS
    # ==========================
    status_row = ttk.Frame(single_pane)
    status_row.pack(fill="x", pady=GUI_PADDING)
    ttk.Label(status_row, text="Status:", font=("TkDefaultFont", 10, "bold")).pack(
        side="left", padx=(0, GUI_PADDING)
    )

    app._editor_status_var = tk.StringVar(value=Status.NOT_REVIEWED.value)
    status_cb = ttk.Combobox(
        status_row,
        textvariable=app._editor_status_var,
        values=[
            Status.NOT_A_FINDING.value,
            Status.OPEN.value,
            Status.NOT_APPLICABLE.value,
            Status.NOT_REVIEWED.value,
        ],
        state="readonly",
        width=20,
    )
    status_cb.pack(side="left")

    app._editor_rule_title_var = tk.StringVar()
    ttk.Label(
        status_row,
        textvariable=app._editor_rule_title_var,
        foreground=app._colors.get("info", "blue"),
        wraplength=400,
    ).pack(side="left", padx=GUI_PADDING_LARGE)

    app._editor_severity_var = tk.StringVar()
    app._editor_severity_lbl = ttk.Label(
        status_row,
        textvariable=app._editor_severity_var,
        font=("TkDefaultFont", 10, "bold"),
    )
    app._editor_severity_lbl.pack(side="right", padx=GUI_PADDING_LARGE)

    app._editor_is_dirty = False

    def _mark_dirty(*args):
        app._editor_is_dirty = True

    app._editor_status_var.trace_add("write", _mark_dirty)

    ttk.Label(single_pane, text="Finding Details (Right-click to Copy/Paste):").pack(
        anchor="w", pady=(GUI_PADDING, 2)
    )
    app._editor_details_txt = ScrolledText(
        single_pane, width=60, height=8, font=GUI_FONT_MONO
    )
    app._editor_details_txt.pack(fill="x", pady=(0, GUI_PADDING))
    app._editor_details_txt.bind("<KeyRelease>", _mark_dirty)
    TextContextMenu(app._editor_details_txt)

    ttk.Label(single_pane, text="Comments (Right-click to Copy/Paste):").pack(
        anchor="w", pady=(GUI_PADDING, 2)
    )
    app._editor_comments_txt = ScrolledText(
        single_pane, width=60, height=5, font=GUI_FONT_MONO
    )
    app._editor_comments_txt.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app._editor_comments_txt.bind("<KeyRelease>", _mark_dirty)
    TextContextMenu(app._editor_comments_txt)

    info_pw = ttk.PanedWindow(single_pane, orient="horizontal")
    info_pw.pack(fill="both", expand=True)

    chk_frame = ttk.LabelFrame(info_pw, text="Check Content")
    info_pw.add(chk_frame, weight=1)
    app._editor_chk_txt = ScrolledText(
        chk_frame, width=30, height=8, wrap="word", state="disabled"
    )
    app._editor_chk_txt.pack(fill="both", expand=True, padx=2, pady=2)

    chk_btn = ttk.Button(
        chk_frame,
        text="📋 Copy",
        command=lambda: _copy_text_widget(app._editor_chk_txt),
    )
    chk_btn.pack(side="right", padx=2, pady=2)
    ToolTip(chk_btn, "Copy Check Content to Clipboard")

    fix_frame = ttk.LabelFrame(info_pw, text="Fix Text")
    info_pw.add(fix_frame, weight=1)
    app._editor_fix_txt = ScrolledText(
        fix_frame, width=30, height=8, wrap="word", state="disabled"
    )
    app._editor_fix_txt.pack(fill="both", expand=True, padx=2, pady=2)

    fix_btn = ttk.Button(
        fix_frame,
        text="📋 Copy",
        command=lambda: _copy_text_widget(app._editor_fix_txt),
    )
    fix_btn.pack(side="right", padx=2, pady=2)
    ToolTip(fix_btn, "Copy Fix Text to Clipboard")

    def _copy_text_widget(widget):
        content = widget.get("1.0", tk.END).strip()
        if content:
            app.root.clipboard_clear()
            app.root.clipboard_append(content)
            app.status_var.set("Copied text to clipboard.")

    app._editor_chk_txt.bind(
        "<Double-Button-1>", lambda e: _copy_text_widget(app._editor_chk_txt)
    )
    app._editor_fix_txt.bind(
        "<Double-Button-1>", lambda e: _copy_text_widget(app._editor_fix_txt)
    )

    btn_row = ttk.Frame(single_pane)
    btn_row.pack(fill="x", pady=GUI_PADDING)

    def _save_current_finding():
        if not app._editor_current_vid or not app._editor_active_xml_tree:
            return

        new_status = app._editor_status_var.get()
        new_details = app._editor_details_txt.get("1.0", "end-1c")
        new_comments = app._editor_comments_txt.get("1.0", "end-1c")

        _update_xml_vuln(app._editor_current_vid, new_status, new_details, new_comments)

        try:
            FO.write_ckl(app._editor_active_xml_tree, app._editor_ckl_path)
            app._editor_is_dirty = False
            app.status_var.set(
                f"Saved {app._editor_current_vid} directly to checklist."
            )
            _refresh_editor_list()
            app._editor_tree.selection_set(app._editor_current_vid)
            app._editor_tree.focus(app._editor_current_vid)
            app._editor_tree.see(app._editor_current_vid)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def _update_severity_badge(severity):
        sev_lower = (severity or "unknown").lower()
        if sev_lower == "high":
            app._editor_severity_lbl.configure(foreground="#ef4444")
            app._editor_severity_var.set("CAT I (High)")
        elif sev_lower == "medium":
            app._editor_severity_lbl.configure(foreground="#f59e0b")
            app._editor_severity_var.set("CAT II (Medium)")
        elif sev_lower == "low":
            app._editor_severity_lbl.configure(foreground="#3b82f6")
            app._editor_severity_var.set("CAT III (Low)")
        else:
            app._editor_severity_lbl.configure(foreground="gray")
            app._editor_severity_var.set(severity or "")

    def _update_xml_vuln(vid, new_status, new_details, new_comments):
        root = app._editor_active_xml_tree.getroot()
        vulns = root.findall(".//VULN")
        for vuln in vulns:
            vuln_vid = None
            for attr_node in vuln.findall("STIG_DATA"):
                if (
                    attr_node.find("VULN_ATTRIBUTE") is not None
                    and attr_node.find("VULN_ATTRIBUTE").text == "Vuln_Num"
                ):
                    if attr_node.find("ATTRIBUTE_DATA") is not None:
                        vuln_vid = attr_node.find("ATTRIBUTE_DATA").text
                        break

            if vuln_vid == vid:
                node_s = vuln.find("STATUS")
                if node_s is not None:
                    node_s.text = new_status
                else:
                    ET.SubElement(vuln, "STATUS").text = new_status

                node_f = vuln.find("FINDING_DETAILS")
                if node_f is not None:
                    node_f.text = new_details
                else:
                    ET.SubElement(vuln, "FINDING_DETAILS").text = new_details

                node_c = vuln.find("COMMENTS")
                if node_c is not None:
                    node_c.text = new_comments
                else:
                    ET.SubElement(vuln, "COMMENTS").text = new_comments

                for item in app._editor_findings_cache:
                    if item.get("vid") == vid:
                        item["status"] = new_status
                        item["finding"] = new_details
                        item["comment"] = new_comments
                        break
                return

    def _save_and_next():
        if not app._editor_current_vid:
            return
        items = app._editor_tree.get_children()
        try:
            idx = items.index(app._editor_current_vid)
            next_vid = items[idx + 1] if idx + 1 < len(items) else None
        except ValueError:
            next_vid = None

        _save_current_finding()

        if next_vid:
            app._editor_tree.selection_set(next_vid)
            app._editor_tree.focus(next_vid)
            app._editor_tree.see(next_vid)

    def _apply_boilerplate():
        if not app._editor_current_vid:
            return

        from datetime import datetime

        current_status = app._editor_status_var.get()

        try:
            # Resolve Asset Hostname from XML if possible
            asset_name = "Unknown"
            if app._editor_active_xml_tree:
                from stig_assessor.xml.schema import Sch

                host_info = app._editor_active_xml_tree.find(f".//{Sch.ASSET}")
                if host_info is not None:
                    asset_node = host_info.find("HOST_NAME")
                    if asset_node is not None and asset_node.text:
                        asset_name = asset_node.text

            current_severity = (
                app._editor_severity_var.get()
                .replace("CAT I (", "")
                .replace("CAT II (", "")
                .replace("CAT III (", "")
                .replace(")", "")
                .lower()
                or "medium"
            )

            kwargs = {
                "asset": asset_name,
                "severity": current_severity,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "vid": app._editor_current_vid,
                "status": current_status,
            }

            new_finding = app.proc.boiler.get_finding(
                app._editor_current_vid, current_status, **kwargs
            )
            new_comment = app.proc.boiler.get_comment(
                app._editor_current_vid, current_status, **kwargs
            )

            if new_finding:
                app._editor_details_txt.delete("1.0", tk.END)
                app._editor_details_txt.insert("1.0", new_finding)
            if new_comment:
                app._editor_comments_txt.delete("1.0", tk.END)
                app._editor_comments_txt.insert("1.0", new_comment)
            app._editor_is_dirty = True
            app.status_var.set(f"Loaded Boilerplate for {current_status}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load boilerplate:\n{e}")

    btn_nxt = ttk.Button(
        btn_row, text="💾 Save & Next", command=_save_and_next, style="Accent.TButton"
    )
    btn_nxt.pack(side="right", padx=(GUI_PADDING, 0))
    ToolTip(btn_nxt, "Save single vulnerability and advance (Ctrl+S)")

    btn_sav = ttk.Button(btn_row, text="💾 Save", command=_save_current_finding)
    btn_sav.pack(side="right", padx=GUI_PADDING)

    btn_bp = ttk.Button(
        btn_row, text="📋 Apply Boilerplate", command=_apply_boilerplate
    )
    btn_bp.pack(side="left", padx=GUI_PADDING)

    # ==========================
    # BULK PANE COMPONENTS
    # ==========================
    ttk.Label(bulk_pane, text="Bulk Edit Mode", font=GUI_FONT_HEADING).pack(
        pady=(20, 10)
    )

    app._editor_bulk_count_var = tk.StringVar()
    ttk.Label(bulk_pane, textvariable=app._editor_bulk_count_var).pack(pady=(0, 10))

    # --- Bulk Status Row (properly created before use) ---
    bulk_status_row = ttk.Frame(bulk_pane)
    bulk_status_row.pack(fill="x", pady=GUI_PADDING)

    ttk.Label(
        bulk_status_row, text="Set Status:", font=("TkDefaultFont", 10, "bold")
    ).pack(side="left", padx=(0, GUI_PADDING))
    app._editor_bulk_status_var = tk.StringVar(value=Status.NOT_A_FINDING.value)
    bulk_cb = ttk.Combobox(
        bulk_status_row,
        textvariable=app._editor_bulk_status_var,
        values=[
            Status.NOT_A_FINDING.value,
            Status.OPEN.value,
            Status.NOT_APPLICABLE.value,
            Status.NOT_REVIEWED.value,
        ],
        state="readonly",
        width=18,
    )
    bulk_cb.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Label(
        bulk_status_row, text="Apply Mode:", font=("TkDefaultFont", 10, "bold")
    ).pack(side="left", padx=(0, GUI_PADDING))
    app._editor_bulk_apply_mode = tk.StringVar(value="append")
    ttk.Combobox(
        bulk_status_row,
        textvariable=app._editor_bulk_apply_mode,
        values=["overwrite", "append", "prepend", "merge"],
        state="readonly",
        width=12,
    ).pack(side="left")

    # Selection helper buttons
    sel_row = ttk.Frame(bulk_pane)
    sel_row.pack(fill="x", pady=(GUI_PADDING, 0))

    def _select_all_filtered():
        for item in app._editor_tree.get_children():
            app._editor_tree.selection_add(item)
        app._editor_tree.event_generate("<<TreeviewSelect>>")

    def _invert_selection():
        all_items = set(app._editor_tree.get_children())
        selected = set(app._editor_tree.selection())
        new_sel = all_items - selected
        (
            app._editor_tree.selection_set(*new_sel)
            if new_sel
            else app._editor_tree.selection_set()
        )
        app._editor_tree.event_generate("<<TreeviewSelect>>")

    def _select_by_severity(sev):
        if not app._editor_findings_cache:
            return
        matching = set()
        for vuln in app._editor_findings_cache:
            vid = vuln.get("vid", "")
            if vuln.get("severity", "").lower() == sev.lower():
                if app._editor_tree.exists(vid):
                    matching.add(vid)
        if matching:
            app._editor_tree.selection_set(*matching)
            app._editor_tree.event_generate("<<TreeviewSelect>>")

    def _mark_all_visible():
        items = app._editor_tree.get_children()
        if not items:
            return
        dialog = tk.Toplevel(app.root)
        dialog.title("Mark All Visible")
        dialog.transient(app.root)
        ttk.Label(
            dialog,
            text=f"Set status for {len(items)} visible VIDs:",
            padding=GUI_PADDING_LARGE,
        ).pack()

        status_var = tk.StringVar(value=Status.NOT_A_FINDING.value)
        ttk.Combobox(
            dialog,
            textvariable=status_var,
            values=[
                Status.NOT_A_FINDING.value,
                Status.OPEN.value,
                Status.NOT_APPLICABLE.value,
                Status.NOT_REVIEWED.value,
            ],
            state="readonly",
        ).pack(padx=GUI_PADDING_LARGE, fill="x")

        def _apply():
            new_status = status_var.get()
            dialog.destroy()
            for vid in items:
                vuln = next(
                    (v for v in app._editor_findings_cache if v.get("vid") == vid), {}
                )
                _update_xml_vuln(
                    vid, new_status, vuln.get("finding", ""), vuln.get("comment", "")
                )
            try:
                FO.write_ckl(app._editor_active_xml_tree, app._editor_ckl_path)
                app.status_var.set(f"Marked {len(items)} visible rules as {new_status}")
                _refresh_editor_list()
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to save {len(items)} rules:\n{e}"
                )

        dlg_btn = ttk.Frame(dialog)
        dlg_btn.pack(pady=GUI_PADDING_LARGE, fill="x", padx=GUI_PADDING_LARGE)
        ttk.Button(dlg_btn, text="Apply", command=_apply).pack(side="right")
        ttk.Button(dlg_btn, text="Cancel", command=dialog.destroy).pack(
            side="right", padx=GUI_PADDING
        )

    def _select_by_status(s):
        if not app._editor_findings_cache:
            return
        matching = set()
        for vuln in app._editor_findings_cache:
            vid = vuln.get("vid", "")
            if vuln.get("status", "") == s:
                if app._editor_tree.exists(vid):
                    matching.add(vid)
        if matching:
            app._editor_tree.selection_set(*matching)
            app._editor_tree.event_generate("<<TreeviewSelect>>")

    # Group 1: Standard Select
    ttk.Button(sel_row, text="☑ All", command=_select_all_filtered).pack(
        side="left", padx=2
    )
    ttk.Button(sel_row, text="⊘ Inv", command=_invert_selection).pack(
        side="left", padx=2
    )
    # Group 2: Severities
    ttk.Button(sel_row, text="CAT I", command=lambda: _select_by_severity("high")).pack(
        side="left", padx=2
    )
    ttk.Button(
        sel_row, text="CAT II", command=lambda: _select_by_severity("medium")
    ).pack(side="left", padx=2)
    ttk.Button(
        sel_row, text="CAT III", command=lambda: _select_by_severity("low")
    ).pack(side="left", padx=2)
    # Group 3: Status
    ttk.Button(
        sel_row, text="Open", command=lambda: _select_by_status(Status.OPEN.value)
    ).pack(side="left", padx=2)
    ttk.Button(
        sel_row,
        text="N.R.",
        command=lambda: _select_by_status(Status.NOT_REVIEWED.value),
    ).pack(side="left", padx=2)
    ttk.Button(sel_row, text="⚡ Mark All Visible...", command=_mark_all_visible).pack(
        side="right", padx=2
    )

    ttk.Label(
        bulk_pane, text="Bulk Finding Details (Leave blank to keep existing):"
    ).pack(anchor="w", pady=(10, 2))
    app._editor_bulk_details = ScrolledText(bulk_pane, height=4, font=GUI_FONT_MONO)
    app._editor_bulk_details.pack(fill="x")

    ttk.Label(bulk_pane, text="Bulk Comments (Leave blank to keep existing):").pack(
        anchor="w", pady=(10, 2)
    )
    app._editor_bulk_comments = ScrolledText(bulk_pane, height=3, font=GUI_FONT_MONO)
    app._editor_bulk_comments.pack(fill="x")

    def _apply_text_mode(existing, new_text, mode):
        """Combine existing and new text using the specified mode."""
        existing = existing or ""
        if not new_text:
            return existing
        if mode == "overwrite":
            return new_text
        elif mode == "prepend":
            return f"{new_text}\n\n{existing}" if existing.strip() else new_text
        elif mode == "merge":
            if existing.strip():
                divider = "\n--- Boilerplate ---\n"
                return f"{existing}{divider}{new_text}"
            return new_text
        else:  # append
            return f"{existing}\n\n{new_text}" if existing.strip() else new_text

    def _execute_bulk_save():
        if not app._editor_active_xml_tree:
            return
        selections = app._editor_tree.selection()
        if not selections:
            return
        new_status = app._editor_bulk_status_var.get()
        bulk_find = app._editor_bulk_details.get("1.0", "end-1c").strip()
        bulk_comm = app._editor_bulk_comments.get("1.0", "end-1c").strip()
        mode = app._editor_bulk_apply_mode.get()

        app._editor_bulk_progress["maximum"] = len(selections)
        app._editor_bulk_progress["value"] = 0
        import time

        start_time = time.time()

        def _process_chunk(idx):
            if idx >= len(selections):
                try:
                    FO.write_ckl(app._editor_active_xml_tree, app._editor_ckl_path)
                    app.status_var.set(
                        f"Bulk saved {len(selections)} records to checklist."
                    )
                    _refresh_editor_list()
                    for vid in selections:
                        try:
                            app._editor_tree.selection_add(vid)
                        except Exception:
                            pass
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to bulk save:\n{e}")
                app._editor_bulk_progress["value"] = 0
                return

            chunk = min(idx + 50, len(selections))
            for i in range(idx, chunk):
                vid = selections[i]
                vuln = next(
                    (v for v in app._editor_findings_cache if v.get("vid") == vid), {}
                )
                final_find = _apply_text_mode(vuln.get("finding", ""), bulk_find, mode)
                final_comm = _apply_text_mode(vuln.get("comment", ""), bulk_comm, mode)
                _update_xml_vuln(vid, new_status, final_find, final_comm)

            app._editor_bulk_progress["value"] = chunk
            elapsed = time.time() - start_time
            eta = (elapsed / chunk) * (len(selections) - chunk) if chunk > 0 else 0
            app.status_var.set(
                f"Bulk saving... {chunk}/{len(selections)} (ETA: {int(eta)}s)"
            )
            app.root.after(10, _process_chunk, chunk)

        _process_chunk(0)

    def _execute_bulk_boilerplate():
        if not app._editor_active_xml_tree:
            return
        selections = app._editor_tree.selection()
        if not selections:
            return

        bp_all = app.proc.boiler.list_all()
        mode = app._editor_bulk_apply_mode.get()
        wildcard = bp_all.get("V-*", {})

        app._editor_bulk_progress["maximum"] = len(selections)
        app._editor_bulk_progress["value"] = 0
        import time

        start_time = time.time()

        def _process_chunk(idx, applied_count):
            if idx >= len(selections):
                if applied_count > 0:
                    try:
                        FO.write_ckl(app._editor_active_xml_tree, app._editor_ckl_path)
                        app.status_var.set(
                            f"Applied boilerplates to {applied_count} out of {len(selections)} selected."
                        )
                        _refresh_editor_list()
                        for vid in selections:
                            try:
                                app._editor_tree.selection_add(vid)
                            except Exception:
                                pass
                    except Exception as e:
                        messagebox.showerror(
                            "Error", f"Failed to bulk save boilerplates:\n{e}"
                        )
                else:
                    app.status_var.set(
                        "No boilerplates matched the selected vulnerabilities."
                    )
                app._editor_bulk_progress["value"] = 0
                return

            from datetime import datetime

            now_str = datetime.now().strftime("%Y-%m-%d")

            # Fetch asset name once for bulk
            asset_name = "Unknown"
            if app._editor_active_xml_tree:
                from stig_assessor.xml.schema import Sch

                host_info = app._editor_active_xml_tree.find(f".//{Sch.ASSET}")
                if host_info is not None:
                    asset_node = host_info.find("HOST_NAME")
                    if asset_node is not None and asset_node.text:
                        asset_name = asset_node.text

            chunk = min(idx + 50, len(selections))
            for i in range(idx, chunk):
                vid = selections[i]
                vuln = next(
                    (v for v in app._editor_findings_cache if v.get("vid") == vid), {}
                )
                current_status = vuln.get("status", Status.NOT_REVIEWED.value)

                kwargs = {
                    "asset": asset_name,
                    "severity": vuln.get("severity", "medium").lower(),
                    "date": now_str,
                    "vid": vid,
                    "status": current_status,
                }

                new_finding = app.proc.boiler.get_finding(vid, current_status, **kwargs)
                new_comment = app.proc.boiler.get_comment(vid, current_status, **kwargs)

                if not new_finding and not new_comment:
                    continue

                final_find = _apply_text_mode(
                    vuln.get("finding", ""), new_finding, mode
                )
                final_comm = _apply_text_mode(
                    vuln.get("comment", ""), new_comment, mode
                )
                _update_xml_vuln(vid, current_status, final_find, final_comm)
                applied_count += 1

            app._editor_bulk_progress["value"] = chunk
            elapsed = time.time() - start_time
            eta = (elapsed / chunk) * (len(selections) - chunk) if chunk > 0 else 0
            app.status_var.set(
                f"Applying boilerplates... {chunk}/{len(selections)} (ETA: {int(eta)}s)"
            )
            app.root.after(10, _process_chunk, chunk, applied_count)

        _process_chunk(0, 0)

    bulk_btn_row = ttk.Frame(bulk_pane)
    bulk_btn_row.pack(pady=20, fill="x")

    app._editor_bulk_progress = ttk.Progressbar(bulk_btn_row, mode="determinate")

    ttk.Button(
        bulk_btn_row,
        text="💾 Bulk Save Status",
        command=_execute_bulk_save,
        style="Accent.TButton",
        width=20,
    ).pack(side="left", padx=10)
    ttk.Button(
        bulk_btn_row,
        text="📋 Bulk Apply Boilerplates",
        command=_execute_bulk_boilerplate,
        width=25,
    ).pack(side="left", padx=10)

    # ==========================
    # Global Bindings & Logic
    # ==========================
    def _bind_save(event):
        try:
            idx = app.notebook.index(app.notebook.select())
            tab_name = app.notebook.tab(idx, "text")
            if "Editor" in tab_name:
                selections = app._editor_tree.selection()
                if len(selections) > 1:
                    _execute_bulk_save()
                else:
                    _save_and_next()
                return "break"
        except Exception:
            pass

    app.root.bind("<Control-s>", _bind_save, add="+")
    app.root.bind("<Control-S>", _bind_save, add="+")

    def _bind_save_next(event):
        try:
            idx = app.notebook.index(app.notebook.select())
            tab_name = app.notebook.tab(idx, "text")
            if "Editor" in tab_name:
                selections = app._editor_tree.selection()
                if len(selections) <= 1:
                    _save_and_next()
                return "break"
        except Exception:
            pass

    app.root.bind("<Control-Return>", _bind_save_next, add="+")

    # Keyboard navigation helper for treeview
    def _tree_key_nav(event):
        try:
            idx = app.notebook.index(app.notebook.select())
            tab_name = app.notebook.tab(idx, "text")
            if "Editor" in tab_name:
                app._editor_tree.focus_set()
        except Exception:
            pass

    app.root.bind("<Up>", _tree_key_nav, add="+")
    app.root.bind("<Down>", _tree_key_nav, add="+")

    def _bind_bp(event):
        try:
            idx = app.notebook.index(app.notebook.select())
            tab_name = app.notebook.tab(idx, "text")
            if "Editor" in tab_name:
                _apply_boilerplate()
                return "break"
        except Exception:
            pass

    app.root.bind("<Control-b>", _bind_bp, add="+")
    app.root.bind("<Control-B>", _bind_bp, add="+")

    def _bind_nav(event, direction):
        try:
            idx = app.notebook.index(app.notebook.select())
            if "Editor" not in app.notebook.tab(idx, "text"):
                return
            if not app._editor_current_vid:
                return
            items = app._editor_tree.get_children()
            if not items:
                return

            try:
                current_idx = items.index(app._editor_current_vid)
            except ValueError:
                return

            new_idx = current_idx + direction
            if 0 <= new_idx < len(items):
                app._editor_tree.selection_set(items[new_idx])
                app._editor_tree.see(items[new_idx])
                return "break"
        except Exception:
            pass

    app.root.bind("<Alt-Up>", lambda e: _bind_nav(e, -1), add="+")
    app.root.bind("<Control-Up>", lambda e: _bind_nav(e, -1), add="+")
    app.root.bind("<Alt-Down>", lambda e: _bind_nav(e, 1), add="+")
    app.root.bind("<Control-Down>", lambda e: _bind_nav(e, 1), add="+")

    def _refresh_editor_list():
        query = search_var.get().lower()
        filter_status = filter_status_var.get()
        selections = app._editor_tree.selection()

        for row in app._editor_tree.get_children():
            app._editor_tree.delete(row)

        cnt_open = 0
        cnt_naf = 0
        cnt_nr = 0
        cnt_na = 0
        total_vulns = len(app._editor_findings_cache)

        for vuln in app._editor_findings_cache:
            vid = vuln.get("vid", "")
            status = vuln.get("status", Status.NOT_REVIEWED.value)
            rt = vuln.get("rule_title", "")
            severity = vuln.get("severity", "medium").lower()

            if status == Status.OPEN.value:
                cnt_open += 1
            elif status == Status.NOT_A_FINDING.value:
                cnt_naf += 1
            elif status == Status.NOT_REVIEWED.value:
                cnt_nr += 1
            elif status == Status.NOT_APPLICABLE.value:
                cnt_na += 1

            if filter_status != "All Statuses" and status != filter_status:
                continue
            if (
                query
                and query not in vid.lower()
                and query not in status.lower()
                and query not in rt.lower()
            ):
                continue

            app._editor_tree.insert(
                "",
                "end",
                iid=vid,
                values=(vid, severity.title(), status),
                tags=(status,),
            )

        app._editor_stats_open.set(f"Open: {cnt_open}")
        app._editor_stats_naf.set(f"NotAFinding: {cnt_naf}")
        app._editor_stats_nr.set(f"Not Reviewed: {cnt_nr}")
        app._editor_stats_na.set(f"N/A: {cnt_na}")

        # Update progress bar
        reviewed = cnt_naf + cnt_na + cnt_open
        pct = (reviewed / total_vulns * 100) if total_vulns > 0 else 0
        app._editor_progress_var.set(pct)
        app._editor_progress_text.set(f"{reviewed}/{total_vulns} ({int(pct)}%)")

        for vid in selections:
            if app._editor_tree.exists(vid):
                app._editor_tree.selection_add(vid)

    def _on_vid_select(event):
        sel = app._editor_tree.selection()
        if not sel:
            return

        # Unsaved changes checking
        if (
            getattr(app, "_editor_is_dirty", False)
            and getattr(app, "_editor_current_vid", None)
            and app._editor_current_vid not in sel
        ):
            if not messagebox.askyesno(
                "Unsaved Changes",
                f"You have unsaved changes in {app._editor_current_vid}.\n\nDiscard changes and continue?",
            ):
                # Cancel tree navigation and restore old selection without firing event again
                app._editor_tree.selection_set(app._editor_current_vid)
                return

        if len(sel) > 1:
            single_pane.grid_remove()
            bulk_pane.grid(row=0, column=0, sticky="nsew")
            app._editor_bulk_count_var.set(
                f"{len(sel)} vulnerabilities currently selected."
            )
        else:
            bulk_pane.grid_remove()
            single_pane.grid(row=0, column=0, sticky="nsew")

            vid = sel[0]
            app._editor_current_vid = vid

            vuln = next(
                (v for v in app._editor_findings_cache if v.get("vid") == vid), {}
            )
            app._editor_status_var.set(vuln.get("status", Status.NOT_REVIEWED.value))

            title = vuln.get("rule_title", "")
            if len(title) > 100:
                title = title[:100] + "..."
            app._editor_rule_title_var.set(title)

            app._editor_details_txt.delete("1.0", tk.END)
            app._editor_details_txt.insert("1.0", vuln.get("finding", ""))

            app._editor_comments_txt.delete("1.0", tk.END)
            app._editor_comments_txt.insert("1.0", vuln.get("comment", ""))

            check_content = ""
            fix_text = ""
            if app._editor_active_xml_tree:
                for vuln_node in app._editor_active_xml_tree.getroot().findall(
                    ".//VULN"
                ):
                    is_match = False
                    for a in vuln_node.findall("STIG_DATA"):
                        if (
                            a.find("VULN_ATTRIBUTE") is not None
                            and a.find("VULN_ATTRIBUTE").text == "Vuln_Num"
                        ):
                            if (
                                a.find("ATTRIBUTE_DATA") is not None
                                and a.find("ATTRIBUTE_DATA").text == vid
                            ):
                                is_match = True
                                break
                    if is_match:
                        for a in vuln_node.findall("STIG_DATA"):
                            if a.find("VULN_ATTRIBUTE") is not None:
                                if a.find("VULN_ATTRIBUTE").text == "Check_Content":
                                    check_content = a.find("ATTRIBUTE_DATA").text or ""
                                elif a.find("VULN_ATTRIBUTE").text == "Fix_Text":
                                    fix_text = a.find("ATTRIBUTE_DATA").text or ""
                        break

            app._editor_chk_txt.config(state="normal")
            app._editor_chk_txt.delete("1.0", tk.END)
            app._editor_chk_txt.insert("1.0", check_content)
            app._editor_chk_txt.config(state="disabled")

            app._editor_fix_txt.config(state="normal")
            app._editor_fix_txt.delete("1.0", tk.END)
            app._editor_fix_txt.insert("1.0", fix_text)
            app._editor_fix_txt.config(state="disabled")

    app._editor_tree.bind("<<TreeviewSelect>>", _on_vid_select)

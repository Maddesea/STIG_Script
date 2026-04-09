"""Interactive Assessment Editor Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import xml.etree.ElementTree as ET

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_FONT_MONO, Status, GUI_FONT_HEADING
from stig_assessor.io.file_ops import FO
from stig_assessor.processor.html_report import _parse_checklist
from stig_assessor.ui.helpers import ToolTip, TextContextMenu

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
        if not path: return
        try:
            data = _parse_checklist(FO.resolve(path))
            app._editor_findings_cache = data.get("vulns", [])
            app._editor_ckl_path = FO.resolve(path)
            app._editor_active_xml_tree = FO.parse_xml(app._editor_ckl_path)
            _refresh_editor_list()
            app.status_var.set(f"Loaded {len(app._editor_findings_cache)} vulnerabilities.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load: {e}")

    app._editor_load = _load_checklist

    ttk.Button(file_row, text="📂 Load", command=_load_checklist).pack(side="left", padx=GUI_PADDING)

    # Mini Progress Dashboard
    status_summary_frame = ttk.Frame(top_frame)
    status_summary_frame.pack(fill="x", pady=(5, 0))
    
    app._editor_stats_open = tk.StringVar(value="Open: 0")
    app._editor_stats_naf = tk.StringVar(value="NotAFinding: 0")
    app._editor_stats_nr = tk.StringVar(value="Not Reviewed: 0")

    ttk.Label(status_summary_frame, textvariable=app._editor_stats_open, foreground="#ef4444", font=(GUI_FONT_NORMAL[0], 9, "bold")).pack(side="left", padx=GUI_PADDING)
    ttk.Label(status_summary_frame, textvariable=app._editor_stats_naf, foreground="#10b981", font=(GUI_FONT_NORMAL[0], 9, "bold")).pack(side="left", padx=GUI_PADDING)
    ttk.Label(status_summary_frame, textvariable=app._editor_stats_nr, foreground="#f59e0b", font=(GUI_FONT_NORMAL[0], 9, "bold")).pack(side="left", padx=GUI_PADDING)

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
        values=["All Statuses", Status.OPEN.value, Status.NOT_A_FINDING.value, Status.NOT_REVIEWED.value, Status.NOT_APPLICABLE.value],
        state="readonly",
        width=15
    )
    status_filter_cb.pack(side="left")

    # Filter Persistence
    if hasattr(app, "_editor_filter_state"):
        search_var.set(app._editor_filter_state.get("query", ""))
        filter_status_var.set(app._editor_filter_state.get("status", "All Statuses"))

    def _save_filter_state():
        app._editor_filter_state = {"query": search_var.get(), "status": filter_status_var.get()}
    
    status_filter_cb.bind("<<ComboboxSelected>>", lambda e: _save_filter_state())


    # ── MAIN SPLIT VIEW ──
    pw = ttk.PanedWindow(frame, orient="horizontal")
    pw.grid(row=1, column=0, sticky="nsew")

    # LEFT: VULN LIST
    list_frame = ttk.Frame(pw)
    pw.add(list_frame, weight=1)

    columns = ("vid", "status")
    app._editor_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
    app._editor_tree.heading("vid", text="VID")
    app._editor_tree.heading("status", text="Status")
    app._editor_tree.column("vid", width=110, anchor="w")
    app._editor_tree.column("status", width=90, anchor="center")
    
    scroll_tree = ttk.Scrollbar(list_frame, orient="vertical", command=app._editor_tree.yview)
    app._editor_tree.configure(yscrollcommand=scroll_tree.set)
    app._editor_tree.pack(side="left", fill="both", expand=True)
    scroll_tree.pack(side="right", fill="y")
    
    app._editor_tree.tag_configure(Status.OPEN.value, foreground=app._colors.get("error", "red"))
    app._editor_tree.tag_configure(Status.NOT_A_FINDING.value, foreground=app._colors.get("ok", "green"))
    app._editor_tree.tag_configure(Status.NOT_REVIEWED.value, foreground=app._colors.get("warn", "orange"))
    app._editor_tree.tag_configure(Status.NOT_APPLICABLE.value, foreground=app._colors.get("info", "gray"))

    # Context Menu for Quick Status
    ctx = tk.Menu(app._editor_tree, tearoff=0)
    
    def _quick_set_status(new_status):
        selections = app._editor_tree.selection()
        if not selections or not app._editor_active_xml_tree: return
        for vid in selections:
            vuln = next((v for v in app._editor_findings_cache if v.get("vid") == vid), {})
            _update_xml_vuln(vid, new_status, vuln.get("finding", ""), vuln.get("comment", ""))
        FO.write_xml(app._editor_active_xml_tree, app._editor_ckl_path)
        app.status_var.set(f"Quick-set {len(selections)} rules to {new_status}")
        _refresh_editor_list()

    ctx.add_command(label="✓ Mark NotAFinding", command=lambda: _quick_set_status(Status.NOT_A_FINDING.value))
    ctx.add_command(label="⚠ Mark Open", command=lambda: _quick_set_status(Status.OPEN.value))
    ctx.add_command(label="⊘ Mark NotApplicable", command=lambda: _quick_set_status(Status.NOT_APPLICABLE.value))
    ctx.add_separator()
    ctx.add_command(label="📋 Apply Boilerplate", command=lambda: _execute_bulk_boilerplate())

    def _show_ctx(event):
        item = app._editor_tree.identify_row(event.y)
        if item:
            if item not in app._editor_tree.selection():
                app._editor_tree.selection_set(item)
            ctx.tk_popup(event.x_root, event.y_root)

    app._editor_tree.bind("<Button-3>", _show_ctx)


    # RIGHT: EDITOR PANE
    editor_frame = ttk.LabelFrame(pw, text="Assessment Details", padding=GUI_PADDING_LARGE)
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
    ttk.Label(status_row, text="Status:", font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(0, GUI_PADDING))
    
    app._editor_status_var = tk.StringVar(value=Status.NOT_REVIEWED.value)
    status_cb = ttk.Combobox(
        status_row, 
        textvariable=app._editor_status_var, 
        values=[Status.NOT_A_FINDING.value, Status.OPEN.value, Status.NOT_APPLICABLE.value, Status.NOT_REVIEWED.value],
        state="readonly",
        width=20
    )
    status_cb.pack(side="left")
    
    app._editor_rule_title_var = tk.StringVar()
    ttk.Label(status_row, textvariable=app._editor_rule_title_var, foreground=app._colors.get("info", "blue"), wraplength=450).pack(side="left", padx=GUI_PADDING_LARGE)
    
    ttk.Label(single_pane, text="Finding Details (Right-click to Copy/Paste):").pack(anchor="w", pady=(GUI_PADDING, 2))
    app._editor_details_txt = ScrolledText(single_pane, width=60, height=8, font=GUI_FONT_MONO)
    app._editor_details_txt.pack(fill="x", pady=(0, GUI_PADDING))
    TextContextMenu(app._editor_details_txt)

    ttk.Label(single_pane, text="Comments (Right-click to Copy/Paste):").pack(anchor="w", pady=(GUI_PADDING, 2))
    app._editor_comments_txt = ScrolledText(single_pane, width=60, height=5, font=GUI_FONT_MONO)
    app._editor_comments_txt.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    TextContextMenu(app._editor_comments_txt)

    info_pw = ttk.PanedWindow(single_pane, orient="horizontal")
    info_pw.pack(fill="both", expand=True)
    
    chk_frame = ttk.LabelFrame(info_pw, text="Check Content")
    info_pw.add(chk_frame, weight=1)
    app._editor_chk_txt = ScrolledText(chk_frame, width=30, height=8, wrap="word", state="disabled")
    app._editor_chk_txt.pack(fill="both", expand=True, padx=2, pady=2)
    
    chk_btn = ttk.Button(chk_frame, text="📋 Copy", command=lambda: _copy_text_widget(app._editor_chk_txt))
    chk_btn.pack(side="right", padx=2, pady=2)
    ToolTip(chk_btn, "Copy Check Content to Clipboard")

    fix_frame = ttk.LabelFrame(info_pw, text="Fix Text")
    info_pw.add(fix_frame, weight=1)
    app._editor_fix_txt = ScrolledText(fix_frame, width=30, height=8, wrap="word", state="disabled")
    app._editor_fix_txt.pack(fill="both", expand=True, padx=2, pady=2)
    
    fix_btn = ttk.Button(fix_frame, text="📋 Copy", command=lambda: _copy_text_widget(app._editor_fix_txt))
    fix_btn.pack(side="right", padx=2, pady=2)
    ToolTip(fix_btn, "Copy Fix Text to Clipboard")

    def _copy_text_widget(widget):
        content = widget.get("1.0", tk.END).strip()
        if content:
            app.root.clipboard_clear()
            app.root.clipboard_append(content)
            app.status_var.set("Copied text to clipboard.")

    app._editor_chk_txt.bind("<Double-Button-1>", lambda e: _copy_text_widget(app._editor_chk_txt))
    app._editor_fix_txt.bind("<Double-Button-1>", lambda e: _copy_text_widget(app._editor_fix_txt))

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
            FO.write_xml(app._editor_active_xml_tree, app._editor_ckl_path)
            app.status_var.set(f"Saved {app._editor_current_vid} directly to checklist.")
            _refresh_editor_list()
            app._editor_tree.selection_set(app._editor_current_vid)
            app._editor_tree.focus(app._editor_current_vid)
            app._editor_tree.see(app._editor_current_vid)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def _update_xml_vuln(vid, new_status, new_details, new_comments):
        root = app._editor_active_xml_tree.getroot()
        vulns = root.findall(".//VULN")
        for vuln in vulns:
            vuln_vid = None
            for attr_node in vuln.findall("STIG_DATA"):
                if attr_node.find("VULN_ATTRIBUTE") is not None and attr_node.find("VULN_ATTRIBUTE").text == "Vuln_Num":
                    if attr_node.find("ATTRIBUTE_DATA") is not None:
                        vuln_vid = attr_node.find("ATTRIBUTE_DATA").text
                        break
            
            if vuln_vid == vid:
                node_s = vuln.find("STATUS")
                if node_s is not None: node_s.text = new_status
                else: ET.SubElement(vuln, "STATUS").text = new_status
                
                node_f = vuln.find("FINDING_DETAILS")
                if node_f is not None: node_f.text = new_details
                else: ET.SubElement(vuln, "FINDING_DETAILS").text = new_details
                
                node_c = vuln.find("COMMENTS")
                if node_c is not None: node_c.text = new_comments
                else: ET.SubElement(vuln, "COMMENTS").text = new_comments
                
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
            next_vid = items[idx+1] if idx + 1 < len(items) else None
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
            
        try:
            bp_all = app.proc.boiler.list_all()
            bp = bp_all.get(app._editor_current_vid)
            if not bp:
                app.status_var.set(f"No boilerplate match found for {app._editor_current_vid}")
                return
                
            app._editor_status_var.set(bp.get("status", Status.OPEN.value))
            if bp.get("finding"):
                app._editor_details_txt.delete("1.0", tk.END)
                app._editor_details_txt.insert("1.0", bp["finding"])
            if bp.get("comment"):
                app._editor_comments_txt.delete("1.0", tk.END)
                app._editor_comments_txt.insert("1.0", bp["comment"])
            app.status_var.set(f"Loaded Boilerplate for {app._editor_current_vid}")
        except Exception as e:
             messagebox.showerror("Error", f"Failed to load boilerplate:\n{e}")

    btn_nxt = ttk.Button(btn_row, text="💾 Save & Next", command=_save_and_next, style="Accent.TButton")
    btn_nxt.pack(side="right", padx=(GUI_PADDING, 0))
    ToolTip(btn_nxt, "Save single vulnerability and advance (Ctrl+S)")
    
    btn_sav = ttk.Button(btn_row, text="💾 Save", command=_save_current_finding)
    btn_sav.pack(side="right", padx=GUI_PADDING)
    
    btn_bp = ttk.Button(btn_row, text="📋 Apply Boilerplate", command=_apply_boilerplate)
    btn_bp.pack(side="left", padx=GUI_PADDING)
    
    # ==========================
    # BULK PANE COMPONENTS
    # ==========================
    ttk.Label(bulk_pane, text="Bulk Edit Mode", font=GUI_FONT_HEADING).pack(pady=(20, 10))
    
    app._editor_bulk_count_var = tk.StringVar()
    ttk.Label(bulk_pane, textvariable=app._editor_bulk_count_var).pack(pady=10)
    
    bulk_cb.pack(side="left")

    app._editor_bulk_append_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(bulk_status_row, text="Append to existing text (Finding/Comments)", variable=app._editor_bulk_append_var).pack(side="left", padx=GUI_PADDING_LARGE)
    
    ttk.Label(bulk_pane, text="Bulk Finding Details (Leave blank to keep existing):").pack(anchor="w", pady=(10, 2))
    app._editor_bulk_details = ScrolledText(bulk_pane, height=4, font=GUI_FONT_MONO)
    app._editor_bulk_details.pack(fill="x")
    
    ttk.Label(bulk_pane, text="Bulk Comments (Leave blank to keep existing):").pack(anchor="w", pady=(10, 2))
    app._editor_bulk_comments = ScrolledText(bulk_pane, height=3, font=GUI_FONT_MONO)
    app._editor_bulk_comments.pack(fill="x")
    
    def _execute_bulk_save():
        if not app._editor_active_xml_tree: return
        selections = app._editor_tree.selection()
        if not selections: return
        new_status = app._editor_bulk_status_var.get()
        bulk_find = app._editor_bulk_details.get("1.0", "end-1c").strip()
        bulk_comm = app._editor_bulk_comments.get("1.0", "end-1c").strip()
        do_append = app._editor_bulk_append_var.get()
        
        for vid in selections:
            vuln = next((v for v in app._editor_findings_cache if v.get("vid") == vid), {})
            
            final_find = vuln.get("finding", "")
            if bulk_find:
                final_find = f"{final_find}\n\n{bulk_find}" if do_append and final_find else bulk_find
            
            final_comm = vuln.get("comment", "")
            if bulk_comm:
                final_comm = f"{final_comm}\n\n{bulk_comm}" if do_append and final_comm else bulk_comm
                
            _update_xml_vuln(vid, new_status, final_find, final_comm)
        
        try:
            FO.write_xml(app._editor_active_xml_tree, app._editor_ckl_path)
            app.status_var.set(f"Bulk saved {len(selections)} records to checklist.")
            _refresh_editor_list()
            for vid in selections:
                try: app._editor_tree.selection_add(vid)
                except Exception: pass
        except Exception as e:
            messagebox.showerror("Error", f"Failed to bulk save:\n{e}")

    def _execute_bulk_boilerplate():
        if not app._editor_active_xml_tree: return
        selections = app._editor_tree.selection()
        if not selections: return
        
        bp_all = app.proc.boiler.list_all()
        applied_count = 0
        for vid in selections:
            bp = bp_all.get(vid)
            if bp:
                new_status = bp.get("status", Status.OPEN.value)
                new_finding = bp.get("finding", "")
                new_comment = bp.get("comment", "")
                _update_xml_vuln(vid, new_status, new_finding, new_comment)
                applied_count += 1
                
        if applied_count > 0:
            try:
                FO.write_xml(app._editor_active_xml_tree, app._editor_ckl_path)
                app.status_var.set(f"Applied boilerplates to {applied_count} out of {len(selections)} selected.")
                _refresh_editor_list()
                for vid in selections:
                    try: app._editor_tree.selection_add(vid)
                    except Exception: pass
            except Exception as e:
                messagebox.showerror("Error", f"Failed to bulk save boilerplates:\n{e}")
        else:
            app.status_var.set("No boilerplates matched the selected vulnerabilities.")

    bulk_btn_row = ttk.Frame(bulk_pane)
    bulk_btn_row.pack(pady=20)
    
    ttk.Button(bulk_btn_row, text="💾 Bulk Save Status", command=_execute_bulk_save, style="Accent.TButton", width=20).pack(side="left", padx=10)
    ttk.Button(bulk_btn_row, text="📋 Bulk Apply Boilerplates", command=_execute_bulk_boilerplate, width=25).pack(side="left", padx=10)


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

    def _refresh_editor_list():
        query = search_var.get().lower()
        filter_status = filter_status_var.get()
        selections = app._editor_tree.selection()
        
        for row in app._editor_tree.get_children():
            app._editor_tree.delete(row)
            
        cnt_open = 0
        cnt_naf = 0
        cnt_nr = 0
        
        for vuln in app._editor_findings_cache:
            vid = vuln.get("vid", "")
            status = vuln.get("status", Status.NOT_REVIEWED.value)
            rt = vuln.get("rule_title", "")
            
            if status == Status.OPEN.value: cnt_open += 1
            elif status == Status.NOT_A_FINDING.value: cnt_naf += 1
            elif status == Status.NOT_REVIEWED.value: cnt_nr += 1
            
            if filter_status != "All Statuses" and status != filter_status:
                continue
            if query and query not in vid.lower() and query not in status.lower() and query not in rt.lower():
                continue
                
            app._editor_tree.insert("", "end", iid=vid, values=(vid, status), tags=(status,))
            
        app._editor_stats_open.set(f"Open: {cnt_open}")
        app._editor_stats_naf.set(f"NotAFinding: {cnt_naf}")
        app._editor_stats_nr.set(f"Not Reviewed: {cnt_nr}")
        
        for vid in selections:
            if app._editor_tree.exists(vid):
                app._editor_tree.selection_add(vid)
            
    def _on_vid_select(event):
        sel = app._editor_tree.selection()
        if not sel: return
        
        if len(sel) > 1:
            single_pane.grid_remove()
            bulk_pane.grid(row=0, column=0, sticky="nsew")
            app._editor_bulk_count_var.set(f"{len(sel)} vulnerabilities currently selected.")
        else:
            bulk_pane.grid_remove()
            single_pane.grid(row=0, column=0, sticky="nsew")
            
            vid = sel[0]
            app._editor_current_vid = vid
            
            vuln = next((v for v in app._editor_findings_cache if v.get("vid") == vid), {})
            app._editor_status_var.set(vuln.get("status", Status.NOT_REVIEWED.value))
            
            title = vuln.get("rule_title", "")
            if len(title) > 100: title = title[:100] + "..."
            app._editor_rule_title_var.set(title)
            
            app._editor_details_txt.delete("1.0", tk.END)
            app._editor_details_txt.insert("1.0", vuln.get("finding", ""))
            
            app._editor_comments_txt.delete("1.0", tk.END)
            app._editor_comments_txt.insert("1.0", vuln.get("comment", ""))
            
            check_content = ""
            fix_text = ""
            if app._editor_active_xml_tree:
                for vuln_node in app._editor_active_xml_tree.getroot().findall(".//VULN"):
                    is_match = False
                    for a in vuln_node.findall("STIG_DATA"):
                        if a.find("VULN_ATTRIBUTE") is not None and a.find("VULN_ATTRIBUTE").text == "Vuln_Num":
                            if a.find("ATTRIBUTE_DATA") is not None and a.find("ATTRIBUTE_DATA").text == vid:
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

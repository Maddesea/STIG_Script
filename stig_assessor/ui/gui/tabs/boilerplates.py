"""Boilerplates Tab module."""
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_FONT_MONO, Status


def build_boilerplates_tab(app, frame):
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(0, weight=1)

    left_frame = ttk.LabelFrame(
        frame, text="Vulnerability IDs", padding=GUI_PADDING_LARGE
    )
    left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, GUI_PADDING_LARGE))

    columns = ("vid", "flags")
    app._bp_vids_list = ttk.Treeview(
        left_frame,
        columns=columns,
        show="headings",
        selectmode="browse",
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

    right_frame = ttk.LabelFrame(
        frame, text="Boilerplate Editor", padding=GUI_PADDING_LARGE
    )
    right_frame.grid(row=0, column=1, sticky="nsew")
    right_frame.rowconfigure(1, weight=1)
    right_frame.columnconfigure(0, weight=1)

    ctrl_frame = ttk.Frame(right_frame)
    ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))
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
    )
    status_cb.pack(side="left", padx=5)

    editors = ttk.Frame(right_frame)
    editors.grid(row=1, column=0, sticky="nsew")
    editors.columnconfigure(0, weight=1)
    editors.rowconfigure(1, weight=1)
    editors.rowconfigure(3, weight=1)

    ttk.Label(editors, text="Finding Details:").grid(
        row=0, column=0, sticky="w"
    )
    app._bp_finding_text = ScrolledText(
        editors, width=60, height=8, font=app._colors.get("font_mono",GUI_FONT_MONO) if hasattr(app,'GUI_FONT_MONO') else ("Courier New", 10)
    )
    app._bp_finding_text.grid(
        row=1, column=0, sticky="nsew", pady=(0, GUI_PADDING_LARGE)
    )

    ttk.Label(editors, text="Comments:").grid(row=2, column=0, sticky="w")
    app._bp_comment_text = ScrolledText(
        editors, width=60, height=8, font=app._colors.get("font_mono",GUI_FONT_MONO) if hasattr(app,'GUI_FONT_MONO') else ("Courier New", 10)
    )
    app._bp_comment_text.grid(row=3, column=0, sticky="nsew")

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

    def _on_bp_vid_select(event):
        sel = app._bp_vids_list.selection()
        if not sel:
            return
        app._bp_current_vid = sel[0]
        _load_bp_editor()

    def _on_bp_status_select(event):
        _load_bp_editor()

    app._bp_vids_list.bind("<<TreeviewSelect>>", _on_select_wrapper := lambda e: _on_bp_vid_select(e))
    status_cb.bind("<<ComboboxSelected>>", _on_status_wrapper := lambda e: _on_bp_status_select(e))

    def _bp_refresh_vids():
        for row in app._bp_vids_list.get_children():
            app._bp_vids_list.delete(row)
        bmap = app.proc.boiler.list_all()
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

            app._bp_vids_list.insert(
                "", tk.END, iid=v, values=(v, flags), tags=(tag,)
            )

    def _bp_add_vid():
        vid = simpledialog.askstring(
            "Add VID", "Enter STIG Check ID (e.g. V-12345):"
        )
        if vid:
            vid = vid.strip()
            if not vid.startswith("V-") and vid != "V-*":
                msg = f"'{vid}' does not look like a STIG Vuln ID (V-12345).\nForce add?"
                if not messagebox.askyesno("Invalid VID format", msg):
                    return

            if not app._bp_vids_list.exists(vid):
                app._bp_vids_list.insert("", tk.END, iid=vid, values=(vid, ""))

            app._bp_vids_list.selection_set(vid)
            app._bp_vids_list.focus(vid)
            app._bp_vids_list.see(vid)
            app._bp_vids_list.event_generate("<<TreeviewSelect>>")

    ttk.Button(left_frame, text="+ Add VID", command=_bp_add_vid).pack(
        side="bottom", fill="x", pady=2
    )

    def _bp_save():
        if not app._bp_current_vid:
            return
        status = app._bp_status_var.get()
        finding = app._bp_finding_text.get("1.0", "end-1c")
        comment = app._bp_comment_text.get("1.0", "end-1c")
        app.proc.boiler.set(app._bp_current_vid, status, finding, comment)
        app.status_var.set(
            f"Saved boilerplate for {app._bp_current_vid} / {status}"
        )
        _bp_refresh_vids()
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
                app._bp_vids_list.selection_set(app._bp_current_vid)
                _load_bp_editor()

    actions = ttk.Frame(right_frame)
    actions.grid(row=2, column=0, sticky="ew", pady=(GUI_PADDING_LARGE, 0))
    ttk.Button(
        actions,
        text="💾 Save",
        command=_bp_save,
        style="Accent.TButton",
    ).pack(side="right", padx=5)
    ttk.Button(actions, text="🗑 Delete", command=_bp_delete).pack(
        side="left", padx=5
    )

    _bp_refresh_vids()

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

    list_container = ttk.Frame(input_frame)
    list_container.grid(
        row=1,
        column=1,
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
    btn_frame.grid(row=1, column=2, sticky="n", pady=GUI_PADDING)
    ttk.Button(btn_frame, text="Add…", command=_add_merge_hist).pack(
        fill="x", pady=2
    )
    ttk.Button(btn_frame, text="Remove", command=_remove_merge_hist).pack(
        fill="x", pady=2
    )
    ttk.Button(btn_frame, text="Clear", command=_clear_merge_hist).pack(
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

    def _do_merge():
        if not app.merge_base.get() or not app.merge_out.get():
            app._show_inline_error(
                btn_merge,
                "Missing input: Please provide base checklist and output path.",
            )
            return

        out_path = Path(app.merge_out.get())
        if out_path.exists():
            if not messagebox.askyesno(
                "Overwrite?",
                f"{out_path.name} already exists.\nOverwrite it?",
            ):
                return

        histories = list(app.merge_histories)

        in_base = app.merge_base.get()
        in_out = app.merge_out.get()
        in_preserve = app.merge_preserve.get()
        in_bp = app.merge_bp.get()

        def work():
            return app.proc.merge(
                in_base,
                histories,
                in_out,
                preserve_history=in_preserve,
                apply_boilerplate=in_bp,
            )

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
                messagebox.showerror("Merge Failed", str(result))
            else:
                updated = result.get("updated", 0)
                skipped = result.get("skipped", 0)
                app.status_var.set(f"✔ Merged checklist: {result.get('output')}")
                messagebox.showinfo(
                    "Merge Complete",
                    f"Merge completed successfully.\n\n"
                    f"Vulnerabilities updated: {updated}\n"
                    f"Unchanged: {skipped}\n"
                    f"Output: {result.get('output', 'N/A')}",
                )

        app.status_var.set("Processing…")
        app._async(work, done)

    btn_merge = ttk.Button(
        frame,
        text="🔀 Merge Checklists",
        command=_do_merge,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_merge.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn_merge)

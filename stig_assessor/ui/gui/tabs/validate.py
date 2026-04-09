"""Validate Checklist Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog
import sys

from stig_assessor.ui.helpers import Debouncer
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_FONT_MONO, GUI_FONT_HEADING


def build_validate_tab(app, frame):
    ttk.Label(frame, text="Validate Checklist", font=GUI_FONT_HEADING).pack(
        anchor="w"
    )

    input_frame = ttk.Frame(frame)
    input_frame.pack(fill="x", pady=GUI_PADDING_LARGE)
    ttk.Label(input_frame, text="Checklist (CKL):").pack(side="left")
    app.validate_ckl = tk.StringVar()
    ent_vc = ttk.Entry(input_frame, textvariable=app.validate_ckl, width=60)
    ent_vc.pack(side="left", padx=GUI_PADDING)
    
    def _browse_validate_ckl():
        path = filedialog.askopenfilename(
            title="Select CKL",
            initialdir=app._last_dir(),
            filetypes=[("CKL Files", "*.ckl")],
        )
        if path:
            app.validate_ckl.set(path)
            app._remember_file(path)

    ttk.Button(
        input_frame,
        text="📂 Browse…",
        command=_browse_validate_ckl,
    ).pack(side="left", padx=GUI_PADDING)
    
    def _do_validate():
        if not app.validate_ckl.get():
            app._show_inline_error(
                app.validate_tree,
                "Missing input: Please select a CKL file.",
            )
            return

        in_ckl = app.validate_ckl.get()

        def work():
            return app.proc.validator.validate(in_ckl)

        def done(result):
            app.validate_tree.delete(*app.validate_tree.get_children())

            if isinstance(result, Exception):
                app.validate_tree.insert(
                    "",
                    "end",
                    values=("Error", "System", str(result)),
                    tags=("error",),
                )
                app.validate_summary_var.set(
                    "✘ Validation failed due to system error."
                )
                return
            ok, errors, warnings_, info = result

            if errors:
                for err in errors:
                    app.validate_tree.insert(
                        "",
                        "end",
                        values=("High", "Error", err),
                        tags=("error",),
                    )
            if warnings_:
                for warn in warnings_:
                    app.validate_tree.insert(
                        "",
                        "end",
                        values=("Medium", "Warning", warn),
                        tags=("warn",),
                    )
            if info:
                for msg in info:
                    app.validate_tree.insert(
                        "",
                        "end",
                        values=("Low", "Info", msg),
                        tags=("info",),
                    )

            if ok:
                app.validate_summary_var.set(
                    "✔ Checklist is STIG Viewer compatible."
                )
                # Add dummy success row if nothing else
                if not errors and not warnings_ and not info:
                    app.validate_tree.insert(
                        "",
                        "end",
                        values=(
                            "OK",
                            "Success",
                            "Validation passed successfully.",
                        ),
                        tags=("ok",),
                    )
            else:
                app.validate_summary_var.set(
                    f"✘ Checklist has {len(errors)} error(s) that must be resolved."
                )

        app.status_var.set("Validating…")
        app._async(work, done)

    ttk.Button(
        input_frame,
        text="✅ Validate",
        command=_do_validate,
        style="Accent.TButton",
    ).pack(side="left")
    app._enable_dnd(ent_vc, app.validate_ckl)

    app._validate_ckl_err = ttk.Label(
        input_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._validate_ckl_err.pack(side="left", padx=GUI_PADDING)

    def _validate_validate_form(*args):
        app._validate_ckl_err.config(
            text=("* Required" if not app.validate_ckl.get().strip() else "")
        )

    debounced_val = Debouncer(app.root, 300, _validate_validate_form)
    app.validate_ckl.trace_add("write", debounced_val)
    app.root.after(100, debounced_val)

    # #12 Validation data grid (TreeView) instead of ScrolledText
    columns = ("severity", "type", "message")
    app.validate_tree = ttk.Treeview(
        frame, columns=columns, show="headings", height=18
    )
    app.validate_tree.heading(
        "severity",
        text="Severity",
        command=lambda: app._sort_tree("severity"),
    )
    app.validate_tree.heading(
        "type", text="Type", command=lambda: app._sort_tree("type")
    )
    app.validate_tree.heading(
        "message",
        text="Message",
        command=lambda: app._sort_tree("message"),
    )
    app.validate_tree.column("severity", width=80, anchor="center")
    app.validate_tree.column("type", width=100, anchor="center")
    app.validate_tree.column("message", width=650)

    tree_scroll = ttk.Scrollbar(
        frame, orient="vertical", command=app.validate_tree.yview
    )
    app.validate_tree.configure(yscrollcommand=tree_scroll.set)
    app.validate_tree.pack(
        side="left", fill="both", expand=True, pady=GUI_PADDING
    )
    tree_scroll.pack(side="right", fill="y", pady=GUI_PADDING)
    # Color tags for tree rows
    app.validate_tree.tag_configure(
        "error", foreground=app._colors.get("error", "#CC0000")
    )
    app.validate_tree.tag_configure(
        "warn", foreground=app._colors.get("warn", "#CC8800")
    )
    app.validate_tree.tag_configure(
        "ok", foreground=app._colors.get("ok", "#008800")
    )
    app.validate_tree.tag_configure(
        "info", foreground=app._colors.get("info", "#0055AA")
    )
    # Right-click copy
    app._attach_tree_context_menu(app.validate_tree)

    # Also keep a text label for the summary line
    app.validate_summary_var = tk.StringVar()
    ttk.Label(
        frame,
        textvariable=app.validate_summary_var,
        font=GUI_FONT_MONO,
    ).pack(anchor="w", pady=2)

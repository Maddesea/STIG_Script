"""Create CKL Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from stig_assessor.ui.helpers import Debouncer, ToolTip
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE
from stig_assessor.xml.schema import Sch


def build_create_tab(app, frame):
    # Input/Output Frame
    files_frame = ttk.LabelFrame(frame, text="Files", padding=GUI_PADDING_LARGE)
    files_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    files_frame.columnconfigure(1, weight=1)

    ttk.Label(files_frame, text="XCCDF File: *").grid(row=0, column=0, sticky="w")
    app.create_xccdf = tk.StringVar()
    ent_xccdf = ttk.Entry(
        files_frame,
        textvariable=app.create_xccdf,
        width=GUI_ENTRY_WIDTH,
    )
    ent_xccdf.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_create_xccdf():
        path = filedialog.askopenfilename(
            title="Select XCCDF",
            initialdir=app._last_dir(),
            filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")],
        )
        if path:
            app.create_xccdf.set(path)
            app._remember_file(path)
            if not app.create_out.get():
                app.create_out.set(str(Path(path).with_suffix(".ckl")))

    ttk.Button(
        files_frame,
        text="📂 Browse…",
        command=_browse_create_xccdf,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_xccdf, app.create_xccdf)

    app._create_xccdf_err = ttk.Label(
        files_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._create_xccdf_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

    ttk.Label(files_frame, text="Output CKL:").grid(row=1, column=0, sticky="w")
    app.create_out = tk.StringVar()
    ttk.Entry(
        files_frame,
        textvariable=app.create_out,
        width=GUI_ENTRY_WIDTH,
    ).grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_create_out():
        path = filedialog.asksaveasfilename(
            title="Save CKL As",
            defaultextension=".ckl",
            filetypes=[("CKL Files", "*.ckl"), ("All Files", "*.*")],
        )
        if path:
            app.create_out.set(path)

    ttk.Button(
        files_frame, text="📂 Browse…", command=_browse_create_out
    ).grid(row=1, column=2)

    def _clear_create_form():
        app.create_xccdf.set("")
        app.create_out.set("")
        app.create_asset.set("")
        app.create_ip.set("")
        app.create_mac.set("")
        app.create_bp.set(False)
        app.create_mark.set("CUI")

    ttk.Button(
        files_frame, text="🗑 Clear Form", command=_clear_create_form
    ).grid(row=1, column=3, padx=GUI_PADDING_LARGE)

    # Asset Info Frame
    asset_frame = ttk.LabelFrame(
        frame, text="Asset Details", padding=GUI_PADDING_LARGE
    )
    asset_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    asset_frame.columnconfigure(1, weight=1)

    r = 0
    ttk.Label(asset_frame, text="Asset Name: *").grid(
        row=r, column=0, sticky="w"
    )
    app.create_asset = tk.StringVar(
        value=app._settings.get("create_asset", "")
    )
    ttk.Entry(
        asset_frame,
        textvariable=app.create_asset,
        width=GUI_ENTRY_WIDTH,
    ).grid(row=r, column=1, padx=GUI_PADDING, sticky="we")
    app._create_asset_err = ttk.Label(
        asset_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._create_asset_err.grid(row=r, column=2, sticky="w", padx=GUI_PADDING)

    def _validate_create_form(*args):
        x_val = app.create_xccdf.get().strip()
        a_val = app.create_asset.get().strip()
        app._create_xccdf_err.config(text="* Required" if not x_val else "")
        app._create_asset_err.config(text="* Required" if not a_val else "")

    debounced_create = Debouncer(app.root, 300, _validate_create_form)
    app.create_xccdf.trace_add("write", debounced_create)
    app.create_asset.trace_add("write", debounced_create)
    app.root.after(100, debounced_create)

    r += 1

    ttk.Label(asset_frame, text="IP Address:").grid(row=r, column=0, sticky="w")
    app.create_ip = tk.StringVar(value=app._settings.get("create_ip", ""))
    ttk.Entry(
        asset_frame, textvariable=app.create_ip, width=GUI_ENTRY_WIDTH
    ).grid(row=r, column=1, padx=GUI_PADDING, sticky="we")
    r += 1

    ttk.Label(asset_frame, text="MAC Address:").grid(
        row=r, column=0, sticky="w"
    )
    app.create_mac = tk.StringVar(value=app._settings.get("create_mac", ""))
    ttk.Entry(
        asset_frame,
        textvariable=app.create_mac,
        width=GUI_ENTRY_WIDTH,
    ).grid(row=r, column=1, padx=GUI_PADDING, sticky="we")
    r += 1

    ttk.Label(asset_frame, text="Marking:").grid(row=r, column=0, sticky="w")
    app.create_mark = tk.StringVar(
        value=app._settings.get("create_mark", "CUI")
    )
    ttk.Combobox(
        asset_frame,
        textvariable=app.create_mark,
        values=sorted(Sch.MARKS),
        width=GUI_ENTRY_WIDTH - 3,
    ).grid(row=r, column=1, padx=GUI_PADDING, sticky="we")
    r += 1

    app.create_bp = tk.BooleanVar(value=app._settings.get("create_bp", False))
    cb_bp = ttk.Checkbutton(
        asset_frame,
        text="Apply boilerplate templates",
        variable=app.create_bp,
    )
    cb_bp.grid(row=r, column=1, sticky="w", pady=(GUI_PADDING, 0))
    ToolTip(
        cb_bp,
        "Automatically populate finding details and comments\nwith default templates for each status.",
    )

    def _do_create():
        if (
            not app.create_xccdf.get()
            or not app.create_asset.get()
            or not app.create_out.get()
        ):
            app._show_inline_error(
                btn_create,
                "Missing input: Please provide XCCDF, asset name, and output path.",
            )
            return

        out_path = Path(app.create_out.get())
        if out_path.exists():
            if not messagebox.askyesno(
                "Overwrite?",
                f"{out_path.name} already exists.\nOverwrite it?",
            ):
                return

        in_xccdf = app.create_xccdf.get()
        out_file = app.create_out.get()
        asset = app.create_asset.get()
        ip = app.create_ip.get()
        mac = app.create_mac.get()
        marking = app.create_mark.get()
        bp = app.create_bp.get()

        def work():
            return app.proc.xccdf_to_ckl(
                in_xccdf,
                out_file,
                asset,
                ip=ip,
                mac=mac,
                marking=marking,
                apply_boilerplate=bp,
            )

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
                messagebox.showerror("Create Failed", str(result))
            else:
                processed = result.get("processed", 0)
                skipped = result.get("skipped", 0)
                errors = result.get("errors", [])
                app.status_var.set(f"✔ Checklist created: {result.get('output')}")
                summary = f"Checklist created successfully.\n\nProcessed: {processed}\nSkipped: {skipped}"
                if errors:
                    summary += (
                        f"\nErrors: {len(errors)}\nFirst error: {errors[0][:120]}"
                    )
                messagebox.showinfo("Create Complete", summary)

        app.status_var.set("Processing…")
        app._async(work, done)

    btn_create = ttk.Button(
        frame,
        text="➕ Create Checklist",
        command=_do_create,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_create.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn_create)
    app.action_create = _do_create

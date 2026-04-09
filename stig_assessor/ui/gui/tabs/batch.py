"""Batch Convert Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE


def build_batch_tab(app, frame):
    io_frame = ttk.LabelFrame(
        frame,
        text="Bulk Data Transformation",
        padding=GUI_PADDING_LARGE,
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Input Directory: *").grid(
        row=0, column=0, sticky="w"
    )
    app.batch_ind = tk.StringVar()
    ent_1 = ttk.Entry(
        io_frame, textvariable=app.batch_ind, width=GUI_ENTRY_WIDTH
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_batch_in():
        path = filedialog.askdirectory(title="Select Input Directory", initialdir=app._last_dir())
        if path:
            app.batch_ind.set(path)

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_batch_in,
    ).grid(row=0, column=2)

    ttk.Label(io_frame, text="Output Directory: *").grid(
        row=1, column=0, sticky="w", pady=GUI_PADDING
    )
    app.batch_out = tk.StringVar()
    ent_2 = ttk.Entry(
        io_frame, textvariable=app.batch_out, width=GUI_ENTRY_WIDTH
    )
    ent_2.grid(
        row=1,
        column=1,
        padx=GUI_PADDING,
        sticky="we",
        pady=GUI_PADDING,
    )

    def _browse_batch_out():
        path = filedialog.askdirectory(title="Select Output Directory", initialdir=app._last_dir())
        if path:
            app.batch_out.set(path)

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_batch_out,
    ).grid(row=1, column=2, pady=GUI_PADDING)

    def _clear_batch_form():
        app.batch_ind.set("")
        app.batch_out.set("")
        app.batch_prefix.set("ASSET")
        app.batch_bp.set(False)

    ttk.Button(
        io_frame,
        text="🗑 Clear Form",
        command=_clear_batch_form,
    ).grid(row=1, column=3, pady=GUI_PADDING, padx=GUI_PADDING_LARGE)

    opt_frame = ttk.LabelFrame(frame, text="Options", padding=GUI_PADDING_LARGE)
    opt_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    ttk.Label(opt_frame, text="Asset Prefix:").grid(row=0, column=0, sticky="w")
    app.batch_prefix = tk.StringVar(value="ASSET")
    ttk.Entry(
        opt_frame,
        textvariable=app.batch_prefix,
        width=20,
    ).grid(row=0, column=1, padx=GUI_PADDING, sticky="w")

    app.batch_bp = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        opt_frame,
        text="Apply boilerplate templates",
        variable=app.batch_bp,
    ).grid(
        row=1,
        column=0,
        columnspan=2,
        sticky="w",
        pady=(GUI_PADDING, 0),
    )

    def _do_batch_convert():
        in_dir = app.batch_ind.get().strip()
        out_dir = app.batch_out.get().strip()
        if not in_dir or not out_dir:
            messagebox.showerror(
                "Missing input",
                "Please provide both input and output directories.",
            )
            return

        prefix = app.batch_prefix.get()
        bp = app.batch_bp.get()

        def work():
            return app.proc.batch_convert(
                xccdf_dir=in_dir,
                out_dir=out_dir,
                asset_prefix=prefix,
                apply_boilerplate=bp,
            )

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Batch convert failed: {result}")
                messagebox.showerror("Batch Convert Error", str(result))
            else:
                successes = result.get("successes", 0)
                failures = result.get("failures", 0)
                total = result.get("total", 0)

                msg = f"Total files: {total}\nSuccesses: {successes}\nFailures: {failures}\n\nOutput saved in: {out_dir}"
                app.status_var.set(
                    f"✔ Batch conversion complete. Output: {out_dir}"
                )
                messagebox.showinfo("Batch Convert Complete", msg)
                
                if successes > 0 and messagebox.askyesno("Open Directory", "Batch conversion complete. Would you like to open the output directory?"):
                    import os, sys, subprocess
                    if os.name == "nt":
                        os.startfile(out_dir)
                    elif sys.platform == "darwin":
                        subprocess.call(["open", out_dir])
                    else:
                        subprocess.call(["xdg-open", out_dir])

        app.status_var.set("Running batch conversion...")
        app._async(work, done)

    btn_batch = ttk.Button(
        frame,
        text="🏭 Convert Batch",
        command=_do_batch_convert,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_batch.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn_batch)
    app.action_batch = _do_batch_convert

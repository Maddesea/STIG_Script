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
        path = filedialog.askdirectory(title="Select Input Directory")
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
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            app.batch_out.set(path)

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_batch_out,
    ).grid(row=1, column=2, pady=GUI_PADDING)

    opt_frame = ttk.LabelFrame(frame, text="Options", padding=GUI_PADDING_LARGE)
    opt_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    ttk.Label(opt_frame, text="Format:").grid(row=0, column=0, sticky="w")
    app.batch_fmt = tk.StringVar(value="csv")
    ttk.Combobox(
        opt_frame,
        textvariable=app.batch_fmt,
        values=["csv", "json"],
        state="readonly",
        width=10,
    ).grid(row=0, column=1, padx=GUI_PADDING, sticky="w")

    app.batch_merge = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        opt_frame,
        text="Merge into single file",
        variable=app.batch_merge,
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

        fmt = app.batch_fmt.get()
        merge = app.batch_merge.get()

        def work():
            return app.proc.batch_convert(
                input_dir=in_dir,
                output_dir=out_dir,
                format_=fmt,
                merge=merge,
            )

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Batch convert failed: {result}")
                messagebox.showerror("Batch Convert Error", str(result))
            else:
                processed = result.get("processed", 0)
                skipped = result.get("skipped", 0)
                errors = result.get("errors", 0)
                out_path = result.get("output", "")

                msg = f"Processed: {processed}\nSkipped: {skipped}\nErrors: {errors}\n\nOutput saved in: {out_path}"
                app.status_var.set(
                    f"✔ Batch conversion complete. Output: {out_path}"
                )
                messagebox.showinfo("Batch Convert Complete", msg)

        app.status_var.set("Running batch conversion...")
        app._async(work, done)

    btn_batch = ttk.Button(
        frame,
        text="🏭 Export Batch",
        command=_do_batch_convert,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_batch.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn_batch)

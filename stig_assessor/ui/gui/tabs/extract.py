"""Extract Fixes Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path

from stig_assessor.ui.helpers import Debouncer
from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE
from stig_assessor.remediation.extractor import FixExt


def build_extract_tab(app, frame):
    # Input/Output
    io_frame = ttk.LabelFrame(
        frame, text="Input & Output", padding=GUI_PADDING_LARGE
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="XCCDF File: *").grid(row=0, column=0, sticky="w")
    app.extract_xccdf = tk.StringVar()
    ent_ex = ttk.Entry(
        io_frame,
        textvariable=app.extract_xccdf,
        width=GUI_ENTRY_WIDTH,
    )
    ent_ex.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_extract_xccdf():
        path = filedialog.askopenfilename(
            title="Select XCCDF",
            initialdir=app._last_dir(),
            filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")],
        )
        if path:
            app.extract_xccdf.set(path)
            app._remember_file(path)

    ttk.Button(
        io_frame, text="📂 Browse…", command=_browse_extract_xccdf
    ).grid(row=0, column=2)
    app._enable_dnd(ent_ex, app.extract_xccdf)
    app._extract_xccdf_err = ttk.Label(
        io_frame, text="", foreground=app._colors.get("error", "red")
    )
    app._extract_xccdf_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

    ttk.Label(io_frame, text="Output Dir: *").grid(row=1, column=0, sticky="w")
    app.extract_outdir = tk.StringVar()
    ent_outdir = ttk.Entry(
        io_frame,
        textvariable=app.extract_outdir,
        width=GUI_ENTRY_WIDTH,
    )
    ent_outdir.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_extract_out():
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            app.extract_outdir.set(path)

    ttk.Button(
        io_frame, text="📂 Browse…", command=_browse_extract_out
    ).grid(row=1, column=2)
    app._extract_outdir_err = ttk.Label(
        io_frame, text="", foreground=app._colors.get("error", "red")
    )
    app._extract_outdir_err.grid(row=1, column=3, sticky="w", padx=GUI_PADDING)

    def _validate_extract_form(*args):
        app._extract_xccdf_err.config(
            text=("* Required" if not app.extract_xccdf.get().strip() else "")
        )
        app._extract_outdir_err.config(
            text=("* Required" if not app.extract_outdir.get().strip() else "")
        )

    debounced_extract = Debouncer(app.root, 300, _validate_extract_form)
    app.extract_xccdf.trace_add("write", debounced_extract)
    app.extract_outdir.trace_add("write", debounced_extract)
    app.root.after(100, debounced_extract)

    # Options
    formats = ttk.LabelFrame(
        frame, text="Export Formats", padding=GUI_PADDING_LARGE
    )
    formats.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app.extract_json = tk.BooleanVar(value=True)
    app.extract_csv = tk.BooleanVar(value=True)
    app.extract_bash = tk.BooleanVar(value=True)
    app.extract_ps = tk.BooleanVar(value=True)
    app.extract_ansible = tk.BooleanVar(value=True)

    # Grid for checkbuttons
    ttk.Checkbutton(formats, text="JSON", variable=app.extract_json).grid(
        row=0, column=0, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="CSV", variable=app.extract_csv).grid(
        row=0, column=1, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="Bash", variable=app.extract_bash).grid(
        row=0, column=2, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(formats, text="PowerShell", variable=app.extract_ps).grid(
        row=0, column=3, padx=GUI_PADDING_LARGE
    )
    ttk.Checkbutton(
        formats, text="Ansible", variable=app.extract_ansible
    ).grid(row=0, column=4, padx=GUI_PADDING_LARGE)

    opts_frame = ttk.Frame(frame)
    opts_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    app.extract_dry = tk.BooleanVar(value=False)
    app.extract_rollbacks = tk.BooleanVar(value=False)

    ttk.Checkbutton(
        opts_frame,
        text="Generate scripts in dry-run mode",
        variable=app.extract_dry,
    ).pack(anchor="center")
    ttk.Checkbutton(
        opts_frame,
        text="Enable PowerShell Registry Rollbacks (`reg export`)",
        variable=app.extract_rollbacks,
    ).pack(anchor="center", pady=(5, 0))

    def _do_extract():
        if not app.extract_xccdf.get() or not app.extract_outdir.get():
            app._show_inline_error(
                btn_extract,
                "Missing input: Please provide XCCDF file and output directory.",
            )
            return

        in_xccdf = app.extract_xccdf.get()
        outdir = Path(app.extract_outdir.get())
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)

        do_json = app.extract_json.get()
        do_csv = app.extract_csv.get()
        do_bash = app.extract_bash.get()
        do_ps = app.extract_ps.get()
        do_ansible = app.extract_ansible.get()
        dry = app.extract_dry.get()

        def work():
            extractor = FixExt(in_xccdf)
            extractor.extract()
            outpaths = []
            if do_json:
                extractor.to_json(outdir / "fixes.json")
                outpaths.append("JSON")
            if do_csv:
                extractor.to_csv(outdir / "fixes.csv")
                outpaths.append("CSV")
            if do_bash:
                extractor.to_bash(outdir / "remediate.sh", dry_run=dry)
                outpaths.append("Bash")
            if do_ps:
                enable_rollbacks = app.extract_rollbacks.get()
                extractor.to_powershell(
                    outdir / "Remediate.ps1",
                    dry_run=dry,
                    enable_rollbacks=enable_rollbacks,
                )
                outpaths.append("PowerShell")
            if do_ansible:
                if hasattr(extractor, "to_ansible"):
                    extractor.to_ansible(outdir / "remediate.yml", dry_run=dry)
                outpaths.append("Ansible")
            return extractor.stats_summary(), outpaths

        def done(result):
            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
            else:
                stats, formats = result
                app.status_var.set(
                    f"✔ Fix extraction complete. Total groups: {stats['total_groups']}"
                )

        app.status_var.set("Processing…")
        app._async(work, done)

    btn_extract = ttk.Button(
        frame,
        text="💾 Extract Fixes",
        command=_do_extract,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_extract.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn_extract)

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
        app.batch_recursive.set(False)
        if hasattr(app, '_batch_tree'):
            for row in app._batch_tree.get_children():
                app._batch_tree.delete(row)

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
        sticky="w",
        pady=(GUI_PADDING, 0),
    )
    
    app.batch_recursive = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        opt_frame,
        text="Recursive scan subdirectories",
        variable=app.batch_recursive,
    ).grid(
        row=1,
        column=1,
        sticky="w",
        pady=(GUI_PADDING, 0),
    )
    
    app._batch_status_var = tk.StringVar(value="Not_Reviewed")
    ttk.Label(opt_frame, text="Default Status:").grid(
        row=2, column=0, sticky="w", pady=(GUI_PADDING, 0)
    )
    ttk.Combobox(
        opt_frame,
        textvariable=app._batch_status_var,
        values=["Not_Reviewed", "Open", "NotAFinding", "Not_Applicable"],
        state="readonly",
        width=17
    ).grid(row=2, column=1, sticky="w", pady=(GUI_PADDING, 0))

    # Results Panel (Treeview)
    results_frame = ttk.LabelFrame(frame, text="Batch Results", padding=GUI_PADDING)
    results_frame.pack(fill="both", expand=True, pady=(0, GUI_PADDING))
    
    tree_cols = ("file", "status", "message")
    app._batch_tree = ttk.Treeview(results_frame, columns=tree_cols, show="headings", height=8)
    app._batch_tree.heading("file", text="Filename")
    app._batch_tree.heading("status", text="Status")
    app._batch_tree.heading("message", text="Message / Errors")
    app._batch_tree.column("file", width=200)
    app._batch_tree.column("status", width=80)
    app._batch_tree.column("message", width=400)
    app._batch_tree.pack(side="left", fill="both", expand=True)
    
    batch_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=app._batch_tree.yview)
    batch_scroll.pack(side="right", fill="y")
    app._batch_tree.config(yscrollcommand=batch_scroll.set)
    
    app._batch_tree.tag_configure("ok", foreground="#10b981")
    app._batch_tree.tag_configure("error", foreground="#ef4444")
    
    # Progress UI
    prog_frame = ttk.Frame(frame)
    prog_frame.pack(fill="x", pady=(0, GUI_PADDING))
    app._batch_progress = ttk.Progressbar(prog_frame, mode="determinate")
    app._batch_progress.pack(fill="x")

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
        recursive = app.batch_recursive.get()
        default_status = app._batch_status_var.get()
        
        in_path = Path(in_dir)
        out_path = Path(out_dir)
        
        if not in_path.exists() or not in_path.is_dir():
            messagebox.showerror("Error", "Input directory does not exist or is not a directory.")
            return
            
        out_path.mkdir(parents=True, exist_ok=True)
        
        files = list(in_path.rglob("*.xml")) if recursive else list(in_path.glob("*.xml"))
        if not files:
            messagebox.showinfo("No Files", f"No XML files found in {in_dir}")
            return
            
        app._batch_progress["maximum"] = len(files)
        app._batch_progress["value"] = 0
        
        for row in app._batch_tree.get_children():
            app._batch_tree.delete(row)
            
        btn_batch.config(state="disabled")
        app.status_var.set(f"Batch processing {len(files)} files...")
        
        import time
        start_time = time.time()
        
        # Disable action buttons
        app._disable_ui()
        
        successes = 0
        failures = 0
        
        def _process_chunk(idx):
            nonlocal successes, failures
            if idx >= len(files):
                app._batch_progress["value"] = 0
                btn_batch.config(state="normal")
                app._enable_ui()
                msg = f"Total files: {len(files)}\nSuccesses: {successes}\nFailures: {failures}\n\nOutput saved in: {out_dir}"
                app.status_var.set(f"✔ Batch conversion complete. Success: {successes}, Failures: {failures}")
                messagebox.showinfo("Batch Convert Complete", msg)
                if successes > 0 and messagebox.askyesno("Open Directory", "Batch conversion complete. Would you like to open the output directory?"):
                    import os, sys, subprocess
                    if os.name == "nt": os.startfile(out_dir)
                    elif sys.platform == "darwin": subprocess.call(["open", out_dir])
                    else: subprocess.call(["xdg-open", out_dir])
                return

            # Process 10 files per chunk minimum
            chunk_end = min(idx + 10, len(files))
            for i in range(idx, chunk_end):
                fpath = files[i]
                asset_name = f"{prefix}_{fpath.stem.replace(' ', '_').replace('-', '_')}"
                out_file = out_path / f"{fpath.stem}.ckl"
                
                try:
                    # Modify xccdf ingestion defaults inside memory if needed, or string hack post-gen.
                    # xccdf_to_ckl unfortunately hard-codes Not_Reviewed. We will replace it quickly if default_status != Not_Reviewed
                    result = app.proc.xccdf_to_ckl(fpath, out_file, asset_name, apply_boilerplate=bp)
                    processed = result.get("processed", 0)
                    
                    if default_status != "Not_Reviewed":
                        from stig_assessor.io.file_ops import FO
                        tree = FO.parse_xml(out_file)
                        from stig_assessor.xml.schema import Sch
                        for v in tree.getroot().findall(".//VULN"):
                            s_node = v.find(Sch.STATUS)
                            if s_node is not None: s_node.text = default_status
                        FO.write_xml(tree, out_file)
                        
                    app._batch_tree.insert("", tk.END, values=(fpath.name, "Success", f"Processed {processed} rules"), tags=("ok",))
                    successes += 1
                except Exception as e:
                    app._batch_tree.insert("", tk.END, values=(fpath.name, "Failed", str(e)), tags=("error",))
                    failures += 1
                
            app._batch_tree.yview_moveto(1.0)
            app._batch_progress["value"] = chunk_end
            
            elapsed = time.time() - start_time
            eta = (elapsed / chunk_end) * (len(files) - chunk_end) if chunk_end > 0 else 0
            app.status_var.set(f"Converting... {chunk_end}/{len(files)} (ETA: {int(eta)}s)")
            
            app.root.after(10, _process_chunk, chunk_end)

        _process_chunk(0)

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

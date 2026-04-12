"""Import Results Tab module."""

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import List

from stig_assessor.core.constants import (GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH, GUI_PADDING,
                                          GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION)
from stig_assessor.core.logging import LOG
from stig_assessor.exceptions import ValidationError
from stig_assessor.remediation.processor import FixResPro
from stig_assessor.ui.helpers import Debouncer, ToolTip


def build_results_tab(app, frame):
    # Batch Import
    batch_frame = ttk.LabelFrame(
        frame,
        text="Batch Import (Multiple JSON Files)",
        padding=GUI_PADDING_LARGE,
    )
    batch_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    ttk.Label(batch_frame, text="Results Files:").grid(
        row=0,
        column=0,
        sticky="nw",
        padx=GUI_PADDING,
        pady=GUI_PADDING,
    )

    list_container = ttk.Frame(batch_frame)
    list_container.grid(row=0, column=1, padx=GUI_PADDING, sticky="ew")

    app.results_list = tk.Listbox(
        list_container, height=5, width=65, selectmode=tk.EXTENDED
    )
    app.results_list.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(
        list_container,
        orient="vertical",
        command=app.results_list.yview,
    )
    scrollbar.pack(side="right", fill="y")
    app.results_list.config(yscrollcommand=scrollbar.set)

    app.results_files: List[str] = []

    def _remove_results_file():
        selections = app.results_list.curselection()
        if not selections:
            return

        for index in reversed(selections):
            app.results_list.delete(index)
            app.results_files.pop(index)

        app.status_var.set(f"{len(app.results_files)} file(s) remaining")

    app._attach_listbox_context_menu(
        app.results_list,
        app.results_files,
        _remove_results_file,
    )

    def _add_results_files():
        paths = filedialog.askopenfilenames(
            title="Select Remediation Results (Ctrl+Click for multiple)",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialdir=app._last_dir(),
        )
        added = 0
        for path in paths:
            if path and path not in app.results_files:
                app.results_files.append(path)
                app.results_list.insert(tk.END, Path(path).name)
                added += 1

        if added:
            app.status_var.set(
                f"✓ Added {added} file(s) - Total: {len(app.results_files)} queued"
            )

    def _paste_results_files():
        try:
            paths = app.root.clipboard_get().splitlines()
            added = 0
            for path in paths:
                path = path.strip().strip('"').strip("'")
                if os.path.exists(path) and path not in app.results_files:
                    app.results_files.append(path)
                    app.results_list.insert(tk.END, Path(path).name)
                    added += 1
            if added:
                app.status_var.set(
                    f"✓ Pasted {added} file(s) - Total: {len(app.results_files)} queued"
                )
            else:
                app.status_var.set("No valid file paths found in clipboard")
        except tk.TclError:
            app.status_var.set("Clipboard is empty or inaccessible")

    def _clear_results_files():
        if not app.results_files:
            return
        if not messagebox.askyesno(
            "Confirm Clear",
            f"Remove all {len(app.results_files)} file(s) from the queue?",
        ):
            return
        app.results_files.clear()
        app.results_list.delete(0, tk.END)
        app.status_var.set("Queue cleared")

    def _add_results_folder():
        directory = filedialog.askdirectory(
            title="Select Folder containing Remediation Results",
            initialdir=app._last_dir(),
        )
        if not directory:
            return

        added = 0
        path_dir = Path(directory)
        for p in path_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in [".json", ".csv"]:
                str_p = str(p)
                if str_p not in app.results_files:
                    app.results_files.append(str_p)
                    app.results_list.insert(tk.END, p.name)
                    added += 1

        if added:
            app.status_var.set(
                f"✓ Added {added} file(s) from folder - Total: {len(app.results_files)} queued"
            )
        else:
            app.status_var.set("No JSON/CSV files found in selected folder")

    btn_container = ttk.Frame(batch_frame)
    btn_container.grid(row=0, column=2, sticky="n", padx=GUI_PADDING)
    ttk.Button(
        btn_container,
        text="Add Files…",
        command=_add_results_files,
        width=15,
    ).pack(fill="x", pady=2)
    ttk.Button(
        btn_container,
        text="Add Folder…",
        command=_add_results_folder,
        width=15,
    ).pack(fill="x", pady=2)
    ttk.Button(
        btn_container,
        text="Paste Files",
        command=_paste_results_files,
        width=15,
    ).pack(fill="x", pady=2)
    ttk.Button(
        btn_container,
        text="Remove",
        command=_remove_results_file,
        width=15,
    ).pack(fill="x", pady=2)
    ttk.Button(
        btn_container,
        text="Clear All",
        command=_clear_results_files,
        width=15,
    ).pack(fill="x", pady=2)

    batch_frame.columnconfigure(1, weight=1)

    # Single File Import
    single_frame = ttk.LabelFrame(
        frame, text="Single File Import", padding=GUI_PADDING_LARGE
    )
    single_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    single_frame.columnconfigure(1, weight=1)

    ttk.Label(single_frame, text="Results JSON:").grid(
        row=0, column=0, sticky="w", padx=GUI_PADDING
    )
    app.results_json = tk.StringVar()
    ent_rj = ttk.Entry(
        single_frame,
        textvariable=app.results_json,
        width=GUI_ENTRY_WIDTH,
    )
    ent_rj.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_results_json():
        path = filedialog.askopenfilename(
            title="Select results JSON",
            initialdir=app._last_dir(),
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if path:
            app.results_json.set(path)
            app._remember_file(path)

    ttk.Button(
        single_frame,
        text="📂 Browse…",
        command=_browse_results_json,
    ).grid(row=0, column=2, padx=GUI_PADDING)
    app._enable_dnd(ent_rj, app.results_json)

    # Target & Output
    target_frame = ttk.LabelFrame(
        frame, text="Target & Output", padding=GUI_PADDING_LARGE
    )
    target_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    target_frame.columnconfigure(1, weight=1)

    ttk.Label(target_frame, text="Target CKL: *").grid(row=0, column=0, sticky="w")
    app.results_ckl = tk.StringVar()
    ent_rc = ttk.Entry(
        target_frame,
        textvariable=app.results_ckl,
        width=GUI_ENTRY_WIDTH,
    )
    ent_rc.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_results_ckl():
        path = filedialog.askopenfilename(
            title="Select checklist",
            initialdir=app._last_dir(),
            filetypes=[("CKL Files", "*.ckl")],
        )
        if path:
            app.results_ckl.set(path)
            app._remember_file(path)
            if not app.results_out.get():
                out_path = Path(path).with_name(Path(path).stem + "_updated.ckl")
                app.results_out.set(str(out_path))

    ttk.Button(
        target_frame,
        text="📂 Browse…",
        command=_browse_results_ckl,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_rc, app.results_ckl)
    app._results_ckl_err = ttk.Label(
        target_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._results_ckl_err.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)

    ttk.Label(target_frame, text="Output CKL: *").grid(row=1, column=0, sticky="w")
    app.results_out = tk.StringVar()
    ent_out = ttk.Entry(
        target_frame,
        textvariable=app.results_out,
        width=GUI_ENTRY_WIDTH,
    )
    ent_out.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_results_out():
        path = filedialog.asksaveasfilename(
            title="Save updated CKL As",
            initialdir=app._last_dir(),
            defaultextension=".ckl",
            filetypes=[("CKL Files", "*.ckl")],
        )
        if path:
            app.results_out.set(path)

    ttk.Button(
        target_frame,
        text="📂 Browse…",
        command=_browse_results_out,
    ).grid(row=1, column=2)
    app._results_out_err = ttk.Label(
        target_frame,
        text="",
        foreground=app._colors.get("error", "red"),
    )
    app._results_out_err.grid(row=1, column=3, sticky="w", padx=GUI_PADDING)

    def _validate_results_form(*args):
        app._results_ckl_err.config(
            text=("* Required" if not app.results_ckl.get().strip() else "")
        )
        app._results_out_err.config(
            text=("* Required" if not app.results_out.get().strip() else "")
        )

    debounced_results = Debouncer(app.root, 300, _validate_results_form)
    app.results_ckl.trace_add("write", debounced_results)
    app.results_out.trace_add("write", debounced_results)
    app.root.after(100, debounced_results)

    # Options
    opts_frame = ttk.Frame(frame)
    opts_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    mode_frame = ttk.Frame(opts_frame)
    mode_frame.pack(fill="x", pady=(0, 5))

    ttk.Label(mode_frame, text="Finding Details Action:").grid(
        row=0, column=0, sticky="w", padx=GUI_PADDING
    )
    app.results_details_mode = tk.StringVar(value="prepend")
    cb_details = ttk.Combobox(
        mode_frame,
        textvariable=app.results_details_mode,
        values=["prepend", "append", "overwrite"],
        state="readonly",
        width=12,
    )
    cb_details.grid(row=0, column=1, sticky="w", padx=GUI_PADDING)
    ToolTip(
        cb_details,
        "How to apply new finding details to existing ones.",
    )

    ttk.Label(mode_frame, text="Comments Action:").grid(
        row=0,
        column=2,
        sticky="w",
        padx=(GUI_PADDING_LARGE, GUI_PADDING),
    )
    app.results_comment_mode = tk.StringVar(value="prepend")
    cb_comment = ttk.Combobox(
        mode_frame,
        textvariable=app.results_comment_mode,
        values=["prepend", "append", "overwrite"],
        state="readonly",
        width=12,
    )
    cb_comment.grid(row=0, column=3, sticky="w", padx=GUI_PADDING)
    ToolTip(cb_comment, "How to apply new comments to existing ones.")

    app.results_auto = tk.BooleanVar(value=True)
    cb_auto = ttk.Checkbutton(
        opts_frame,
        text="Auto-mark successful remediations as NotAFinding",
        variable=app.results_auto,
    )
    cb_auto.pack(anchor="center")
    ToolTip(
        cb_auto,
        "When a remediation result reports 'pass', automatically\nset the vulnerability status to NotAFinding.",
    )

    app.results_dry = tk.BooleanVar(value=False)
    cb_dry = ttk.Checkbutton(
        opts_frame,
        text="Dry run (preview only)",
        variable=app.results_dry,
    )
    cb_dry.pack(anchor="center")
    ToolTip(
        cb_dry,
        "Preview what would change without writing the output file.\nUseful for verifying results before committing.",
    )

    def _do_results(force_dry=False):
        if not app.results_ckl.get() or (not app.results_out.get() and not force_dry):
            app._show_inline_error(
                btn_results,
                "Missing input: Please provide checklist and output path.",
            )
            return

        # Collect files: batch list takes priority over single field
        files_to_process = []
        if app.results_files:
            files_to_process = list(app.results_files)
        elif app.results_json.get():
            files_to_process = [app.results_json.get()]
        else:
            app._show_inline_error(
                btn_results,
                "Missing input: Please add result files or specify single JSON file.",
            )
            return

        dry = True if force_dry else app.results_dry.get()
        auto = app.results_auto.get()
        in_ckl = app.results_ckl.get()
        out_ckl = app.results_out.get()
        details_mode = (
            app.results_details_mode.get()
            if hasattr(app, "results_details_mode")
            else "prepend"
        )
        comment_mode = (
            app.results_comment_mode.get()
            if hasattr(app, "results_comment_mode")
            else "prepend"
        )

        def work():
            combined_processor = FixResPro()
            total_loaded = 0
            total_skipped = 0
            failed_files = []

            for idx, result_file in enumerate(files_to_process, 1):
                try:
                    app.queue.put(
                        (
                            "status",
                            f"Loading {idx}/{len(files_to_process)}: {Path(result_file).name}",
                        )
                    )
                    app.queue.put(("progress", (idx / len(files_to_process)) * 100))
                    imported, skipped = combined_processor.load(result_file)
                    total_loaded += imported
                    total_skipped += skipped
                except (
                    FileNotFoundError,
                    PermissionError,
                    ValueError,
                    ValidationError,
                ) as exc:
                    LOG.e(f"Failed to load {result_file}: {exc}")
                    failed_files.append((Path(result_file).name, str(exc)))
                    continue

            app.queue.put(("status", "Applying results to CKL..."))
            app.queue.put(("progress", 0))

            if not combined_processor.results:
                raise ValidationError("No valid results loaded from any file")

            result = combined_processor.update_ckl(
                in_ckl,
                out_ckl,
                auto_status=auto,
                dry=dry,
                details_mode=details_mode,
                comment_mode=comment_mode,
            )
            result["total_loaded"] = total_loaded
            result["total_skipped"] = total_skipped
            result["files_processed"] = len(files_to_process)
            result["failed_files"] = failed_files
            result["processor_results"] = combined_processor.results
            return result

        def done(result):
            # Update Preview Tree
            for row in app._res_preview_tree.get_children():
                app._res_preview_tree.delete(row)

            if isinstance(result, Exception):
                app.status_var.set(f"✘ Error: {result}")
                messagebox.showerror("Import Failed", str(result))
            else:
                nf = result.get("not_found", [])
                nf_display = f"{len(nf)} VIDs" if nf else "None"

                proc_results = result.get("processor_results", {})
                for vid, r in proc_results.items():
                    status_text = "Pass" if r.ok else "Fail"
                    app._res_preview_tree.insert(
                        "", tk.END, values=(vid, status_text, r.message)
                    )

                summary = (
                    f"✔ Batch import complete!\n"
                    f"Files: {result.get('files_processed', 0)} | "
                    f"Results loaded: {result.get('total_loaded', 0)} | "
                    f"Skipped: {result.get('total_skipped', 0)}\n"
                    f"Vulnerabilities updated: {result.get('updated', 0)} | "
                    f"Not found: {nf_display}\n"
                    f"Output: {result.get('output', 'dry run')}"
                )

                app.status_var.set(
                    f"Batch import complete: {result.get('updated', 0)} updated"
                )
                messagebox.showinfo("Success", summary)

        app.status_var.set("Processing batch import…")
        app._async(work, done)

    # Actions
    def _clear_results_form():
        if app.results_files:
            if not messagebox.askyesno(
                "Confirm Clear", "Clear all form inputs and the batch file queue?"
            ):
                return
            app.results_files.clear()
            app.results_list.delete(0, tk.END)
        app.results_json.set("")
        app.results_ckl.set("")
        app.results_out.set("")
        app.results_details_mode.set("prepend")
        app.results_comment_mode.set("prepend")
        app.results_auto.set(True)
        app.results_dry.set(False)

    app._res_preview_frame = ttk.LabelFrame(
        frame, text="Results Preview", padding=GUI_PADDING
    )
    app._res_preview_frame.pack(fill="both", expand=True, pady=(0, GUI_PADDING))

    res_cols = ("vid", "status", "msg")
    app._res_preview_tree = ttk.Treeview(
        app._res_preview_frame, columns=res_cols, show="headings", height=5
    )
    app._res_preview_tree.heading("vid", text="VID")
    app._res_preview_tree.heading("status", text="Pass / Fail")
    app._res_preview_tree.heading("msg", text="Message")

    app._res_preview_tree.column("vid", width=120)
    app._res_preview_tree.column("status", width=100)
    app._res_preview_tree.column("msg", width=400)
    app._res_preview_tree.pack(side="left", fill="both", expand=True)

    res_scroll = ttk.Scrollbar(
        app._res_preview_frame, orient="vertical", command=app._res_preview_tree.yview
    )
    res_scroll.pack(side="right", fill="y")
    app._res_preview_tree.config(yscrollcommand=res_scroll.set)

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=GUI_PADDING_SECTION)

    btn_preview = ttk.Button(
        btn_row,
        text="👁 Preview Import",
        command=lambda: _do_results(force_dry=True),
        width=18,
    )
    btn_preview.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    btn_results = ttk.Button(
        btn_row,
        text="📥 Apply Remediation Results",
        command=lambda: _do_results(force_dry=False),
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn_results.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    ttk.Button(btn_row, text="🗑 Clear Form", command=_clear_results_form).pack(
        side="left"
    )

    app._action_buttons.append(btn_results)
    app.action_results = _do_results

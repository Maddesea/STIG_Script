"""Graphical user interface (tkinter-based)."""

from __future__ import annotations
from typing import Any, Callable, List, Tuple
from pathlib import Path
from datetime import datetime
from contextlib import suppress
import threading
import queue
import platform

# Temporary imports from monolithic file - will be replaced when other teams complete their modules
# This allows Team 12 to work in parallel while Teams 0-11 modularize their components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from STIG_Script import (
        # Core components (Team 1)
        Cfg, LOG, Deps, APP_NAME, VERSION, BUILD_DATE, STIG_VIEWER_VERSION,
        # XML components (Teams 2, 4)
        Sch, San,
        # Processor (Team 11)
        Proc,
        # Remediation (Teams 8, 10)
        FixExt, FixResPro,
        # Evidence (Team 9)
        EvidenceMgr,
        # Exceptions (Team 0)
        ValidationError,
    )
    from STIG_Script import PresetMgr
except ImportError:
    # If running as part of the full modular package
    from stig_assessor.core.config import Cfg, APP_NAME, VERSION, BUILD_DATE, STIG_VIEWER_VERSION
    from stig_assessor.core.logging import LOG
    from stig_assessor.core.deps import Deps
    from stig_assessor.xml.schema import Sch
    from stig_assessor.xml.sanitizer import San
    from stig_assessor.processor.processor import Proc
    from stig_assessor.remediation.extractor import FixExt
    from stig_assessor.remediation.processor import FixResPro
    from stig_assessor.evidence.manager import EvidenceMgr
    from stig_assessor.exceptions import ValidationError
    from stig_assessor.ui.presets import PresetMgr

# Tkinter imports - only if available
if Deps.HAS_TKINTER:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    from tkinter.scrolledtext import ScrolledText


    class GUI:
        """Graphical interface."""

        def __init__(self):
            self.root = tk.Tk()
            self.root.title(f"{APP_NAME} v{VERSION}")
            self.root.geometry("1100x760")
            with suppress(Exception):
                self.root.iconbitmap(False)

            self.proc = Proc()
            self.evidence = EvidenceMgr()
            self.presets = PresetMgr()
            self.queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

            self._build_menus()
            self._build_tabs()
            self.root.protocol("WM_DELETE_WINDOW", self._close)
            self.root.after(200, self._process_queue)

        # --------------------------------------------------------------- UI setup
        def _build_menus(self) -> None:
            menu = tk.Menu(self.root)
            self.root.config(menu=menu)

            file_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(label="Save Preset…", command=self._save_preset)
            file_menu.add_command(label="Load Preset…", command=self._load_preset)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self._close)

            tools_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Tools", menu=tools_menu)
            tools_menu.add_command(label="Export History…", command=self._export_history)
            tools_menu.add_command(label="Import History…", command=self._import_history)
            tools_menu.add_separator()
            tools_menu.add_command(label="Export Boilerplates…", command=self._export_boiler)
            tools_menu.add_command(label="Import Boilerplates…", command=self._import_boiler)
            tools_menu.add_separator()
            tools_menu.add_command(label="Cleanup Old Files", command=self._cleanup_old)

            help_menu = tk.Menu(menu, tearoff=0)
            menu.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="About", command=self._about)

        def _build_tabs(self) -> None:
            notebook = ttk.Notebook(self.root)
            notebook.pack(fill="both", expand=True, padx=5, pady=5)

            tabs = [
                ("Create CKL", self._tab_create),
                ("Merge Checklists", self._tab_merge),
                ("Extract Fixes", self._tab_extract),
                ("Import Results", self._tab_results),
                ("Evidence", self._tab_evidence),
                ("Validate", self._tab_validate),
            ]

            for title, builder in tabs:
                frame = ttk.Frame(notebook, padding=10)
                notebook.add(frame, text=title)
                builder(frame)

        # --------------------------------------------------------------- tabs
        def _tab_create(self, frame):
            r = 0
            ttk.Label(frame, text="XCCDF File:").grid(row=r, column=0, sticky="w")
            self.create_xccdf = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_xccdf, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_create_xccdf).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Asset Name: *").grid(row=r, column=0, sticky="w")
            self.create_asset = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_asset, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="IP Address:").grid(row=r, column=0, sticky="w")
            self.create_ip = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_ip, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="MAC Address:").grid(row=r, column=0, sticky="w")
            self.create_mac = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_mac, width=70).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="Marking:").grid(row=r, column=0, sticky="w")
            self.create_mark = tk.StringVar(value="CUI")
            ttk.Combobox(
                frame,
                textvariable=self.create_mark,
                values=sorted(Sch.MARKS),
                width=67,
                state="readonly",
            ).grid(row=r, column=1, padx=5)
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.create_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.create_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_create_out).grid(row=r, column=2)
            r += 1

            self.create_bp = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                frame,
                text="Apply boilerplate templates",
                variable=self.create_bp,
            ).grid(row=r, column=1, sticky="w")
            r += 1

            ttk.Button(
                frame,
                text="Create Checklist",
                command=self._do_create,
                width=25,
            ).grid(row=r, column=1, pady=15)
            r += 1

            self.create_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.create_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_merge(self, frame):
            r = 0
            ttk.Label(frame, text="Base Checklist:").grid(row=r, column=0, sticky="w")
            self.merge_base = tk.StringVar()
            ttk.Entry(frame, textvariable=self.merge_base, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_merge_base).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Historical Files:").grid(row=r, column=0, sticky="nw")
            list_frame = ttk.Frame(frame)
            list_frame.grid(row=r, column=1, padx=5, sticky="ew")
            self.merge_list = tk.Listbox(list_frame, height=6, width=60)
            self.merge_list.pack(side="left", fill="both", expand=True)
            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.merge_list.yview)
            scrollbar.pack(side="right", fill="y")
            self.merge_list.config(yscrollcommand=scrollbar.set)

            btn_frame = ttk.Frame(frame)
            btn_frame.grid(row=r, column=2, sticky="n")
            ttk.Button(btn_frame, text="Add…", command=self._add_merge_hist).pack(fill="x", pady=2)
            ttk.Button(btn_frame, text="Remove", command=self._remove_merge_hist).pack(fill="x", pady=2)
            ttk.Button(btn_frame, text="Clear", command=self._clear_merge_hist).pack(fill="x", pady=2)
            self.merge_histories: List[str] = []
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.merge_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.merge_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_merge_out).grid(row=r, column=2)
            r += 1

            options = ttk.LabelFrame(frame, text="Options", padding=10)
            options.grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
            self.merge_preserve = tk.BooleanVar(value=True)
            ttk.Checkbutton(options, text="Preserve full history", variable=self.merge_preserve).pack(anchor="w")
            self.merge_bp = tk.BooleanVar(value=True)
            ttk.Checkbutton(options, text="Apply boilerplates when missing", variable=self.merge_bp).pack(anchor="w")
            r += 1

            ttk.Button(frame, text="Merge Checklists", command=self._do_merge, width=25).grid(row=r, column=1, pady=15)
            r += 1

            self.merge_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.merge_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_extract(self, frame):
            r = 0
            ttk.Label(frame, text="XCCDF File:").grid(row=r, column=0, sticky="w")
            self.extract_xccdf = tk.StringVar()
            ttk.Entry(frame, textvariable=self.extract_xccdf, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_extract_xccdf).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Output Directory:").grid(row=r, column=0, sticky="w")
            self.extract_outdir = tk.StringVar()
            ttk.Entry(frame, textvariable=self.extract_outdir, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_extract_out).grid(row=r, column=2)
            r += 1

            formats = ttk.LabelFrame(frame, text="Export Formats", padding=10)
            formats.grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
            self.extract_json = tk.BooleanVar(value=True)
            self.extract_csv = tk.BooleanVar(value=True)
            self.extract_bash = tk.BooleanVar(value=True)
            self.extract_ps = tk.BooleanVar(value=True)
            ttk.Checkbutton(formats, text="JSON", variable=self.extract_json).grid(row=0, column=0, padx=10)
            ttk.Checkbutton(formats, text="CSV", variable=self.extract_csv).grid(row=0, column=1, padx=10)
            ttk.Checkbutton(formats, text="Bash", variable=self.extract_bash).grid(row=0, column=2, padx=10)
            ttk.Checkbutton(formats, text="PowerShell", variable=self.extract_ps).grid(row=0, column=3, padx=10)
            r += 1

            self.extract_dry = tk.BooleanVar(value=False)
            ttk.Checkbutton(frame, text="Generate scripts in dry-run mode", variable=self.extract_dry).grid(
                row=r, column=1, sticky="w"
            )
            r += 1

            ttk.Button(frame, text="Extract Fixes", command=self._do_extract, width=25).grid(row=r, column=1, pady=15)
            r += 1

            self.extract_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.extract_status, wraplength=860, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )

        def _tab_results(self, frame):
            """Results import tab with batch file support."""
            r = 0

            # ═══ BATCH IMPORT ═══
            batch_frame = ttk.LabelFrame(frame, text="📁 Batch Import (Multiple JSON Files)", padding=10)
            batch_frame.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(0, 10))

            ttk.Label(batch_frame, text="Results Files:").grid(row=0, column=0, sticky="nw", padx=5, pady=5)

            list_container = ttk.Frame(batch_frame)
            list_container.grid(row=0, column=1, padx=5, sticky="ew")

            self.results_list = tk.Listbox(list_container, height=5, width=65, selectmode=tk.EXTENDED)
            self.results_list.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.results_list.yview)
            scrollbar.pack(side="right", fill="y")
            self.results_list.config(yscrollcommand=scrollbar.set)

            self.results_files: List[str] = []

            btn_container = ttk.Frame(batch_frame)
            btn_container.grid(row=0, column=2, sticky="n", padx=5)
            ttk.Button(btn_container, text="Add Files…", command=self._add_results_files, width=15).pack(fill="x", pady=2)
            ttk.Button(btn_container, text="Remove", command=self._remove_results_file, width=15).pack(fill="x", pady=2)
            ttk.Button(btn_container, text="Clear All", command=self._clear_results_files, width=15).pack(fill="x", pady=2)

            batch_frame.columnconfigure(1, weight=1)
            r += 1

            # ═══ SINGLE FILE (LEGACY) ═══
            single_frame = ttk.LabelFrame(frame, text="📄 Single File Import", padding=10)
            single_frame.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(0, 10))

            ttk.Label(single_frame, text="Results JSON:").grid(row=0, column=0, sticky="w", padx=5)
            self.results_json = tk.StringVar()
            ttk.Entry(single_frame, textvariable=self.results_json, width=70).grid(row=0, column=1, padx=5)
            ttk.Button(single_frame, text="Browse…", command=self._browse_results_json).grid(row=0, column=2, padx=5)
            r += 1

            # ═══ TARGET CHECKLIST ═══
            ttk.Label(frame, text="Target Checklist (CKL):").grid(row=r, column=0, sticky="w")
            self.results_ckl = tk.StringVar()
            ttk.Entry(frame, textvariable=self.results_ckl, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_results_ckl).grid(row=r, column=2)
            r += 1

            ttk.Label(frame, text="Output CKL:").grid(row=r, column=0, sticky="w")
            self.results_out = tk.StringVar()
            ttk.Entry(frame, textvariable=self.results_out, width=70).grid(row=r, column=1, padx=5)
            ttk.Button(frame, text="Browse…", command=self._browse_results_out).grid(row=r, column=2)
            r += 1

            # ═══ OPTIONS ═══
            self.results_auto = tk.BooleanVar(value=True)
            ttk.Checkbutton(
                frame,
                text="Auto-mark successful remediations as NotAFinding",
                variable=self.results_auto,
            ).grid(row=r, column=1, sticky="w")
            r += 1

            self.results_dry = tk.BooleanVar(value=False)
            ttk.Checkbutton(frame, text="Dry run (preview only)", variable=self.results_dry).grid(
                row=r, column=1, sticky="w"
            )
            r += 1

            # ═══ ACTION ═══
            ttk.Button(frame, text="Apply Remediation Results", command=self._do_results, width=30).grid(row=r, column=1, pady=15)
            r += 1

            # ═══ STATUS ═══
            self.results_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.results_status, wraplength=900, foreground="blue").grid(
                row=r, column=0, columnspan=3, pady=5
            )


        # Add helper methods for batch file management:

        def _add_results_files(self):
            """Add multiple result files to batch queue."""
            paths = filedialog.askopenfilenames(
                title="Select Remediation Results (Ctrl+Click for multiple)",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
            )
            added = 0
            for path in paths:
                if path and path not in self.results_files:
                    self.results_files.append(path)
                    self.results_list.insert(tk.END, Path(path).name)
                    added += 1

            if added:
                self.results_status.set(f"✓ Added {added} file(s) - Total: {len(self.results_files)} queued")

        def _remove_results_file(self):
            """Remove selected files from batch queue."""
            selections = self.results_list.curselection()
            if not selections:
                return

            for index in reversed(selections):
                self.results_list.delete(index)
                self.results_files.pop(index)

            self.results_status.set(f"{len(self.results_files)} file(s) remaining")

        def _clear_results_files(self):
            """Clear all files from batch queue."""
            self.results_files.clear()
            self.results_list.delete(0, tk.END)
            self.results_status.set("Queue cleared")



        def _do_results(self):
            """Apply remediation results with batch import support."""
            if not self.results_ckl.get() or not self.results_out.get():
                messagebox.showerror("Missing input", "Please provide checklist and output path.")
                return

            # Collect files: batch list takes priority over single field
            files_to_process = []
            if self.results_files:
                files_to_process = list(self.results_files)
            elif self.results_json.get():
                files_to_process = [self.results_json.get()]
            else:
                messagebox.showerror("Missing input", "Please add result files or specify single JSON file.")
                return

            dry = self.results_dry.get()
            auto = self.results_auto.get()

            def work():
                """Background batch processor."""
                combined_processor = FixResPro()
                total_loaded = 0
                total_skipped = 0
                failed_files = []

                for idx, result_file in enumerate(files_to_process, 1):
                    try:
                        LOG.i(f"Loading {idx}/{len(files_to_process)}: {Path(result_file).name}")
                        imported, skipped = combined_processor.load(result_file)
                        total_loaded += imported
                        total_skipped += skipped
                    except Exception as exc:
                        LOG.e(f"Failed to load {result_file}: {exc}")
                        failed_files.append((Path(result_file).name, str(exc)))
                        continue

                if not combined_processor.results:
                    raise ValidationError("No valid results loaded from any file")

                result = combined_processor.update_ckl(
                    self.results_ckl.get(),
                    self.results_out.get(),
                    auto_status=auto,
                    dry=dry,
                )
                result['total_loaded'] = total_loaded
                result['total_skipped'] = total_skipped
                result['files_processed'] = len(files_to_process)
                result['failed_files'] = failed_files
                return result

            def done(result):
                """Completion handler."""
                if isinstance(result, Exception):
                    self.results_status.set(f"✘ Error: {result}")
                    messagebox.showerror("Import Failed", str(result))
                else:
                    nf = result.get("not_found", [])
                    nf_display = f"{len(nf)} VIDs" if nf else "None"

                    summary = (
                        f"✔ Batch import complete!\n"
                        f"Files: {result.get('files_processed', 0)} | "
                        f"Results loaded: {result.get('total_loaded', 0)} | "
                        f"Skipped: {result.get('total_skipped', 0)}\n"
                        f"Vulnerabilities updated: {result.get('updated', 0)} | "
                        f"Not found: {nf_display}\n"
                        f"Output: {result.get('output', 'dry run')}"
                    )

                    self.results_status.set(summary)
                    messagebox.showinfo("Success", summary)

            self.results_status.set("Processing batch import…")
            self._async(work, done)




        def _tab_evidence(self, frame):
            ttk.Label(frame, text="Evidence Manager", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")

            import_frame = ttk.LabelFrame(frame, text="Import Evidence", padding=10)
            import_frame.pack(fill="x", pady=10)
            ttk.Label(import_frame, text="Vuln ID:").grid(row=0, column=0, sticky="w")
            self.evid_vid = tk.StringVar()
            ttk.Entry(import_frame, textvariable=self.evid_vid, width=25).grid(row=0, column=1, padx=5)
            ttk.Label(import_frame, text="Description:").grid(row=0, column=2, sticky="w")
            self.evid_desc = tk.StringVar()
            ttk.Entry(import_frame, textvariable=self.evid_desc, width=30).grid(row=0, column=3, padx=5)
            ttk.Label(import_frame, text="Category:").grid(row=0, column=4, sticky="w")
            self.evid_cat = tk.StringVar(value="general")
            ttk.Entry(import_frame, textvariable=self.evid_cat, width=15).grid(row=0, column=5, padx=5)
            ttk.Button(import_frame, text="Select & Import…", command=self._import_evidence).grid(row=0, column=6, padx=5)

            action_frame = ttk.LabelFrame(frame, text="Export / Package", padding=10)
            action_frame.pack(fill="x", pady=10)
            ttk.Button(action_frame, text="Export All…", command=self._export_evidence).grid(row=0, column=0, padx=5, pady=5)
            ttk.Button(action_frame, text="Create Package…", command=self._package_evidence).grid(row=0, column=1, padx=5, pady=5)
            ttk.Button(action_frame, text="Import Package…", command=self._import_evidence_package).grid(
                row=0, column=2, padx=5, pady=5
            )

            summary_frame = ttk.LabelFrame(frame, text="Summary", padding=10)
            summary_frame.pack(fill="both", expand=True, pady=10)
            self.evid_summary = tk.StringVar()
            ttk.Label(summary_frame, textvariable=self.evid_summary, justify="left", font=("Courier New", 10)).pack(
                anchor="w", pady=5
            )
            self._refresh_evidence_summary()

        def _tab_validate(self, frame):
            ttk.Label(frame, text="Validate Checklist", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")

            input_frame = ttk.Frame(frame)
            input_frame.pack(fill="x", pady=10)
            ttk.Label(input_frame, text="Checklist (CKL):").pack(side="left")
            self.validate_ckl = tk.StringVar()
            ttk.Entry(input_frame, textvariable=self.validate_ckl, width=60).pack(side="left", padx=5)
            ttk.Button(input_frame, text="Browse…", command=self._browse_validate_ckl).pack(side="left", padx=5)
            ttk.Button(input_frame, text="Validate", command=self._do_validate).pack(side="left")

            self.validate_text = ScrolledText(frame, width=120, height=25, font=("Courier New", 10))
            self.validate_text.pack(fill="both", expand=True, pady=5)

            self.validate_status = tk.StringVar()
            ttk.Label(frame, textvariable=self.validate_status, wraplength=860, foreground="blue").pack(pady=5)

        # --------------------------------------------------------- action helpers
        def _async(self, work_func, callback):
            def worker():
                try:
                    result = work_func()
                except Exception as exc:
                    result = exc
                self.queue.put(("callback", callback, result))

            threading.Thread(target=worker, daemon=True).start()

        def _process_queue(self):
            """Process async callback queue with status update support."""
            try:
                while True:
                    item = self.queue.get_nowait()

                    # Handle different message types with validation
                    try:
                        if not isinstance(item, tuple):
                            LOG.w(f"Invalid queue item type: {type(item)}")
                            continue

                        if len(item) == 3:
                            # Standard callback format
                            kind, func, payload = item
                            if kind == "callback" and callable(func):
                                func(payload)
                            else:
                                LOG.w(f"Invalid callback item: kind={kind}, callable={callable(func)}")
                        elif len(item) == 2:
                            # Status update format
                            kind, message = item
                            if kind == "status":
                                self.results_status.set(message)
                                self.root.update_idletasks()  # Force UI refresh
                            else:
                                LOG.w(f"Unknown queue item kind: {kind}")
                        else:
                            LOG.w(f"Invalid queue item length: {len(item)}")
                    except Exception as e:
                        LOG.e(f"Error processing queue item: {e}", exc=True)
            except queue.Empty:
                pass

            self.root.after(200, self._process_queue)


        # -------------------------------------------------------------- browse
        def _browse_create_xccdf(self):
            path = filedialog.askopenfilename(title="Select XCCDF", filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")])
            if path:
                self.create_xccdf.set(path)
                if not self.create_out.get():
                    self.create_out.set(str(Path(path).with_suffix(".ckl")))

        def _browse_create_out(self):
            path = filedialog.asksaveasfilename(
                title="Save CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl"), ("All Files", "*.*")],
            )
            if path:
                self.create_out.set(path)

        def _browse_merge_base(self):
            path = filedialog.askopenfilename(title="Select base CKL", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.merge_base.set(path)

        def _browse_merge_out(self):
            path = filedialog.asksaveasfilename(
                title="Save merged CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.merge_out.set(path)

        def _browse_extract_xccdf(self):
            path = filedialog.askopenfilename(title="Select XCCDF", filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")])
            if path:
                self.extract_xccdf.set(path)

        def _browse_extract_out(self):
            path = filedialog.askdirectory(title="Select output directory")
            if path:
                self.extract_outdir.set(path)

        def _browse_results_json(self):
            path = filedialog.askopenfilename(title="Select results JSON", filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
            if path:
                self.results_json.set(path)

        def _browse_results_ckl(self):
            path = filedialog.askopenfilename(title="Select checklist", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.results_ckl.set(path)
                if not self.results_out.get():
                    out_path = Path(path).with_name(Path(path).stem + "_updated.ckl")
                    self.results_out.set(str(out_path))

        def _browse_results_out(self):
            path = filedialog.asksaveasfilename(
                title="Save updated CKL As",
                defaultextension=".ckl",
                filetypes=[("CKL Files", "*.ckl")],
            )
            if path:
                self.results_out.set(path)

        def _browse_validate_ckl(self):
            path = filedialog.askopenfilename(title="Select CKL", filetypes=[("CKL Files", "*.ckl")])
            if path:
                self.validate_ckl.set(path)

        # ------------------------------------------------------------ actions
        def _do_create(self):
            if not self.create_xccdf.get() or not self.create_asset.get() or not self.create_out.get():
                messagebox.showerror("Missing input", "Please provide XCCDF, asset name, and output path.")
                return

            def work():
                return self.proc.xccdf_to_ckl(
                    self.create_xccdf.get(),
                    self.create_out.get(),
                    self.create_asset.get(),
                    ip=self.create_ip.get(),
                    mac=self.create_mac.get(),
                    marking=self.create_mark.get(),
                    apply_boilerplate=self.create_bp.get(),
                )

            def done(result):
                if isinstance(result, Exception):
                    self.create_status.set(f"✘ Error: {result}")
                else:
                    self.create_status.set(
                        f"✔ Checklist created: {result.get('output')}\n"
                        f"Processed: {result.get('processed')} | Skipped: {result.get('skipped')}"
                    )

            self.create_status.set("Processing…")
            self._async(work, done)

        def _add_merge_hist(self):
            paths = filedialog.askopenfilenames(title="Select historical CKL", filetypes=[("CKL Files", "*.ckl")])
            for path in paths:
                if path not in self.merge_histories:
                    self.merge_histories.append(path)
                    self.merge_list.insert(tk.END, path)

        def _remove_merge_hist(self):
            selection = self.merge_list.curselection()
            if not selection:
                return
            index = selection[0]
            path = self.merge_histories.pop(index)
            self.merge_list.delete(index)
            LOG.d(f"Removed historical checklist: {path}")

        def _clear_merge_hist(self):
            self.merge_histories.clear()
            self.merge_list.delete(0, tk.END)

        def _do_merge(self):
            if not self.merge_base.get() or not self.merge_out.get():
                messagebox.showerror("Missing input", "Please provide base checklist and output path.")
                return

            histories = list(self.merge_histories)

            def work():
                return self.proc.merge(
                    self.merge_base.get(),
                    histories,
                    self.merge_out.get(),
                    preserve_history=self.merge_preserve.get(),
                    apply_boilerplate=self.merge_bp.get(),
                )

            def done(result):
                if isinstance(result, Exception):
                    self.merge_status.set(f"✘ Error: {result}")
                else:
                    self.merge_status.set(
                        f"✔ Merged checklist: {result.get('output')}\n"
                        f"Updated: {result.get('updated')} | Skipped: {result.get('skipped')}"
                    )

            self.merge_status.set("Processing…")
            self._async(work, done)

        def _do_extract(self):
            if not self.extract_xccdf.get() or not self.extract_outdir.get():
                messagebox.showerror("Missing input", "Please provide XCCDF file and output directory.")
                return

            outdir = Path(self.extract_outdir.get())
            outdir.mkdir(parents=True, exist_ok=True)

            def work():
                extractor = FixExt(self.extract_xccdf.get())
                fixes = extractor.extract()
                outpaths = []
                if self.extract_json.get():
                    extractor.to_json(outdir / "fixes.json")
                    outpaths.append("JSON")
                if self.extract_csv.get():
                    extractor.to_csv(outdir / "fixes.csv")
                    outpaths.append("CSV")
                if self.extract_bash.get():
                    extractor.to_bash(outdir / "remediate.sh", dry_run=self.extract_dry.get())
                    outpaths.append("Bash")
                if self.extract_ps.get():
                    extractor.to_powershell(outdir / "Remediate.ps1", dry_run=self.extract_dry.get())
                    outpaths.append("PowerShell")
                return extractor.stats_summary(), outpaths

            def done(result):
                if isinstance(result, Exception):
                    self.extract_status.set(f"✘ Error: {result}")
                else:
                    stats, formats = result
                    self.extract_status.set(
                        f"✔ Fix extraction complete\n"
                        f"Total groups: {stats['total_groups']} | With fixes: {stats['with_fix']} | "
                        f"Commands: {stats['with_command']}\n"
                        f"Formats: {', '.join(formats)}"
                    )

            self.extract_status.set("Processing…")
            self._async(work, done)

        def _import_evidence(self):
            vid = self.evid_vid.get()
            if not vid:
                messagebox.showerror("Missing input", "Please enter a vulnerability ID.")
                return
            try:
                San.vuln(vid)
            except Exception:
                messagebox.showerror("Invalid Vuln ID", "Please enter a valid Vuln ID (e.g. V-12345).")
                return
            path = filedialog.askopenfilename(title="Select evidence file")
            if not path:
                return

            def work():
                return self.evidence.import_file(
                    vid,
                    path,
                    description=self.evid_desc.get(),
                    category=self.evid_cat.get() or "general",
                )

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Error importing evidence", str(result))
                else:
                    messagebox.showinfo("Evidence Imported", f"Evidence stored at:\n{result}")
                    self._refresh_evidence_summary()
                    self.evid_vid.set("")
                    self.evid_desc.set("")
                    self.evid_cat.set("general")

            self._async(work, done)

        def _export_evidence(self):
            path = filedialog.askdirectory(title="Select export directory")
            if not path:
                return

            def work():
                return self.evidence.export_all(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo("Evidence Export", f"Exported {result} file(s) to {path}")

            self._async(work, done)

        def _package_evidence(self):
            path = filedialog.asksaveasfilename(
                title="Save evidence package",
                defaultextension=".zip",
                filetypes=[("ZIP Files", "*.zip")],
            )
            if not path:
                return

            def work():
                return self.evidence.package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Package error", str(result))
                else:
                    messagebox.showinfo("Evidence Package", f"Package created:\n{result}")

            self._async(work, done)

        def _import_evidence_package(self):
            path = filedialog.askopenfilename(title="Select evidence package", filetypes=[("ZIP Files", "*.zip")])
            if not path:
                return

            def work():
                return self.evidence.import_package(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo("Evidence import", f"Imported {result} file(s)")
                    self._refresh_evidence_summary()

            self._async(work, done)

        def _do_validate(self):
            if not self.validate_ckl.get():
                messagebox.showerror("Missing input", "Please select a CKL file.")
                return

            def work():
                return self.proc.validator.validate(self.validate_ckl.get())

            def done(result):
                if isinstance(result, Exception):
                    self.validate_text.insert("end", f"✘ Error: {result}\n")
                    return
                ok, errors, warnings_, info = result
                self.validate_text.delete("1.0", "end")
                self.validate_text.insert("end", "=" * 80 + "\n")
                self.validate_text.insert("end", f"Validation Report - {datetime.now()}\n")
                self.validate_text.insert("end", "=" * 80 + "\n\n")
                if errors:
                    self.validate_text.insert("end", "Errors:\n", "error")
                    for err in errors:
                        self.validate_text.insert("end", f"  - {err}\n")
                    self.validate_text.insert("end", "\n")
                if warnings_:
                    self.validate_text.insert("end", "Warnings:\n", "warn")
                    for warn in warnings_:
                        self.validate_text.insert("end", f"  - {warn}\n")
                    self.validate_text.insert("end", "\n")
                if info:
                    self.validate_text.insert("end", "Information:\n", "info")
                    for msg in info:
                        self.validate_text.insert("end", f"  - {msg}\n")
                    self.validate_text.insert("end", "\n")
                if ok:
                    self.validate_text.insert("end", "✔ Checklist is STIG Viewer compatible.\n", "ok")
                else:
                    self.validate_text.insert("end", "✘ Checklist has errors that must be resolved.\n", "error")

            self.validate_status.set("Validating…")
            self._async(work, done)

        # ------------------------------------------------------------ menu actions
        def _save_preset(self):
            name = simpledialog.askstring("Save Preset", "Preset name:")
            if not name:
                return
            preset = {
                "xccdf": self.create_xccdf.get(),
                "asset": self.create_asset.get(),
                "ip": self.create_ip.get(),
                "mac": self.create_mac.get(),
                "mark": self.create_mark.get(),
                "apply_boilerplate": self.create_bp.get(),
            }
            try:
                self.presets.save(name, preset)
                messagebox.showinfo("Preset saved", f"Preset '{name}' saved.")
            except Exception as exc:
                messagebox.showerror("Preset error", str(exc))

        def _load_preset(self):
            names = self.presets.list()
            if not names:
                messagebox.showinfo("No presets", "No presets available.")
                return
            name = simpledialog.askstring("Load Preset", f"Available presets:\n{', '.join(names)}\n\nEnter name:")
            if not name:
                return
            preset = self.presets.load(name)
            if not preset:
                messagebox.showerror("Preset error", f"Preset '{name}' not found.")
                return
            self.create_xccdf.set(preset.get("xccdf", ""))
            self.create_asset.set(preset.get("asset", ""))
            self.create_ip.set(preset.get("ip", ""))
            self.create_mac.set(preset.get("mac", ""))
            self.create_mark.set(preset.get("mark", "CUI"))
            self.create_bp.set(bool(preset.get("apply_boilerplate", False)))
            messagebox.showinfo("Preset loaded", f"Preset '{name}' loaded.")

        def _export_history(self):
            path = filedialog.asksaveasfilename(
                title="Export history",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return

            def work():
                self.proc.history.export(path)
                return path

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Export error", str(result))
                else:
                    messagebox.showinfo("History export", f"History exported to {result}")

            self._async(work, done)

        def _import_history(self):
            path = filedialog.askopenfilename(title="Import history", filetypes=[("JSON Files", "*.json")])
            if not path:
                return

            def work():
                return self.proc.history.imp(path)

            def done(result):
                if isinstance(result, Exception):
                    messagebox.showerror("Import error", str(result))
                else:
                    messagebox.showinfo("History import", f"Imported {result} history entries.")

            self._async(work, done)

        def _export_boiler(self):
            path = filedialog.asksaveasfilename(
                title="Export boilerplates",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json")],
            )
            if not path:
                return
            try:
                self.proc.boiler.export(path)
                messagebox.showinfo("Boilerplates", f"Boilerplates exported to {path}")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _import_boiler(self):
            path = filedialog.askopenfilename(title="Import boilerplates", filetypes=[("JSON Files", "*.json")])
            if not path:
                return
            try:
                self.proc.boiler.imp(path)
                messagebox.showinfo("Boilerplates", "Custom boilerplates imported.")
            except Exception as exc:
                messagebox.showerror("Boilerplate error", str(exc))

        def _cleanup_old(self):
            try:
                backups, logs = Cfg.cleanup_old()
                messagebox.showinfo("Cleanup", f"Removed {backups} backup(s) and {logs} log(s).")
            except Exception as exc:
                messagebox.showerror("Cleanup error", str(exc))

        def _about(self):
            messagebox.showinfo(
                "About",
                f"{APP_NAME}\nVersion: {VERSION}\nBuild: {BUILD_DATE}\n"
                f"STIG Viewer: {STIG_VIEWER_VERSION}\n"
                f"Python: {platform.python_version()}\n"
                f"Platform: {platform.system()} {platform.release()}",
            )

        # --------------------------------------------------------------- helpers
        def _refresh_evidence_summary(self):
            summary = self.evidence.summary()
            text = (
                f"Vulnerabilities with evidence: {summary['vulnerabilities']}\n"
                f"Total files: {summary['files']}\n"
                f"Total size: {summary['size_mb']:.2f} MB ({summary['size_bytes']} bytes)\n"
                f"Storage path: {summary['storage']}"
            )
            self.evid_summary.set(text)

        def _close(self):
            self.root.destroy()

        def run(self):
            self.root.mainloop()

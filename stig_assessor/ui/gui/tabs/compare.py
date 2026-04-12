"""Compare Checklists Tab module."""

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from stig_assessor.core.constants import (GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH, GUI_FONT_MONO,
                                          GUI_PADDING, GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION)


def build_compare_tab(app, frame):
    # --- Top Control Frame ---
    io_frame = ttk.LabelFrame(frame, text="Input Checklists", padding=GUI_PADDING_LARGE)
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Baseline CKL:").grid(row=0, column=0, sticky="w")
    app.diff_ckl1 = tk.StringVar()
    ent_1 = ttk.Entry(io_frame, textvariable=app.diff_ckl1, width=GUI_ENTRY_WIDTH)
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl1():
        path = filedialog.askopenfilename(
            initialdir=app._last_dir(),
            filetypes=[("Checklist", "*.ckl"), ("Compressed Checklist", "*.cklb")],
        )
        if path:
            app.diff_ckl1.set(path)
            app._last_dir(os.path.dirname(path))

    ttk.Button(
        io_frame,
        text="📂 Browse",
        command=_browse_ckl1,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_1, app.diff_ckl1)

    ttk.Label(io_frame, text="Target CKL:").grid(row=1, column=0, sticky="w")
    app.diff_ckl2 = tk.StringVar()
    ent_2 = ttk.Entry(io_frame, textvariable=app.diff_ckl2, width=GUI_ENTRY_WIDTH)
    ent_2.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl2():
        path = filedialog.askopenfilename(
            initialdir=app._last_dir(),
            filetypes=[("Checklist", "*.ckl"), ("Compressed Checklist", "*.cklb")],
        )
        if path:
            app.diff_ckl2.set(path)
            app._last_dir(os.path.dirname(path))

    ttk.Button(
        io_frame,
        text="📂 Browse",
        command=_browse_ckl2,
    ).grid(row=1, column=2)
    app._enable_dnd(ent_2, app.diff_ckl2)

    # --- Summary Bar ---
    summary_frame = ttk.Frame(frame)
    summary_frame.pack(fill="x", pady=(0, GUI_PADDING))

    app.diff_summary_labels = {}
    for i, label in enumerate(["Changes", "Added", "Removed"]):
        f = ttk.Frame(summary_frame, padding=(10, 5))
        f.pack(side="left", padx=5)
        ttk.Label(f, text=label, font=("TkDefaultFont", 9, "bold")).pack(side="top")
        var = tk.StringVar(value="0")
        app.diff_summary_labels[label.lower()] = var
        ttk.Label(f, textvariable=var, font=("TkDefaultFont", 12)).pack(side="bottom")

    # --- Actions Frame ---
    actions_frame = ttk.Frame(frame)
    actions_frame.pack(fill="x", pady=GUI_PADDING)

    ttk.Label(actions_frame, text="Filter View:").pack(
        side="left", padx=(0, GUI_PADDING)
    )
    app._diff_filter_var = tk.StringVar(value="All Differences")
    cb = ttk.Combobox(
        actions_frame,
        textvariable=app._diff_filter_var,
        values=[
            "All Differences",
            "Only Status Changes",
            "Only Details/Comments",
            "Only Rules Added/Removed",
        ],
        state="readonly",
        width=25,
    )
    cb.pack(side="left", padx=(0, GUI_PADDING_LARGE))

    def _render_diff_tree():
        if not hasattr(app, "_diff_full_data"):
            return

        results = app._diff_full_data
        filter_mode = app._diff_filter_var.get()

        for item in app.diff_tree.get_children():
            app.diff_tree.delete(item)

        # Populate Tree
        for ch in results.get("changes", []):
            vid = ch.get("vid")
            for df in ch.get("differences", []):
                field = df.get("field", "status")

                # Apply filter
                if filter_mode == "Only Status Changes" and field != "status":
                    continue
                if filter_mode == "Only Details/Comments" and field == "status":
                    continue
                if filter_mode == "Only Rules Added/Removed":
                    continue

                val_from = df.get("from", "")
                val_to = df.get("to", "")

                disp_from = str(val_from).replace("\n", " ")[:100]
                disp_to = str(val_to).replace("\n", " ")[:100]

                tags = []
                if field == "status":
                    if val_to == "NotAFinding":
                        tags.append("success")
                    elif val_to == "Open":
                        tags.append("danger")

                app.diff_tree.insert(
                    "",
                    "end",
                    values=(vid, field.replace("_", " ").title(), disp_from, disp_to),
                    tags=tags,
                )

        # Added/Removed
        if filter_mode in ["All Differences", "Only Rules Added/Removed"]:
            for vid in results.get("added", []):
                app.diff_tree.insert(
                    "",
                    "end",
                    values=(vid, "Rule", "(Not in Baseline)", "ADDED TO CHECKLIST"),
                    tags=("success",),
                )
            for vid in results.get("removed", []):
                app.diff_tree.insert(
                    "",
                    "end",
                    values=(
                        vid,
                        "Rule",
                        "PRESENT IN BASELINE",
                        "(Removed from Target)",
                    ),
                    tags=("danger",),
                )

    cb.bind("<<ComboboxSelected>>", lambda e: _render_diff_tree())

    def _do_diff_tab():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            messagebox.showerror(
                "Error", "Please provide two checklists for comparison."
            )
            return

        app.status_var.set("Comparing checklists...")

        def work():
            return app.proc.diff(
                app.diff_ckl1.get(), app.diff_ckl2.get(), output_format="json"
            )

        def done(results):
            if isinstance(results, Exception):
                messagebox.showerror("Diff Error", str(results))
                return

            app._diff_full_data = results  # Store for detailed view
            s = results.get("summary", {})
            app.diff_summary_labels["changes"].set(str(s.get("changed", 0)))
            app.diff_summary_labels["added"].set(str(s.get("only_in_comparison", 0)))
            app.diff_summary_labels["removed"].set(str(s.get("only_in_baseline", 0)))

            _render_diff_tree()
            app.status_var.set(
                f"Diff complete. {s.get('changed', 0)} changes identified."
            )

        app._async(work, done)

    btn_compare = ttk.Button(
        actions_frame,
        text="🔍 Run Comparison",
        command=_do_diff_tab,
        style="Accent.TButton",
        width=20,
    )
    btn_compare.pack(side="left", padx=GUI_PADDING)
    app._action_buttons.append(btn_compare)

    def _export_html_diff():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            return
        out = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML", "*.html")]
        )
        if out:
            from stig_assessor.processor.html_diff import generate_html_diff

            generate_html_diff(app.diff_ckl1.get(), app.diff_ckl2.get(), out)
            messagebox.showinfo("Export Success", f"HTML Diff report saved to:\n{out}")

    ttk.Button(
        actions_frame, text="🌐 Export HTML Diff", command=_export_html_diff
    ).pack(side="left", padx=GUI_PADDING)

    def _export_csv_diff():
        if not app.diff_tree.get_children():
            return
        out = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv")]
        )
        if not out:
            return
        import csv

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Vulnerability ID", "Field", "Baseline Value", "Target Value"]
            )
            for item in app.diff_tree.get_children():
                writer.writerow(app.diff_tree.item(item)["values"])
        messagebox.showinfo("Export Success", f"CSV Diff report saved to:\n{out}")

    ttk.Button(actions_frame, text="📊 Export CSV", command=_export_csv_diff).pack(
        side="left", padx=GUI_PADDING
    )

    # --- Treeview for Results ---
    tree_frame = ttk.Frame(frame)
    tree_frame.pack(fill="both", expand=True)

    columns = ("vid", "field", "baseline", "target")
    app.diff_tree = ttk.Treeview(
        tree_frame, columns=columns, show="headings", selectmode="browse"
    )

    app.diff_tree.heading("vid", text="Vulnerability ID")
    app.diff_tree.heading("field", text="Field")
    app.diff_tree.heading("baseline", text="Baseline Value")
    app.diff_tree.heading("target", text="Target Value")

    app.diff_tree.column("vid", width=120, minwidth=100)
    app.diff_tree.column("field", width=120, minwidth=100)
    app.diff_tree.column("baseline", width=300)
    app.diff_tree.column("target", width=300)

    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=app.diff_tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=app.diff_tree.xview)
    app.diff_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    app.diff_tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")

    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    # Tag colors
    app.diff_tree.tag_configure("success", foreground="#28a745")
    app.diff_tree.tag_configure("danger", foreground="#dc3545")

    # Cherry-pick Context Menu
    ctx = tk.Menu(app.diff_tree, tearoff=0)

    def _cherry_pick(to_baseline=True):
        selection = app.diff_tree.selection()
        if not selection:
            return
        item = app.diff_tree.item(selection[0])
        vid = item["values"][0]
        field = item["values"][1].lower().replace(" ", "_")

        # Need actual full values
        real_baseline = str(item["values"][2])
        real_target = str(item["values"][3])
        if hasattr(app, "_diff_full_data"):
            for ch in app._diff_full_data.get("changes", []):
                if ch.get("vid") == vid:
                    for df in ch.get("differences", []):
                        if df.get("field") == field:
                            real_baseline = str(df.get("from", ""))
                            real_target = str(df.get("to", ""))
                            break
                    break

        try:
            import xml.etree.ElementTree as ET

            from stig_assessor.io.file_ops import FO

            dest_file = app.diff_ckl1.get() if to_baseline else app.diff_ckl2.get()
            val_to_write = real_target if to_baseline else real_baseline

            tree = FO.parse_xml(dest_file)
            root = tree.getroot()
            changed = False

            tag_map = {
                "status": "STATUS",
                "finding_details": "FINDING_DETAILS",
                "comments": "COMMENTS",
            }
            xml_tag = tag_map.get(field, None)
            if not xml_tag:
                messagebox.showerror("Error", f"Cannot cherry-pick field: {field}")
                return

            for vuln in root.findall(".//VULN"):
                found_vid = None
                for attr_node in vuln.findall("STIG_DATA"):
                    if (
                        attr_node.find("VULN_ATTRIBUTE") is not None
                        and attr_node.find("VULN_ATTRIBUTE").text == "Vuln_Num"
                    ):
                        if attr_node.find("ATTRIBUTE_DATA") is not None:
                            found_vid = attr_node.find("ATTRIBUTE_DATA").text
                            break
                if found_vid == vid:
                    node = vuln.find(xml_tag)
                    if node is not None:
                        node.text = val_to_write
                    else:
                        ET.SubElement(vuln, xml_tag).text = val_to_write
                    changed = True
                    break

            if changed:
                FO.write_xml(tree, dest_file)
                app.status_var.set(
                    f"Cherry-picked {vid} {field} to {Path(dest_file).name}"
                )
                _do_diff_tab()
        except Exception as e:
            messagebox.showerror("Cherry-Pick Error", str(e))

    ctx.add_command(
        label="⬅ Cherry-Pick Target to Baseline",
        command=lambda: _cherry_pick(to_baseline=True),
    )
    ctx.add_command(
        label="➡ Cherry-Pick Baseline to Target",
        command=lambda: _cherry_pick(to_baseline=False),
    )

    def _show_ctx(event):
        item = app.diff_tree.identify_row(event.y)
        if item:
            app.diff_tree.selection_set(item)
            vals = app.diff_tree.item(item)["values"]
            if (
                vals[1] != "Rule"
                and vals[2] != "(Not in Baseline)"
                and vals[3] != "(Removed from Target)"
            ):
                ctx.tk_popup(event.x_root, event.y_root)

    app.diff_tree.bind("<Button-3>", _show_ctx)

    # --- Detailed Diff View ---
    def _show_detailed_diff(event=None):
        selection = app.diff_tree.selection()
        if not selection:
            return
        item = app.diff_tree.item(selection[0])
        vid, field = item["values"][0], item["values"][1].lower().replace(" ", "_")

        # Find the full data for this VID/Field
        if not hasattr(app, "_diff_full_data"):
            return

        target_diff = None
        for ch in app._diff_full_data.get("changes", []):
            if ch.get("vid") == vid:
                for df in ch.get("differences", []):
                    if df.get("field") == field:
                        target_diff = df
                        break
                break

        if not target_diff:
            # Maybe it's an added/removed rule
            return

        # Pop up new window
        top = tk.Toplevel(app.root)
        top.title(f"Detailed Diff: {vid} - {field.title()}")
        top.geometry("900x600")
        top.transient(app.root)

        main = ttk.Frame(top, padding=10)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text=f"Comparing {field.title()} for {vid}",
            font=("TkDefaultFont", 10, "bold"),
        ).pack(pady=(0, 10))

        paned = ttk.PanedWindow(main, orient="horizontal")
        paned.pack(fill="both", expand=True)

        f_left = ttk.LabelFrame(paned, text="Baseline")
        f_right = ttk.LabelFrame(paned, text="Target")

        paned.add(f_left, weight=1)
        paned.add(f_right, weight=1)

        t_left = tk.Text(
            f_left,
            font=GUI_FONT_MONO,
            wrap="word",
            bg="#f8f9fa" if app._current_theme == "light" else "#1c2128",
            fg="#24292f" if app._current_theme == "light" else "#adbac7",
        )
        t_right = tk.Text(
            f_right,
            font=GUI_FONT_MONO,
            wrap="word",
            bg="#f8f9fa" if app._current_theme == "light" else "#1c2128",
            fg="#24292f" if app._current_theme == "light" else "#adbac7",
        )

        t_left.pack(fill="both", expand=True)
        t_right.pack(fill="both", expand=True)

        # Set content
        old_txt = str(target_diff.get("from", ""))
        new_txt = str(target_diff.get("to", ""))

        t_left.insert("1.0", old_txt)
        t_right.insert("1.0", new_txt)

        t_left.config(state="disabled")
        t_right.config(state="disabled")

        ttk.Button(main, text="Close", command=top.destroy).pack(pady=10)

    app.diff_tree.bind("<Double-1>", _show_detailed_diff)

    hint = ttk.Label(
        frame,
        text="💡 Double-click any row to view full side-by-side text differences.",
        font=("TkDefaultFont", 8),
        foreground="gray",
    )
    hint.pack(pady=5)

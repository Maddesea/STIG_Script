"""Compare Checklists Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import os

from stig_assessor.core.constants import (
    GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, 
    GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE, GUI_FONT_MONO
)


def build_compare_tab(app, frame):
    # --- Top Control Frame ---
    io_frame = ttk.LabelFrame(
        frame, text="Input Checklists", padding=GUI_PADDING_LARGE
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Baseline CKL:").grid(
        row=0, column=0, sticky="w"
    )
    app.diff_ckl1 = tk.StringVar()
    ent_1 = ttk.Entry(
        io_frame, textvariable=app.diff_ckl1, width=GUI_ENTRY_WIDTH
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl1():
        path = filedialog.askopenfilename(
            initialdir=app._last_dir(), 
            filetypes=[("Checklist", "*.ckl"), ("Compressed Checklist", "*.cklb")]
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

    ttk.Label(io_frame, text="Target CKL:").grid(
        row=1, column=0, sticky="w"
    )
    app.diff_ckl2 = tk.StringVar()
    ent_2 = ttk.Entry(
        io_frame, textvariable=app.diff_ckl2, width=GUI_ENTRY_WIDTH
    )
    ent_2.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl2():
        path = filedialog.askopenfilename(
            initialdir=app._last_dir(), 
            filetypes=[("Checklist", "*.ckl"), ("Compressed Checklist", "*.cklb")]
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

    def _do_diff_tab():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            messagebox.showerror("Error", "Please provide two checklists for comparison.")
            return
        
        app.status_var.set("Comparing checklists...")
        
        def work():
            return app.proc.diff(app.diff_ckl1.get(), app.diff_ckl2.get(), output_format="json")

        def done(results):
            if isinstance(results, Exception):
                messagebox.showerror("Diff Error", str(results))
                return
            
            # Clear existing
            for item in app.diff_tree.get_children():
                app.diff_tree.delete(item)
            
            app._diff_full_data = results # Store for detailed view
            s = results.get("summary", {})
            app.diff_summary_labels["changes"].set(str(s.get("changed", 0)))
            app.diff_summary_labels["added"].set(str(s.get("only_in_comparison", 0)))
            app.diff_summary_labels["removed"].set(str(s.get("only_in_baseline", 0)))

            # Populate Tree
            for ch in results.get("changes", []):
                vid = ch.get("vid")
                title = ch.get("rule_title", "")
                for df in ch.get("differences", []):
                    field = df.get("field", "status")
                    val_from = df.get("from", "")
                    val_to = df.get("to", "")
                    
                    # Truncate for tree display
                    disp_from = str(val_from).replace("\n", " ")[:100]
                    disp_to = str(val_to).replace("\n", " ")[:100]
                    
                    tags = []
                    if field == "status":
                        if val_to == "NotAFinding": tags.append("success")
                        elif val_to == "Open": tags.append("danger")

                    app.diff_tree.insert("", "end", values=(vid, field.replace("_", " ").title(), disp_from, disp_to), tags=tags)

            # Added/Removed
            for vid in results.get("added", []):
                app.diff_tree.insert("", "end", values=(vid, "Rule", "(Not in Baseline)", "ADDED TO CHECKLIST"), tags=("success",))
            for vid in results.get("removed", []):
                app.diff_tree.insert("", "end", values=(vid, "Rule", "PRESENT IN BASELINE", "(Removed from Target)"), tags=("danger",))

            app.status_var.set(f"Diff complete. {s.get('changed', 0)} changes identified.")

        app._async(work, done)

    btn_compare = ttk.Button(
        actions_frame,
        text="🔍 Run Comparison",
        command=_do_diff_tab,
        style="Accent.TButton",
        width=20
    )
    btn_compare.pack(side="left", padx=GUI_PADDING)
    app._action_buttons.append(btn_compare)

    def _export_html_diff():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            return
        out = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if out:
            from stig_assessor.processor.html_diff import generate_html_diff
            generate_html_diff(app.diff_ckl1.get(), app.diff_ckl2.get(), out)
            messagebox.showinfo("Export Success", f"HTML Diff report saved to:\n{out}")

    ttk.Button(
        actions_frame, text="🌐 Export HTML Diff", command=_export_html_diff
    ).pack(side="left", padx=GUI_PADDING)

    # --- Treeview for Results ---
    tree_frame = ttk.Frame(frame)
    tree_frame.pack(fill="both", expand=True)

    columns = ("vid", "field", "baseline", "target")
    app.diff_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
    
    app.diff_tree.heading("vid", text="Vulnerability ID")
    app.diff_tree.heading("field", text="Field")
    app.diff_tree.heading("baseline", text="Baseline Value")
    app.diff_tree.heading("target", text="Target Value")
    
    app.diff_tree.column("vid", width=120, minwidth=100)
    app.diff_tree.column("field", width=120, minwidth=100)
    app.diff_tree.column("baseline", width=300)
    app.diff_tree.column("target", width=300)

    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=app.diff_tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=app.diff_tree.yview)
    app.diff_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    
    app.diff_tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    
    tree_frame.columnconfigure(0, weight=1)
    tree_frame.rowconfigure(0, weight=1)

    # Tag colors
    app.diff_tree.tag_configure("success", foreground="#28a745")
    app.diff_tree.tag_configure("danger", foreground="#dc3545")

    # --- Detailed Diff View ---
    def _show_detailed_diff(event=None):
        selection = app.diff_tree.selection()
        if not selection: return
        item = app.diff_tree.item(selection[0])
        vid, field = item["values"][0], item["values"][1].lower().replace(" ", "_")
        
        # Find the full data for this VID/Field
        if not hasattr(app, "_diff_full_data"): return
        
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
        
        ttk.Label(main, text=f"Comparing {field.title()} for {vid}", font=("TkDefaultFont", 10, "bold")).pack(pady=(0, 10))

        paned = ttk.PanedWindow(main, orient="horizontal")
        paned.pack(fill="both", expand=True)

        f_left = ttk.LabelFrame(paned, text="Baseline")
        f_right = ttk.LabelFrame(paned, text="Target")
        
        paned.add(f_left, weight=1)
        paned.add(f_right, weight=1)

        t_left = tk.Text(f_left, font=GUI_FONT_MONO, wrap="word", bg="#f8f9fa" if app._current_theme == "light" else "#1c2128", fg="#24292f" if app._current_theme == "light" else "#adbac7")
        t_right = tk.Text(f_right, font=GUI_FONT_MONO, wrap="word", bg="#f8f9fa" if app._current_theme == "light" else "#1c2128", fg="#24292f" if app._current_theme == "light" else "#adbac7")
        
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
    
    hint = ttk.Label(frame, text="💡 Double-click any row to view full side-by-side text differences.", font=("TkDefaultFont", 8), foreground="gray")
    hint.pack(pady=5)

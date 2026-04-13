"""Stats and Analytics Tab module."""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import (GUI_BUTTON_WIDTH_WIDE,
                                          GUI_ENTRY_WIDTH, GUI_FONT_MONO,
                                          GUI_FONT_NORMAL, GUI_PADDING,
                                          GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION, Status)
from stig_assessor.processor.fleet_stats import FleetStats
from stig_assessor.ui.helpers import PremiumChart


def build_analytics_tab(app, frame):
    # Mode Selector Header
    header_frame = ttk.Frame(frame)
    header_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    ttk.Label(header_frame, text="View Analysis for:", font=GUI_FONT_NORMAL).pack(
        side="left"
    )
    app.analytics_mode = tk.StringVar(value="single")

    def _on_mode_change(*args):
        mode = app.analytics_mode.get()
        if mode == "single":
            single_ctrl_frame.pack(fill="x", after=header_frame)
            fleet_ctrl_frame.pack_forget()
        else:
            fleet_ctrl_frame.pack(fill="x", after=header_frame)
            single_ctrl_frame.pack_forget()

    ttk.Radiobutton(
        header_frame,
        text="Single Checklist",
        variable=app.analytics_mode,
        value="single",
        command=_on_mode_change,
    ).pack(side="left", padx=GUI_PADDING_LARGE)
    ttk.Radiobutton(
        header_frame,
        text="Fleet / Enclave",
        variable=app.analytics_mode,
        value="fleet",
        command=_on_mode_change,
    ).pack(side="left", padx=GUI_PADDING)

    # ── SINGLE CHECKLIST CONTROLS ──
    single_ctrl_frame = ttk.LabelFrame(
        frame, text="Single Checklist Analysis", padding=GUI_PADDING_LARGE
    )
    single_ctrl_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    single_ctrl_frame.columnconfigure(1, weight=1)

    ttk.Label(single_ctrl_frame, text="Checklist:").grid(row=0, column=0, sticky="w")
    app.stats_ckl = tk.StringVar()
    ent_1 = ttk.Entry(
        single_ctrl_frame, textvariable=app.stats_ckl, width=GUI_ENTRY_WIDTH
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_stats_ckl():
        app.stats_ckl.set(
            filedialog.askopenfilename(
                initialdir=app._last_dir(), filetypes=[("CKL", "*.ckl")]
            )
        )

    ttk.Button(single_ctrl_frame, text="📂 Browse…", command=_browse_stats_ckl).grid(
        row=0, column=2
    )
    app._enable_dnd(ent_1, app.stats_ckl)

    # ── FLEET / ENCLAVE CONTROLS ──
    fleet_ctrl_frame = ttk.LabelFrame(
        frame, text="Fleet / Enclave Analytics", padding=GUI_PADDING_LARGE
    )
    fleet_ctrl_frame.columnconfigure(1, weight=1)

    ttk.Label(fleet_ctrl_frame, text="Enclave Dir/ZIP:").grid(
        row=0, column=0, sticky="w"
    )
    app.fleet_source = tk.StringVar()
    ent_fleet = ttk.Entry(
        fleet_ctrl_frame, textvariable=app.fleet_source, width=GUI_ENTRY_WIDTH
    )
    ent_fleet.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_fleet():
        path = filedialog.askdirectory(title="Select Enclave Directory")
        if not path:
            path = filedialog.askopenfilename(
                title="Select Enclave ZIP", filetypes=[("ZIP Archive", "*.zip")]
            )
        if path:
            app.fleet_source.set(path)

    ttk.Button(fleet_ctrl_frame, text="📂 Browse…", command=_browse_fleet).grid(
        row=0, column=2
    )
    app._enable_dnd(ent_fleet, app.fleet_source)

    # Start with single mode
    _on_mode_change()

    def _do_stats_tab():
        mode = app.analytics_mode.get()
        source = app.stats_ckl.get() if mode == "single" else app.fleet_source.get()
        if not source:
            return

        def work():
            if mode == "single":
                return {
                    "json": app.proc.generate_stats(source, output_format="json"),
                    "text": app.proc.generate_stats(source, output_format="text"),
                }
            else:
                import os

                fs = FleetStats()
                if os.path.isfile(source) and source.lower().endswith(".zip"):
                    res = fs.process_zip(source)
                else:
                    res = fs.process_directory(source)

                # Generate a meaningful text summary for the fleet
                summary = [
                    "=== FLEET ANALYTICS REPORT ===",
                    f"Source: {source}",
                    f"Total Assets: {res.get('total_assets', 0)}",
                    f"Total Rules: {res.get('total_vulns', 0)}",
                    f"Overall Compliance: {res.get('compliance_pct', 0.0):.1f}%",
                    "",
                    "--- Compliance by Asset ---",
                ]
                for asset in res.get("asset_compliance", [])[:20]:  # Top 20
                    summary.append(f"{asset['compliance_pct']:5.1f}% | {asset['file']}")
                if len(res.get("asset_compliance", [])) > 20:
                    summary.append(
                        f"... and {len(res['asset_compliance']) - 20} more assets."
                    )

                return {"json": res, "text": "\n".join(summary)}

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror("Error", str(result))
                return

            stats_dict = result["json"]
            app.stats_results_txt.configure(state="normal")
            app.stats_results_txt.delete("1.0", tk.END)
            app.stats_results_txt.insert(tk.END, str(result["text"]))
            app.stats_results_txt.configure(state="disabled")

            app.stats_canvas.delete("all")
            total = stats_dict.get("total_vulns", 0)
            if total == 0:
                app.stats_canvas.create_text(
                    300,
                    110,
                    text="No vulnerabilities found.",
                    fill="gray",
                    font=GUI_FONT_NORMAL,
                )
                return

            colors = {
                Status.NOT_A_FINDING.value: "#10b981",
                Status.OPEN.value: "#ef4444",
                Status.NOT_APPLICABLE.value: "#6366f1",
                Status.NOT_REVIEWED.value: "#f59e0b",
            }
            width = max(600, int(app.stats_canvas.winfo_width()))
            height = 220

            title_txt = (
                f"Compliance Posture: {source[:40]}..."
                if mode == "single"
                else f"Enclave Performance ({stats_dict.get('total_assets', 0)} Assets)"
            )
            app.stats_canvas.create_text(
                width / 2,
                20,
                text=title_txt,
                fill=app._colors.get("fg", "#374151"),
                font=(GUI_FONT_NORMAL[0], 12, "bold"),
            )

            by_status = stats_dict.get("by_status", {})
            bars = [
                Status.NOT_A_FINDING.value,
                Status.OPEN.value,
                Status.NOT_APPLICABLE.value,
                Status.NOT_REVIEWED.value,
            ]
            labels = ["Not A Finding", "Open", "N/A", "Not Reviewed"]

            max_h = height - 80
            bar_w = 70
            gap = (width - (bar_w * len(bars))) / (len(bars) + 1)
            x_pos = gap

            for i, k in enumerate(bars):
                count = by_status.get(k, 0)
                h = (count / total) * max_h if total else 2
                PremiumChart.draw_bar(
                    app.stats_canvas,
                    x_pos,
                    height - 35,
                    bar_w,
                    h,
                    colors.get(k, "#3b82f6"),
                    labels[i],
                    count,
                    GUI_FONT_NORMAL,
                    GUI_FONT_NORMAL,
                    app._colors.get("fg", "#1f2937"),
                    app._colors.get("text", "#4b5563"),
                )
                x_pos += bar_w + gap

        app.status_var.set("Analyzing...")
        app._async(work, done)

    def _clear_analytics_form():
        app.stats_ckl.set("")
        app.fleet_source.set("")
        app.stats_results_txt.configure(state="normal")
        app.stats_results_txt.delete("1.0", tk.END)
        app.stats_results_txt.configure(state="disabled")
        app.stats_canvas.delete("all")
        app.stats_canvas.create_text(
            300,
            110,
            text="Load data to view graphical compliance dashboard",
            fill="gray",
            font=GUI_FONT_NORMAL,
        )

    def _export_analytics():
        text = app.stats_results_txt.get("1.0", tk.END).strip()
        if not text:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt")]
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                messagebox.showinfo("Export Successful", f"Saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    btn_row = ttk.Frame(frame)
    btn_row.pack(pady=GUI_PADDING_SECTION)

    btn = ttk.Button(
        btn_row,
        text="📊 Run Analytics",
        command=_do_stats_tab,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn.pack(side="left", padx=GUI_PADDING)
    ttk.Button(btn_row, text="💾 Export Report", command=_export_analytics).pack(
        side="left", padx=GUI_PADDING
    )
    ttk.Button(btn_row, text="🗑 Clear Form", command=_clear_analytics_form).pack(
        side="left", padx=GUI_PADDING
    )

    app.stats_canvas = tk.Canvas(
        frame, height=220, bg=app._colors.get("bg", "#ffffff"), highlightthickness=0
    )
    app.stats_canvas.pack(fill="x", pady=(0, GUI_PADDING))
    app.stats_canvas.create_text(
        300,
        110,
        text="Load data to view graphical compliance dashboard",
        fill="gray",
        font=GUI_FONT_NORMAL,
    )

    app.stats_results_txt = ScrolledText(frame, font=GUI_FONT_MONO, height=10)
    app.stats_results_txt.pack(fill="both", expand=True)

    app.action_analytics = _do_stats_tab

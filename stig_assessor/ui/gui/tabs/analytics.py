"""Stats and Analytics Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE, GUI_FONT_MONO, GUI_FONT_NORMAL


def build_analytics_tab(app, frame):
    io_frame = ttk.LabelFrame(
        frame, text="Checklist Analytics", padding=GUI_PADDING_LARGE
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Checklist: *").grid(row=0, column=0, sticky="w")
    app.stats_ckl = tk.StringVar()
    ent_1 = ttk.Entry(
        io_frame, textvariable=app.stats_ckl, width=GUI_ENTRY_WIDTH
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_stats_ckl():
        app.stats_ckl.set(
            filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
        )

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_stats_ckl,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_1, app.stats_ckl)

    def _do_stats_tab():
        if not app.stats_ckl.get():
            return
        try:
            stats_dict = app.proc.generate_stats(
                app.stats_ckl.get(), output_format="json"
            )
            s_text = app.proc.generate_stats(
                app.stats_ckl.get(), output_format="text"
            )
            app.stats_results_txt.configure(state="normal")
            app.stats_results_txt.delete("1.0", tk.END)
            app.stats_results_txt.insert(tk.END, str(s_text))
            app.stats_results_txt.configure(state="disabled")

            # Parse counts for visual graph
            by_status = stats_dict.get("by_status", {})
            total = stats_dict.get("total_vulns", 0)

            app.stats_canvas.delete("all")
            if total == 0:
                app.stats_canvas.create_text(
                    300,
                    110,
                    text="No vulnerabilities found.",
                    fill="#6b7280",
                    font=GUI_FONT_NORMAL,
                )
                return

            colors = {
                "NotAFinding": "#10b981",
                "Open": "#ef4444",
                "Not_Applicable": "#6b7280",
                "Not_Reviewed": "#f59e0b",
            }
            width = int(app.stats_canvas.winfo_width())
            if width <= 10:
                width = 600
            height = int(app.stats_canvas.winfo_height())
            if height <= 10:
                height = 220

            app.stats_canvas.create_text(
                width / 2,
                20,
                text=f"Compliance Posture Overview ({total} Total Rules)",
                fill="#374151",
                font=(GUI_FONT_NORMAL[0], 12, "bold"),
            )

            bars = [
                "NotAFinding",
                "Open",
                "Not_Applicable",
                "Not_Reviewed",
            ]
            bar_labels = [
                "Not A Finding",
                "Open",
                "Not Applicable",
                "Not Reviewed",
            ]
            max_h = height - 80
            bar_w = width / (len(bars) * 2)
            gap = bar_w
            current_x = gap / 2

            for i, k in enumerate(bars):
                count = by_status.get(k, 0)
                h = (count / total) * max_h if total else 0
                color = colors.get(k, "#3b82f6")

                app.stats_canvas.create_rectangle(
                    current_x,
                    height - 30 - h,
                    current_x + bar_w,
                    height - 30,
                    fill=color,
                    outline=color,
                )
                app.stats_canvas.create_text(
                    current_x + bar_w / 2,
                    height - 30 - h - 12,
                    text=str(count),
                    fill="#1f2937",
                    font=(GUI_FONT_NORMAL[0], 10, "bold"),
                )
                app.stats_canvas.create_text(
                    current_x + bar_w / 2,
                    height - 15,
                    text=bar_labels[i],
                    fill="#4b5563",
                    font=(GUI_FONT_NORMAL[0], 10),
                )

                current_x += bar_w + gap

        except Exception as e:
            messagebox.showerror("Stats Error", str(e))

    btn = ttk.Button(
        frame,
        text="📊 Generate Vis & Stats",
        command=_do_stats_tab,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn.pack(pady=GUI_PADDING_SECTION)

    app.stats_canvas = tk.Canvas(
        frame,
        height=220,
        bg="#ffffff",
        highlightthickness=1,
        highlightbackground="#e5e7eb",
    )
    app.stats_canvas.pack(fill="x", pady=(0, GUI_PADDING))
    app.stats_canvas.create_text(
        300,
        110,
        text="Load a checklist to view graphical compliance dashboard",
        fill="#9ca3af",
        font=GUI_FONT_NORMAL,
    )

    app.stats_results_txt = ScrolledText(frame, font=app._colors.get("font_mono",GUI_FONT_MONO) if hasattr(app,'GUI_FONT_MONO') else ("Courier New", 10), height=12)
    app.stats_results_txt.pack(fill="both", expand=True)

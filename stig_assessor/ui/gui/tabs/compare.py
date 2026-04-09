"""Compare Checklists Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from pathlib import Path

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_PADDING_SECTION, GUI_BUTTON_WIDTH_WIDE, GUI_FONT_MONO


def build_compare_tab(app, frame):
    io_frame = ttk.LabelFrame(
        frame, text="Input Checklists", padding=GUI_PADDING_LARGE
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Old/Base CKL: *").grid(
        row=0, column=0, sticky="w"
    )
    app.diff_ckl1 = tk.StringVar()
    ent_1 = ttk.Entry(
        io_frame, textvariable=app.diff_ckl1, width=GUI_ENTRY_WIDTH
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl1():
        app.diff_ckl1.set(
            filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
        )

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_ckl1,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_1, app.diff_ckl1)

    ttk.Label(io_frame, text="New/Target CKL: *").grid(
        row=1, column=0, sticky="w"
    )
    app.diff_ckl2 = tk.StringVar()
    ent_2 = ttk.Entry(
        io_frame, textvariable=app.diff_ckl2, width=GUI_ENTRY_WIDTH
    )
    ent_2.grid(row=1, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_ckl2():
        app.diff_ckl2.set(
            filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
        )

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_ckl2,
    ).grid(row=1, column=2)
    app._enable_dnd(ent_2, app.diff_ckl2)

    def _do_diff_tab():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            messagebox.showerror(
                "Error",
                "Please provide two checklists down for comparison.",
            )
            return
        try:
            d = app.proc.diff(
                app.diff_ckl1.get(),
                app.diff_ckl2.get(),
                output_format="text",
            )
            app.diff_results_txt.configure(state="normal")
            app.diff_results_txt.delete("1.0", tk.END)
            if isinstance(d, dict):
                output = [
                    f"Comparison: {Path(app.diff_ckl1.get()).name} vs {Path(app.diff_ckl2.get()).name}"
                ]
                for k, v in d.items():
                    output.append(f"\n[{str(k).upper()}]")
                    if isinstance(v, list):
                        for ln in v:
                            output.append(str(ln))
                    else:
                        output.append(str(v))
                app.diff_results_txt.insert(tk.END, "\n".join(output))
            else:
                app.diff_results_txt.insert(tk.END, str(d))
            app.diff_results_txt.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Diff Error", str(e))

    btn = ttk.Button(
        frame,
        text="🔍 Compare",
        command=_do_diff_tab,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn.pack(pady=GUI_PADDING_SECTION)

    app.diff_results_txt = ScrolledText(
        frame, font=app._colors.get("font_mono",GUI_FONT_MONO) if hasattr(app,'GUI_FONT_MONO') else ("Courier New", 10), wrap=tk.NONE, height=15
    )
    app.diff_results_txt.pack(fill="both", expand=True)

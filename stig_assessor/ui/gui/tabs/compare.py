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
            filedialog.askopenfilename(initialdir=app._last_dir(), filetypes=[("CKL", "*.ckl")])
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
            filedialog.askopenfilename(initialdir=app._last_dir(), filetypes=[("CKL", "*.ckl")])
        )

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_ckl2,
    ).grid(row=1, column=2)
    app._enable_dnd(ent_2, app.diff_ckl2)

    def _swap_diff():
        tmp = app.diff_ckl1.get()
        app.diff_ckl1.set(app.diff_ckl2.get())
        app.diff_ckl2.set(tmp)

    btn_swap = ttk.Button(
        io_frame,
        text="🔁 Swap",
        command=_swap_diff,
    )
    btn_swap.grid(row=0, column=3, rowspan=2, sticky="ns", padx=(GUI_PADDING_LARGE, GUI_PADDING), pady=GUI_PADDING)

    def _clear_compare_form():
        app.diff_ckl1.set("")
        app.diff_ckl2.set("")
        app.diff_results_txt.configure(state="normal")
        app.diff_results_txt.delete("1.0", tk.END)
        app.diff_results_txt.configure(state="disabled")

    btn_clear = ttk.Button(
        io_frame,
        text="🗑 Clear Form",
        command=_clear_compare_form,
    )
    btn_clear.grid(row=0, column=4, rowspan=2, sticky="ns", padx=GUI_PADDING, pady=GUI_PADDING)

    try:
        from stig_assessor.ui.helpers import ToolTip
        ToolTip(btn_swap, "Swap Base and Target checklists to reverse the diff perspective")
        ToolTip(btn_clear, "Clear current form")
    except ImportError:
        pass

    def _do_diff_tab():
        if not app.diff_ckl1.get() or not app.diff_ckl2.get():
            messagebox.showerror(
                "Error",
                "Please provide two checklists for comparison.",
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
        except (ValueError, FileNotFoundError, OSError, TypeError) as e:
            messagebox.showerror("Diff Error", str(e))

    btn = ttk.Button(
        frame,
        text="🔍 Compare",
        command=_do_diff_tab,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn.pack(pady=GUI_PADDING_SECTION)
    app._action_buttons.append(btn)
    app.action_compare = _do_diff_tab

    app.diff_results_txt = ScrolledText(
        frame, font=GUI_FONT_MONO, wrap=tk.NONE, height=15
    )
    app.diff_results_txt.pack(fill="both", expand=True)

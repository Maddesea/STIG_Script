"""Drift Analysis Tab module."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from stig_assessor.core.constants import GUI_PADDING, GUI_PADDING_LARGE, GUI_ENTRY_WIDTH, GUI_BUTTON_WIDTH_WIDE, GUI_FONT_NORMAL


def build_drift_tab(app, frame):
    io_frame = ttk.LabelFrame(
        frame,
        text="Track Checklist History",
        padding=GUI_PADDING_LARGE,
    )
    io_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    io_frame.columnconfigure(1, weight=1)

    ttk.Label(io_frame, text="Completed CKL: *").grid(
        row=0, column=0, sticky="w"
    )
    app.drift_track_ckl = tk.StringVar()
    ent_1 = ttk.Entry(
        io_frame,
        textvariable=app.drift_track_ckl,
        width=GUI_ENTRY_WIDTH,
    )
    ent_1.grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _browse_drift_ckl():
        app.drift_track_ckl.set(
            filedialog.askopenfilename(filetypes=[("CKL", "*.ckl")])
        )

    ttk.Button(
        io_frame,
        text="📂 Browse…",
        command=_browse_drift_ckl,
    ).grid(row=0, column=2)
    app._enable_dnd(ent_1, app.drift_track_ckl)

    def _do_track_ckl():
        if not app.drift_track_ckl.get():
            return
        ckl_path = app.drift_track_ckl.get()
        if not app.proc.history.db:
            messagebox.showerror("Error", "SQLite History DB is not initialized.")
            return
        try:
            tree = app.proc._load_file_as_xml(Path(ckl_path))
            root = tree.getroot()
            vulns = app.proc._extract_vuln_data(root)
            asset_elem = root.find(".//HOST_NAME")
            asset_name = asset_elem.text if asset_elem is not None else "Unknown"

            results = []
            for vid, vdata in vulns.items():
                results.append(
                    {
                        "vid": vid,
                        "status": vdata.get("status", "Not_Reviewed"),
                        "severity": vdata.get("severity", "medium"),
                        "find": vdata.get("finding_details", ""),
                        "comm": vdata.get("comments", ""),
                    }
                )

            db_id = app.proc.history.db.save_assessment(
                asset_name, ckl_path, "STIG", results
            )
            messagebox.showinfo(
                "Success",
                f"Successfully ingested {len(results)} findings into database.\nAssessment ID: {db_id}",
            )
        except Exception as e:
            messagebox.showerror("Tracking Error", str(e))

    btn1 = ttk.Button(
        io_frame,
        text="📈 Track Checklist",
        command=_do_track_ckl,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn1.grid(row=1, column=1, pady=GUI_PADDING, sticky="e")

    drift_frame = ttk.LabelFrame(
        frame, text="Analyze Asset Drift", padding=GUI_PADDING_LARGE
    )
    drift_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    drift_frame.columnconfigure(1, weight=1)

    ttk.Label(drift_frame, text="Asset Name: *").grid(
        row=0, column=0, sticky="w"
    )
    app.drift_asset = tk.StringVar()
    ttk.Entry(
        drift_frame,
        textvariable=app.drift_asset,
        width=GUI_ENTRY_WIDTH,
    ).grid(row=0, column=1, padx=GUI_PADDING, sticky="we")

    def _do_show_drift():
        asset_name = app.drift_asset.get().strip()
        if not asset_name:
            return
        if not app.proc.history.db:
            messagebox.showerror("Error", "SQLite History DB is not initialized.")
            return
        try:
            with app.proc.history.db._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM assessments WHERE asset_name = ? ORDER BY timestamp DESC LIMIT 1",
                    (asset_name,),
                )
                row = cursor.fetchone()
                if not row:
                    messagebox.showwarning(
                        "No Data",
                        f"No assessments found for asset '{asset_name}'",
                    )
                    return
                latest_id = row[0]

            drift = app.proc.history.db.get_drift(asset_name, latest_id)
            if "error" in drift:
                messagebox.showerror("Drift Error", drift["error"])
                return

            app.drift_canvas.delete("all")

            width = int(app.drift_canvas.winfo_width())
            if width <= 10:
                width = 600
            height = int(app.drift_canvas.winfo_height())
            if height <= 10:
                height = 220

            app.drift_canvas.create_text(
                width / 2,
                20,
                text=f"Compliance Drift Analysis: {asset_name}",
                fill="#374151",
                font=(GUI_FONT_NORMAL[0], 12, "bold"),
            )

            bars = [
                ("Fixed", len(drift["fixed"]), "#10b981"),
                ("Regressed", len(drift["regressed"]), "#ef4444"),
                ("Changed", len(drift["changed"]), "#f59e0b"),
                ("New Rules", len(drift["new"]), "#3b82f6"),
                ("Removed", len(drift["removed"]), "#6b7280"),
            ]

            max_val = max([b[1] for b in bars] + [1]) if any(b[1] for b in bars) else 1
            max_h = height - 80
            bar_w = width / (len(bars) * 2)
            gap = bar_w
            current_x = gap / 2

            for label, count, color in bars:
                h = (count / max_val) * max_h
                if h < 2 and count > 0:
                    h = 2

                app.drift_canvas.create_rectangle(
                    current_x,
                    height - 30 - h,
                    current_x + bar_w,
                    height - 30,
                    fill=color,
                    outline=color,
                )
                app.drift_canvas.create_text(
                    current_x + bar_w / 2,
                    height - 30 - h - 12,
                    text=str(count),
                    fill="#1f2937",
                    font=(GUI_FONT_NORMAL[0], 10, "bold"),
                )
                app.drift_canvas.create_text(
                    current_x + bar_w / 2,
                    height - 15,
                    text=label,
                    fill="#4b5563",
                    font=(GUI_FONT_NORMAL[0], 10),
                )

                current_x += bar_w + gap

        except Exception as e:
            messagebox.showerror("Drift Error", str(e))

    btn2 = ttk.Button(
        drift_frame,
        text="🔍 Analyze Drift",
        command=_do_show_drift,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn2.grid(row=1, column=1, pady=GUI_PADDING, sticky="e")

    app.drift_canvas = tk.Canvas(
        frame,
        height=220,
        bg="#ffffff",
        highlightthickness=1,
        highlightbackground="#e5e7eb",
    )
    app.drift_canvas.pack(
        fill="x", padx=GUI_PADDING_LARGE, pady=(0, GUI_PADDING_LARGE)
    )
    app.drift_canvas.create_text(
        300,
        110,
        text="Analyze an asset to view compliance drift",
        fill="#9ca3af",
        font=GUI_FONT_NORMAL,
    )

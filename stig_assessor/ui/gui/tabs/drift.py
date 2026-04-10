import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from stig_assessor.core.constants import (
    GUI_PADDING,
    GUI_PADDING_LARGE,
    GUI_ENTRY_WIDTH,
    GUI_BUTTON_WIDTH_WIDE,
    GUI_FONT_NORMAL,
)
from stig_assessor.ui.helpers import PremiumChart


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
            filedialog.askopenfilename(initialdir=app._last_dir(), filetypes=[("CKL", "*.ckl")])
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
            
            # Simple manual extraction for tracking
            vulns = {}
            for vnode in root.findall(".//VULN"):
                vid = ""
                for sd in vnode.findall("STIG_DATA"):
                    if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num":
                        vid = sd.findtext("ATTRIBUTE_DATA")
                        break
                if vid:
                    vulns[vid] = {
                        "status": vnode.findtext("STATUS", "Not_Reviewed"),
                        "finding_details": vnode.findtext("FINDING_DETAILS", ""),
                        "comments": vnode.findtext("COMMENTS", "")
                    }

            asset_elem = root.find(".//HOST_NAME")
            asset_name = asset_elem.text if asset_elem is not None else "Unknown"

            results = []
            for vid, vdata in vulns.items():
                results.append(
                    {
                        "vid": vid,
                        "status": vdata.get("status", "Not_Reviewed"),
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
        except (ValueError, OSError, TypeError) as e:
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

            width = max(600, int(app.drift_canvas.winfo_width()))
            height = 220

            app.drift_canvas.create_text(
                width / 2,
                20,
                text=f"Compliance Drift Analysis: {asset_name}",
                fill=app._colors.get("fg", "#374151"),
                font=(GUI_FONT_NORMAL[0], 12, "bold"),
            )

            bars = [
                ("Fixed", len(drift["fixed"]), "#10b981"),
                ("Regressed", len(drift["regressed"]), "#ef4444"),
                ("Changed", len(drift["changed"]), "#f59e0b"),
                ("New", len(drift["new"]), "#3b82f6"),
                ("Removed", len(drift["removed"]), "#6b7280"),
            ]

            max_val = max([b[1] for b in bars] + [1])
            max_h = height - 80
            bar_w = 70
            gap = (width - (bar_w * len(bars))) / (len(bars) + 1)
            x_pos = gap

            for label, count, color in bars:
                h = (count / max_val) * max_h if count > 0 else 2
                PremiumChart.draw_bar(
                    app.drift_canvas, x_pos, height - 35, bar_w, h,
                    color, label, count,
                    GUI_FONT_NORMAL, GUI_FONT_NORMAL,
                    app._colors.get("fg", "#1f2937"), app._colors.get("text", "#4b5563")
                )
                x_pos += bar_w + gap

        except Exception as e:
            messagebox.showerror("Drift Error", str(e))

    def _clear_drift_form():
        app.drift_track_ckl.set("")
        app.drift_asset.set("")
        app.drift_canvas.delete("all")
        app.drift_canvas.create_text(
            300,
            110,
            text="Analyze an asset to view compliance drift",
            fill=app._colors.get("text", "#9ca3af"),
            font=GUI_FONT_NORMAL,
        )

    btn_row = ttk.Frame(drift_frame)
    btn_row.grid(row=1, column=1, pady=GUI_PADDING, sticky="e")

    btn2 = ttk.Button(
        btn_row,
        text="🔍 Analyze Drift",
        command=_do_show_drift,
        width=GUI_BUTTON_WIDTH_WIDE,
        style="Accent.TButton",
    )
    btn2.pack(side="left", padx=GUI_PADDING)
    
    ttk.Button(
        btn_row, text="🗑 Clear Form", command=_clear_drift_form
    ).pack(side="left")

    app.drift_canvas = tk.Canvas(
        frame,
        height=220,
        bg=app._colors.get("bg", "#ffffff"),
        highlightthickness=0,
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
    app.action_drift = _do_show_drift

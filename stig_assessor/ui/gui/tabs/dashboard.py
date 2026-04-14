"""Welcome Dashboard Tab module."""

import tkinter as tk
from pathlib import Path
from tkinter import ttk

from stig_assessor import VERSION
from stig_assessor.core.constants import (GUI_FONT_HEADING, GUI_FONT_NORMAL, GUI_FONT_MONO,
                                          GUI_FONT_SMALL, GUI_PADDING, GUI_PADDING_LARGE)
from stig_assessor.ui.helpers import ToolTip


def build_dashboard_tab(app, frame):
    # Overall layout
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    colors = app._colors

    # ── HEADER ──
    header = ttk.Frame(frame, padding=(0, 0, 0, GUI_PADDING_LARGE))
    header.grid(row=0, column=0, sticky="ew")

    title_lbl = ttk.Label(
        header,
        text="STIG Assessor — Command Center",
        font=(GUI_FONT_HEADING[0], 16, "bold"),
        foreground=colors.get("accent", "#58A6FF"),
    )
    title_lbl.pack(anchor="w")

    sub_lbl = ttk.Label(
        header,
        text=f"Air-Gapped Enclave Compliance & Remediation Console  ─  v{VERSION}",
        font=GUI_FONT_SMALL,
        foreground=colors.get("muted", "#8B949E"),
    )
    sub_lbl.pack(anchor="w", pady=(2, 0))

    # ── MAIN CONTENT GRID ──
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=1, column=0, sticky="nsew")
    content_frame.columnconfigure(0, weight=1)
    content_frame.columnconfigure(1, weight=2)
    content_frame.rowconfigure(0, weight=1)

    # ── LEFT COLUMN: Quick Actions & Recent ──
    left_col = ttk.Frame(content_frame)
    left_col.grid(row=0, column=0, sticky="nsew", padx=(0, GUI_PADDING_LARGE))

    qa_lbl = ttk.Label(
        left_col, text="⚡ Quick Actions", font=GUI_FONT_HEADING,
        foreground=colors.get("fg", "#E6EDF3"),
    )
    qa_lbl.pack(anchor="w", pady=(0, GUI_PADDING))

    actions = [
        ("🚀  Parse New Benchmark", "Create a new CKL from XCCDF Benchmark", 1),
        ("📝  Assessment Editor", "Open the last edited checklist", 2),
        ("🔨  Batch Remediation", "Extract and map SCAP findings", 9),
        ("📈  Fleet Analytics", "Analyze an entire enclave or directory", 12),
    ]

    for i, (text, hint, tab_idx) in enumerate(actions):
        btn = ttk.Button(
            left_col,
            text=text,
            command=lambda idx=tab_idx: app._switch_tab(idx),
            style="Accent.TButton" if i == 0 else "TButton",
            width=28,
        )
        btn.pack(pady=3, fill="x")
        ToolTip(btn, hint)

    # Separator
    ttk.Separator(left_col, orient="horizontal").pack(fill="x", pady=GUI_PADDING_LARGE)

    # Recent Files
    recent_lbl = ttk.Label(
        left_col,
        text="📂 Recent Checklists",
        font=GUI_FONT_HEADING,
        foreground=colors.get("fg", "#E6EDF3"),
    )
    recent_lbl.pack(anchor="w", pady=(0, GUI_PADDING))

    recent_frame = ttk.Frame(left_col)
    recent_frame.pack(fill="both", expand=True)

    recent_files = app._settings.get("recent_files", [])
    if not recent_files:
        ttk.Label(
            recent_frame,
            text="No recent assessments logged.",
            foreground=colors.get("muted", "#8B949E"),
            font=GUI_FONT_SMALL,
        ).pack(anchor="w")
    else:
        for path in recent_files[:5]:
            p = Path(path)
            item_f = ttk.Frame(recent_frame)
            item_f.pack(fill="x", pady=3)

            lbl = ttk.Label(
                item_f,
                text=f"  📄 {p.name}",
                font=(GUI_FONT_NORMAL[0], 10),
                foreground=colors.get("accent", "#58A6FF"),
                cursor="hand2",
            )
            lbl.pack(side="left")

            def _load_recent(evt, target_path=path):
                if hasattr(app, "editor_ckl_var"):
                    app.editor_ckl_var.set(target_path)
                    app._switch_tab(2)  # Editor tab
                    if hasattr(app, "_editor_load"):
                        app._editor_load()

            lbl.bind("<Button-1>", _load_recent)
            ToolTip(lbl, f"Load into Editor:\n{path}")

    # ── RIGHT COLUMN: Charts ──
    right_col = ttk.Frame(content_frame)
    right_col.grid(row=0, column=1, sticky="nsew")

    stats_lbl = ttk.Label(
        right_col,
        text="📊 Compliance Trend",
        font=GUI_FONT_HEADING,
        foreground=colors.get("fg", "#E6EDF3"),
    )
    stats_lbl.pack(anchor="w", pady=(0, GUI_PADDING))

    # Canvas card
    card_bg = colors.get("card_bg", colors.get("frame_bg", "#1C2333"))
    border_color = colors.get("border", "#30363D")
    app.dash_canvas = tk.Canvas(
        right_col,
        height=320,
        bg=card_bg,
        highlightthickness=1,
        highlightbackground=border_color,
    )
    app.dash_canvas.pack(fill="both", expand=True, pady=(0, GUI_PADDING))

    rec_frame = ttk.Frame(right_col)
    rec_frame.pack(fill="x")

    app.dash_rec_label = ttk.Label(
        rec_frame,
        text="🔍 Scanning recent activity...",
        font=(GUI_FONT_SMALL[0], GUI_FONT_SMALL[1], "italic"),
        foreground=colors.get("muted", "#8B949E"),
    )
    app.dash_rec_label.pack(side="left")

    def _refresh_dash_stats():
        app.dash_canvas.delete("all")
        if not app.proc.history.db:
            app.dash_canvas.create_text(
                200, 100, text="Telemetry DB not initialized.", fill=colors.get("muted", "gray"), font=GUI_FONT_NORMAL
            )
            return

        try:
            recent_files = app._settings.get("recent_files", [])
            if recent_files:
                p = Path(recent_files[0])
                app.dash_rec_label.config(
                    text=f"💡 Continue assessing '{p.name}'",
                    foreground=colors.get("accent", "#58A6FF"),
                    cursor="hand2",
                )
                app.dash_rec_label.bind(
                    "<Button-1>",
                    lambda e, path=recent_files[0]: _load_recent(None, path),
                )
            else:
                app.dash_rec_label.config(
                    text="💡 Drop a DISA STIG Benchmark into 'Parse New' to begin.",
                    foreground=colors.get("muted", "#8B949E"),
                )

            with app.proc.history.db._get_conn() as conn:
                import sqlite3
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    SELECT asset_name, 
                           SUM(CASE WHEN status='NotAFinding' THEN 1 ELSE 0 END) as naf,
                           COUNT(*) as total
                    FROM findings
                    JOIN assessments ON assessments.id = findings.assessment_id
                    GROUP BY assessment_id
                    ORDER BY assessments.timestamp DESC
                    LIMIT 8
                '''
                )
                rows = list(reversed(cursor.fetchall()))

            width = int(app.dash_canvas.winfo_width())
            height = int(app.dash_canvas.winfo_height())

            if width <= 1:
                width = 600
            if height <= 1:
                height = 380

            if not rows:
                app.dash_canvas.create_text(
                    width / 2, height / 2,
                    text="Ready for Operations\n\nRun an assessment to populate tracking.",
                    justify="center",
                    fill=colors.get("muted", "gray"),
                    font=GUI_FONT_NORMAL
                )
                return

            line_y_base = height - 60
            line_x_step = width / (len(rows) + 1)
            points = []

            # Subtle grid lines
            for i in range(1, 5):
                gy = line_y_base - (i * 0.25 * (height - 100))
                app.dash_canvas.create_line(
                    40, gy, width - 40, gy,
                    fill=colors.get("border", "#30363D"), dash=(2, 4)
                )
                # Axis label
                app.dash_canvas.create_text(
                    28, gy, text=f"{i*25}%",
                    font=GUI_FONT_SMALL,
                    fill=colors.get("muted", "#8B949E"),
                    anchor="e",
                )

            accent_color = colors.get("accent", "#58A6FF")
            ok_color = colors.get("ok", "#3FB950")
            text_color = colors.get("fg", "#E6EDF3")
            muted_color = colors.get("muted", "#8B949E")

            for idx, row in enumerate(rows):
                total = row["total"] or 1
                score = row["naf"] / total
                x = line_x_step * (idx + 1)
                y = line_y_base - (score * (height - 100))
                points.append((x, y))

                # Outer ring + filled dot
                app.dash_canvas.create_oval(
                    x - 8, y - 8, x + 8, y + 8,
                    outline=accent_color, width=2, fill=""
                )
                app.dash_canvas.create_oval(
                    x - 4, y - 4, x + 4, y + 4,
                    fill=accent_color, outline=""
                )

                # Percentage label
                app.dash_canvas.create_text(
                    x, y - 18,
                    text=f"{int(score*100)}%",
                    font=(GUI_FONT_MONO[0], 9, "bold"),
                    fill=text_color,
                )

                # Asset name (rotated)
                lbl = row["asset_name"][:12]
                app.dash_canvas.create_text(
                    x, line_y_base + 25,
                    text=lbl,
                    font=GUI_FONT_SMALL,
                    angle=30,
                    fill=muted_color,
                )

            # Trend line
            if len(points) > 1:
                app.dash_canvas.create_line(
                    points, fill=accent_color, width=3, smooth=True, capstyle="round"
                )

            # ATO Goal Line
            goal_y = line_y_base - (0.8 * (height - 100))
            app.dash_canvas.create_line(
                40, goal_y, width - 40, goal_y,
                fill=ok_color, dash=(6, 4), width=2
            )
            app.dash_canvas.create_text(
                80, goal_y - 12,
                text="ATO Target (80%)",
                font=(GUI_FONT_SMALL[0], GUI_FONT_SMALL[1], "bold"),
                fill=ok_color,
                anchor="w",
            )

        except Exception as e:
            app.dash_canvas.create_text(
                200, 100, text=f"Telemetry Render Error: {e}",
                fill=colors.get("error", "red"), font=GUI_FONT_NORMAL
            )

    # Initial draw
    app.root.after(800, _refresh_dash_stats)
    app.dash_refresh = _refresh_dash_stats

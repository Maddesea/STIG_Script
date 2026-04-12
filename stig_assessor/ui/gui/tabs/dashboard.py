"""Welcome Dashboard Tab module."""

import tkinter as tk
from pathlib import Path
from tkinter import ttk

from stig_assessor.core.constants import (GUI_FONT_HEADING, GUI_FONT_NORMAL, GUI_FONT_MONO,
                                          GUI_PADDING, GUI_PADDING_LARGE,
                                          GUI_PADDING_SECTION, Status)
from stig_assessor.ui.helpers import ToolTip


def build_dashboard_tab(app, frame):
    # Overall layout
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    # ── HEADER (Premium Styling) ──
    header = ttk.Frame(frame, padding=(0, 0, 0, GUI_PADDING_LARGE))
    header.grid(row=0, column=0, sticky="ew")

    title_lbl = ttk.Label(
        header,
        text="✨ STIG Assessor Command Center",
        font=(GUI_FONT_HEADING[0], 22, "bold"),
        foreground=app._colors.get("accent", "#3B82F6"),
    )
    title_lbl.pack(anchor="w")
    
    sub_lbl = ttk.Label(
        header,
        text="Air-Gapped Enclave Compliance & Remediation Console",
        font=(GUI_FONT_NORMAL[0], 12),
        foreground=app._colors.get("fg", "#1E2432"),
    )
    sub_lbl.pack(anchor="w", pady=(4, 0))

    # ── MAIN CONTENT GRID ──
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=1, column=0, sticky="nsew")
    content_frame.columnconfigure(0, weight=1)
    content_frame.columnconfigure(1, weight=2)
    content_frame.rowconfigure(0, weight=1)

    # LEFT COLUMN: Quick Actions & Recent Checklists
    left_col = ttk.Frame(content_frame)
    left_col.grid(row=0, column=0, sticky="nsew", padx=(0, GUI_PADDING_LARGE))

    # SEC: Quick Actions
    qa_lbl = ttk.Label(
        left_col, text="⚡ Quick Actions", font=(GUI_FONT_HEADING[0], 14, "bold")
    )
    qa_lbl.pack(anchor="w", pady=(0, GUI_PADDING))

    actions = [
        ("🚀 Parse New STIG Benchmark", "Create a new CKL from XCCDF Benchmark", 0),
        ("📝 Open Assessment Editor", "Open the last edited checklist", 1),
        ("🔨 Batch Remediation", "Extract and map SCAP findings", 8),
        ("📈 Fleet Analytics", "Analyze an entire enclave or directory", 11),
    ]

    for text, hint, tab_idx in actions:
        btn = ttk.Button(
            left_col,
            text=text,
            command=lambda idx=tab_idx: app._switch_tab(idx),
            style="Accent.TButton",
            width=30,
        )
        btn.pack(pady=6, fill="x", ipady=4)
        ToolTip(btn, hint)

    # SEC: Recent Files
    recent_lbl = ttk.Label(
        left_col, 
        text="📂 Recent Checklists", 
        font=(GUI_FONT_HEADING[0], 14, "bold")
    )
    recent_lbl.pack(anchor="w", pady=(GUI_PADDING_SECTION, GUI_PADDING))

    recent_frame = ttk.Frame(left_col)
    recent_frame.pack(fill="both", expand=True)

    recent_files = app._settings.get("recent_files", [])
    if not recent_files:
        ttk.Label(recent_frame, text="No recent assessments logged.", foreground="gray").pack(anchor="w")
    else:
        for path in recent_files[:5]:
            p = Path(path)
            item_f = ttk.Frame(recent_frame)
            item_f.pack(fill="x", pady=4)
            
            lbl = ttk.Label(
                item_f,
                text=f"📄 {p.name}",
                font=(GUI_FONT_NORMAL[0], 11),
                foreground=app._colors.get("accent", "#3B82F6"),
                cursor="hand2",
            )
            lbl.pack(side="left")

            def _load_recent(evt, target_path=path):
                app.editor_ckl_var.set(target_path)
                app._switch_tab(1)  # Editor
                if hasattr(app, "_editor_load"):
                    app._editor_load()

            lbl.bind("<Button-1>", _load_recent)
            ToolTip(lbl, f"Load into Editor:\n{path}")

    # RIGHT COLUMN: Highlights / Stats
    right_col = ttk.Frame(content_frame)
    right_col.grid(row=0, column=1, sticky="nsew")

    stats_lbl = ttk.Label(
        right_col, 
        text="📊 Intelligence & Drift", 
        font=(GUI_FONT_HEADING[0], 14, "bold")
    )
    stats_lbl.pack(anchor="w", pady=(0, GUI_PADDING))

    # Canvas Card mimicking a premium glasspane
    card_bg = app._colors.get("frame_bg", "#1E293B")
    app.dash_canvas = tk.Canvas(
        right_col,
        height=400,
        bg=card_bg,
        highlightthickness=1,
        highlightbackground=app._colors.get("select_bg", "#0A2F6B"),
    )
    app.dash_canvas.pack(fill="both", expand=True, pady=(0, GUI_PADDING))

    rec_frame = ttk.Frame(right_col)
    rec_frame.pack(fill="x")

    app.dash_rec_label = ttk.Label(
        rec_frame,
        text="🔍 Scanning recent activity...",
        font=(GUI_FONT_NORMAL[0], 11, "italic"),
        foreground="gray",
    )
    app.dash_rec_label.pack(side="left")

    def _refresh_dash_stats():
        app.dash_canvas.delete("all")
        if not app.proc.history.db:
            app.dash_canvas.create_text(
                200, 100, text="Telemetry DB not initialized.", fill="gray", font=GUI_FONT_NORMAL
            )
            return

        try:
            recent_files = app._settings.get("recent_files", [])
            if recent_files:
                p = Path(recent_files[0])
                app.dash_rec_label.config(
                    text=f"💡 Suggestion: Continue assessing '{p.name}'",
                    foreground=app._colors.get("accent", "#3B82F6"),
                    cursor="hand2",
                )
                app.dash_rec_label.bind(
                    "<Button-1>",
                    lambda e, path=recent_files[0]: _load_recent(None, path),
                )
            else:
                app.dash_rec_label.config(
                    text="💡 Tip: Drop a DISA STIG Benchmark into 'Parse New' to begin.", foreground="gray"
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
                height = 400

            if not rows:
                app.dash_canvas.create_text(
                    width / 2, height / 2,
                    text="Ready for Operations\n\nRun an assessment to populate tracking.",
                    justify="center",
                    fill="gray",
                    font=GUI_FONT_NORMAL
                )
                return

            line_y_base = height - 80
            line_x_step = width / (len(rows) + 1)
            points = []

            # Background grid lines
            for i in range(1, 5):
                gy = line_y_base - (i * 0.25 * (height - 120))
                app.dash_canvas.create_line(
                    40, gy, width - 40, gy, 
                    fill=app._colors.get("select_bg", "#DBEAFE"), dash=(2, 4)
                )

            accent_color = app._colors.get("accent", "#3B82F6")
            text_color = app._colors.get("fg", "black")

            for idx, row in enumerate(rows):
                total = row["total"] or 1
                score = row["naf"] / total
                x = line_x_step * (idx + 1)
                y = line_y_base - (score * (height - 120))
                points.append((x, y))

                # Sleek nodes
                app.dash_canvas.create_oval(
                    x - 6, y - 6, x + 6, y + 6, 
                    fill=accent_color, outline=card_bg, width=2
                )
                app.dash_canvas.create_text(
                    x, y - 20,
                    text=f"{int(score*100)}%",
                    font=(GUI_FONT_MONO[0], 10, "bold"),
                    fill=text_color,
                )

                lbl = row["asset_name"][:12]
                app.dash_canvas.create_text(
                    x, line_y_base + 30,
                    text=lbl,
                    font=(GUI_FONT_NORMAL[0], 9),
                    angle=35,
                    fill=text_color,
                )

            if len(points) > 1:
                app.dash_canvas.create_line(
                    points, fill=accent_color, width=4, smooth=True, capstyle="round"
                )

            # ATO Goal Line
            goal_y = line_y_base - (0.8 * (height - 120))
            app.dash_canvas.create_line(
                40, goal_y, width - 40, goal_y,
                fill=app._colors.get("ok", "#10B981"), dash=(8, 4), width=2
            )
            app.dash_canvas.create_text(
                80, goal_y - 12,
                text="ATO Target (80%)",
                font=(GUI_FONT_NORMAL[0], 10, "bold"),
                fill=app._colors.get("ok", "#10B981"),
            )

        except Exception as e:
            app.dash_canvas.create_text(
                200, 100, text=f"Telemetry Render Error: {e}", fill="red", font=GUI_FONT_NORMAL
            )

    # Initial draw
    app.root.after(800, _refresh_dash_stats)
    app.dash_refresh = _refresh_dash_stats

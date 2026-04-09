"""Welcome Dashboard Tab module."""
import tkinter as tk
from tkinter import ttk
from pathlib import Path

from stig_assessor.core.constants import (
    GUI_PADDING, GUI_PADDING_LARGE, GUI_FONT_HEADING, GUI_FONT_NORMAL, Status
)
from stig_assessor.ui.helpers import ToolTip, PremiumChart


def build_dashboard_tab(app, frame):
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(1, weight=1)

    # ── HEADER ──
    header = ttk.Frame(frame)
    header.grid(row=0, column=0, sticky="ew", pady=(0, GUI_PADDING_LARGE))
    
    ttk.Label(header, text="Welcome to STIG Assessor", font=(GUI_FONT_HEADING[0], 18, "bold"), foreground=app._colors.get("accent", "#0969da")).pack(anchor="w")
    ttk.Label(header, text="Streamlined compliance assessment for air-gapped enclaves.", font=GUI_FONT_NORMAL).pack(anchor="w")

    # ── MAIN CONTENT ──
    main_pw = ttk.PanedWindow(frame, orient="horizontal")
    main_pw.grid(row=1, column=0, sticky="nsew")

    # LEFT: Quick Actions & Recent
    left_side = ttk.Frame(main_pw)
    main_pw.add(left_side, weight=1)

    # SEC: Quick Actions
    qa_frame = ttk.LabelFrame(left_side, text="Quick Actions", padding=GUI_PADDING_LARGE)
    qa_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))

    actions = [
        ("🆕 New Checklist", "Create a new CKL from XCCDF Benchmark", 0),
        ("📂 Assessment Editor", "Open the last edited checklist", 1),
        ("🏗 Batch Convert", "Convert multiple XCCDFs to CKLs", 8),
        ("📊 Fleet Analytics", "Analyze an entire enclave or directory", 11),
    ]

    for text, hint, tab_idx in actions:
        btn = ttk.Button(qa_frame, text=text, command=lambda idx=tab_idx: app._switch_tab(idx), style="Accent.TButton", width=25)
        btn.pack(pady=4, fill="x")
        ToolTip(btn, hint)

    # SEC: Recent Files
    recent_frame = ttk.LabelFrame(left_side, text="Recent Checklists", padding=GUI_PADDING_LARGE)
    recent_frame.pack(fill="both", expand=True)

    recent_files = app._settings.get("recent_files", [])
    if not recent_files:
        ttk.Label(recent_frame, text="No recent files found.", foreground="gray").pack()
    else:
        for path in recent_files[:5]:
            p = Path(path)
            # Use small frame for hover effect
            item_f = ttk.Frame(recent_frame)
            item_f.pack(fill="x", pady=2)
            
            lbl = ttk.Label(item_f, text=f"📄 {p.name}", foreground=app._colors.get("accent", "blue"), cursor="hand2")
            lbl.pack(side="left")
            
            def _load_recent(evt, target_path=path):
                app.editor_ckl_var.set(target_path)
                app._switch_tab(1) # Editor
                if hasattr(app, "_editor_load"):
                    app._editor_load()
            
            lbl.bind("<Button-1>", _load_recent)
            ToolTip(lbl, f"Load into Editor:\n{path}")

    # RIGHT: Highlights / Stats
    right_side = ttk.Frame(main_pw)
    main_pw.add(right_side, weight=2)

    stats_frame = ttk.LabelFrame(right_side, text="Compliance Intelligence", padding=GUI_PADDING_LARGE)
    stats_frame.pack(fill="both", expand=True, padx=(GUI_PADDING_LARGE, 0))

    # SEC: Recommendations
    rec_frame = ttk.Frame(stats_frame)
    rec_frame.pack(fill="x", pady=(0, GUI_PADDING_LARGE))
    
    app.dash_rec_label = ttk.Label(rec_frame, text="🔍 Scanning recent activity...", font=(GUI_FONT_NORMAL[0], 10, "italic"), foreground="gray")
    app.dash_rec_label.pack(side="left")
    
    app.dash_canvas = tk.Canvas(stats_frame, height=300, bg=app._colors.get("bg", "#ffffff"), highlightthickness=0)
    app.dash_canvas.pack(fill="both", expand=True)

    def _refresh_dash_stats():
        app.dash_canvas.delete("all")
        if not app.proc.history.db:
            app.dash_canvas.create_text(200, 100, text="History DB not initialized.", fill="gray")
            return
            
        try:
            # 1. Pull Recommendation Data
            recent_files = app._settings.get("recent_files", [])
            if recent_files:
                p = Path(recent_files[0])
                app.dash_rec_label.config(text=f"💡 Suggestion: Continue assessing {p.name}", foreground=app._colors.get("accent", "blue"), cursor="hand2")
                app.dash_rec_label.bind("<Button-1>", lambda e, path=recent_files[0]: _load_recent(None, path))
            else:
                app.dash_rec_label.config(text="💡 Tip: Create a new checklist to begin.", foreground="gray")

            # 2. Pull compliance stats for trending
            with app.proc.history.db._get_conn() as conn:
                import sqlite3
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT asset_name, 
                           SUM(CASE WHEN status='NotAFinding' THEN 1 ELSE 0 END) as naf,
                           COUNT(*) as total
                    FROM findings
                    JOIN assessments ON assessments.id = findings.assessment_id
                    GROUP BY assessment_id
                    ORDER BY assessments.timestamp DESC
                    LIMIT 6
                """)
                rows = list(reversed(cursor.fetchall()))

            if not rows:
                app.dash_canvas.create_text(200, 100, text="No historical data found.\nStart an assessment to see stats here!", justify="center", fill="gray")
                return

            width = max(500, int(app.dash_canvas.winfo_width()))
            height = 300
            
            # Draw Trend Line
            line_y_base = height - 60
            line_x_step = width / (len(rows) + 1)
            points = []
            
            # Heading
            app.dash_canvas.create_text(width/2, 25, text="Enclave Compliance Trend (Recent Assessments)", font=(GUI_FONT_NORMAL[0], 11, "bold"), fill=app._colors.get("fg", "black"))

            for idx, row in enumerate(rows):
                total = row['total'] or 1
                score = (row['naf'] / total)
                x = line_x_step * (idx + 1)
                y = line_y_base - (score * 180)
                points.append((x, y))
                
                # Small data point
                app.dash_canvas.create_oval(x-4, y-4, x+4, y+4, fill="#0969da", outline="#ffffff")
                app.dash_canvas.create_text(x, y-15, text=f"{int(score*100)}%", font=(GUI_FONT_NORMAL[0], 8), fill=app._colors.get("text", "gray"))
                
                # Label
                lbl = row['asset_name'][:10]
                app.dash_canvas.create_text(x, line_y_base + 15, text=lbl, font=(GUI_FONT_NORMAL[0], 8), angle=45, fill=app._colors.get("text", "gray"))

            if len(points) > 1:
                app.dash_canvas.create_line(points, fill="#0969da", width=3, smooth=True, capstyle="round")
                
            # Goal line (80%)
            goal_y = line_y_base - (0.8 * 180)
            app.dash_canvas.create_line(line_x_step, goal_y, width-line_x_step, goal_y, fill="#22c55e", dash=(4, 4))
            app.dash_canvas.create_text(width-line_x_step + 30, goal_y, text="Goal (80%)", font=(GUI_FONT_NORMAL[0], 8), fill="#22c55e")

        except Exception as e:
            app.dash_canvas.create_text(200, 100, text=f"Error loading stats: {e}", fill="red", width=350)

    # Initial draw
    app.root.after(500, _refresh_dash_stats)
    app.dash_refresh = _refresh_dash_stats

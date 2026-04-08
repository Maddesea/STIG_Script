"""HTML Graphical Diff Generator for Checklists."""

import os
from typing import Dict, Any
import html
from stig_assessor.processor.processor import Proc

def generate_html_diff(ckl1: str, ckl2: str, out_path: str) -> str:
    """
    Generate an interactive side-by-side HTML diff.
    """
    proc = Proc()
    # Ensure detailed output
    diff_data = proc.diff(ckl1, ckl2, output_format="json")
    
    # Render
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STIG Checklist Diff Report</title>
    <style>
        :root {{
            --bg-base: #0f111a;
            --bg-surface: #1a1e2e;
            --bg-card: #23283c;
            --tx-main: #e2e8f0;
            --tx-muted: #94a3b8;
            --bg-red: rgba(239, 68, 68, 0.15);
            --bg-green: rgba(34, 197, 94, 0.15);
            --fg-red: #fca5a5;
            --fg-green: #86efac;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-base);
            color: var(--tx-main);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        .header {{
            background-color: var(--bg-surface);
            padding: 2rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            text-align: center;
        }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .header p {{ color: var(--tx-muted); margin: 0; font-size: 0.95rem; }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .summary-banner {{
            display: flex;
            gap: 2rem;
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            justify-content: center;
        }}
        .stat {{ text-align: center; }}
        .stat-val {{ font-size: 2rem; font-weight: bold; margin-bottom: 0.25rem; }}
        .stat-label {{ color: var(--tx-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }}
        
        .diff-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .diff-table th, .diff-table td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            vertical-align: top;
        }}
        .diff-table th {{
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            color: var(--tx-muted);
        }}
        .vid-col {{ font-family: monospace; font-size: 0.95rem; font-weight: bold; width: 120px; }}
        .field-col {{ color: var(--tx-muted); font-size: 0.9rem; width: 100px; }}
        
        .diff-side {{ width: 35%; white-space: pre-wrap; font-size: 0.9rem; }}
        .diff-old {{ background-color: var(--bg-red); color: var(--fg-red); }}
        .diff-new {{ background-color: var(--bg-green); color: var(--fg-green); }}
        
        .empty {{ color: var(--tx-muted); font-style: italic; }}
    </style>
</head>
<body>

<div class="header">
    <h1>STIG Checklist Diff Report</h1>
    <p>Baseline: {html.escape(os.path.basename(ckl1))} &nbsp;|&nbsp; Target: {html.escape(os.path.basename(ckl2))}</p>
</div>

<div class="container">
    <div class="summary-banner">
        <div class="stat">
            <div class="stat-val">{len(diff_data.get('changes', []))}</div>
            <div class="stat-label">Changed Items</div>
        </div>
        <div class="stat">
            <div class="stat-val" style="color: var(--fg-green);">{len(diff_data.get('added', []))}</div>
            <div class="stat-label">Added Rules</div>
        </div>
        <div class="stat">
            <div class="stat-val" style="color: var(--fg-red);">{len(diff_data.get('removed', []))}</div>
            <div class="stat-label">Removed Rules</div>
        </div>
    </div>
    
    <table class="diff-table">
        <thead>
            <tr>
                <th class="vid-col">Vulnerability ID</th>
                <th class="field-col">Field Changed</th>
                <th class="diff-side">Baseline (Previous)</th>
                <th class="diff-side">Target (Current)</th>
            </tr>
        </thead>
        <tbody>
"""

    for ch in diff_data.get("changes", []):
        old_val = ch.get("old", "")
        new_val = ch.get("new", "")
        html_content += f"""
            <tr>
                <td class="vid-col">{html.escape(ch.get("vid", ""))}</td>
                <td class="field-col">{html.escape(ch.get("field", ""))}</td>
                <td class="diff-side diff-old">{html.escape(str(old_val)) if old_val else '<span class="empty">empty</span>'}</td>
                <td class="diff-side diff-new">{html.escape(str(new_val)) if new_val else '<span class="empty">empty</span>'}</td>
            </tr>
"""

    for ad in diff_data.get("added", []):
        html_content += f"""
            <tr>
                <td class="vid-col">{html.escape(ad)}</td>
                <td class="field-col">Rule</td>
                <td class="diff-side diff-old"><span class="empty">not present</span></td>
                <td class="diff-side diff-new">Added to checklist</td>
            </tr>
"""

    for rm in diff_data.get("removed", []):
        html_content += f"""
            <tr>
                <td class="vid-col">{html.escape(rm)}</td>
                <td class="field-col">Rule</td>
                <td class="diff-side diff-old">Present in baseline</td>
                <td class="diff-side diff-new"><span class="empty">removed</span></td>
            </tr>
"""

    html_content += """
        </tbody>
    </table>
</div>

</body>
</html>
"""

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    return out_path

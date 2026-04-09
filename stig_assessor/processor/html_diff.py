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
            --bg-base: #0a0c10;
            --bg-surface: #12161b;
            --bg-card: #1c2128;
            --tx-main: #adbac7;
            --tx-muted: #768390;
            --bg-red: rgba(229, 83, 75, 0.15);
            --bg-green: rgba(52, 125, 57, 0.15);
            --fg-red: #e5534b;
            --fg-green: #57ab5a;
            --accent: #539bf5;
            --border: #444c56;
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
            padding: 2.5rem 2rem;
            border-bottom: 1px solid var(--border);
            text-align: center;
        }}
        .header h1 {{ margin: 0 0 10px 0; color: #fff; font-weight: 300; letter-spacing: 1px; }}
        .header p {{ color: var(--tx-muted); margin: 0; font-size: 0.95rem; }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .summary-banner {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-3px); }}
        .stat-val {{ font-size: 2.5rem; font-weight: 700; color: var(--accent); display: block; }}
        .stat-label {{ color: var(--tx-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }}
        
        .diff-section {{ margin-bottom: 3rem; }}
        .section-title {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; color: #fff; display: flex; align-items: center; gap: 10px; }}
        .badge {{ font-size: 0.7rem; padding: 2px 8px; border-radius: 10px; background: var(--border); }}

        .diff-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
        }}
        .diff-table th, .diff-table td {{
            padding: 1.25rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        .diff-table th {{
            background: rgba(68, 76, 86, 0.3);
            font-weight: 600;
            color: var(--tx-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }}
        .vid-col {{ font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 0.9rem; font-weight: 600; width: 150px; color: var(--accent); }}
        .field-col {{ color: var(--tx-muted); font-size: 0.85rem; width: 120px; font-weight: 500; }}
        
        .diff-side {{ width: 40%; white-space: pre-wrap; font-size: 0.85rem; font-family: ui-monospace, SFMono-Regular, monospace; }}
        .diff-old {{ background-color: var(--bg-red); border-left: 3px solid var(--fg-red); }}
        .diff-new {{ background-color: var(--bg-green); border-left: 3px solid var(--fg-green); }}
        
        .empty {{ color: var(--tx-muted); font-style: italic; opacity: 0.6; }}
        
        .rule-title {{ display: block; font-size: 0.75rem; color: var(--tx-muted); font-weight: 400; margin-top: 4px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>STIG Comparison Engine</h1>
    <p>Baseline: {html.escape(os.path.basename(ckl1))} &nbsp;&rarr;&nbsp; Target: {html.escape(os.path.basename(ckl2))}</p>
</div>

<div class="container">
    <div class="summary-banner">
        <div class="stat-card">
            <span class="stat-val">{diff_data.get('summary', {}).get('changed', 0)}</span>
            <span class="stat-label">Changed Findings</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color: var(--fg-green);">{diff_data.get('summary', {}).get('only_in_comparison', 0)}</span>
            <span class="stat-label">Added Rules</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color: var(--fg-red);">{diff_data.get('summary', {}).get('only_in_baseline', 0)}</span>
            <span class="stat-label">Removed Rules</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color: var(--tx-muted);">{diff_data.get('summary', {}).get('unchanged', 0)}</span>
            <span class="stat-label">Unchanged</span>
        </div>
    </div>
    
    <div class="diff-section">
        <div class="section-title">Differences Found <span class="badge">{len(diff_data.get('changes', []))} items</span></div>
        <table class="diff-table">
            <thead>
                <tr>
                    <th class="vid-col">Vulnerability</th>
                    <th class="field-col">Field</th>
                    <th class="diff-side">Baseline</th>
                    <th class="diff-side">Target</th>
                </tr>
            </thead>
            <tbody>
"""

    for ch in diff_data.get("changes", []):
        vid = ch.get("vid", "Unknown")
        title = ch.get("rule_title", "")
        for df in ch.get("differences", []):
            field = df.get("field", "status")
            old_val = df.get("from", "")
            new_val = df.get("to", "")
            
            # Special handling for text diffs to make them look cleaner in HTML
            old_display = html.escape(str(old_val)) if old_val else '<span class="empty">empty</span>'
            new_display = html.escape(str(new_val)) if new_val else '<span class="empty">empty</span>'

            html_content += f"""
                <tr>
                    <td class="vid-col">{html.escape(vid)}<span class="rule-title">{html.escape(title[:80])}</span></td>
                    <td class="field-col">{html.escape(field.replace('_', ' ').title())}</td>
                    <td class="diff-side diff-old">{old_display}</td>
                    <td class="diff-side diff-new">{new_display}</td>
                </tr>
"""

    # Handle Added/Removed
    for ad in diff_data.get("added", []):
        html_content += f"""
            <tr>
                <td class="vid-col">{html.escape(ad)}</td>
                <td class="field-col">Checklist</td>
                <td class="diff-side diff-old"><span class="empty">Not present in baseline</span></td>
                <td class="diff-side diff-new"><span style="color:var(--fg-green); font-weight:bold;">+ ADDED TO CHECKLIST</span></td>
            </tr>
"""

    for rm in diff_data.get("removed", []):
        html_content += f"""
            <tr>
                <td class="vid-col">{html.escape(rm)}</td>
                <td class="field-col">Checklist</td>
                <td class="diff-side diff-old"><span style="color:var(--fg-red); font-weight:bold;">- REMOVED FROM CHECKLIST</span></td>
                <td class="diff-side diff-new"><span class="empty">Not present in comparison</span></td>
            </tr>
"""

    html_content += """
            </tbody>
        </table>
    </div>
    
    <div style="text-align:center; color: var(--tx-muted); font-size: 0.8rem; margin-top: 4rem; border-top: 1px solid var(--border); padding-top: 2rem;">
        Generated by STIG Assessor Comparison Engine &middot; High Efficiency Compliance Diff
    </div>
</div>

</body>
</html>
"""

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    return out_path

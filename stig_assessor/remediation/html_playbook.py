"""HTML Remediation Playbook Generator for STIG Assessor."""

from typing import List, Dict, Any
import html
import json
import base64

def generate_html_playbook(extractor: Any, out_path: str) -> str:
    """
    Generate an interactive offline HTML remediation playbook from extracted fixes.
    
    Args:
        extractor: The FixExt instance containing .fixes
        out_path: Output HTML file path
        
    Returns:
        The path to the generated HTML file.
    """
    fixes = extractor.fixes
    
    high = [f for f in fixes if f.severity.lower() == "high"]
    medium = [f for f in fixes if f.severity.lower() == "medium"]
    low = [f for f in fixes if f.severity.lower() == "low"]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STIG Remediation Playbook</title>
    <style>
        :root {{
            --bg-base: #0f111a;
            --bg-surface: #1a1e2e;
            --bg-card: #23283c;
            --tx-main: #e2e8f0;
            --tx-muted: #94a3b8;
            --ac-primary: #3b82f6;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #3b82f6;
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
        .header h1 {{ margin: 0 0 10px 0; font-size: 2rem; letter-spacing: -0.5px; }}
        .header p {{ color: var(--tx-muted); margin: 0; font-size: 1.1rem; }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .stats-grid {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            justify-content: center;
        }}
        .stat-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            min-width: 150px;
            border-top: 4px solid var(--ac-primary);
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card.high {{ border-color: var(--high); }}
        .stat-card.medium {{ border-color: var(--medium); }}
        .stat-card.low {{ border-color: var(--low); }}
        .stat-card h3 {{ margin: 0; font-size: 2rem; }}
        .stat-card span {{ color: var(--tx-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }}

        .tabs {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            padding-bottom: 1rem;
        }}
        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--tx-muted);
            font-size: 1.1rem;
            padding: 0.5rem 1rem;
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.2s;
        }}
        .tab-btn:hover {{ background: rgba(255,255,255,0.05); color: var(--tx-main); }}
        .tab-btn.active {{ background: var(--bg-surface); color: var(--tx-main); box-shadow: inset 0 2px 0 var(--ac-primary); }}

        .fix-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 4px solid var(--ac-primary);
        }}
        .fix-card.high {{ border-left-color: var(--high); }}
        .fix-card.medium {{ border-left-color: var(--medium); }}
        .fix-card.low {{ border-left-color: var(--low); }}
        
        .fix-header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}
        .fix-title {{ font-weight: 600; font-size: 1.1rem; margin-bottom: 0.25rem; color: #fff; }}
        .fix-vid {{ font-family: monospace; color: var(--tx-muted); font-size: 0.9rem; background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 4px; }}
        
        .fix-text {{ color: #cbd5e1; font-size: 0.95rem; margin-bottom: 1rem; white-space: pre-wrap; }}
        
        .code-block {{
            background: #000;
            border-radius: 6px;
            padding: 1rem;
            position: relative;
            font-family: Consolas, Monaco, monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .copy-btn {{
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: rgba(255,255,255,0.1);
            border: none;
            color: #fff;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
        }}
        .copy-btn:hover {{ background: rgba(255,255,255,0.2); }}
        
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
</head>
<body>

<div class="header">
    <h1>STIG Remediation Playbook</h1>
    <p>Automated extract of remediation instructions and shell scripts</p>
</div>

<div class="container">
    <div class="stats-grid">
        <div class="stat-card high">
            <h3>{len(high)}</h3>
            <span>CAT I (High)</span>
        </div>
        <div class="stat-card medium">
            <h3>{len(medium)}</h3>
            <span>CAT II (Medium)</span>
        </div>
        <div class="stat-card low">
            <h3>{len(low)}</h3>
            <span>CAT III (Low)</span>
        </div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('all')">All Findings ({len(fixes)})</button>
        <button class="tab-btn" onclick="switchTab('high')">CAT I ({len(high)})</button>
        <button class="tab-btn" onclick="switchTab('medium')">CAT II ({len(medium)})</button>
        <button class="tab-btn" onclick="switchTab('low')">CAT III ({len(low)})</button>
    </div>

    <div id="tab-all" class="tab-content active">
"""
    
    def render_fix(f):
        sev_class = f.severity.lower()
        cmd_html = ""
        if f.fix_command:
            safe_id = f.vid.replace("-", "_")
            # Base64 encode command to safely store in attribute for JS
            b64_cmd = base64.b64encode(f.fix_command.encode('utf-8')).decode('ascii')
            cmd_html = f"""
        <div class="code-block" id="code-{safe_id}">
            <button class="copy-btn" onclick="copyCode(this, '{b64_cmd}')">Copy</button>
            <code>{html.escape(f.fix_command)}</code>
        </div>
"""
        return f"""
        <div class="fix-card {sev_class}">
            <div class="fix-header">
                <div>
                    <div class="fix-title">{html.escape(f.title)}</div>
                    <span class="fix-vid">{html.escape(f.vid)}</span>
                    <span class="fix-vid">{html.escape(f.rule_id)}</span>
                </div>
            </div>
            <div class="fix-text">{html.escape(f.fix_text)}</div>
            {cmd_html}
        </div>
"""

    for f in fixes:
        html_content += render_fix(f)
        
    html_content += "</div>\n"
    
    html_content += '<div id="tab-high" class="tab-content">\n'
    for f in high: html_content += render_fix(f)
    html_content += "</div>\n"

    html_content += '<div id="tab-medium" class="tab-content">\n'
    for f in medium: html_content += render_fix(f)
    html_content += "</div>\n"

    html_content += '<div id="tab-low" class="tab-content">\n'
    for f in low: html_content += render_fix(f)
    html_content += "</div>\n"

    html_content += """
</div>

<script>
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById('tab-' + tabId).classList.add('active');
    event.currentTarget.classList.add('active');
}

function copyCode(btn, b64Code) {
    const txt = atob(b64Code);
    navigator.clipboard.writeText(txt).then(() => {
        const oldText = btn.innerText;
        btn.innerText = "Copied!";
        btn.style.background = "#22c55e";
        setTimeout(() => {
            btn.innerText = oldText;
            btn.style.background = "rgba(255,255,255,0.1)";
        }, 2000);
    });
}
</script>

</body>
</html>
"""

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    return out_path

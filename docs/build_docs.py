import os
import sys
import subprocess
from pathlib import Path

def install_deps():
    try:
        import markdown
    except ImportError:
        print("Installing markdown package...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "markdown"])
        import markdown

install_deps()
import markdown

CSS = """
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* Premium Modern Glassmorphism Styles for Auto-Generated Docs */
:root {
    --bg-color: #0b0f19;
    --bg-gradient: linear-gradient(135deg, #0b0f19 0%, #171b2d 100%);
    --glass-bg: rgba(25, 30, 50, 0.6);
    --glass-border: rgba(255, 255, 255, 0.08);
    --card-hover-bg: rgba(30, 36, 60, 0.8);
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #3b82f6;
    --accent-glow: rgba(59, 130, 246, 0.4);
    --accent-hover: #60a5fa;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.7;
    color: var(--text-main);
    background: var(--bg-gradient);
    background-attachment: fixed;
    max-width: 1000px;
    margin: 0 auto;
    padding: 3rem 2rem;
    padding-bottom: 5rem;
    min-height: 100vh;
}

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.2); }
::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

h1, h2, h3, h4, h5, h6 {
    color: var(--text-main);
    font-weight: 700;
    line-height: 1.3;
    margin-top: 2em;
    margin-bottom: 0.75em;
}

h1 { 
    font-size: 2.8rem; 
    background: linear-gradient(135deg, #fff, #94a3b8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    border-bottom: 2px solid var(--glass-border); 
    padding-bottom: 0.3em; 
    margin-top: 1em; 
}
h2 { font-size: 2rem; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.3em; margin-top: 2.5em; }
h3 { font-size: 1.5em; color: var(--accent-hover); margin-top: 2em; }

a { color: var(--accent); text-decoration: none; transition: color 0.2s ease; }
a:hover { text-decoration: underline; color: var(--accent-hover); }

pre {
    background: rgba(10, 12, 20, 0.8);
    border: 1px solid var(--glass-border);
    border-radius: 12px;
    padding: 1.5rem;
    overflow-x: auto;
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.2), 0 5px 15px rgba(0,0,0,0.2);
    transition: transform 0.2s, box-shadow 0.2s;
    font-size: 0.9em;
    margin: 25px 0;
}

pre:hover {
    transform: translateY(-2px);
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.2), 0 15px 35px rgba(0,0,0,0.4), 0 0 15px var(--accent-glow);
    border-color: rgba(59, 130, 246, 0.3);
}

code {
    font-family: "JetBrains Mono", Consolas, Menlo, Monaco, monospace;
    background-color: rgba(59, 130, 246, 0.1);
    color: var(--accent-hover);
    padding: 0.2em 0.4em;
    border-radius: 4px;
    font-size: 0.9em;
    border: 1px solid rgba(59, 130, 246, 0.2);
}

pre code {
    background-color: transparent;
    color: #e2e8f0;
    padding: 0;
    border: none;
}

blockquote {
    border-left: 4px solid var(--accent);
    padding: 1rem 1.5rem;
    margin: 2rem 0;
    color: var(--text-muted);
    background: var(--glass-bg);
    border-radius: 0 8px 8px 0;
    backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border);
    border-left-width: 4px;
    font-size: 1.1rem;
    font-style: italic;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 2.5rem 0;
    background: rgba(10, 12, 20, 0.4);
    border-radius: 12px;
    border: 1px solid var(--glass-border);
    overflow: hidden;
    box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    backdrop-filter: blur(10px);
}

th, td {
    padding: 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.02);
    text-align: left;
}

th {
    background: rgba(255,255,255,0.03);
    font-weight: 600;
    color: var(--accent-hover);
    border-bottom: 2px solid rgba(255,255,255,0.05);
}

tr:hover td {
    background-color: rgba(255, 255, 255, 0.02);
}

img {
    max-width: 100%;
    height: auto;
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    margin: 2rem 0;
    border: 1px solid var(--glass-border);
}

hr {
    border: 0;
    height: 1px;
    background: var(--glass-border);
    margin: 3rem 0;
}

/* Nav */
.nav {
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--glass-border);
    font-size: 0.95rem;
    color: var(--text-muted);
    padding: 15px;
    background: var(--glass-bg);
    border-radius: 8px;
    backdrop-filter: blur(10px);
}
.nav strong { color: var(--text-main); }
</style>
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {css}
</head>
<body>
    <div class="nav">
        <strong>STIG Assessor Documentation</strong> - {title}
    </div>
    {content}
</body>
</html>
"""

def main():
    root_dir = Path("c:/Users/Madden/Desktop/_Personal_GitHub_Repos/STIG_Script")
    out_dir = root_dir / "docs" / "html_docs"
    
    md_files = []
    for md_file in root_dir.glob("**/*.md"):
        # Ignore things in .git or sub-repos or venv
        if ".git" in md_file.parts or "venv" in md_file.parts or "wheels" in md_file.parts or "html_docs" in md_file.parts:
            continue
        md_files.append(md_file)
        
    out_dir.mkdir(parents=True, exist_ok=True)
    
    for f in md_files:
        print(f"Processing {f.relative_to(root_dir)}")
        with open(f, "r", encoding="utf-8") as in_f:
            text = in_f.read()
            
        md = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc', 'sane_lists'])
        html_content = md.convert(text)
        
        rel_path = f.relative_to(root_dir)
        out_file = out_dir / rel_path.with_suffix(".html")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        final_html = HTML_TEMPLATE.format(
            title=f.stem,
            css=CSS,
            content=html_content
        )
        
        with open(out_file, "w", encoding="utf-8", errors='replace') as out_f:
            out_f.write(final_html)
            
    # Generate the index.html
    index_html = ""
    index_html += "<!DOCTYPE html>\\n<html lang='en'>\\n<head>\\n<title>STIG Assessor Documentation Index</title>\\n"
    index_html += CSS
    index_html += "</head>\\n<body>\\n"
    index_html += "<h1>📚 STIG Assessor Documentation Hub</h1>\\n"
    index_html += "<p>Welcome to the official offline, HTML-rendered documentation for the STIG Assessor ecosystem.</p>\\n"
    index_html += "<h2>Available Documents</h2>\\n<ul>\\n"
    
    # Sort files alphabetically for the index
    for f in sorted(md_files):
        rel_path = f.relative_to(root_dir)
        html_rel_path = rel_path.with_suffix(".html")
        html_link = html_rel_path.as_posix() # Forward slashes for URLs
        
        # Format the title nicely 
        name = f.stem.replace("_", " ").title()
        directory = f.parent.name.capitalize()
        if directory == "Stig_script":
            directory = "Root"
            
        index_html += f"  <li><strong>{directory}:</strong> <a href='{html_link}'>{name}</a></li>\\n"
        
    index_html += "</ul>\\n</body>\\n</html>"
    
    index_file = out_dir / "index.html"
    with open(index_file, "w", encoding="utf-8") as index_f:
        index_f.write(index_html)
        
    print(f"\\nAll done! Converted {len(md_files)} files.")
    print(f"Generated Index Hub: {index_file}")
    print(f"Output directory: {out_dir}")

if __name__ == "__main__":
    main()

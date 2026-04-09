"""Self-contained HTML compliance report generator.

Generates a beautiful, single-file HTML report from CKL/CKLB checklist data.
Zero external dependencies — all CSS, SVG charts, and JavaScript are inline.
100% air-gap compatible.

Example:
    >>> from stig_assessor.processor.html_report import generate_html_report
    >>> generate_html_report("checklist.ckl", "report.html")
"""

from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from stig_assessor.core.constants import APP_NAME, VERSION, Status
from stig_assessor.io.file_ops import FO


def _parse_checklist(path: Path) -> Dict[str, Any]:
    """Parse CKL/CKLB and return normalized data for the report."""
    suffix = path.suffix.lower()

    if suffix == ".cklb":
        data = json.loads(FO.read(path))
        asset_name = data.get("target_data", {}).get("HOST_NAME", "Unknown")
        stig_title = data.get("stig_data", {}).get("title", "Unknown STIG")
        stig_version = data.get("stig_data", {}).get("version", "")
        release = data.get("stig_data", {}).get("releaseinfo", "")
        vulns = []
        for rev in data.get("reviews", []):
            vulns.append({
                "vid": rev.get("Vuln_Num", ""),
                "severity": rev.get("Severity", "medium"),
                "rule_title": rev.get("Rule_Title", ""),
                "status": rev.get("status", Status.NOT_REVIEWED),
                "finding": rev.get("detail", ""),
                "comment": rev.get("comment", ""),
            })
        return {
            "asset": asset_name,
            "title": stig_title,
            "version": stig_version,
            "release": release,
            "vulns": vulns,
            "source": path.name,
        }

    # CKL XML path
    tree = FO.parse_xml(path)
    root = tree.getroot()

    asset_elem = root.find("ASSET")
    asset_name = "Unknown"
    if asset_elem is not None:
        hn = asset_elem.find("HOST_NAME")
        if hn is not None and hn.text:
            asset_name = hn.text.strip()

    stig_title = "Unknown STIG"
    stig_version = ""
    release = ""
    stigs = root.find("STIGS")
    if stigs is not None:
        for istig in stigs.findall("iSTIG"):
            stig_info = istig.find("STIG_INFO")
            if stig_info is not None:
                for si in stig_info.findall("SI_DATA"):
                    name = (si.findtext("SID_NAME") or "").strip()
                    val = (si.findtext("SID_DATA") or "").strip()
                    if name == "title":
                        stig_title = val
                    elif name == "version":
                        stig_version = val
                    elif name == "releaseinfo":
                        release = val

    vulns: List[Dict[str, str]] = []
    if stigs is not None:
        for istig in stigs.findall("iSTIG"):
            for vuln in istig.findall("VULN"):
                vdata: Dict[str, str] = {}
                for sd in vuln.findall("STIG_DATA"):
                    attr = (sd.findtext("VULN_ATTRIBUTE") or "").strip()
                    val = (sd.findtext("ATTRIBUTE_DATA") or "").strip()
                    if attr == "Vuln_Num":
                        vdata["vid"] = val
                    elif attr == "Severity":
                        vdata["severity"] = val
                    elif attr == "Rule_Title":
                        vdata["rule_title"] = val

                vdata["status"] = (vuln.findtext("STATUS") or Status.NOT_REVIEWED).strip()
                vdata["finding"] = (vuln.findtext("FINDING_DETAILS") or "").strip()
                vdata["comment"] = (vuln.findtext("COMMENTS") or "").strip()
                vulns.append(vdata)

    return {
        "asset": asset_name,
        "title": stig_title,
        "version": stig_version,
        "release": release,
        "vulns": vulns,
        "source": path.name,
    }


def _compute_stats(vulns: List[Dict[str, str]]) -> Dict[str, Any]:
    """Compute compliance statistics from vulnerability data."""
    status_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    severity_status: Dict[str, Counter] = defaultdict(Counter)

    for v in vulns:
        status = v.get("status", Status.NOT_REVIEWED)
        severity = v.get("severity", "medium").lower()
        status_counts[status] += 1
        severity_counts[severity] += 1
        severity_status[severity][status] += 1

    total = len(vulns)
    naf = status_counts.get(Status.NOT_A_FINDING, 0)
    na = status_counts.get(Status.NOT_APPLICABLE, 0)
    compliant = naf + na
    compliance_pct = (compliant / total * 100) if total > 0 else 0
    reviewed = total - status_counts.get(Status.NOT_REVIEWED, 0)
    reviewed_pct = (reviewed / total * 100) if total > 0 else 0

    return {
        "total": total,
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "severity_status": {k: dict(v) for k, v in severity_status.items()},
        "compliant": compliant,
        "compliance_pct": compliance_pct,
        "reviewed": reviewed,
        "reviewed_pct": reviewed_pct,
    }


def _svg_donut(stats: Dict[str, Any]) -> str:
    """Generate an SVG donut chart for status distribution."""
    total = stats["total"]
    if total == 0:
        return "<p>No data available.</p>"

    colors = {
        Status.NOT_A_FINDING: "#22c55e",
        Status.NOT_APPLICABLE: "#64748b",
        Status.OPEN: "#ef4444",
        Status.NOT_REVIEWED: "#f59e0b",
    }

    segments = []
    offset = 0
    for status, count in sorted(stats["status_counts"].items(), key=lambda x: -x[1]):
        pct = count / total * 100
        dash = pct * 2.51327  # circumference of r=40 ≈ 251.327
        gap = 251.327 - dash
        color = colors.get(status, "#94a3b8")
        segments.append(
            f'<circle cx="60" cy="60" r="40" fill="none" stroke="{color}" '
            f'stroke-width="20" stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'stroke-dashoffset="{-offset * 2.51327:.2f}" '
            f'transform="rotate(-90 60 60)"/>'
        )
        offset += pct

    compliance_pct = stats["compliance_pct"]
    color_class = "good" if compliance_pct >= 80 else ("warn" if compliance_pct >= 50 else "bad")

    svg = f"""<svg viewBox="0 0 120 120" class="donut-chart">
        <circle cx="60" cy="60" r="40" fill="none" stroke="#1e293b" stroke-width="20"/>
        {''.join(segments)}
        <text x="60" y="56" text-anchor="middle" class="donut-pct {color_class}">{compliance_pct:.0f}%</text>
        <text x="60" y="70" text-anchor="middle" class="donut-label">compliant</text>
    </svg>"""
    return svg


def _build_html(data: Dict[str, Any], stats: Dict[str, Any]) -> str:
    """Build the complete HTML report string."""
    e = html.escape
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Status badge colors
    badge = {
        Status.NOT_A_FINDING: ("NotAFinding", "#22c55e", "#052e16"),
        Status.NOT_APPLICABLE: ("Not_Applicable", "#64748b", "#f8fafc"),
        Status.OPEN: ("Open", "#ef4444", "#fff"),
        Status.NOT_REVIEWED: ("Not_Reviewed", "#f59e0b", "#1c1917"),
    }

    # Severity label
    sev_badge = {
        "high": ("CAT I", "#dc2626"),
        "medium": ("CAT II", "#f97316"),
        "low": ("CAT III", "#eab308"),
    }

    # Build legend items
    legend_items = []
    for status, count in sorted(stats["status_counts"].items(), key=lambda x: -x[1]):
        label, bg, fg = badge.get(status, (status, "#94a3b8", "#fff"))
        legend_items.append(
            f'<span class="legend-item"><span class="legend-dot" style="background:{bg}"></span>'
            f'{e(label)} <strong>{count}</strong></span>'
        )

    # Build severity breakdown
    sev_rows = []
    for sev in ("high", "medium", "low"):
        if sev in stats["severity_counts"]:
            cat, color = sev_badge[sev]
            statuses = stats["severity_status"].get(sev, {})
            open_c = statuses.get(Status.OPEN, 0)
            naf_c = statuses.get(Status.NOT_A_FINDING, 0)
            na_c = statuses.get(Status.NOT_APPLICABLE, 0)
            nr_c = statuses.get(Status.NOT_REVIEWED, 0)
            total_sev = stats["severity_counts"][sev]
            sev_rows.append(
                f'<tr><td><span class="sev-badge" style="background:{color}">{cat}</span></td>'
                f'<td>{total_sev}</td><td class="c-open">{open_c}</td>'
                f'<td class="c-naf">{naf_c}</td><td class="c-na">{na_c}</td>'
                f'<td class="c-nr">{nr_c}</td></tr>'
            )

    # Build findings table rows
    finding_rows = []
    for v in data["vulns"]:
        vid = e(v.get("vid", ""))
        sev = v.get("severity", "medium").lower()
        cat_label, cat_color = sev_badge.get(sev, ("?", "#64748b"))
        st = v.get("status", Status.NOT_REVIEWED)
        st_label, st_bg, st_fg = badge.get(st, (st, "#94a3b8", "#fff"))
        title = e(v.get("rule_title", "")[:120])
        finding = e(v.get("finding", "")) or "No finding details provided."
        comment = e(v.get("comment", "")) or "No comments provided."
        
        row_cls = f'status-{st_label.lower().replace("_","")}'
        
        finding_rows.append(
            f'<tr class="{row_cls} main-row" onclick="toggleDetails(\'{vid}\')" style="cursor:pointer">'
            f'<td class="vid"><span class="expander" id="exp-{vid}">&#9654;</span> {vid}</td>'
            f'<td><span class="sev-badge" style="background:{cat_color}">{cat_label}</span></td>'
            f'<td><span class="status-badge" style="background:{st_bg};color:{st_fg}">{st_label}</span></td>'
            f'<td class="title">{title}</td></tr>'
        )
        finding_rows.append(
            f'<tr id="details-{vid}" class="details-row {row_cls}" style="display:none;">'
            f'<td colspan="4">'
            f'<div class="details-content">'
            f'<div class="detail-block"><strong>Finding Details:</strong><pre>{finding}</pre></div>'
            f'<div class="detail-block"><strong>Comments:</strong><pre>{comment}</pre></div>'
            f'</div></td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STIG Compliance Report — {e(data['asset'])}</title>
<meta name="description" content="STIG compliance report for {e(data['asset'])} generated by {APP_NAME} v{VERSION}">
<style>
:root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #f1f5f9; --text2: #94a3b8; --accent: #3b82f6;
    --border: #475569; --radius: 12px;
}}
[data-theme="light"] {{
    --bg: #f1f5f9; --surface: #fff; --surface2: #e2e8f0;
    --text: #0f172a; --text2: #64748b; --border: #cbd5e1;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    min-height: 100vh;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }}
header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid var(--border); padding: 1.5rem 0;
}}
[data-theme="light"] header {{
    background: linear-gradient(135deg, #fff 0%, #f1f5f9 100%);
}}
.header-inner {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
h1 {{ font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }}
h1 span {{ color: var(--accent); }}
.meta {{ color: var(--text2); font-size: 0.85rem; }}
.theme-toggle {{
    background: var(--surface2); border: 1px solid var(--border); color: var(--text);
    padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem;
}}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; margin: 2rem 0; }}
.card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1.5rem; transition: box-shadow 0.2s;
}}
.card:hover {{ box-shadow: 0 4px 24px rgba(0,0,0,0.15); }}
.card h2 {{ font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text2); margin-bottom: 1rem; }}
.stat-big {{ font-size: 2.5rem; font-weight: 800; letter-spacing: -0.03em; }}
.stat-sub {{ color: var(--text2); font-size: 0.85rem; }}
.donut-chart {{ width: 120px; height: 120px; margin: 0 auto; display: block; }}
.donut-pct {{ font-size: 18px; font-weight: 800; fill: var(--text); }}
.donut-pct.good {{ fill: #22c55e; }} .donut-pct.warn {{ fill: #f59e0b; }} .donut-pct.bad {{ fill: #ef4444; }}
.donut-label {{ font-size: 9px; fill: var(--text2); }}
.legend {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1rem; justify-content: center; }}
.legend-item {{ display: flex; align-items: center; gap: 0.35rem; font-size: 0.8rem; color: var(--text2); }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
.sev-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
.sev-table th {{ text-align: left; color: var(--text2); padding: 0.5rem; font-weight: 600; border-bottom: 1px solid var(--border); }}
.sev-table td {{ padding: 0.5rem; border-bottom: 1px solid var(--border); }}
.sev-badge {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-weight: 700; font-size: 0.75rem; }}
.status-badge {{ padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; white-space: nowrap; }}
.c-open {{ color: #ef4444; font-weight: 700; }} .c-naf {{ color: #22c55e; }} .c-na {{ color: var(--text2); }} .c-nr {{ color: #f59e0b; }}
.findings {{ margin-top: 2rem; }}
.findings h2 {{ font-size: 1.1rem; margin-bottom: 1rem; }}
.filter-bar {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }}
.filter-btn {{
    background: var(--surface2); border: 1px solid var(--border); color: var(--text);
    padding: 0.3rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem;
}}
.filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.findings-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
.findings-table th {{
    text-align: left; padding: 0.6rem 0.5rem; color: var(--text2); font-weight: 600;
    border-bottom: 2px solid var(--border); position: sticky; top: 0; background: var(--surface);
}}
.findings-table td {{ padding: 0.5rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
.findings-table .vid {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.82rem; white-space: nowrap; }}
.findings-table .title {{ max-width: 500px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.findings-table tr.main-row:hover {{ background: var(--surface2); }}
.expander {{ font-size: 0.7rem; color: var(--text2); display: inline-block; width: 12px; transition: transform 0.2s; }}
.details-row td {{ background: var(--surface2); border-bottom: 2px solid var(--border); padding: 0; }}
.details-content {{ padding: 1rem 1.5rem; background: var(--bg); border: 1px inset var(--border); border-radius: 4px; margin: 0.5rem; display: flex; flex-direction: column; gap: 1rem; }}
.detail-block strong {{ color: var(--accent); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 0.4rem; }}
.detail-block pre {{ font-family: 'Segoe UI', system-ui, sans-serif; font-size: 0.85rem; white-space: pre-wrap; word-wrap: break-word; color: var(--text); padding-left: 0.5rem; border-left: 2px solid var(--border); margin: 0; }}
footer {{ text-align: center; padding: 2rem 0; color: var(--text2); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
@media print {{
    body {{ background: #fff; color: #000; }}
    .theme-toggle, .filter-bar {{ display: none; }}
    .card {{ border: 1px solid #ccc; box-shadow: none; }}
    header {{ background: none; border-bottom: 2px solid #000; }}
}}
@media (max-width: 640px) {{ .container {{ padding: 1rem; }} .cards {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
<div class="container header-inner">
    <div>
        <h1><span>⛊</span> STIG Compliance Report</h1>
        <div class="meta">{e(data['asset'])} &middot; {e(data['title'])} &middot; v{e(data['version'])} &middot; {e(data['release'])}</div>
    </div>
    <button class="theme-toggle" onclick="toggleTheme()">☀ / ☽</button>
</div>
</header>

<main class="container">
<div class="cards">
    <div class="card">
        <h2>Compliance Score</h2>
        {_svg_donut(stats)}
        <div class="legend">{''.join(legend_items)}</div>
    </div>
    <div class="card">
        <h2>Summary</h2>
        <div class="stat-big">{stats['total']}</div>
        <div class="stat-sub">Total Controls</div>
        <div style="margin-top: 1rem">
            <div class="stat-sub">Reviewed: <strong>{stats['reviewed']}</strong> / {stats['total']} ({stats['reviewed_pct']:.0f}%)</div>
            <div class="stat-sub">Compliant: <strong>{stats['compliant']}</strong> / {stats['total']} ({stats['compliance_pct']:.1f}%)</div>
            <div class="stat-sub">Open Findings: <strong class="c-open">{stats['status_counts'].get(Status.OPEN, 0)}</strong></div>
        </div>
    </div>
    <div class="card">
        <h2>By Severity</h2>
        <table class="sev-table">
            <tr><th>CAT</th><th>Total</th><th>Open</th><th>NaF</th><th>N/A</th><th>NR</th></tr>
            {''.join(sev_rows)}
        </table>
    </div>
</div>

<div class="findings">
    <h2>All Findings ({stats['total']})</h2>
    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterRows('all')">All</button>
        <button class="filter-btn" onclick="filterRows('open')">Open</button>
        <button class="filter-btn" onclick="filterRows('notafinding')">Not A Finding</button>
        <button class="filter-btn" onclick="filterRows('not_reviewed')">Not Reviewed</button>
        <button class="filter-btn" onclick="filterRows('not_applicable')">N/A</button>
        <input type="text" id="searchInput" class="search-input" placeholder="Search VIDs or Rule Titles..." onkeyup="searchTable()">
    </div>
    <div style="overflow-x: auto; border-radius: var(--radius); border: 1px solid var(--border);">
    <table class="findings-table" id="findingsTable">
        <thead><tr>
            <th onclick="sortTable(0)">VID &#x21D5;</th>
            <th onclick="sortTable(1)">Severity &#x21D5;</th>
            <th onclick="sortTable(2)">Status &#x21D5;</th>
            <th onclick="sortTable(3)">Rule Title &#x21D5;</th>
        </tr></thead>
        <tbody>
        {''.join(finding_rows)}
        </tbody>
    </table>
    </div>
</div>
</main>

<footer>
    <div class="container">
        Generated by {APP_NAME} v{VERSION} on {now} &middot; Source: {e(data['source'])}
    </div>
</footer>

<script>
function toggleTheme() {{
    const html = document.documentElement;
    html.dataset.theme = html.dataset.theme === 'dark' ? 'light' : 'dark';
}}

function toggleDetails(vid) {{
    let detailsRow = document.getElementById('details-' + vid);
    let expander = document.getElementById('exp-' + vid);
    if(detailsRow.style.display === 'none') {{
        detailsRow.style.display = '';
        expander.innerHTML = '&#9660;';
    }} else {{
        detailsRow.style.display = 'none';
        expander.innerHTML = '&#9654;';
    }}
}}

function filterRows(status) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    
    document.getElementById('searchInput').value = '';
    
    document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
        if(row.classList.contains('details-row')) {{
            row.style.display = 'none'; // Always hide details on filter change
            return;
        }}
        
        let exp = row.querySelector('.expander');
        if(exp) exp.innerHTML = '&#9654;';
        
        if (status === 'all') {{ 
            row.style.display = ''; 
            return; 
        }}
        
        row.style.display = row.classList.contains('status-' + status) ? '' : 'none';
    }});
}}

function searchTable() {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.filter-btn').classList.add('active'); // Reset to ALL
    
    let input = document.getElementById("searchInput").value.toUpperCase();
    let mainRows = document.querySelectorAll("#findingsTable .main-row");
    
    mainRows.forEach(row => {{
        let tdVid = row.getElementsByTagName("td")[0];
        let tdTitle = row.getElementsByTagName("td")[3];
        
        let detailsRow = row.nextElementSibling;
        if(detailsRow && detailsRow.classList.contains('details-row')) {{
            detailsRow.style.display = 'none';
        }}
        
        let exp = row.querySelector('.expander');
        if(exp) exp.innerHTML = '&#9654;';
        
        let txtVid = tdVid ? (tdVid.textContent || tdVid.innerText) : "";
        let txtTitle = tdTitle ? (tdTitle.textContent || tdTitle.innerText) : "";
        
        if (txtVid.toUpperCase().indexOf(input) > -1 || txtTitle.toUpperCase().indexOf(input) > -1) {{
            row.style.display = "";
        }} else {{
            row.style.display = "none";
        }}
    }});
}}

let sortAsc = false;
function sortTable(n) {{
    let table = document.getElementById("findingsTable");
    let tbody = table.querySelector("tbody");
    let rows, switching, i, x, y, shouldSwitch;
    switching = true;
    sortAsc = !sortAsc;
    
    while (switching) {{
        switching = false;
        rows = tbody.querySelectorAll(".main-row");
        for (i = 0; i < (rows.length - 1); i++) {{
            shouldSwitch = false;
            x = rows[i].getElementsByTagName("td")[n];
            y = rows[i + 1].getElementsByTagName("td")[n];
            
            if(!x || !y) continue;
            
            let cmpX = x.innerHTML.toLowerCase().replace(/<[^>]+>/g, '').trim();
            let cmpY = y.innerHTML.toLowerCase().replace(/<[^>]+>/g, '').trim();
            
            if (sortAsc) {{
                if (cmpX > cmpY) {{ shouldSwitch = true; break; }}
            }} else {{
                if (cmpX < cmpY) {{ shouldSwitch = true; break; }}
            }}
        }}
        if (shouldSwitch) {{
            let r1 = rows[i];
            let r1_det = (r1.nextElementSibling && r1.nextElementSibling.classList.contains('details-row')) ? r1.nextElementSibling : null;
            let r2 = rows[i + 1];
            let r2_det = (r2.nextElementSibling && r2.nextElementSibling.classList.contains('details-row')) ? r2.nextElementSibling : null;
            
            if (r2_det) {{
                tbody.insertBefore(r1, r2_det.nextSibling);
            }} else {{
                tbody.insertBefore(r1, r2.nextSibling);
            }}
            
            if(r1_det) {{
                tbody.insertBefore(r1_det, r1.nextSibling);
            }}
            
            switching = true;
        }}
    }}
    }}
}}
</script>
</body>
</html>"""


def generate_html_report(
    ckl_path: Union[str, Path],
    output_path: Union[str, Path],
) -> Path:
    """Generate a self-contained HTML compliance report from a CKL/CKLB file.

    Args:
        ckl_path: Path to the input CKL or CKLB checklist file.
        output_path: Path for the generated HTML report.

    Returns:
        Path to the generated HTML report.

    Raises:
        FileError: If the input file cannot be read.
        ParseError: If the checklist cannot be parsed.
    """
    from stig_assessor.xml.sanitizer import San

    ckl_path = San.path(ckl_path, exist=True, file=True)
    output_path = San.path(output_path, mkpar=True)

    data = _parse_checklist(ckl_path)
    stats = _compute_stats(data["vulns"])
    html_content = _build_html(data, stats)

    with FO.atomic(output_path, mode="w", enc="utf-8", bak=False) as f:
        f.write(html_content)

    return output_path

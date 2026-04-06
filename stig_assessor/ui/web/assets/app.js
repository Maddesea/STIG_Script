/**
 * STIG Assessor — Air-Gapped Web Client v2.0
 * Sidebar navigation layout. Zero external dependencies.
 *
 * Maps to the sidebar nav-item[data-panel] → section.panel#panel-{name}
 * architecture chosen by the user.
 */
'use strict';

/* ═══════════════════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════════════════ */

function toBase64(file) {
    return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result.split(',')[1]);
        r.onerror = reject;
        r.readAsDataURL(file);
    });
}

function downloadB64(b64, filename) {
    const bytes = atob(b64);
    const arr = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
    const blob = new Blob([arr]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
}

function downloadText(text, filename, mime = 'text/csv') {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
}

function showToast(msg, type = 'info') {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => { t.style.animation = 'fadeOut .3s ease forwards'; setTimeout(() => t.remove(), 300); }, 4000);
}

function statBox(val, label, color = 'info') {
    return `<div class="stat-box"><div class="num ${color}">${val}</div><div class="lbl">${label}</div></div>`;
}


/* ═══════════════════════════════════════════════════════════════════
   API LAYER
   ═══════════════════════════════════════════════════════════════════ */

async function postApi(url, payload, btn) {
    if (btn) btn.disabled = true;
    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (data.status === 'error') showToast(data.message || 'API Error', 'error');
        return data;
    } catch (err) {
        showToast(`Network error: ${err.message}`, 'error');
        return { status: 'error', message: err.message };
    } finally {
        if (btn) btn.disabled = false;
    }
}


/* ═══════════════════════════════════════════════════════════════════
   NAVIGATION — Sidebar panel switching
   ═══════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    // Sidebar nav
    const navItems = document.querySelectorAll('.nav-item[data-panel]');
    const panels = document.querySelectorAll('.panel');
    const headerTitle = document.getElementById('header-title');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            item.classList.add('active');
            const target = document.getElementById('panel-' + item.dataset.panel);
            if (target) target.classList.add('active');
            if (headerTitle) headerTitle.textContent = item.querySelector('span')?.textContent || '';
        });
    });

    // Hamburger
    document.getElementById('hamburger-btn')?.addEventListener('click', () => {
        document.getElementById('sidebar')?.classList.toggle('open');
    });

    // Theme
    document.getElementById('theme-toggle')?.addEventListener('click', () => {
        const h = document.documentElement;
        h.setAttribute('data-theme', h.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
    });

    // Modal close
    document.getElementById('modal-close')?.addEventListener('click', () => {
        document.getElementById('result-modal')?.classList.add('hidden');
    });

    // Init all features
    initDropZones();
    wireGenerate();
    wireExtract();
    wireRemediate();
    wireMerge();
    wireAnalytics();
    wireDashboard();
    wireDiff();
    wireDrift();
    wireEvidence();
    wireBoilerplates();
    wireValidate();
    wireRepair();
    wireApiDocs();
});


/* ═══════════════════════════════════════════════════════════════════
   UNIVERSAL DROP ZONE WIRING
   ═══════════════════════════════════════════════════════════════════ */

function initDZ(zoneId, inputId, labelId, onReady) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    if (!zone || !input) return;

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault(); zone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            showLabel(labelId, e.dataTransfer.files);
            if (onReady) onReady(e.dataTransfer.files);
        }
    });
    input.addEventListener('change', () => {
        showLabel(labelId, input.files);
        if (onReady && input.files.length) onReady(input.files);
    });
}

function showLabel(id, files) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = Array.from(files).map(f => f.name).join(', ');
}

function initDropZones() {
    // Generate
    initDZ('gen-upload-zone', 'gen-xccdf-file', 'gen-file-label', () => {
        const btn = document.getElementById('gen-submit'); if (btn) btn.disabled = false;
    });
    // Extract
    initDZ('ext-upload-zone', 'ext-xccdf-file', 'ext-file-label', () => {
        const btn = document.getElementById('ext-submit'); if (btn) btn.disabled = false;
    });
    // Remediate
    initDZ('rem-ckl-zone', 'rem-ckl-file', 'rem-ckl-label', checkRemReady);
    initDZ('rem-json-zone', 'rem-json-file', 'rem-json-label', checkRemReady);
    // Merge
    initDZ('merge-base-zone', 'merge-base-file', 'merge-base-label', checkMergeReady);
    initDZ('merge-hist-zone', 'merge-hist-files', 'merge-hist-label', checkMergeReady);
    // Analytics
    initDZ('analytics-upload-zone', 'analytics-ckl-file', 'analytics-file-label');
    // Dashboard
    initDZ('dash-upload-zone', 'dash-ckl-file', 'dash-file-label');
    // Diff
    initDZ('diff-ckl1-zone', 'diff-ckl1-file', 'diff-ckl1-label', checkDiffReady);
    initDZ('diff-ckl2-zone', 'diff-ckl2-file', 'diff-ckl2-label', checkDiffReady);
    // Track
    initDZ('track-upload-zone', 'track-ckl-file', 'track-file-label', () => {
        const btn = document.getElementById('track-submit'); if (btn) btn.disabled = false;
    });
    // Evidence
    initDZ('ev-upload-zone', 'ev-file', 'ev-file-label', () => {
        const btn = document.getElementById('ev-import-btn'); if (btn) btn.disabled = false;
    });
    // Validate
    initDZ('val-upload-zone', 'val-ckl-file', 'val-file-label', () => {
        const btn = document.getElementById('val-submit'); if (btn) btn.disabled = false;
    });
    // Repair
    initDZ('repair-upload-zone', 'repair-ckl-file', 'repair-file-label', () => {
        const btn = document.getElementById('repair-submit'); if (btn) btn.disabled = false;
    });
}

function checkRemReady() {
    const btn = document.getElementById('rem-submit');
    if (btn) btn.disabled = !(document.getElementById('rem-ckl-file')?.files?.length && document.getElementById('rem-json-file')?.files?.length);
}
function checkMergeReady() {
    const btn = document.getElementById('merge-submit');
    if (btn) btn.disabled = !(document.getElementById('merge-base-file')?.files?.length && document.getElementById('merge-hist-files')?.files?.length);
}
function checkDiffReady() {
    const btn = document.getElementById('diff-submit');
    if (btn) btn.disabled = !(document.getElementById('diff-ckl1-file')?.files?.length && document.getElementById('diff-ckl2-file')?.files?.length);
}


/* ═══════════════════════════════════════════════════════════════════
   RESULT MODAL
   ═══════════════════════════════════════════════════════════════════ */

function showModal(title, message, statsHtml, b64, filename, errors) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;

    const statsEl = document.getElementById('modal-stats');
    const gridEl = document.getElementById('modal-stats-grid');
    if (statsHtml) { statsEl.classList.remove('hidden'); gridEl.innerHTML = statsHtml; }
    else { statsEl.classList.add('hidden'); }

    const errEl = document.getElementById('modal-errors');
    if (errors?.length) { errEl.classList.remove('hidden'); errEl.textContent = errors.join('\n'); }
    else { errEl.classList.add('hidden'); }

    const actions = document.getElementById('modal-actions');
    actions.innerHTML = '';
    if (b64 && filename) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-success';
        btn.textContent = 'Download ' + filename;
        btn.onclick = () => downloadB64(b64, filename);
        actions.appendChild(btn);
    }

    document.getElementById('result-modal').classList.remove('hidden');
}


/* ═══════════════════════════════════════════════════════════════════
   GENERATE CKL
   ═══════════════════════════════════════════════════════════════════ */

function wireGenerate() {
    document.getElementById('gen-submit')?.addEventListener('click', async () => {
        const file = document.getElementById('gen-xccdf-file')?.files[0];
        const asset = document.getElementById('gen-asset')?.value?.trim();
        if (!file) { showToast('Upload an XCCDF XML first.', 'error'); return; }
        if (!asset) { showToast('Asset name is required.', 'error'); return; }

        const btn = document.getElementById('gen-submit');
        showToast('Converting XCCDF…', 'info');
        const res = await postApi('/api/v1/xccdf_to_ckl', {
            xccdf_b64: await toBase64(file),
            filename: file.name,
            asset,
            ip: document.getElementById('gen-ip')?.value || '',
            mac: document.getElementById('gen-mac')?.value || '',
            role: 'None',
        }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            showModal('CKL Generated', res.message || 'Success',
                statBox(d.processed||0,'Processed','success') + statBox(d.skipped||0,'Skipped','danger') + statBox(d.total||0,'Total','info'),
                d.ckl_b64, d.filename, d.errors);
            showToast('CKL generated!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   EXTRACT FIXES
   ═══════════════════════════════════════════════════════════════════ */

function wireExtract() {
    document.getElementById('ext-submit')?.addEventListener('click', async () => {
        const file = document.getElementById('ext-xccdf-file')?.files[0];
        if (!file) { showToast('Upload an XCCDF first.', 'error'); return; }

        const btn = document.getElementById('ext-submit');
        showToast('Extracting fixes…', 'info');
        const res = await postApi('/api/v1/extract', {
            b64_content: await toBase64(file),
            filename: file.name,
            enable_rollbacks: document.getElementById('ext-rollbacks')?.checked || false,
            do_ansible: document.getElementById('ext-ansible')?.checked !== false,
        }, btn);

        if (res.status === 'success') {
            const s = res.stats || {};
            showModal('Fixes Extracted', 'Remediation package ready.',
                statBox(s.total_fixes||0,'Fixes','success') + statBox(s.total_vulns||0,'Vulns','info'),
                res.package_b64, res.filename);
            showToast('Extraction complete!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   APPLY RESULTS (REMEDIATE)
   ═══════════════════════════════════════════════════════════════════ */

function wireRemediate() {
    document.getElementById('rem-submit')?.addEventListener('click', async () => {
        const cklFile = document.getElementById('rem-ckl-file')?.files[0];
        const jsonFile = document.getElementById('rem-json-file')?.files[0];
        if (!cklFile || !jsonFile) return;

        const btn = document.getElementById('rem-submit');
        showToast('Applying results…', 'info');
        const res = await postApi('/api/v1/apply_results', {
            ckl_b64: await toBase64(cklFile),
            results_b64: await toBase64(jsonFile),
            results_filename: jsonFile.name,
            filename: cklFile.name,
            details_mode: document.getElementById('rem-details-mode')?.value || 'prepend',
            comment_mode: document.getElementById('rem-comment-mode')?.value || 'prepend',
        }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            showModal('Results Applied', res.message || 'Done',
                statBox(d.updated||0,'Updated','success') + statBox(d.not_found?.length||0,'Not Found','warn'),
                d.ckl_b64, d.filename);
            showToast('Remediation applied!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   MERGE
   ═══════════════════════════════════════════════════════════════════ */

function wireMerge() {
    document.getElementById('merge-submit')?.addEventListener('click', async () => {
        const base = document.getElementById('merge-base-file')?.files[0];
        const hists = document.getElementById('merge-hist-files')?.files;
        if (!base || !hists?.length) return;

        const btn = document.getElementById('merge-submit');
        showToast('Merging…', 'info');
        const histB64 = [];
        for (const f of hists) histB64.push(await toBase64(f));

        const res = await postApi('/api/v1/merge_ckls', {
            base_b64: await toBase64(base),
            histories_b64: histB64,
            filename: base.name.replace('.ckl', '_merged.ckl'),
            preserve_history: document.getElementById('merge-preserve')?.checked !== false,
        }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            showModal('Merge Complete', res.message || 'Done',
                statBox(d.processed||0,'Total','info') + statBox(d.updated||0,'Updated','success') + statBox(d.skipped||0,'Unchanged','warn'),
                d.ckl_b64, d.filename);
            showToast('Merge complete!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   ANALYTICS
   ═══════════════════════════════════════════════════════════════════ */

let _analyticsData = [];

function wireAnalytics() {
    document.getElementById('analytics-ckl-file')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        showToast('Analyzing CKL…', 'info');
        const res = await postApi('/api/v1/stats', { ckl_b64: await toBase64(file) });

        if (res.status === 'success') {
            const s = res.stats_data;
            const counts = s.status_counts || {};
            const details = s.findings_details || [];
            _analyticsData = details;

            document.getElementById('analytics-results')?.classList.remove('hidden');

            // Stats
            document.getElementById('analytics-stats-grid').innerHTML =
                statBox(s.total_vulns || 0, 'Total Vulns', 'info') +
                statBox(counts.Open || 0, 'Open', 'danger') +
                statBox(counts.NotAFinding || 0, 'Not a Finding', 'success') +
                statBox(counts.Not_Applicable || 0, 'N/A', 'info') +
                statBox(counts.Not_Reviewed || 0, 'Not Reviewed', 'warn') +
                statBox((s.compliance_pct || 0).toFixed(1) + '%', 'Compliance', 'success') +
                statBox((s.completion_pct || 0).toFixed(1) + '%', 'Completion', 'info');

            // Severity chart
            const bySev = s.by_severity || {};
            drawDonut('analytics-severity-chart', bySev);

            // Status × Severity matrix
            const matrix = s.by_status_and_severity || {};
            renderMatrix('analytics-matrix', matrix);

            // Table
            renderAnalyticsTable(details);

            // Search
            const search = document.getElementById('analytics-search');
            if (search) search.oninput = () => renderAnalyticsTable(details, search.value);

            showToast('Analytics loaded!', 'success');
        }
    });
}

function renderAnalyticsTable(details, filter = '') {
    const tbody = document.getElementById('analytics-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const lc = filter.toLowerCase();
    details.forEach(f => {
        if (filter && !(f.vid||'').toLowerCase().includes(lc) && !(f.rule_title||'').toLowerCase().includes(lc)) return;
        const tr = document.createElement('tr');
        const sevClass = f.severity === 'high' ? 'fail' : f.severity === 'low' ? 'na' : 'nr';
        const statusClass = f.status === 'Open' ? 'fail' : f.status === 'NotAFinding' ? 'pass' : f.status === 'Not_Applicable' ? 'na' : 'nr';
        tr.innerHTML = `
            <td><strong>${f.vid}</strong></td>
            <td><span class="badge-${f.status === 'Open' ? 'Open' : f.status}">${f.status}</span></td>
            <td><span class="badge-sev-${f.severity || 'medium'}">${f.severity || 'medium'}</span></td>
            <td title="${(f.rule_title||'').replace(/"/g,'&quot;')}">${(f.rule_title||'').substring(0,80)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderMatrix(containerId, matrix) {
    const el = document.getElementById(containerId);
    if (!el || !Object.keys(matrix).length) { if (el) el.innerHTML = '<p style="color:var(--tx-muted);padding:12px;">No data</p>'; return; }
    let html = '<table class="data-table" style="width:100%;"><thead><tr><th>Status</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>';
    for (const [status, sevs] of Object.entries(matrix)) {
        html += `<tr><td>${status}</td><td>${sevs.high||0}</td><td>${sevs.medium||0}</td><td>${sevs.low||0}</td></tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
}


/* ═══════════════════════════════════════════════════════════════════
   DASHBOARD
   ═══════════════════════════════════════════════════════════════════ */

function wireDashboard() {
    document.getElementById('dash-ckl-file')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        showToast('Building dashboard…', 'info');
        const res = await postApi('/api/v1/stats', { ckl_b64: await toBase64(file) });

        if (res.status === 'success') {
            const s = res.stats_data;
            const counts = s.status_counts || {};

            document.getElementById('dash-results')?.classList.remove('hidden');

            document.getElementById('dash-stats-grid').innerHTML =
                statBox(s.total_vulns||0, 'Total Vulns', 'info') +
                statBox(counts.Open||0, 'Open', 'danger') +
                statBox(counts.NotAFinding||0, 'Compliant', 'success') +
                statBox((s.compliance_pct||0).toFixed(1)+'%', 'Compliance', 'success') +
                statBox((s.completion_pct||0).toFixed(1)+'%', 'Completion', 'info');

            drawDonut('dash-donut-chart', s.by_severity || {});
            drawBarChart('dash-bar-chart', counts);
            showToast('Dashboard ready!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   SVG CHARTS — Bar + Donut (pure inline SVG, zero deps)
   ═══════════════════════════════════════════════════════════════════ */

function drawBarChart(containerId, statusCounts) {
    const c = document.getElementById(containerId);
    if (!c) return;
    const colors = { Open:'#f85149', NotAFinding:'#3fb950', Not_Applicable:'#7d8590', Not_Reviewed:'#d29922' };
    const labels = { Open:'Open', NotAFinding:'Pass', Not_Applicable:'N/A', Not_Reviewed:'NR' };
    const keys = Object.keys(colors);
    const max = Math.max(1, ...keys.map(k => statusCounts[k]||0));
    const w=400, h=200, pad=45, barW=60, gap=20;
    const startX = (w - keys.length*(barW+gap))/2 + gap/2;
    let svg = `<svg viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:100%;">`;
    svg += `<line x1="${pad}" y1="${h-pad}" x2="${w-10}" y2="${h-pad}" stroke="rgba(255,255,255,.1)" stroke-width="1"/>`;
    keys.forEach((k,i) => {
        const v = statusCounts[k]||0;
        const bH = Math.max(3, (v/max)*(h-pad*2));
        const x = startX + i*(barW+gap), y = h-pad-bH;
        svg += `<rect x="${x}" y="${y}" width="${barW}" height="${bH}" rx="5" fill="${colors[k]}" opacity=".85"><animate attributeName="height" from="0" to="${bH}" dur=".6s" fill="freeze"/><animate attributeName="y" from="${h-pad}" to="${y}" dur=".6s" fill="freeze"/></rect>`;
        svg += `<text x="${x+barW/2}" y="${y-6}" text-anchor="middle" fill="white" font-size="13" font-weight="600">${v}</text>`;
        svg += `<text x="${x+barW/2}" y="${h-pad+16}" text-anchor="middle" fill="rgba(255,255,255,.5)" font-size="10">${labels[k]}</text>`;
    });
    svg += '</svg>';
    c.innerHTML = svg;
}

function drawDonut(containerId, bySeverity) {
    const c = document.getElementById(containerId);
    if (!c) return;
    const data = [
        { label:'CAT I', value: bySeverity.high||0, color:'#f85149' },
        { label:'CAT II', value: bySeverity.medium||0, color:'#d29922' },
        { label:'CAT III', value: bySeverity.low||0, color:'#58a6ff' },
    ];
    const total = data.reduce((s,d) => s+d.value, 0) || 1;
    const cx=100, cy=90, r=70, ir=45;
    let svg = `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:100%;">`;
    let cum = -Math.PI/2;
    data.forEach(d => {
        if (d.value <= 0) { cum += 0; return; }
        const a = (d.value/total)*2*Math.PI;
        const x1=cx+r*Math.cos(cum), y1=cy+r*Math.sin(cum);
        const x2=cx+r*Math.cos(cum+a), y2=cy+r*Math.sin(cum+a);
        const ix1=cx+ir*Math.cos(cum+a), iy1=cy+ir*Math.sin(cum+a);
        const ix2=cx+ir*Math.cos(cum), iy2=cy+ir*Math.sin(cum);
        const la = a>Math.PI?1:0;
        svg += `<path d="M${x1},${y1} A${r},${r} 0 ${la},1 ${x2},${y2} L${ix1},${iy1} A${ir},${ir} 0 ${la},0 ${ix2},${iy2} Z" fill="${d.color}" opacity=".85"/>`;
        cum += a;
    });
    svg += `<text x="${cx}" y="${cy-4}" text-anchor="middle" fill="white" font-size="20" font-weight="700">${total}</text>`;
    svg += `<text x="${cx}" y="${cy+13}" text-anchor="middle" fill="rgba(255,255,255,.4)" font-size="10">TOTAL</text>`;
    data.forEach((d,i) => {
        const lx = 10 + i*68;
        svg += `<rect x="${lx}" y="185" width="10" height="10" rx="2" fill="${d.color}"/>`;
        svg += `<text x="${lx+14}" y="194" fill="rgba(255,255,255,.6)" font-size="9">${d.label}: ${d.value}</text>`;
    });
    svg += '</svg>';
    c.innerHTML = svg;
}


/* ═══════════════════════════════════════════════════════════════════
   DIFF / COMPARE
   ═══════════════════════════════════════════════════════════════════ */

function wireDiff() {
    document.getElementById('diff-submit')?.addEventListener('click', async () => {
        const f1 = document.getElementById('diff-ckl1-file')?.files[0];
        const f2 = document.getElementById('diff-ckl2-file')?.files[0];
        if (!f1 || !f2) return;

        const btn = document.getElementById('diff-submit');
        showToast('Comparing…', 'info');
        const res = await postApi('/api/v1/diff', {
            ckl1_b64: await toBase64(f1), ckl2_b64: await toBase64(f2),
        }, btn);

        if (res.status === 'success') {
            const d = res.diff_data || {};
            const s = d.summary || {};
            document.getElementById('diff-results')?.classList.remove('hidden');

            document.getElementById('diff-stats-grid').innerHTML =
                statBox(d.total_vulnerabilities||s.total_in_baseline||0, 'Baseline', 'info') +
                statBox(d.changes_count||s.changed||0, 'Changed', 'danger') +
                statBox(d.unchanged_count||s.unchanged||0, 'Unchanged', 'success') +
                statBox(d.only_in_baseline_count||s.only_in_baseline||0, 'Only Base', 'warn');

            // Changed detail table
            const tbody = document.getElementById('diff-tbody');
            if (tbody) {
                tbody.innerHTML = '';
                (d.changed || []).forEach(ch => {
                    (ch.differences || []).forEach(df => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `<td>${ch.vid}</td><td>${df.field}</td><td>${df.from||df.from_length||''}</td><td>${df.to||df.to_length||''}</td>`;
                        tbody.appendChild(tr);
                    });
                });
            }
            showToast('Diff complete!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   DRIFT & HISTORY
   ═══════════════════════════════════════════════════════════════════ */

function wireDrift() {
    // Ingest
    document.getElementById('track-submit')?.addEventListener('click', async () => {
        const file = document.getElementById('track-ckl-file')?.files[0];
        if (!file) return;
        const btn = document.getElementById('track-submit');
        showToast('Ingesting CKL…', 'info');
        const res = await postApi('/api/v1/track_ckl', { ckl_b64: await toBase64(file) }, btn);
        if (res.status === 'success') showToast(res.message || 'Tracked!', 'success');
    });

    // Drift query
    document.getElementById('drift-submit')?.addEventListener('click', async () => {
        const asset = document.getElementById('drift-asset')?.value?.trim();
        if (!asset) { showToast('Enter an asset name.', 'error'); return; }
        const btn = document.getElementById('drift-submit');
        showToast('Computing drift…', 'info');
        const res = await postApi('/api/v1/show_drift', { asset_name: asset }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            document.getElementById('drift-results')?.classList.remove('hidden');
            document.getElementById('drift-stats-grid').innerHTML =
                statBox(d.fixed?.length||0, 'Fixed', 'success') +
                statBox(d.regressed?.length||0, 'Regressed', 'danger') +
                statBox(d.changed?.length||0, 'Changed', 'warn') +
                statBox(d.new?.length||0, 'New', 'info');
            showToast('Drift analysis done!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   EVIDENCE
   ═══════════════════════════════════════════════════════════════════ */

function wireEvidence() {
    document.getElementById('ev-import-btn')?.addEventListener('click', async () => {
        const file = document.getElementById('ev-file')?.files[0];
        const vid = document.getElementById('ev-vid')?.value?.trim();
        if (!file || !vid) { showToast('VID and file are required.', 'error'); return; }

        showToast('Uploading evidence…', 'info');
        const res = await postApi('/api/v1/evidence/import', {
            vid, filename: file.name,
            description: document.getElementById('ev-desc')?.value || '',
            category: document.getElementById('ev-cat')?.value || 'general',
            content_b64: await toBase64(file),
        });
        if (res.status === 'success') showToast(`Evidence imported for ${vid}!`, 'success');
    });

    document.getElementById('ev-package-btn')?.addEventListener('click', async () => {
        showToast('Packaging…', 'info');
        const res = await postApi('/api/v1/evidence/package', {});
        if (res.status === 'success') {
            downloadB64(res.data?.package_b64 || res.package_b64, 'evidence_package.zip');
            showToast('Evidence packaged!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   BOILERPLATES
   ═══════════════════════════════════════════════════════════════════ */

let _bpData = {}, _selectedVid = null;

function wireBoilerplates() {
    loadBpList();
    document.getElementById('bp-save-btn')?.addEventListener('click', async () => {
        const vid = document.getElementById('bp-vid')?.value?.trim();
        if (!vid) { showToast('VID required.', 'error'); return; }
        const res = await postApi('/api/v1/bp_set', {
            vid,
            status: document.getElementById('bp-status')?.value,
            finding: document.getElementById('bp-finding')?.value || '',
            comment: document.getElementById('bp-comment')?.value || '',
        });
        if (res.status === 'success') { showToast('Saved!', 'success'); loadBpList(); }
    });

    document.getElementById('bp-delete-btn')?.addEventListener('click', async () => {
        const vid = document.getElementById('bp-vid')?.value?.trim();
        if (!vid) return;
        const res = await postApi('/api/v1/bp_delete', { vid, status: document.getElementById('bp-status')?.value });
        if (res.status === 'success') { showToast('Deleted.', 'success'); loadBpList(); }
    });

    document.getElementById('bp-search')?.addEventListener('input', (e) => {
        const f = e.target.value.toLowerCase();
        document.querySelectorAll('#bp-list li').forEach(li => {
            li.style.display = li.textContent.toLowerCase().includes(f) ? '' : 'none';
        });
    });
}

async function loadBpList() {
    const res = await postApi('/api/v1/bp_list', {});
    if (res.status !== 'success') return;
    _bpData = res.data || {};
    const list = document.getElementById('bp-list');
    if (!list) return;
    list.innerHTML = '';
    Object.keys(_bpData).sort().forEach(vid => {
        const li = document.createElement('li');
        li.textContent = vid;
        li.addEventListener('click', () => {
            list.querySelectorAll('li').forEach(l => l.classList.remove('active'));
            li.classList.add('active');
            _selectedVid = vid;
            document.getElementById('bp-vid').value = vid;
            document.getElementById('bp-editor-title').textContent = vid;
            const statuses = _bpData[vid] || {};
            const first = Object.keys(statuses)[0] || 'NotAFinding';
            document.getElementById('bp-status').value = first;
            const entry = statuses[first] || {};
            document.getElementById('bp-finding').value = entry.finding || '';
            document.getElementById('bp-comment').value = entry.comment || '';
        });
        list.appendChild(li);
    });
}


/* ═══════════════════════════════════════════════════════════════════
   VALIDATE
   ═══════════════════════════════════════════════════════════════════ */

function wireValidate() {
    document.getElementById('val-submit')?.addEventListener('click', async () => {
        const file = document.getElementById('val-ckl-file')?.files[0];
        if (!file) return;
        const btn = document.getElementById('val-submit');
        showToast('Validating…', 'info');
        const res = await postApi('/api/v1/validate', { ckl_b64: await toBase64(file) }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            const el = document.getElementById('val-results');
            el?.classList.remove('hidden');

            let html = `<div class="card" style="margin-top:20px;"><div class="card-header"><h3>${d.valid ? '✓ Validation Passed' : '✗ Validation Failed'}</h3></div>`;
            html += `<div class="stats-grid">${statBox(d.error_count||0,'Errors','danger')}${statBox(d.warning_count||0,'Warnings','warn')}${statBox(d.info?.length||0,'Info','info')}</div>`;

            if (d.errors?.length) {
                html += '<div class="val-section val-errors"><h4>Errors</h4><ul>';
                d.errors.forEach(e => html += `<li>${e}</li>`);
                html += '</ul></div>';
            }
            if (d.warnings?.length) {
                html += '<div class="val-section val-warnings"><h4>Warnings</h4><ul>';
                d.warnings.forEach(w => html += `<li>${w}</li>`);
                html += '</ul></div>';
            }
            html += '</div>';
            if (el) el.innerHTML = html;
            showToast(d.valid ? 'Validation passed!' : 'Issues found.', d.valid ? 'success' : 'error');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   REPAIR
   ═══════════════════════════════════════════════════════════════════ */

function wireRepair() {
    document.getElementById('repair-submit')?.addEventListener('click', async () => {
        const file = document.getElementById('repair-ckl-file')?.files[0];
        if (!file) return;
        const btn = document.getElementById('repair-submit');
        showToast('Repairing…', 'info');
        const res = await postApi('/api/v1/repair', {
            ckl_b64: await toBase64(file), filename: file.name,
        }, btn);

        if (res.status === 'success') {
            const d = res.data || {};
            document.getElementById('repair-results')?.classList.remove('hidden');
            const log = document.getElementById('repair-log');
            if (log) {
                let html = `<p>${res.message}</p>`;
                if (d.details?.length) {
                    html += '<ul>';
                    d.details.forEach(det => html += `<li>${det}</li>`);
                    html += '</ul>';
                }
                log.innerHTML = html;
            }
            const dlBtn = document.getElementById('repair-download');
            if (dlBtn && d.ckl_b64) {
                dlBtn.classList.remove('hidden');
                dlBtn.onclick = () => downloadB64(d.ckl_b64, d.filename || 'repaired.ckl');
            }
            showToast('Repair complete!', 'success');
        }
    });
}


/* ═══════════════════════════════════════════════════════════════════
   API DOCS (auto-generated reference)
   ═══════════════════════════════════════════════════════════════════ */

function wireApiDocs() {
    const container = document.getElementById('api-docs-list');
    if (!container) return;
    const endpoints = [
        { path:'/api/v1/ping', desc:'Health check. Returns server status.' },
        { path:'/api/v1/xccdf_to_ckl', desc:'Convert XCCDF benchmark XML to CKL format. Params: xccdf_b64, filename, asset, ip, mac, role.' },
        { path:'/api/v1/apply_results', desc:'Apply remediation results to a CKL. Params: ckl_b64, results_b64, results_filename, filename, details_mode, comment_mode.' },
        { path:'/api/v1/merge_ckls', desc:'Merge multiple CKLs. Params: base_b64, histories_b64[], filename, preserve_history.' },
        { path:'/api/v1/extract', desc:'Extract fixes from XCCDF. Params: b64_content, filename, enable_rollbacks, do_ansible.' },
        { path:'/api/v1/diff', desc:'Compare two CKLs. Params: ckl1_b64, ckl2_b64.' },
        { path:'/api/v1/stats', desc:'Generate compliance stats from CKL. Params: ckl_b64.' },
        { path:'/api/v1/track_ckl', desc:'Ingest CKL into history DB. Params: ckl_b64.' },
        { path:'/api/v1/show_drift', desc:'Show drift for an asset. Params: asset_name.' },
        { path:'/api/v1/list_assets', desc:'List all tracked asset names. No params.' },
        { path:'/api/v1/validate', desc:'Validate CKL structure. Params: ckl_b64.' },
        { path:'/api/v1/repair', desc:'Repair broken CKL. Params: ckl_b64, filename.' },
        { path:'/api/v1/verify_integrity', desc:'Checksums and validation. Params: ckl_b64.' },
        { path:'/api/v1/bp_list', desc:'List all boilerplate templates. No params.' },
        { path:'/api/v1/bp_set', desc:'Save boilerplate. Params: vid, status, finding, comment.' },
        { path:'/api/v1/bp_delete', desc:'Delete boilerplate. Params: vid, status.' },
        { path:'/api/v1/evidence/summary', desc:'Evidence summary stats. No params.' },
        { path:'/api/v1/evidence/import', desc:'Import evidence file. Params: vid, filename, content_b64, description, category.' },
        { path:'/api/v1/evidence/package', desc:'Package all evidence as ZIP. No params.' },
    ];
    let html = '';
    endpoints.forEach(ep => {
        html += `<div class="card" style="margin-bottom:10px;padding:14px 18px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <code style="color:var(--ac-primary);font-size:.95rem;font-weight:600;">POST ${ep.path}</code>
            </div>
            <p style="margin:6px 0 0;color:var(--tx-muted);font-size:.88rem;">${ep.desc}</p>
        </div>`;
    });
    container.innerHTML = html;
}

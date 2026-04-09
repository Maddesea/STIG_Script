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
    
    let icon = 'ℹ️';
    if(type === 'success') icon = '✅';
    if(type === 'error') icon = '❌';
    if(type === 'warn') icon = '⚠️';
    
    t.innerHTML = `<div style="display:flex;align-items:center;gap:10px;">
        <span style="font-size:1.15rem;">${icon}</span>
        <span style="flex:1;">${msg}</span>
    </div>`;
    
    c.appendChild(t);
    setTimeout(() => { t.style.animation = 'fadeOut .4s cubic-bezier(0.16, 1, 0.3, 1) forwards'; setTimeout(() => t.remove(), 400); }, 4500);
}

function statBox(val, label, color = 'info') {
    return `<div class="stat-box"><div class="num ${color}">${val}</div><div class="lbl">${label}</div></div>`;
}


/* ═══════════════════════════════════════════════════════════════════
   LOADING OVERLAY
   ═══════════════════════════════════════════════════════════════════ */

function showLoading(msg = 'Processing…') {
    let overlay = document.getElementById('loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `<div class="loading-card"><div class="loading-spinner"></div><div class="loading-text" id="loading-text">${msg}</div></div>`;
        document.body.appendChild(overlay);
    }
    const txt = document.getElementById('loading-text');
    if (txt) txt.textContent = msg;
    overlay.classList.add('active');
}

function hideLoading() {
    document.getElementById('loading-overlay')?.classList.remove('active');
}


/* ═══════════════════════════════════════════════════════════════════
   API LAYER
   ═══════════════════════════════════════════════════════════════════ */

async function postApi(url, payload, btn, loadingMsg) {
    if (btn) btn.disabled = true;
    if (loadingMsg !== false) showLoading(loadingMsg || 'Processing…');
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
        hideLoading();
        if (btn) btn.disabled = false;
    }
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard!', 'success');
    } catch (err) {
        showToast('Failed to copy', 'error');
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
    const savedTheme = localStorage.getItem('theme-preference') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    document.getElementById('theme-toggle')?.addEventListener('click', () => {
        const h = document.documentElement;
        const newTheme = h.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        h.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme-preference', newTheme);
    });

    // Modal close
    document.getElementById('modal-close')?.addEventListener('click', () => {
        document.getElementById('result-modal')?.classList.add('hidden');
    });
    
    // A11y Keyboard Handlers
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            const el = document.activeElement;
            if (el && (el.classList.contains('nav-item') || el.classList.contains('upload-zone') || el.classList.contains('gs-step'))) {
                e.preventDefault();
                el.click();
            }
        }
    });

    // Mouse tracking for premium glassmorphism hover effect
    document.addEventListener('mousemove', e => {
        document.querySelectorAll('.card').forEach(card => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });

    // Init all features
    initDropZones();
    wireGenerate();
    wireExtract();
    wireRemediate();
    wireMerge();
    wireAnalytics();
    wireFleet();
    wireDashboard();
    wireDiff();
    wireDrift();
    wireEvidence();
    wireBoilerplates();
    wireValidate();
    wireRepair();
    wireBulkOps();
    wireAssessmentEditor();
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
    zone.addEventListener('dragleave', () => { setTimeout(() => zone.classList.remove('drag-over'), 50); });
    zone.addEventListener('drop', e => {
        e.preventDefault(); 
        zone.classList.remove('drag-over');
        zone.style.transform = 'scale(0.97)';
        setTimeout(() => zone.style.transform = '', 150);
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
    // Editor
    initDZ('editor-upload-zone', 'editor-ckl-file', 'editor-file-label');
}
    // Analytics & Fleet
    initDZ('analytics-upload-zone', 'analytics-ckl-file', 'analytics-file-label');
    initDZ('fleet-upload-zone', 'fleet-zip-file', 'fleet-file-label');
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
    // Bulk Ops
    initDZ('bulk-upload-zone', 'bulk-ckl-file', 'bulk-file-label', () => {
        const btn = document.getElementById('btn-run-bulk'); if (btn) btn.disabled = false;
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
            out_ext: document.getElementById('gen-out-ext')?.value || '.ckl',
            asset,
            ip: document.getElementById('gen-ip')?.value || '',
            mac: document.getElementById('gen-mac')?.value || '',
            role: 'None',
        }, btn, 'Converting XCCDF to CKL…');

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
        }, btn, 'Extracting remediation scripts…');

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
        }, btn, 'Applying remediation results…');

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
        }, btn, 'Merging checklists…');

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
            let debounceTimer;
            if (search) {
                search.oninput = () => {
                    clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(() => {
                        renderAnalyticsTable(details, search.value);
                    }, 300);
                };
            }

            // Export CSV
            const exportBtn = document.getElementById('analytics-export-csv');
            if (exportBtn) {
                exportBtn.onclick = () => {
                    if (!_analyticsData || !_analyticsData.length) return;
                    const headers = ['VID', 'Status', 'Severity', 'Rule Title'];
                    const rows = [headers.join(',')];
                    let currentData = _analyticsData;
                    const searchVal = search ? search.value.toLowerCase() : '';
                    if (searchVal) {
                        currentData = currentData.filter(f => (f.vid||'').toLowerCase().includes(searchVal) || (f.rule_title||'').toLowerCase().includes(searchVal));
                    }
                    currentData.forEach(d => {
                        const row = [d.vid, d.status, d.severity || 'medium', `"${(d.rule_title||'').replace(/"/g, '""')}"`];
                        rows.push(row.join(','));
                    });
                    downloadText(rows.join('\n'), 'analytics_export.csv', 'text/csv');
                };
            }

            // Export HTML
            const htmlBtn = document.getElementById('analytics-export-html');
            if (htmlBtn) {
                htmlBtn.onclick = () => {
                    if (!s.html_report) {
                        showToast('HTML report is not available for this checklist.', 'error');
                        return;
                    }
                    downloadText(s.html_report, 'compliance_report.html', 'text/html');
                };
            }

            // Export POAM
            const poamBtn = document.getElementById('analytics-export-poam');
            if (poamBtn) {
                poamBtn.onclick = async () => {
                    showToast('Generating POAM...', 'info');
                    const res = await postApi('/api/v1/export_poam', { ckl_b64: await toBase64(file), filename: file.name });
                    if (res.status === 'success' && res.data?.poam_b64) {
                        const dlWrap = document.createElement('a');
                        dlWrap.href = 'data:text/csv;base64,' + res.data.poam_b64;
                        dlWrap.download = res.data.filename || 'poam.csv';
                        dlWrap.click();
                        showToast('POAM Generated Successfully!', 'success');
                    }
                };
            }

            showToast('Analytics loaded!', 'success');
        }
    });
}

/* ═══════════════════════════════════════════════════════════════════
   FLEET DASHBOARD
   ═══════════════════════════════════════════════════════════════════ */

function wireFleet() {
    document.getElementById('fleet-zip-file')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        showToast('Analyzing Fleet ZIP…', 'info');
        document.getElementById('fleet-getting-started')?.classList.add('hidden');
        const res = await postApi('/api/v1/fleet_stats', { zip_b64: await toBase64(file) }, null, 'Processing Enclave Checklists...');

        if (res.status === 'success') {
            const f = res.fleet_data;
            document.getElementById('fleet-results')?.classList.remove('hidden');

            document.getElementById('fleet-top-stats').innerHTML =
                statBox(f.total_assets || 0, 'Total Assets', 'info') +
                statBox(f.total_vulns || 0, 'Total Vulns', 'info') +
                statBox(f.by_status?.Open || 0, 'Open Finds', 'danger') +
                statBox((f.compliance_pct || 0).toFixed(1) + '%', 'Fleet Compliance', 'success');

            drawDonut('fleet-donut-chart', f.by_severity || {});
            // Use the correct dictionary key here if it exists, otherwise pass empty.
            if (f.by_status_and_severity && Object.keys(f.by_status_and_severity).length > 0) {
               renderMatrix('fleet-matrix', f.by_status_and_severity || {});
            } else {
               document.getElementById('fleet-matrix').innerHTML = '<div class="sub-text" style="padding:24px;text-align:center;">Detailed status matrix not generated across batch contexts.</div>';
            }

            const tbody = document.getElementById('fleet-assets-tbody');
            if (tbody) {
                tbody.innerHTML = '';
                (f.asset_compliance || []).forEach(a => {
                    const tr = document.createElement('tr');
                    const compClass = a.compliance_pct > 90 ? 'pass' : a.compliance_pct > 70 ? 'warn' : 'fail';
                    tr.innerHTML = `
                        <td>${a.file}</td>
                        <td class="${compClass} font-bold">${a.compliance_pct.toFixed(1)}%</td>
                        <td>${a.compliant}</td>
                        <td>${a.reviewed}</td>
                        <td>${a.total}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            showToast('Fleet analytics loaded!', 'success');
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
    svg += `<defs><filter id="glowBar"><feGaussianBlur stdDeviation="2.5" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
    svg += `<line x1="${pad}" y1="${h-pad}" x2="${w-10}" y2="${h-pad}" stroke="rgba(255,255,255,.1)" stroke-width="1"/>`;
    keys.forEach((k,i) => {
        const v = statusCounts[k]||0;
        const bH = Math.max(3, (v/max)*(h-pad*2));
        const x = startX + i*(barW+gap), y = h-pad-bH;
        svg += `<rect x="${x}" y="${y}" width="${barW}" height="${bH}" rx="6" fill="${colors[k]}" opacity=".9" filter="url(#glowBar)"><title>${labels[k]}: ${v} vulnerability(ies)</title><animate attributeName="height" from="0" to="${bH}" dur=".8s" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1" fill="freeze"/><animate attributeName="y" from="${h-pad}" to="${y}" dur=".8s" calcMode="spline" keySplines="0.16 1 0.3 1" keyTimes="0;1" fill="freeze"/></rect>`;
        svg += `<text x="${x+barW/2}" y="${y-8}" text-anchor="middle" fill="white" font-size="14" font-weight="700">${v}</text>`;
        svg += `<text x="${x+barW/2}" y="${h-pad+16}" text-anchor="middle" fill="rgba(255,255,255,.6)" font-size="11" font-weight="500">${labels[k]}</text>`;
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
    svg += `<defs><filter id="glowDonut"><feGaussianBlur stdDeviation="1.5" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
    let cum = -Math.PI/2;
    data.forEach(d => {
        if (d.value <= 0) { cum += 0; return; }
        const a = (d.value/total)*2*Math.PI;
        const x1=cx+r*Math.cos(cum), y1=cy+r*Math.sin(cum);
        const x2=cx+r*Math.cos(cum+a), y2=cy+r*Math.sin(cum+a);
        const ix1=cx+ir*Math.cos(cum+a), iy1=cy+ir*Math.sin(cum+a);
        const ix2=cx+ir*Math.cos(cum), iy2=cy+ir*Math.sin(cum);
        const la = a>Math.PI?1:0;
        svg += `<path d="M${x1},${y1} A${r},${r} 0 ${la},1 ${x2},${y2} L${ix1},${iy1} A${ir},${ir} 0 ${la},0 ${ix2},${iy2} Z" fill="${d.color}" opacity="0.95" filter="url(#glowDonut)" stroke="var(--bg-surface)" stroke-width="2"><title>${d.label}: ${d.value} findings</title></path>`;
        cum += a;
    });
    svg += `<text x="${cx}" y="${cy-4}" text-anchor="middle" fill="white" font-size="22" font-weight="800">${total}</text>`;
    svg += `<text x="${cx}" y="${cy+14}" text-anchor="middle" fill="rgba(255,255,255,.5)" font-size="10" font-weight="600">TOTAL</text>`;
    data.forEach((d,i) => {
        const lx = 10 + i*68;
        svg += `<rect x="${lx}" y="186" width="10" height="10" rx="3" fill="${d.color}"/>`;
        svg += `<text x="${lx+15}" y="195" fill="rgba(255,255,255,.7)" font-size="10" font-weight="500">${d.label}: ${d.value}</text>`;
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
            const btnExport = document.getElementById('drift-export-csv');
            if (btnExport) {
                btnExport.onclick = () => {
                    const rows = ['VID,Category,From,To'];
                    Object.entries(d).forEach(([category, items]) => {
                        if (Array.isArray(items)) {
                            items.forEach(item => {
                                rows.push(`${item.vid},${category},${item.from || ''},${item.to || item.status || ''}`);
                            });
                        }
                    });
                    if (rows.length > 1) {
                        downloadText(rows.join('\n'), `drift_${asset}.csv`, 'text/csv');
                    } else {
                        showToast('No drift data to export', 'warn');
                    }
                };
            }

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

    // Save boilerplate
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

    // Delete boilerplate
    document.getElementById('bp-delete-btn')?.addEventListener('click', async () => {
        const vid = document.getElementById('bp-vid')?.value?.trim();
        if (!vid) return;
        if (!confirm(`Delete boilerplate for ${vid} / ${document.getElementById('bp-status')?.value}?`)) return;
        const res = await postApi('/api/v1/bp_delete', { vid, status: document.getElementById('bp-status')?.value });
        if (res.status === 'success') { showToast('Deleted.', 'success'); loadBpList(); }
    });

    // Status change → reload editor fields
    document.getElementById('bp-status')?.addEventListener('change', () => {
        if (!_selectedVid || !_bpData[_selectedVid]) return;
        const status = document.getElementById('bp-status').value;
        const entry = (_bpData[_selectedVid] || {})[status] || {};
        document.getElementById('bp-finding').value = entry.finding_details || '';
        document.getElementById('bp-comment').value = entry.comments || '';
    });

    // Search / filter
    document.getElementById('bp-search')?.addEventListener('input', (e) => {
        const f = e.target.value.toLowerCase();
        document.querySelectorAll('#bp-list li').forEach(li => {
            li.style.display = li.textContent.toLowerCase().includes(f) ? '' : 'none';
        });
    });

    // Add new VID
    document.getElementById('bp-add-vid-btn')?.addEventListener('click', () => {
        const vid = prompt('Enter Vulnerability ID (e.g. V-12345 or V-* for global):');
        if (!vid || !vid.trim()) return;
        const trimmed = vid.trim();
        // Auto-select the new VID in the editor
        document.getElementById('bp-vid').value = trimmed;
        document.getElementById('bp-editor-title').textContent = trimmed;
        document.getElementById('bp-finding').value = '';
        document.getElementById('bp-comment').value = '';
        document.getElementById('bp-status').value = 'NotAFinding';
        _selectedVid = trimmed;
        showToast(`Editing new VID: ${trimmed}. Set fields and click Save.`, 'info');
    });

    // Export boilerplates
    document.getElementById('bp-export-btn')?.addEventListener('click', async () => {
        showToast('Exporting boilerplates…', 'info');
        const res = await postApi('/api/v1/bp_export', {});
        if (res.status === 'success' && res.data?.bp_b64) {
            downloadB64(res.data.bp_b64, 'boilerplates.json');
            showToast('Boilerplates exported!', 'success');
        }
    });

    // Import boilerplates
    const bpImportInput = document.getElementById('bp-import-file');
    document.getElementById('bp-import-btn')?.addEventListener('click', () => {
        bpImportInput?.click();
    });
    bpImportInput?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        showToast('Importing boilerplates…', 'info');
        const res = await postApi('/api/v1/bp_import', {
            bp_b64: await toBase64(file),
        });
        if (res.status === 'success') {
            showToast(res.message || 'Imported!', 'success');
            loadBpList();
        }
        bpImportInput.value = ''; // Reset for re-import
    });

    // Reset to defaults
    document.getElementById('bp-reset-btn')?.addEventListener('click', async () => {
        if (!confirm('Reset ALL boilerplates to factory defaults? This cannot be undone.')) return;
        const res = await postApi('/api/v1/bp_reset', {});
        if (res.status === 'success') {
            showToast('Boilerplates reset to defaults.', 'success');
            loadBpList();
        }
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
        const statuses = Object.keys(_bpData[vid] || {});
        // Show VID name + status count badge
        li.innerHTML = `<span class="bp-vid-name">${vid}</span>` +
            `<span class="bp-status-count">${statuses.length}</span>`;
        li.title = `Statuses: ${statuses.join(', ') || 'none'}`;
        li.addEventListener('click', () => {
            list.querySelectorAll('li').forEach(l => l.classList.remove('active'));
            li.classList.add('active');
            _selectedVid = vid;
            document.getElementById('bp-vid').value = vid;
            document.getElementById('bp-editor-title').textContent = vid;
            const statusSel = document.getElementById('bp-status');
            // Pick the first available status, or keep current
            const first = statuses[0] || statusSel.value || 'NotAFinding';
            statusSel.value = first;
            const entry = (_bpData[vid] || {})[first] || {};
            document.getElementById('bp-finding').value = entry.finding_details || '';
            document.getElementById('bp-comment').value = entry.comments || '';
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
                    html += '<ul id="repair-log-list">';
                    d.details.forEach(det => html += `<li>${det}</li>`);
                    html += '</ul>';
                    html += `<div style="margin-top: 10px;"><button class="btn btn-ghost btn-sm" onclick="copyToClipboard(document.getElementById('repair-log-list').innerText)"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy Log to Clipboard</button></div>`;
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
        { path:'/api/v1/fleet_stats', desc:'Generate fleet compliance stats from a ZIP map of CKLs. Params: zip_b64.' },
        { path:'/api/v1/export_poam', desc:'Generate an eMASS-compatible POAM. Params: ckl_b64, filename.' },
        { path:'/api/v1/bulk_edit', desc:'Apply bulk changes to a checklist. Params: ckl_b64, filename, severity, regex_vid, new_status, new_comment, append_comment.' },
        { path:'/api/v1/bp_list', desc:'List all boilerplate templates. No params.' },
        { path:'/api/v1/bp_set', desc:'Save boilerplate. Params: vid, status, finding, comment.' },
        { path:'/api/v1/bp_delete', desc:'Delete boilerplate. Params: vid, status.' },
        { path:'/api/v1/bp_export', desc:'Export all boilerplates as base64 JSON. No params.' },
        { path:'/api/v1/bp_import', desc:'Import boilerplates from base64 JSON (merges). Params: bp_b64.' },
        { path:'/api/v1/bp_reset', desc:'Reset boilerplates to factory defaults. No params.' },
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

/* ═══════════════════════════════════════════════════════════════════
   BULK OPERATIONS
   ═══════════════════════════════════════════════════════════════════ */

function wireBulkOps() {
    let _bulkFile = null;
    let _bulkFileB64 = null;
    
    document.getElementById('bulk-ckl-file')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        _bulkFile = file;
        _bulkFileB64 = await toBase64(file);
        
        document.getElementById('bulk-file-label').textContent = file.name;
        document.getElementById('bulk-file-label').classList.remove('hidden');
        document.getElementById('bulk-form-card')?.classList.remove('hidden');
        document.getElementById('btn-run-bulk')?.classList.remove('hidden');
        document.getElementById('btn-dl-bulk')?.classList.add('hidden');
        showToast('Checklist loaded for bulk edit.', 'success');
    });
    
    document.getElementById('btn-run-bulk')?.addEventListener('click', async () => {
        if (!_bulkFileB64) return;
        
        const severity = document.getElementById('bulk-severity')?.value;
        const regex_vid = document.getElementById('bulk-regex')?.value;
        const new_status = document.getElementById('bulk-status')?.value;
        const new_comment = document.getElementById('bulk-comment')?.value;
        const append_comment = document.getElementById('bulk-append')?.checked;
        
        if (!new_status) {
            showToast('New Status is required!', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-run-bulk');
        showToast('Running Bulk Overrides...', 'info');
        
        const res = await postApi('/api/v1/bulk_edit', {
            ckl_b64: _bulkFileB64,
            filename: _bulkFile.name,
            severity,
            regex_vid,
            new_status,
            new_comment,
            append_comment
        }, btn, 'Executing Changes...');
        
        if (res.status === 'success') {
            document.getElementById('btn-run-bulk')?.classList.add('hidden');
            const dlBtn = document.getElementById('btn-dl-bulk');
            if (dlBtn) {
                dlBtn.classList.remove('hidden');
                dlBtn.onclick = () => {
                   const a = document.createElement('a');
                   a.href = 'data:application/xml;base64,' + res.data.ckl_b64;
                   a.download = res.data.filename;
                   a.click();
                };
            }
            showModal('Success', res.message, statBox(res.data.updates, 'Vulns modified', 'success'));
            showToast(res.message, 'success');
        }
    });
}

/* ═══════════════════════════════════════════════════════════════════
   ASSESSMENT EDITOR
   ═══════════════════════════════════════════════════════════════════ */

function wireAssessmentEditor() {
    let editorVisibleFile = null;
    let editorB64Str = null;
    let editorFindingsCache = [];
    let editorActiveVid = null;
    let editorDetailsPane = document.getElementById('editor-details-pane');
    let editorPlaceholder = document.getElementById('editor-placeholder');
    
    document.getElementById('editor-ckl-file')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        showToast('Loading Checklist details for editing...', 'info');
        
        editorVisibleFile = file;
        editorB64Str = await toBase64(file);
        
        const res = await postApi('/api/v1/stats', { ckl_b64: editorB64Str });
        if (res.status === 'success') {
            document.getElementById('editor-workspace').classList.remove('hidden');
            
            const stats = res.stats_data || {};
            editorFindingsCache = stats.findings_details || [];
            
            // Draw summary stats
            const counts = stats.status_counts || {};
            document.getElementById('editor-stats-grid').innerHTML =
                statBox(stats.total_vulns || 0, 'Total Vulns', 'info') +
                statBox(counts.Open || 0, 'Open', 'danger') +
                statBox(counts.NotAFinding || 0, 'Compliant', 'success') +
                statBox((stats.compliance_pct || 0).toFixed(1) + '%', 'Compliance', 'success');

            renderEditorVulnList();
            showToast('Checklist loaded successfully!', 'success');
        }
    });
    
    function renderEditorVulnList(filterText = '') {
        const ul = document.getElementById('editor-vuln-list');
        ul.innerHTML = '';
        
        const searchVal = filterText.toLowerCase();
        
        editorFindingsCache.forEach(vuln => {
            if (searchVal && !(vuln.vid||'').toLowerCase().includes(searchVal) && !(vuln.status||'').toLowerCase().includes(searchVal)) return;

            const li = document.createElement('li');
            li.className = 'vuln-list-item' + (editorActiveVid === vuln.vid ? ' active' : '');
            
            let statusClass = 'nr';
            if (vuln.status === 'Open') statusClass = 'fail';
            else if (vuln.status === 'NotAFinding') statusClass = 'pass';
            else if (vuln.status === 'Not_Applicable') statusClass = 'na';
            
            li.innerHTML = `
                <div class="vid-text">${vuln.vid}</div>
                <div class="status-indicator ${statusClass}" title="${vuln.status}"></div>
            `;
            
            li.addEventListener('click', () => {
                editorActiveVid = vuln.vid;
                renderEditorVulnList(document.getElementById('editor-search').value);
                
                // Show pane
                editorPlaceholder.classList.add('hidden');
                editorDetailsPane.classList.remove('hidden');
                
                // Populate pane
                document.getElementById('editor-vid-title').textContent = vuln.vid;
                document.getElementById('editor-rule-title').textContent = vuln.rule_title;
                document.getElementById('editor-check-content').textContent = vuln.check_content;
                document.getElementById('editor-fix-text').textContent = vuln.fix_text;
                
                document.getElementById('editor-status').value = vuln.status;
                document.getElementById('editor-finding-details').value = vuln.details || '';
                document.getElementById('editor-comments').value = vuln.comments || '';
                
                // Badge
                const badge = document.getElementById('editor-status-badge');
                badge.style.display = 'inline-block';
                badge.className = `status-badge badge-${vuln.status === 'Open' ? 'Open' : vuln.status}`;
                badge.textContent = vuln.status;
            });
            ul.appendChild(li);
        });
    }

    document.getElementById('editor-search')?.addEventListener('input', (e) => {
        renderEditorVulnList(e.target.value);
    });
    
    document.getElementById('editor-save-btn')?.addEventListener('click', async () => {
        if (!editorActiveVid || !editorB64Str) return;
        
        const newStatus = document.getElementById('editor-status').value;
        const newDetails = document.getElementById('editor-finding-details').value;
        const newComments = document.getElementById('editor-comments').value;
        const btn = document.getElementById('editor-save-btn');
        
        const res = await postApi('/api/v1/assess_update', {
            ckl_b64: editorB64Str,
            filename: editorVisibleFile.name,
            vid: editorActiveVid,
            status: newStatus,
            finding_details: newDetails,
            comments: newComments
        }, btn, `Saving ${editorActiveVid}...`);
        
        if (res.status === 'success') {
            editorB64Str = res.data.ckl_b64;
            const idx = editorFindingsCache.findIndex(v => v.vid === editorActiveVid);
            if (idx > -1) {
                editorFindingsCache[idx].status = newStatus;
                editorFindingsCache[idx].details = newDetails;
                editorFindingsCache[idx].comments = newComments;
            }
            
            showToast(`${editorActiveVid} saved!`, 'success');
            renderEditorVulnList(document.getElementById('editor-search').value);
            
            document.getElementById('editor-status-badge').className = `status-badge badge-${newStatus === 'Open' ? 'Open' : newStatus}`;
            document.getElementById('editor-status-badge').textContent = newStatus;
            
            document.getElementById('editor-download-btn')?.classList.add('btn-pulse');
            setTimeout(() => document.getElementById('editor-download-btn')?.classList.remove('btn-pulse'), 3000);
            
            // Allow caller to hook into post-save success
            return true;
        }
        return false;
    });

    // Keyboard Shortcuts
    document.addEventListener('keydown', async (e) => {
        // Ensure Editor is actually visible/loaded before intercepting
        if (!editorActiveVid || editorDetailsPane.classList.contains('hidden')) return;

        if (e.ctrlKey && e.key.toLowerCase() === 's') {
            e.preventDefault();
            
            if (e.shiftKey) {
                // Save & Next
                const success = await document.getElementById('editor-save-btn').click();
                const elList = document.querySelectorAll('#editor-vuln-list li');
                const currIdx = Array.from(elList).findIndex(li => li.classList.contains('active'));
                if (currIdx > -1 && currIdx < elList.length - 1) {
                    elList[currIdx + 1].click();
                    elList[currIdx + 1].scrollIntoView({ block: 'nearest' });
                }
            } else {
                // Just Save
                document.getElementById('editor-save-btn').click();
            }
        } else if (!e.ctrlKey && !e.shiftKey && !e.altKey && !e.metaKey) {
            // Traverse Vuln List if not inside a textarea
            if (e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'SELECT') {
                if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                    e.preventDefault();
                    const elList = document.querySelectorAll('#editor-vuln-list li');
                    const currIdx = Array.from(elList).findIndex(li => li.classList.contains('active'));
                    if (currIdx > -1) {
                        const nextIdx = e.key === 'ArrowDown' ? currIdx + 1 : currIdx - 1;
                        if (nextIdx >= 0 && nextIdx < elList.length) {
                            elList[nextIdx].click();
                            elList[nextIdx].scrollIntoView({ block: 'nearest' });
                        }
                    }
                }
            }
        }
    });

    document.getElementById('editor-download-btn')?.addEventListener('click', () => {
        if (!editorB64Str) return;
        downloadB64(editorB64Str, editorVisibleFile.name.replace('.ckl', '_edited.ckl'));
        showToast('Checklist Downloaded!', 'success');
    });
}

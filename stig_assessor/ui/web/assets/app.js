document.addEventListener('DOMContentLoaded', () => {

    // --- Tab Switching Logic ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all tabs and contents
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Set active
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // --- Theme Toggle Logic ---
    const themeBtn = document.getElementById('theme-toggle');
    themeBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        document.documentElement.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
    });

    // --- Toast Notifications ---
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'fadeOut 0.3s forwards';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }


    // --- Global Utility / Drag & Drop ---
    const toBase64 = file => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = error => reject(error);
    });

    function setupDropZone(dzId, inputId, multiple = false) {
        const dz = document.getElementById(dzId);
        const input = document.getElementById(inputId);
        const nameDisplay = dz.querySelector('.file-name');

        const stop = e => { e.preventDefault(); e.stopPropagation(); };
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => dz.addEventListener(evt, stop, false));

        ['dragenter', 'dragover'].forEach(evt => dz.addEventListener(evt, () => dz.classList.add('drag-over'), false));
        ['dragleave', 'drop'].forEach(evt => dz.addEventListener(evt, () => dz.classList.remove('drag-over'), false));

        dz.addEventListener('drop', e => {
            const dt = e.dataTransfer;
            input.files = dt.files;
            input.dispatchEvent(new Event('change'));
        });

        dz.addEventListener('click', () => input.click());

        input.addEventListener('change', () => {
            if (input.files.length > 0) {
                if (multiple) {
                    nameDisplay.textContent = `${input.files.length} files selected`;
                } else {
                    nameDisplay.textContent = input.files[0].name;
                }
                nameDisplay.classList.remove('hidden');
            } else {
                nameDisplay.classList.add('hidden');
            }
        });
    }

    // Initialize all drop zones
    setupDropZone('dz-generate', 'file-generate');
    setupDropZone('dz-rem-ckl', 'file-rem-ckl');
    setupDropZone('dz-rem-json', 'file-rem-json');
    setupDropZone('dz-merge-base', 'file-merge-base');
    setupDropZone('dz-merge-hist', 'file-merge-hist', true);
    setupDropZone('dz-extract', 'file-extract');
    setupDropZone('dz-diff-1', 'file-diff-1');
    setupDropZone('dz-diff-2', 'file-diff-2');
    setupDropZone('dz-analytics', 'file-analytics');
    setupDropZone('dz-evidence', 'file-evidence');
    setupDropZone('dz-dashboard', 'file-dashboard');
    setupDropZone('dz-track', 'file-track');

    // --- Modal Logic ---
    const modal = document.getElementById('results-modal');
    const closeModalBtn = document.getElementById('close-modal');
    const msgElement = document.getElementById('result-message');
    const errorConsole = document.getElementById('error-log');
    const statsContainer = document.getElementById('modal-stats');
    const downloadTrigger = document.getElementById('download-trigger');

    closeModalBtn.addEventListener('click', () => modal.classList.add('hidden'));

    function createStatBox(value, label, colorClass) {
        return `
            <div class="stat-box">
                <div class="num ${colorClass}">${value}</div>
                <div class="lbl">${label}</div>
            </div>
        `;
    }

    function spawnModal(title, msg, statsHtml, errors, filename, b64_ckl) {
        document.querySelector('.modal-header h3').textContent = title;
        msgElement.textContent = msg;
        statsContainer.innerHTML = statsHtml;

        if (errors && errors.length > 0) {
            errorConsole.classList.remove('hidden');
            errorConsole.innerHTML = '<strong>Notices:</strong><br>';
            errors.forEach(err => {
                const div = document.createElement('div');
                div.textContent = String(err);
                errorConsole.appendChild(div);
            });
        } else {
            errorConsole.classList.add('hidden');
        }

        downloadTrigger.href = `data:application/xml;base64,${b64_ckl}`;
        downloadTrigger.download = filename;

        modal.classList.remove('hidden');
    }


    // --- API Interactions ---
    async function postApi(endpoint, payload, btn, spinner) {
        btn.disabled = true;
        spinner.classList.remove('hidden');
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok || data.status !== 'success') {
                throw new Error(data.message || 'Server error');
            }
            return data;
        } catch (err) {
            showToast("Operation Failed: " + err.message, "error");
            throw err;
        } finally {
            btn.disabled = false;
            spinner.classList.add('hidden');
        }
    }


    // Tab 1: Generate Action
    document.getElementById('form-generate').addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = document.getElementById('file-generate').files[0];
        if (!file) return showToast("Select an XCCDF file!", "error");

        const ipEl = document.getElementById('gen-ip');
        const macEl = document.getElementById('gen-mac');
        
        // Simple Input Validation
        let fetchValid = true;
        [ipEl, macEl].forEach(el => {
            if (el.value && !/^[A-Za-z0-9.:\-]+$/.test(el.value)) {
                el.classList.add('invalid');
                fetchValid = false;
            } else {
                el.classList.remove('invalid');
            }
        });
        if (!fetchValid) return showToast("Invalid IP or MAC format.", "error");

        const payload = {
            content_b64: await toBase64(file),
            filename: file.name,
            asset: document.getElementById('gen-asset').value,
            ip: document.getElementById('gen-ip').value,
            mac: document.getElementById('gen-mac').value,
            role: document.getElementById('gen-role').value
        };

        const btn = document.querySelector('#form-generate button');
        const spinner = btn.querySelector('.spinner');
        
        try {
            const res = await postApi('/api/v1/xccdf_to_ckl', payload, btn, spinner);
            const stats = createStatBox(res.data.processed, "Vulns", "success") +
                          createStatBox(res.data.skipped, "Skipped", res.data.skipped > 0 ? "danger" : "info");
            spawnModal("Checklist Generated", res.message, stats, res.data.errors, res.data.filename, res.data.ckl_b64);
        } catch(e) {}
    });

    // Tab 2: Remediate Action
    document.getElementById('form-remediate').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fileCkl = document.getElementById('file-rem-ckl').files[0];
        const fileJson = document.getElementById('file-rem-json').files[0];
        if (!fileCkl || !fileJson) return showToast("Select both CKL and JSON mapped files!", "error");

        const payload = {
            ckl_b64: await toBase64(fileCkl),
            json_b64: await toBase64(fileJson),
            filename: fileCkl.name.replace(".ckl", "_updated.ckl"),
            details_mode: document.getElementById('rem-details-mode').value,
            comment_mode: document.getElementById('rem-comment-mode').value
        };

        const btn = document.querySelector('#form-remediate button');
        const spinner = btn.querySelector('.spinner');

        try {
            const res = await postApi('/api/v1/apply_results', payload, btn, spinner);
            const stats = createStatBox(res.data.imported, "Applied", "success") +
                          createStatBox(res.data.not_found, "Missing", res.data.not_found > 0 ? "danger" : "info");
            spawnModal("Remediations Applied", res.message, stats, [], res.data.filename, res.data.ckl_b64);
        } catch(e) {}
    });

    // Tab 3: Merge Action
    document.getElementById('form-merge').addEventListener('submit', async (e) => {
        e.preventDefault();
        const baseCkl = document.getElementById('file-merge-base').files[0];
        const histFiles = document.getElementById('file-merge-hist').files;
        if (!baseCkl || histFiles.length === 0) return showToast("Select base CKL and at least 1 history CKL.", "error");

        const histories = [];
        for (let i = 0; i < histFiles.length; i++) {
            histories.push(await toBase64(histFiles[i]));
        }

        const payload = {
            base_b64: await toBase64(baseCkl),
            histories_b64: histories,
            filename: baseCkl.name.replace(".ckl", "_merged.ckl"),
            preserve_history: document.getElementById('merge-preserve').checked
        };

        const btn = document.querySelector('#form-merge button');
        const spinner = btn.querySelector('.spinner');

        try {
            const res = await postApi('/api/v1/merge_ckls', payload, btn, spinner);
            const stats = createStatBox(res.data.processed, "Evaluated", "info") +
                          createStatBox(histFiles.length, "Files", "success");
            spawnModal("Master Merge Complete", res.message, stats, [], res.data.filename, res.data.ckl_b64);
        } catch(e) {}
    });

    // Extract Tab Support
    document.getElementById('form-extract')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = document.getElementById('file-extract').files[0];
        if (!file) return showToast("Select an XCCDF or CKL file to extract!", "error");

        const btn = document.querySelector('#form-extract button');
        const spinner = btn.querySelector('.spinner');
        
        try {
            const payload = {
                content_b64: await toBase64(file),
                filename: file.name,
                enable_rollbacks: document.getElementById('extract-rollbacks').checked,
                do_ansible: document.getElementById('extract-ansible').checked
            };
            
            const res = await postApi('/api/v1/extract', payload, btn, spinner);
            
            showToast("Remediations loop generated correctly! Downloading package...", "success");
            // Trigger zip download
            const link = document.createElement("a");
            link.href = `data:application/zip;base64,${res.package_b64}`;
            link.download = res.filename;
            link.click();
            
            // Stats overlay if desired
            if (res.stats) {
                const metricsText = `Extracted: ${res.stats.bash_scripts || 0} Bash, ${res.stats.ps_scripts || 0} PS1`;
                showToast(metricsText, "info");
            }

        } catch (e) {
            console.error(e);
        }
    });

    // Diff Tab Support
    document.getElementById('form-diff')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const file1 = document.getElementById('file-diff-1').files[0];
        const file2 = document.getElementById('file-diff-2').files[0];
        if (!file1 || !file2) return showToast("Select both checklists to compare", "error");

        const btn = document.querySelector('#form-diff button');
        const spinner = btn.querySelector('.spinner');

        try {
            const payload = {
                ckl1_b64: await toBase64(file1),
                ckl2_b64: await toBase64(file2)
            };
            
            const res = await postApi('/api/v1/diff', payload, btn, spinner);
            
            const diffResults = document.getElementById('diff-results');
            const diffMetrics = document.getElementById('diff-metrics');
            const diffCode = document.getElementById('diff-code');
            
            diffResults.classList.remove('hidden');
            
            const data = res.diff_data;
            diffMetrics.innerHTML = createStatBox(data.total_vulnerabilities || 0, "Total Vulns", "info") +
                                    createStatBox(data.changes_count || 0, "Changes", data.changes_count > 0 ? "warn" : "success");
            
            diffCode.textContent = data.formatted_text || JSON.stringify(data.differences, null, 2);
            showToast("Checklists successfully compared.", "success");
        } catch (e) {
            console.error(e);
        }
    });

    // --- Boilerplates Tab Logic ---
    let currentBpData = {};
    let currentBpVid = null;

    const bpVidList = document.getElementById('bp-vid-list');
    const bpStatusSelect = document.getElementById('bp-status-select');
    const bpFindingText = document.getElementById('bp-finding-text');
    const bpCommentText = document.getElementById('bp-comment-text');

    async function loadBoilerplates() {
        try {
            const response = await fetch('/api/v1/bp_list', { method: 'POST', body: '{}', headers: {'Content-Type': 'application/json'}});
            const data = await response.json();
            if (data.status === 'success') {
                currentBpData = data.data.boilerplates;
                renderBpList();
            }
        } catch (e) {
            console.error("Failed to load boilerplates", e);
        }
    }

    function renderBpList(filter = "") {
        bpVidList.innerHTML = '';
        let vids = Object.keys(currentBpData).sort();
        if (!vids.includes("V-*")) vids.unshift("V-*");
        else {
            vids = vids.filter(v => v !== "V-*");
            vids.unshift("V-*");
        }

        vids.forEach(vid => {
            if (filter && !vid.toLowerCase().includes(filter.toLowerCase())) return;
            const li = document.createElement('li');
            li.textContent = vid;
            if (vid === currentBpVid) li.classList.add('selected');
            li.addEventListener('click', () => {
                currentBpVid = vid;
                renderBpList(filter); // Update selection styling
                loadBpEditor();
            });
            bpVidList.appendChild(li);
        });
    }

    document.getElementById('bp-search').addEventListener('input', (e) => {
        renderBpList(e.target.value);
    });

    function loadBpEditor() {
        if (!currentBpVid) return;
        const status = bpStatusSelect.value;
        const entry = (currentBpData[currentBpVid] && currentBpData[currentBpVid][status]) || {};
        bpFindingText.value = entry.finding_details || '';
        bpCommentText.value = entry.comments || '';
    }

    bpStatusSelect.addEventListener('change', loadBpEditor);

    document.getElementById('btn-bp-add').addEventListener('click', () => {
        const check = prompt("Enter new STIG Check ID (e.g. V-12345):");
        if (check && check.trim()) {
            currentBpVid = check.trim();
            if (!currentBpData[currentBpVid]) currentBpData[currentBpVid] = {};
            document.getElementById('bp-search').value = '';
            renderBpList();
            loadBpEditor();
        }
    });

    document.getElementById('btn-bp-save').addEventListener('click', async () => {
        if (!currentBpVid) return showToast("Select a VID first", "error");
        const payload = {
            vid: currentBpVid,
            status: bpStatusSelect.value,
            finding: bpFindingText.value,
            comment: bpCommentText.value
        };
        const btn = document.getElementById('btn-bp-save');
        btn.textContent = "Saving...";
        try {
            await fetch('/api/v1/bp_set', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            await loadBoilerplates(); // Reload latest
            btn.textContent = "Saved ✓";
            showToast("Boilerplate saved successfully", "success");
            setTimeout(() => btn.textContent = "Save Boilerplate", 2000);
        } catch(e) {
            showToast("Save failed: " + e.message, "error");
            btn.textContent = "Save Boilerplate";
        }
    });

    document.getElementById('btn-bp-delete').addEventListener('click', async () => {
        if (!currentBpVid) return;
        if (!confirm(`Delete boilerplate for ${currentBpVid} / ${bpStatusSelect.value}?`)) return;
        
        try {
            await fetch('/api/v1/bp_delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vid: currentBpVid, status: bpStatusSelect.value })
            });
            await loadBoilerplates();
            loadBpEditor();
            showToast("Boilerplate deleted.", "success");
        } catch(e) {
            showToast("Delete failed.", "error");
        }
    });

    // Load data when tab becomes active
    document.querySelector('[data-target="tab-boilerplates"]').addEventListener('click', () => {
        loadBoilerplates();
    });

    // --- Dashboard Tab Logic (SVG Native Rendering) ---
    function drawBarChart(data) {
        const svgContainer = document.getElementById('svg-canvas');
        svgContainer.innerHTML = '';
        const ns = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(ns, "svg");
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', '100%');
        svg.setAttribute('viewBox', '0 0 800 400');
        
        const metrics = data.stats_data.status_counts;
        const total = Object.values(metrics).reduce((a,b)=>a+b, 0);
        if(total === 0) return;

        const colors = {
            'NotAFinding': '#10B981',
            'Open': '#EF4444',
            'Not_Applicable': '#9CA3AF',
            'Not_Reviewed': '#F59E0B'
        };

        const keys = ['NotAFinding', 'Open', 'Not_Applicable', 'Not_Reviewed'];
        const barWidth = 100;
        const gap = (800 - 4*barWidth) / 5;
        const maxH = 250;
        let currentX = gap;

        keys.forEach((k) => {
            const count = metrics[k] || 0;
            const h = total > 0 ? (count / total) * maxH : 0;
            
            // Bar Background
            const bgRect = document.createElementNS(ns, 'rect');
            bgRect.setAttribute('x', currentX);
            bgRect.setAttribute('y', 50);
            bgRect.setAttribute('width', barWidth);
            bgRect.setAttribute('height', maxH);
            bgRect.setAttribute('fill', 'var(--bg-glass)');
            bgRect.setAttribute('rx', '6');

            // Bar Foreground (animated via CSS ideally, static here)
            const rect = document.createElementNS(ns, 'rect');
            rect.setAttribute('x', currentX);
            rect.setAttribute('y', 50 + maxH - h);
            rect.setAttribute('width', barWidth);
            rect.setAttribute('height', h);
            rect.setAttribute('fill', colors[k]);
            rect.setAttribute('rx', '6');
            rect.setAttribute('class', 'svg-chart-bar');

            // Label
            const text = document.createElementNS(ns, 'text');
            text.setAttribute('x', currentX + barWidth/2);
            text.setAttribute('y', 50 + maxH + 30);
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('fill', 'currentColor');
            text.setAttribute('font-family', 'Outfit, sans-serif');
            text.setAttribute('font-size', '16');
            text.setAttribute('font-weight', '500');
            text.textContent = k.replace('_', ' ');
            
            // Value
            const val = document.createElementNS(ns, 'text');
            val.setAttribute('x', currentX + barWidth/2);
            val.setAttribute('y', 50 + maxH - h - 15);
            val.setAttribute('text-anchor', 'middle');
            val.setAttribute('fill', 'currentColor');
            val.setAttribute('font-family', 'Outfit, sans-serif');
            val.setAttribute('font-size', '24');
            val.setAttribute('font-weight', '700');
            val.textContent = count;

            svg.appendChild(bgRect);
            svg.appendChild(rect);
            svg.appendChild(text);
            svg.appendChild(val);
            
            currentX += barWidth + gap;
        });
        
        svgContainer.appendChild(svg);
        document.getElementById('svg-dashboard-container').classList.remove('hidden');
    }

    document.getElementById('file-dashboard')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        showToast("Generating Visual Dashboard...", "info");
        try {
            const b64 = await toBase64(file);
            const payload = { ckl_b64: b64 };
            const dummyBtn = document.createElement('button');
            const dummySpinner = document.createElement('div');
            
            const res = await postApi('/api/v1/stats', payload, dummyBtn, dummySpinner);
            
            if (res.status === 'success') {
                drawBarChart(res);
                showToast("Dashboard successfully rendered!", "success");
            }
        } catch (err) {
            showToast("Failed to construct dashboard: " + err.message, "error");
        }
    });

    // --- Analytics Tab Logic ---
    document.getElementById('file-analytics')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        showToast("Processing CKL via Backend API...", "info");
        try {
            const b64 = await toBase64(file);
            const payload = { ckl_b64: b64 };
            
            // Use dummy btn / spinner since there's no form submit for file change
            const dummyBtn = document.createElement('button');
            const dummySpinner = document.createElement('div');
            
            const res = await postApi('/api/v1/stats', payload, dummyBtn, dummySpinner);
            
            if (res.status === 'success') {
                const sData = res.stats_data;
                const metrics = sData.status_counts || {};
                const details = sData.findings_details || [];
                
                document.getElementById('analytics-dashboard').classList.remove('hidden');
            
                let statsHtml = '';
                ['Open', 'NotAFinding', 'Not_Applicable', 'Not_Reviewed'].forEach(key => {
                    let color = 'info';
                    if (key === 'NotAFinding') color = 'success';
                    else if (key === 'Open') color = 'danger';
                    else if (key === 'Not_Reviewed') color = 'warn'; 
                    statsHtml += createStatBox(metrics[key] || 0, key.replace('_', ' '), color);
                });
                document.getElementById('analytics-metrics').innerHTML = statsHtml;

                const tbody = document.getElementById('analytics-tbody');
                const renderTable = (filterText = '') => {
                    tbody.innerHTML = '';
                    details.forEach(f => {
                        if (filterText) {
                            const matchVid = (f.vid||"").toLowerCase().includes(filterText.toLowerCase());
                            const matchDet = (f.details||"").toLowerCase().includes(filterText.toLowerCase());
                            if (!matchVid && !matchDet) return;
                        }
                        const tr = document.createElement('tr');
                        
                        const textNode = document.createTextNode(f.details || 'No detail mapped');
                        const safeDetails = document.createElement('div');
                        safeDetails.appendChild(textNode);
                        let displayDet = safeDetails.innerHTML;
                        if (displayDet.length > 150) displayDet = displayDet.substring(0, 150) + '...';

                        const tdVid = document.createElement('td');
                        tdVid.style.fontFamily = 'monospace';
                        tdVid.style.fontWeight = '600';
                        tdVid.textContent = f.vid;

                        const tdStatus = document.createElement('td');
                        const badge = document.createElement('span');
                        badge.className = `status-badge-sm badge-${(f.status || '').replace(/[^\w-]/g, '')}`;
                        badge.textContent = (f.status || '').replace('_', ' ');
                        tdStatus.appendChild(badge);

                        const tdDet = document.createElement('td');
                        tdDet.style.fontSize = '0.9rem';
                        tdDet.style.color = 'var(--tx-muted)';
                        tdDet.textContent = displayDet;

                        tr.appendChild(tdVid);
                        tr.appendChild(tdStatus);
                        tr.appendChild(tdDet);
                        tbody.appendChild(tr);
                    });
                };
                
                renderTable();
                
                const searchEl = document.getElementById('analytics-search');
                const newSearchEl = searchEl.cloneNode(true);
                searchEl.parentNode.replaceChild(newSearchEl, searchEl);
                newSearchEl.addEventListener('input', (event) => renderTable(event.target.value));
                
                showToast("Analytics generated successfully via API!", "success");
            }

        } catch (err) {
            showToast("Failed to process file: " + err.message, "error");
        }
    });

    // --- Evidence Tab Logic ---
    document.querySelector('[data-target="tab-evidence"]').addEventListener('click', () => {
        loadEvidenceSummary();
    });

    async function loadEvidenceSummary() {
        try {
            const res = await fetch('/api/v1/evidence/summary', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.status === 'success') {
                const s = data.summary;
                let html = createStatBox(s.files, 'Total Files', 'info');
                html += createStatBox(s.vulnerabilities, 'Mapped VIDs', 'success');
                html += createStatBox(s.size_mb.toFixed(2) + ' MB', 'Storage Size', 'warn');
                document.getElementById('evidence-metrics').innerHTML = html;
            }
        } catch (e) {
            console.error("Failed to load evidence summary", e);
        }
    }

    document.getElementById('file-evidence').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const vidInput = document.getElementById('evid-vid');
        if (!vidInput.value.trim()) {
            showToast("Vulnerability ID is required before attaching evidence.", "error");
            e.target.value = "";
            return;
        }

        showToast("Uploading evidence...", "info");
        try {
            const b64 = await toBase64(file);
            const payload = {
                vid: vidInput.value.trim(),
                description: document.getElementById('evid-desc').value.trim(),
                category: document.getElementById('evid-cat').value.trim(),
                filename: file.name,
                content_b64: b64
            };
            
            const btn = document.createElement('button'); // dummy btn for postApi
            const spin = document.createElement('div');
            
            const result = await postApi('/api/v1/evidence/import', payload, btn, spin);
            if (result.status === 'success') {
                showToast(`Evidence successfully mapped to ${vidInput.value.trim()}`, 'success');
                loadEvidenceSummary();
            } else {
                showToast(`Upload failed: ${result.message}`, 'error');
            }
        } catch (err) {
            // postApi handles toast already, but we catch
        } finally {
            e.target.value = "";
            const dz = document.getElementById('dz-evidence');
            dz.classList.remove('dragover', 'has-file');
            dz.querySelector('.file-name').classList.add('hidden');
        }
    });

    document.getElementById('btn-export-evidence').addEventListener('click', async (e) => {
        const btn = e.target.closest('button');
        showToast("Packaging evidence, please wait...", "info");
        const origHtml = btn.innerHTML;
        btn.innerHTML = 'Packaging...';
        btn.disabled = true;
        try {
            const res = await fetch('/api/v1/evidence/package', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.status === 'success' && data.package_b64) {
                // Trigger download
                const link = document.createElement("a");
                link.href = `data:application/zip;base64,${data.package_b64}`;
                link.download = data.filename || "evidence_package.zip";
                link.click();
                showToast("Package downloaded successfully!", "success");
            } else {
                showToast("Failed to package evidence: " + (data.message || 'Unknown error'), "error");
            }
        } catch (err) {
            showToast("Package error: " + err.message, "error");
        } finally {
            btn.innerHTML = origHtml;
            btn.disabled = false;
        }
    });

    // --- Drift Analysis Tab Logic ---
    document.getElementById('file-track')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        showToast("Uploading checklist for history tracking...", "info");
        try {
            const b64 = await toBase64(file);
            const payload = { ckl_b64: b64 };
            const dummyBtn = document.createElement('button');
            const dummySpinner = document.createElement('div');
            
            const res = await postApi('/api/v1/track_ckl', payload, dummyBtn, dummySpinner);
            
            if (res.status === 'success') {
                showToast(`Checklist successfully tracked for asset: ${res.data.asset_name}`, "success");
            }
        } catch (err) {
            // postApi handles toast already
        } finally {
            e.target.value = "";
            const dz = document.getElementById('dz-track');
            dz.classList.remove('dragover', 'has-file');
            dz.querySelector('.file-name').classList.add('hidden');
        }
    });

    document.getElementById('form-drift')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const assetName = document.getElementById('drift-asset').value.trim();
        if (!assetName) return showToast("Asset Name is required", "error");

        const btn = document.querySelector('#form-drift button');
        const spinner = btn.querySelector('.spinner');

        try {
            const payload = { asset_name: assetName };
            const res = await postApi('/api/v1/show_drift', payload, btn, spinner);
            
            if (res.status === 'success') {
                const drift = res.data;
                document.getElementById('drift-results').classList.remove('hidden');
                
                let statsHtml = '';
                statsHtml += createStatBox(drift.fixed.length, 'Fixed', 'success');
                statsHtml += createStatBox(drift.regressed.length, 'Regressed', drift.regressed.length > 0 ? 'danger' : 'success');
                statsHtml += createStatBox(drift.changed.length, 'Changed', 'warn');
                statsHtml += createStatBox(drift.new.length, 'New', 'info');
                statsHtml += createStatBox(drift.removed.length, 'Removed', 'info');
                
                document.getElementById('drift-metrics').innerHTML = statsHtml;
                showToast(`Drift Analysis calculated for ${assetName}`, "success");
            }
        } catch (err) {
            // postApi handles toast already
        }
    });

});

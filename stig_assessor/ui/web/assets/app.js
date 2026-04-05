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
            alert("Operation Failed: " + err.message);
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
        if (!file) return alert("Select an XCCDF file!");

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
        if (!fileCkl || !fileJson) return alert("Select both CKL and JSON mapped files!");

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
        if (!baseCkl || histFiles.length === 0) return alert("Select base CKL and at least 1 history CKL.");

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

});

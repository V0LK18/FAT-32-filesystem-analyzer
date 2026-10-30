document.addEventListener('DOMContentLoaded', () => {
    const navItems = document.querySelectorAll('.nav-item');
    const tabViews = document.querySelectorAll('.tab-view');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');
    const selectedFilename = document.getElementById('selected-filename');
    const btnRun = document.getElementById('btn-run');
    const progressCard = document.getElementById('progress-card');
    const progressFill = document.getElementById('progress-fill');
    const progressPercent = document.getElementById('progress-percent');
    const processLog = document.getElementById('process-log');
    
    let currentFile = null;
    let activeJobId = null;

    // --- Navigation ---
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tabId = item.getAttribute('data-tab');
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            tabViews.forEach(v => v.classList.remove('active'));
            document.getElementById(`tab-${tabId}`).classList.add('active');
        });
    });

    // --- File Handling ---
    if (dropZone) {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]);
        });
    }
    if (fileInput) fileInput.addEventListener('change', (e) => { if(e.target.files.length) handleFileSelect(e.target.files[0]); });

    function handleFileSelect(file) {
        currentFile = file;
        selectedFilename.textContent = file.name;
        fileInfo.classList.remove('hidden');
        dropZone.classList.add('hidden');
        btnRun.disabled = false;
        log(`Selected: ${file.name}`);
    }

    // --- Execution ---
    if (btnRun) {
        btnRun.addEventListener('click', async () => {
            if (!currentFile) return;
            try {
                btnRun.disabled = true;
                progressCard.classList.remove('hidden');
                
                // Upload
                const formData = new FormData();
                formData.append('file', currentFile);
                const upRes = await fetch('/upload', { method: 'POST', body: formData });
                const upData = await upRes.json();
                
                log('Upload finished.');
                log('Starting analysis.');

                // Run
                const runRes = await fetch(`/run/${upData.filename}`, { method: 'POST' });
                if (!runRes.ok) throw new Error("Backend error");
                const runData = await runRes.json();

                activeJobId = runData.job_id;
                startPolling(activeJobId);
            } catch (e) {
                log(`Error: ${e.message}`, 'error');
                btnRun.disabled = false;
            }
        });
    }

    function startPolling(jobId) {
        const interval = setInterval(async () => {
            const res = await fetch(`/status/${jobId}`);
            const data = await res.json();

            if (data.status === 'completed') {
                clearInterval(interval);
                finishJob(jobId);
            } else if (data.status === 'failed') {
                clearInterval(interval);
                log(`Failed: ${data.error}`, 'error');
            } else if (data.progress) {
                progressFill.style.width = `${data.progress}%`;
                progressPercent.textContent = `${data.progress}%`;
            }
        }, 1000);
    }

    async function finishJob(jobId) {
        progressFill.style.width = '100%';
        progressPercent.textContent = '100%';
        log('Analysis finished.');
        
        await loadTimeline(jobId);
        await loadFiles(jobId);
        
        setTimeout(() => document.querySelector('[data-tab="files"]').click(), 1000);
    }

    async function loadTimeline(jobId) {
        const res = await fetch(`/timeline/${jobId}`);
        const data = await res.json();
        const tbody = document.getElementById('timeline-body');
        tbody.innerHTML = '';
        
        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No events found.</td></tr>';
            return;
        }

        data.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="mono" style="color: var(--accent);">${row.Date}</td>
                <td class="mono" style="color: #cbd5e1;">${row.Path}</td>
                <td>${row.Event}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    async function loadFiles(jobId) {
        const res = await fetch(`/files/${jobId}`);
        const files = await res.json();
        
        const recoveredGrid = document.getElementById('recovered-file-grid');
        const existingGrid = document.getElementById('existing-file-grid');
        
        recoveredGrid.innerHTML = ''; 
        existingGrid.innerHTML = '';
        
        if (!files.length) return;

        files.forEach(file => {
            const div = document.createElement('div');
            div.className = 'file-item';
            div.innerHTML = `
                <div class="file-top">
                    <i data-lucide="file" class="file-icon"></i>
                    <span class="file-name" title="${file.name}">${file.name}</span>
                </div>
                <div class="file-actions">
                    <span class="file-size">${(file.size/1024).toFixed(1)} KB</span>
                    <button class="btn-download" onclick="downloadFile('${jobId}', '${file.path}')">
                        <i data-lucide="download"></i>
                    </button>
                </div>
            `;
            
            if (file.category === 'recovered') recoveredGrid.appendChild(div);
            else existingGrid.appendChild(div);
        });
        
        // Re-init icons for new elements
        if (window.lucide) window.lucide.createIcons();
    }

    function log(msg, type = '') {
        const d = document.createElement('div');
        d.className = `log-entry ${type}`;
        d.textContent = `> ${msg}`;
        processLog.appendChild(d);
        processLog.scrollTop = processLog.scrollHeight;
    }

    // Expose download function globally for onclick
    window.downloadFile = (jobId, path) => {
        // Create a temporary link to trigger download
        const url = `/download/${jobId}?path=${encodeURIComponent(path)}`;
        const a = document.createElement('a');
        a.href = url;
        a.download = ''; // Browser detects filename from headers
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };
});
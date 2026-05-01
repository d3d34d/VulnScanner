document.addEventListener('DOMContentLoaded', () => {
    const targetInput = document.getElementById('target-url');
    const scanBtn = document.getElementById('scan-btn');
    const newScanBtn = document.getElementById('new-scan-btn');
    
    const inputGroup = document.querySelector('.input-group');
    const statusContainer = document.getElementById('status-container');
    const resultsContainer = document.getElementById('results-container');
    const progressFill = document.getElementById('progress-fill');
    const statusText = document.getElementById('status-text');

    let pollInterval;

    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) {
            targetInput.focus();
            return;
        }

        // UI Transitions
        inputGroup.classList.add('hidden');
        statusContainer.classList.remove('hidden');
        progressFill.style.width = '10%';
        statusText.textContent = 'Initializing Modules...';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });

            const data = await response.json();
            if (data.error) throw new Error(data.error);

            progressFill.style.width = '30%';
            statusText.textContent = 'Running Port Scan & Crawler...';

            // Poll for results
            pollInterval = setInterval(() => checkStatus(data.scan_id), 2000);
        } catch (error) {
            handleError(error);
        }
    });

    async function checkStatus(scanId) {
        try {
            const response = await fetch(`/api/scan/${scanId}`);
            const data = await response.json();

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                progressFill.style.width = '100%';
                statusText.textContent = 'Scan Complete!';
                
                setTimeout(() => {
                    displayResults(data.results);
                }, 500);
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                handleError(new Error(data.error));
            } else {
                // Faking progress for UX
                let currentW = parseInt(progressFill.style.width);
                if(currentW < 90) progressFill.style.width = (currentW + 5) + '%';
            }
        } catch (error) {
            clearInterval(pollInterval);
            handleError(error);
        }
    }

    function displayResults(results) {
        statusContainer.classList.add('hidden');
        resultsContainer.classList.remove('hidden');

        // Ports
        const portsList = document.getElementById('ports-list');
        portsList.innerHTML = '';
        if (results.open_ports && results.open_ports.length > 0) {
            results.open_ports.forEach(port => {
                const li = document.createElement('li');
                li.textContent = `Port ${port} is open`;
                portsList.appendChild(li);
            });
        } else {
            portsList.innerHTML = '<li class="empty-state">No open ports detected.</li>';
        }

        // Headers
        const headersList = document.getElementById('headers-list');
        headersList.innerHTML = '';
        if (results.security_headers && results.security_headers.missing && results.security_headers.missing.length > 0) {
            results.security_headers.missing.forEach(header => {
                const li = document.createElement('li');
                li.textContent = header;
                headersList.appendChild(li);
            });
        } else {
            headersList.innerHTML = '<li class="empty-state">No missing security headers detected.</li>';
        }

        // Vulnerabilities
        const vulnList = document.getElementById('vuln-list');
        vulnList.innerHTML = '';
        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            results.vulnerabilities.forEach(v => {
                const div = document.createElement('div');
                div.className = 'vuln-item';
                div.innerHTML = `
                    <div><strong>Type:</strong> ${v.type}</div>
                    <div><strong>URL:</strong> ${v.url}</div>
                    ${v.param ? `<div><strong>Parameter:</strong> ${v.param}</div>` : ''}
                    ${v.payload ? `<div><strong>Payload:</strong> ${v.payload}</div>` : ''}
                `;
                vulnList.appendChild(div);
            });
        } else {
            vulnList.innerHTML = '<div class="empty-state">No critical XSS or SQLi vulnerabilities identified.</div>';
        }
    }

    function handleError(error) {
        statusText.textContent = `Error: ${error.message}`;
        statusText.style.color = 'var(--danger)';
        document.querySelector('.radar').style.borderColor = 'var(--danger)';
        document.querySelector('.sweep').style.background = 'linear-gradient(90deg, transparent, var(--danger))';
        progressFill.style.background = 'var(--danger)';
        progressFill.style.boxShadow = '0 0 10px var(--danger)';
        
        setTimeout(() => resetUI(), 4000);
    }

    function resetUI() {
        resultsContainer.classList.add('hidden');
        statusContainer.classList.add('hidden');
        inputGroup.classList.remove('hidden');
        targetInput.value = '';
        
        // Reset styles
        statusText.style.color = 'var(--primary)';
        document.querySelector('.radar').style.borderColor = 'var(--primary-glow)';
        document.querySelector('.sweep').style.background = 'linear-gradient(90deg, transparent, var(--primary))';
        progressFill.style.background = 'var(--primary)';
        progressFill.style.boxShadow = '0 0 10px var(--primary)';
    }

    newScanBtn.addEventListener('click', resetUI);
});

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const btnScan = document.getElementById('btn-scan');
    const btnText = btnScan.querySelector('.btn-text');
    const spinner = btnScan.querySelector('.spinner');

    const resultsPanel = document.getElementById('results-panel');
    const liveLogs = document.getElementById('live-logs');
    const insightsDashboard = document.getElementById('insights-dashboard');

    // Metrics
    const valRaw = document.getElementById('val-raw');
    const valBlocked = document.getElementById('val-blocked');
    const valTime = document.getElementById('val-time');
    const valBypassed = document.getElementById('val-bypassed');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const repoUrl = document.getElementById('repo-url').value;
        const riskProfile = document.getElementById('risk-profile').value;

        if (!repoUrl) return;

        // Reset UI
        btnScan.disabled = true;
        btnText.textContent = 'Scanning...';
        spinner.classList.remove('hidden');

        resultsPanel.classList.remove('hidden');
        insightsDashboard.classList.add('hidden');
        liveLogs.innerHTML = '';

        appendLog(`[INIT] Starting contextual scan for ${repoUrl}`, 'info');
        appendLog(`[INIT] Applying Risk Profile: ${riskProfile.toUpperCase()}`, 'info');

        try {
            // 1. Send POST request to start Job
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repo_url: repoUrl, profile: riskProfile })
            });

            if (!res.ok) {
                const errText = await res.text();
                throw new Error(errText || 'Failed to initialize scan');
            }

            const data = await res.json();
            const jobId = data.job_id;

            // 2. Connect to SSE for live terminal feed
            const eventSource = new EventSource(`/api/scan/${jobId}/stream`);

            eventSource.onmessage = (event) => {
                const msg = JSON.parse(event.data);

                if (msg.type === 'log') {
                    appendLog(msg.text, msg.level);
                } else if (msg.type === 'complete') {
                    eventSource.close();
                    finishScan(msg.metrics);
                } else if (msg.type === 'error') {
                    eventSource.close();
                    appendLog(`[FATAL] ${msg.text}`, 'error');
                    resetBtn();
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                appendLog('[SYS] Connection to scan engine lost.', 'error');
                resetBtn();
            };

        } catch (err) {
            appendLog(`[ERROR] ${err.message}`, 'error');
            resetBtn();
        }
    });

    function appendLog(text, level = 'info') {
        const div = document.createElement('div');
        div.className = `log-line ${level}`;

        // Add timestamp
        const now = new Date();
        const time = now.toISOString().split('T')[1].substring(0, 8);
        div.textContent = `[${time}] ${text}`;

        liveLogs.appendChild(div);
        liveLogs.scrollTop = liveLogs.scrollHeight;
    }

    function resetBtn() {
        btnScan.disabled = false;
        btnText.textContent = 'Initialize Scan';
        spinner.classList.add('hidden');
    }

    function finishScan(metrics) {
        resetBtn();
        btnText.textContent = 'Scan New Repository';

        // Reveal dashboard
        insightsDashboard.classList.remove('hidden');

        // Animate numbers
        animateValue(valRaw, 0, metrics.raw_vulns, 1000);
        animateValue(valBlocked, 0, metrics.blocked_vulns, 1000);
        animateValue(valBypassed, 0, metrics.bypassed_vulns, 1000);

        // Assumes 1 hour saved per bypassed vulnerability triage
        animateValue(valTime, 0, metrics.bypassed_vulns, 1000, 'h');

        appendLog('[SYS] Scan complete. Insights generated.', 'success');
    }

    // Helper to animate numbers counting up
    function animateValue(obj, start, end, duration, suffix = '') {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start) + suffix;
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
});

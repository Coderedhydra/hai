class VulnerabilityScanner {
    constructor() {
        this.isScanning = false;
        this.progressModal = new bootstrap.Modal(document.getElementById('progress-modal'));
        this.init();
    }

    init() {
        this.bindEvents();
        this.updateStatus();
        setInterval(() => this.updateStatus(), 5000); // Update status every 5 seconds
    }

    bindEvents() {
        // Configuration form
        document.getElementById('config-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.configure();
        });

        // Ollama toggle
        document.getElementById('use-ollama').addEventListener('change', (e) => {
            this.toggleOllamaConfig(e.target.checked);
        });

        // Discover URLs button
        document.getElementById('discover-urls').addEventListener('click', () => {
            this.discoverUrls();
        });

        // Start scan button
        document.getElementById('start-scan').addEventListener('click', () => {
            this.startScan();
        });

        // Refresh results button
        document.getElementById('refresh-results').addEventListener('click', () => {
            this.loadResults();
        });
    }

    toggleOllamaConfig(useOllama) {
        const geminiConfig = document.getElementById('gemini-config');
        const ollamaConfig = document.getElementById('ollama-config');
        
        if (useOllama) {
            geminiConfig.style.display = 'none';
            ollamaConfig.style.display = 'block';
        } else {
            geminiConfig.style.display = 'block';
            ollamaConfig.style.display = 'none';
        }
    }

    async configure() {
        const targetUrl = document.getElementById('target-url').value;
        const apiKey = document.getElementById('api-key').value;
        const ollamaModel = document.getElementById('ollama-model').value;
        const useOllama = document.getElementById('use-ollama').checked;

        if (!targetUrl) {
            this.showAlert('Please enter a target URL', 'warning');
            return;
        }

        if (!useOllama && !apiKey) {
            this.showAlert('Please enter a Gemini API key or enable Ollama', 'warning');
            return;
        }

        try {
            const response = await fetch('/configure', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    api_key: apiKey,
                    ollama_model: ollamaModel,
                    use_ollama: useOllama
                })
            });

            if (response.ok) {
                this.showAlert('Configuration saved successfully!', 'success');
                this.updateStatusIndicator('configured', 'Configured');
            } else {
                this.showAlert('Failed to save configuration', 'danger');
            }
        } catch (error) {
            console.error('Configuration error:', error);
            this.showAlert('Error saving configuration', 'danger');
        }
    }

    async discoverUrls() {
        const button = document.getElementById('discover-urls');
        const originalText = button.innerHTML;
        
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Discovering...';
        button.disabled = true;

        try {
            const response = await fetch('/discover_urls', {
                method: 'POST'
            });

            const data = await response.json();
            
            if (response.ok) {
                this.displayUrls(data.urls);
                this.showAlert(`Discovered ${data.urls.length} URLs`, 'success');
            } else {
                this.showAlert(data.error || 'Failed to discover URLs', 'danger');
            }
        } catch (error) {
            console.error('URL discovery error:', error);
            this.showAlert('Error discovering URLs', 'danger');
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
        }
    }

    displayUrls(urls) {
        const urlsList = document.getElementById('urls-list');
        document.getElementById('urls-count').textContent = urls.length;
        
        if (urls.length === 0) {
            urlsList.innerHTML = '<div class="text-muted text-center">No URLs discovered</div>';
            return;
        }

        urlsList.innerHTML = urls.map(url => `
            <div class="url-item d-flex justify-content-between align-items-center">
                <span class="text-truncate" title="${url}">${url}</span>
                <span class="badge bg-secondary">Ready</span>
            </div>
        `).join('');
    }

    async startScan() {
        if (this.isScanning) {
            this.showAlert('Scan already in progress', 'info');
            return;
        }

        const scanTypes = this.getSelectedScanTypes();
        if (scanTypes.length === 0) {
            this.showAlert('Please select at least one vulnerability type', 'warning');
            return;
        }

        this.isScanning = true;
        this.showProgressModal();

        const button = document.getElementById('start-scan');
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        button.disabled = true;

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    scan_types: scanTypes
                })
            });

            if (response.ok) {
                this.updateStatusIndicator('scanning', 'Scanning...');
                this.monitorScanProgress();
            } else {
                const data = await response.json();
                this.showAlert(data.error || 'Failed to start scan', 'danger');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showAlert('Error starting scan', 'danger');
        } finally {
            setTimeout(() => {
                button.innerHTML = '<i class="fas fa-play"></i> Start Comprehensive Scan';
                button.disabled = false;
                this.isScanning = false;
                this.progressModal.hide();
            }, 30000); // Hide progress after 30 seconds
        }
    }

    getSelectedScanTypes() {
        const types = [];
        const checkboxes = [
            'sql-injection',
            'xss', 
            'lfi',
            'command-injection',
            'xxe'
        ];

        checkboxes.forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox && checkbox.checked) {
                types.push(id.replace('-', '_'));
            }
        });

        return types;
    }

    showProgressModal() {
        const progressText = document.getElementById('progress-text');
        progressText.textContent = 'Initializing comprehensive scan...';
        this.progressModal.show();

        // Simulate progress updates
        const messages = [
            'Discovering internal URLs...',
            'Generating LLM-powered payloads...',
            'Testing SQL injection vulnerabilities...',
            'Checking for XSS vulnerabilities...',
            'Scanning for file inclusion issues...',
            'Testing command injection...',
            'Analyzing XXE vulnerabilities...',
            'Finalizing scan results...'
        ];

        let messageIndex = 0;
        const interval = setInterval(() => {
            if (messageIndex < messages.length) {
                progressText.textContent = messages[messageIndex];
                messageIndex++;
            } else {
                clearInterval(interval);
                progressText.textContent = 'Scan completed! Loading results...';
            }
        }, 3000);
    }

    monitorScanProgress() {
        const interval = setInterval(() => {
            if (!this.isScanning) {
                clearInterval(interval);
                return;
            }
            
            this.updateStatus();
            this.loadResults();
        }, 2000);
    }

    async updateStatus() {
        try {
            const response = await fetch('/status');
            const data = await response.json();
            
            document.getElementById('urls-count').textContent = data.discovered_urls_count || 0;
            document.getElementById('vulns-count').textContent = data.vulnerabilities_found || 0;
            
            if (data.llm_configured) {
                this.updateStatusIndicator('ready', 'Ready');
            }
        } catch (error) {
            console.error('Status update error:', error);
        }
    }

    async loadResults() {
        try {
            const response = await fetch('/results');
            const data = await response.json();
            
            this.displayResults(data.results);
        } catch (error) {
            console.error('Results loading error:', error);
        }
    }

    displayResults(results) {
        const container = document.getElementById('results-container');
        document.getElementById('tests-count').textContent = results.length;
        
        if (results.length === 0) {
            container.innerHTML = '<div class="text-muted text-center">No scan results yet</div>';
            return;
        }

        // Count vulnerabilities
        const vulnerabilities = results.filter(r => r.is_vulnerable);
        document.getElementById('vulns-count').textContent = vulnerabilities.length;

        // Group results by vulnerability type
        const grouped = this.groupResultsByType(results);
        
        container.innerHTML = Object.entries(grouped).map(([type, typeResults]) => `
            <div class="mb-4">
                <h6 class="text-uppercase fw-bold text-muted">${type.replace('_', ' ')}</h6>
                ${typeResults.map(result => this.renderResult(result)).join('')}
            </div>
        `).join('');
    }

    groupResultsByType(results) {
        return results.reduce((acc, result) => {
            const type = result.vulnerability_type.toLowerCase().replace(' ', '_');
            if (!acc[type]) acc[type] = [];
            acc[type].push(result);
            return acc;
        }, {});
    }

    renderResult(result) {
        const severityClass = this.getSeverityClass(result.severity || 'LOW', result.is_vulnerable, result.data_extracted);
        
        let statusBadge;
        if (result.data_extracted) {
            statusBadge = '<span class="badge bg-danger pulse"><i class="fas fa-skull-crossbones"></i> DATA EXTRACTED</span>';
        } else if (result.is_vulnerable) {
            statusBadge = '<span class="badge bg-warning">Vulnerable</span>';
        } else {
            statusBadge = '<span class="badge bg-success">Safe</span>';
        }
        
        // Format extracted data for display
        let extractedDataHtml = '';
        if (result.data_extracted && result.extracted_data) {
            extractedDataHtml = this.formatExtractedData(result.extracted_data);
        }
        
        const cardClass = result.data_extracted ? 'border-danger bg-danger-subtle' : 
                         result.is_vulnerable ? 'border-warning' : '';
        
        return `
            <div class="card mb-3 vulnerability-item ${severityClass} ${cardClass}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h6 class="card-title mb-0 ${result.data_extracted ? 'text-danger fw-bold' : ''}">${result.vulnerability_type}</h6>
                        ${statusBadge}
                    </div>
                    
                    <div class="vulnerability-details mb-2">
                        <strong>URL:</strong> <code class="text-break">${result.target_url}</code><br>
                        <strong>Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}<br>
                        <strong>Response Code:</strong> ${result.response_code}<br>
                        <strong>Severity:</strong> <span class="badge ${this.getSeverityBadgeClass(result.severity || 'LOW')}">${result.severity || 'LOW'}</span><br>
                        <strong>Confidence:</strong> 
                        <span class="${this.getConfidenceClass(result.confidence_score)}">
                            ${(result.confidence_score * 100).toFixed(1)}%
                        </span>
                    </div>
                    
                    <div class="mb-2">
                        <strong>Payload:</strong>
                        <div class="payload-code mt-1">${this.escapeHtml(result.payload)}</div>
                    </div>
                    
                    ${extractedDataHtml}
                    
                    ${result.data_extracted ? `
                        <div class="alert alert-danger mt-2 mb-0">
                            <i class="fas fa-skull-crossbones"></i>
                            <strong>CRITICAL: Data Extraction Successful!</strong> 
                            This vulnerability has been confirmed with actual data extraction. Immediate action required!
                        </div>
                    ` : result.is_vulnerable ? `
                        <div class="alert alert-warning mt-2 mb-0">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Vulnerability Detected!</strong> This endpoint may be vulnerable to ${result.vulnerability_type}.
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    formatExtractedData(extractedData) {
        if (!extractedData) return '';
        
        let html = '<div class="mt-3"><strong class="text-danger">🔥 EXTRACTED DATA:</strong><div class="border border-danger rounded p-2 mt-2 bg-light">';
        
        if (typeof extractedData === 'object') {
            for (const [key, value] of Object.entries(extractedData)) {
                if (key === '_credentials') {
                    html += `<div class="mb-2"><strong class="text-danger">Credentials Found:</strong>`;
                    if (Array.isArray(value)) {
                        value.forEach(cred => {
                            html += `<br><code class="text-danger">${this.escapeHtml(cred)}</code>`;
                        });
                    }
                    html += '</div>';
                } else if (key === 'database_type') {
                    html += `<div class="mb-1"><strong>Database:</strong> <span class="badge bg-info">${value}</span></div>`;
                } else if (key === 'databases') {
                    html += `<div class="mb-1"><strong>Database Names:</strong> ${Array.isArray(value) ? value.join(', ') : value}</div>`;
                } else if (key === 'tables') {
                    html += `<div class="mb-1"><strong>Tables:</strong> ${Array.isArray(value) ? value.join(', ') : value}</div>`;
                } else if (key === 'user_data') {
                    html += `<div class="mb-1"><strong class="text-danger">User Data:</strong> ${Array.isArray(value) ? value.join('<br>') : value}</div>`;
                } else if (typeof value === 'object' && value.content) {
                    html += `<div class="mb-2"><strong>File ${key}:</strong><br>`;
                    html += `<small class="text-muted">Type: ${value.type}, Size: ${value.size} bytes</small><br>`;
                    html += `<pre class="small text-danger">${this.escapeHtml(value.content.substring(0, 200))}${value.content.length > 200 ? '...' : ''}</pre></div>`;
                } else {
                    html += `<div class="mb-1"><strong>${key}:</strong> ${this.escapeHtml(String(value))}</div>`;
                }
            }
        } else {
            html += `<pre class="text-danger">${this.escapeHtml(String(extractedData))}</pre>`;
        }
        
        html += '</div></div>';
        return html;
    }

    getSeverityClass(severity, isVulnerable, dataExtracted) {
        if (dataExtracted) return 'critical-risk';
        if (!isVulnerable) return 'low-risk';
        
        switch(severity) {
            case 'CRITICAL': return 'critical-risk';
            case 'HIGH': return 'high-risk';
            case 'MEDIUM': return 'medium-risk';
            default: return 'low-risk';
        }
    }
    
    getSeverityBadgeClass(severity) {
        switch(severity) {
            case 'CRITICAL': return 'bg-danger';
            case 'HIGH': return 'bg-warning';
            case 'MEDIUM': return 'bg-info';
            default: return 'bg-secondary';
        }
    }

    getConfidenceClass(confidence) {
        if (confidence >= 0.7) return 'confidence-high';
        if (confidence >= 0.4) return 'confidence-medium';
        return 'confidence-low';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateStatusIndicator(status, text) {
        const indicator = document.getElementById('status-indicator');
        const icon = indicator.querySelector('i');
        
        icon.className = 'fas fa-circle';
        
        switch (status) {
            case 'ready':
                icon.classList.add('text-success');
                break;
            case 'configured':
                icon.classList.add('text-primary');
                break;
            case 'scanning':
                icon.classList.add('text-warning', 'pulse');
                break;
            case 'error':
                icon.classList.add('text-danger');
                break;
            default:
                icon.classList.add('text-secondary');
        }
        
        indicator.innerHTML = icon.outerHTML + ' ' + text;
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.createElement('div');
        alertContainer.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertContainer.style.cssText = 'top: 80px; right: 20px; z-index: 1050; min-width: 300px;';
        
        alertContainer.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertContainer);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertContainer.parentNode) {
                alertContainer.remove();
            }
        }, 5000);
    }
}

// Initialize the scanner when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new VulnerabilityScanner();
});
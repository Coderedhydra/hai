class VulnerabilityScanner {
    constructor() {
        this.isScanning = false;
        this.progressModal = new bootstrap.Modal(document.getElementById('progress-modal'));
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadAvailableModels(); // Load models on startup
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
            this.loadAvailableModels();
        } else {
            geminiConfig.style.display = 'block';
            ollamaConfig.style.display = 'none';
        }
    }

    async loadAvailableModels() {
        const modelSelect = document.getElementById('ollama-model');
        const modelStatus = document.getElementById('model-status');

        try {
            const response = await fetch('/api/models');
            const data = await response.json();

            if (response.ok && data.models) {
                modelSelect.innerHTML = '<option value="">Select a model...</option>';

                data.models.forEach(model => {
                    const option = document.createElement('option');
                    option.value = `${model.provider}/${model.name}`;
                    option.textContent = `${model.name} (${model.provider})`;
                    option.title = `Provider: ${model.provider}, Available: ${model.is_available ? 'Yes' : 'No'}`;
                    if (model.is_available) {
                        option.selected = true;
                    }
                    modelSelect.appendChild(option);
                });

                modelStatus.innerHTML = `<i class="fas fa-check text-success"></i> Found ${data.models.length} models`;
            } else {
                modelSelect.innerHTML = '<option value="">No models available</option>';
                modelStatus.innerHTML = '<i class="fas fa-exclamation-triangle text-warning"></i> No models detected';
            }
        } catch (error) {
            console.error('Error loading models:', error);
            modelSelect.innerHTML = '<option value="">Error loading models</option>';
            modelStatus.innerHTML = '<i class="fas fa-times text-danger"></i> Failed to load models';
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

        // Validate URL format
        try {
            new URL(targetUrl);
        } catch {
            this.showAlert('Please enter a valid URL', 'warning');
            return;
        }

        if (!useOllama && !apiKey) {
            this.showAlert('Please enter a Gemini API key or select a local model', 'warning');
            return;
        }

        const configButton = document.querySelector('#config-form button[type="submit"]');
        const originalText = configButton.innerHTML;
        configButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Configuring...';
        configButton.disabled = true;

        try {
            const response = await fetch('/api/config', {
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

            const data = await response.json();

            if (response.ok) {
                // Store session information
                this.currentTarget = targetUrl;
                this.scanSessionId = data.session_id;
                this.csrfToken = data.csrf_token;

                // Update UI
                this.clearResults();
                this.clearUrls();

                // Reset counters
                document.getElementById('urls-count').textContent = '0';
                document.getElementById('vulns-count').textContent = '0';
                document.getElementById('tests-count').textContent = '0';

                this.showAlert(`Configuration saved for ${targetUrl}`, 'success');
                this.updateStatusIndicator('configured', `Ready - ${targetUrl}`);
                this.updateTargetDisplay();

                // Load initial status
                this.updateStatus();

            } else {
                this.showAlert(data.error || 'Failed to save configuration', 'danger');
            }
        } catch (error) {
            console.error('Configuration error:', error);
            this.showAlert('Error saving configuration', 'danger');
        } finally {
            configButton.innerHTML = originalText;
            configButton.disabled = false;
        }
    }
    
    clearResults() {
        const container = document.getElementById('results-container');
        container.innerHTML = '<div class="text-muted text-center">No scan results for current target</div>';
    }
    
    clearUrls() {
        const urlsList = document.getElementById('urls-list');
        urlsList.innerHTML = '<div class="text-muted text-center">No URLs discovered yet</div>';
    }
    
    updateTargetDisplay() {
        if (this.currentTarget) {
            // Add target info to the navbar or create a target display
            const navbar = document.querySelector('.navbar .container-fluid');
            let targetDisplay = navbar.querySelector('.current-target');
            
            if (!targetDisplay) {
                targetDisplay = document.createElement('div');
                targetDisplay.className = 'current-target text-light me-3';
                navbar.appendChild(targetDisplay);
            }
            
            targetDisplay.innerHTML = `<small>Target: <strong>${this.currentTarget}</strong></small>`;
        }
    }

    async discoverUrls() {
        if (!this.currentTarget) {
            this.showAlert('Please configure a target first', 'warning');
            return;
        }

        const button = document.getElementById('discover-urls');
        const originalText = button.innerHTML;

        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Discovering...';
        button.disabled = true;

        try {
            const response = await fetch('/api/discover_urls', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    csrf_token: this.csrfToken
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.displayUrls(data.urls);
                document.getElementById('urls-count').textContent = data.count;
                this.showAlert(`Discovered ${data.count} URLs`, 'success');

                // Update session ID if provided
                if (data.session_id) {
                    this.scanSessionId = data.session_id;
                }
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

        if (!this.currentTarget) {
            this.showAlert('Please configure a target first', 'warning');
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
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting Scan...';
        button.disabled = true;

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    scan_types: scanTypes,
                    csrf_token: this.csrfToken,
                    session_id: this.scanSessionId
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.updateStatusIndicator('scanning', 'Scanning...');
                this.monitorScanProgress();
                this.showAlert(data.message || 'Scan started successfully', 'success');
            } else {
                this.showAlert(data.error || 'Failed to start scan', 'danger');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showAlert('Error starting scan', 'danger');
        } finally {
            setTimeout(() => {
                if (this.isScanning) {
                    button.innerHTML = '<i class="fas fa-play"></i> Start Comprehensive Scan';
                    button.disabled = false;
                    this.isScanning = false;
                    this.progressModal.hide();
                    this.showAlert('Scan may still be running in the background', 'info');
                }
            }, 60000); // Hide progress after 60 seconds
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
            const response = await fetch('/api/status');
            const data = await response.json();

            if (response.ok) {
                // Update system health
                const systemHealth = data.system_health;
                if (systemHealth && systemHealth.status !== 'healthy') {
                    this.showAlert(`System health: ${systemHealth.message}`, 'warning');
                }

                // Update scan statistics
                const scanStats = data.scan_statistics;
                if (scanStats) {
                    document.getElementById('urls-count').textContent = scanStats.active_scans || 0;
                    document.getElementById('vulns-count').textContent = scanStats.total_vulnerabilities || 0;
                }

                // Update status indicator
                const availableModels = data.available_models || 0;
                if (availableModels > 0) {
                    this.updateStatusIndicator('ready', `Ready (${availableModels} models)`);
                } else {
                    this.updateStatusIndicator('warning', 'No models available');
                }

                // Update security status
                const securityStatus = data.security_status;
                if (securityStatus) {
                    // Could add security status indicators to UI
                    console.log('Security status:', securityStatus);
                }
            } else {
                console.error('Error updating status:', data.error);
                this.updateStatusIndicator('error', 'Status update failed');
            }
        } catch (error) {
            console.error('Status update error:', error);
            this.updateStatusIndicator('error', 'Connection failed');
        }
    }

    async loadResults() {
        if (!this.currentTarget) {
            return;
        }

        try {
            const params = new URLSearchParams({
                session_id: this.scanSessionId || '',
                limit: '200',
                offset: '0'
            });

            const response = await fetch(`/api/results?${params}`);
            const data = await response.json();

            if (response.ok) {
                this.displayResults(data.results);
                document.getElementById('tests-count').textContent = data.total_count || data.results.length;

                // Update vulnerabilities count
                const vulnerabilities = data.results.filter(r => r.is_vulnerable);
                document.getElementById('vulns-count').textContent = vulnerabilities.length;

                // Show critical findings count
                const criticalFindings = data.results.filter(r => r.data_extracted);
                if (criticalFindings.length > 0) {
                    this.showAlert(`Found ${criticalFindings.length} critical vulnerabilities!`, 'danger');
                }
            } else {
                console.error('Error loading results:', data.error);
            }
        } catch (error) {
            console.error('Results loading error:', error);
        }
    }

    displayResults(results) {
        const container = document.getElementById('results-container');
        document.getElementById('tests-count').textContent = results.length;
        
        if (results.length === 0) {
            container.innerHTML = `
                <div class="text-center">
                    <div class="text-muted">No scan results for current target</div>
                    ${this.currentTarget ? `<small class="text-muted">Target: ${this.currentTarget}</small>` : ''}
                </div>
            `;
            return;
        }

        // Count vulnerabilities and critical findings
        const vulnerabilities = results.filter(r => r.is_vulnerable);
        const criticalFindings = results.filter(r => r.data_extracted);
        
        document.getElementById('vulns-count').textContent = vulnerabilities.length;
        
        // Show critical findings first
        let html = '';
        if (criticalFindings.length > 0) {
            html += `
                <div class="alert alert-danger mb-4">
                    <h5><i class="fas fa-skull-crossbones"></i> CRITICAL FINDINGS - DATA EXTRACTED!</h5>
                    <p class="mb-0">${criticalFindings.length} vulnerabilities with confirmed data extraction found!</p>
                </div>
            `;
        }

        // Group results by vulnerability type
        const grouped = this.groupResultsByType(results);
        
        html += Object.entries(grouped).map(([type, typeResults]) => {
            const criticalCount = typeResults.filter(r => r.data_extracted).length;
            const vulnCount = typeResults.filter(r => r.is_vulnerable).length;
            
            return `
                <div class="mb-4">
                    <h6 class="text-uppercase fw-bold text-muted d-flex justify-content-between align-items-center">
                        ${type.replace('_', ' ')}
                        <div>
                            ${criticalCount > 0 ? `<span class="badge bg-danger me-1">${criticalCount} Critical</span>` : ''}
                            ${vulnCount > 0 ? `<span class="badge bg-warning">${vulnCount} Vulnerable</span>` : ''}
                        </div>
                    </h6>
                    ${typeResults.map(result => this.renderResult(result)).join('')}
                </div>
            `;
        }).join('');
        
        container.innerHTML = html;
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
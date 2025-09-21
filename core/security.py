#!/usr/bin/env python3
"""
Security Manager
===============

Security management system for the vulnerability scanner.
Handles CSRF protection, input validation, authentication, and security monitoring.
"""

import hashlib
import hmac
import secrets
import time
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging
import ipaddress
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    enable_csrf: bool = True
    enable_rate_limiting: bool = True
    enable_input_validation: bool = True
    enable_ip_whitelist: bool = False
    enable_ip_blacklist: bool = False
    session_timeout: int = 3600
    max_payload_size: int = 10000
    allowed_domains: List[str] = None
    blocked_domains: List[str] = None

    def __post_init__(self):
        if self.allowed_domains is None:
            self.allowed_domains = []
        if self.blocked_domains is None:
            self.blocked_domains = []

class SecurityManager:
    """Comprehensive security management"""

    def __init__(self):
        self.config = SecurityConfig()
        self.csrf_tokens: Dict[str, float] = {}
        self.ip_blacklist: set = set()
        self.ip_whitelist: set = set()
        self.failed_attempts: Dict[str, List[float]] = {}
        self.suspicious_patterns: Dict[str, str] = {
            'sql_injection': r'(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(from|where|table|database)\b|\b(or|and)\b.*\b(=|>|<|like)\b.*\d+|\b(script|javascript|vbscript|onload|onerror)\b)',
            'xss': r'(<script|<iframe|<object|<embed|<form|<input|<meta|<link|<style|<svg|<math|<img|<audio|<video|<source|<track|<applet|<base|<body|<head|<html|<title|<div|<span|<a|<p|<b|<i|<u|<font|<center|<table|<tr|<td|<th|<ul|<ol|<li|<h1|<h2|<h3|<h4|<h5|<h6)',
            'command_injection': r'(\||;|\`|\$\(|\&\&|\|\||\bcmd\b|\bexec\b|\bsystem\b|\bshell_exec\b|\bpassthru\b|\beval\b|\bassert\b)',
            'path_traversal': r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c)',
            'xxe': r'(<!DOCTYPE|<!ENTITY|SYSTEM\s+"|PUBLIC\s+"|%[a-zA-Z])'
        }

        # Clean up expired tokens periodically
        import threading
        self._cleanup_timer = threading.Timer(300, self._cleanup_expired_tokens)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def generate_csrf_token(self, session_id: str) -> str:
        """Generate a CSRF token for the session"""
        if not self.config.enable_csrf:
            return ""

        timestamp = str(int(time.time()))
        token_data = f"{session_id}:{timestamp}"

        # Create HMAC-based token
        secret_key = hashlib.sha256(b'secret-key-for-csrf').hexdigest()
        token = hmac.new(
            secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()

        self.csrf_tokens[token] = time.time()
        return token

    def validate_csrf_token(self, token: str) -> bool:
        """Validate CSRF token"""
        if not self.config.enable_csrf:
            return True

        if token not in self.csrf_tokens:
            return False

        # Check if token is expired (15 minutes)
        if time.time() - self.csrf_tokens[token] > 900:
            del self.csrf_tokens[token]
            return False

        return True

    def validate_input(self, data: Dict[str, Any], input_type: str = 'general') -> Tuple[bool, List[str]]:
        """Validate input data for security issues"""
        if not self.config.enable_input_validation:
            return True, []

        errors = []

        for key, value in data.items():
            if isinstance(value, str):
                # Check for suspicious patterns
                for pattern_name, pattern in self.suspicious_patterns.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        errors.append(f"Suspicious pattern '{pattern_name}' detected in {key}")

                # Check for oversized input
                if len(value) > self.config.max_payload_size:
                    errors.append(f"Input {key} exceeds maximum size ({len(value)} > {self.config.max_payload_size})")

                # Validate URLs
                if 'url' in key.lower() and value:
                    if not self._validate_url(value):
                        errors.append(f"Invalid URL format in {key}: {value}")

                # Validate email addresses
                if 'email' in key.lower() and value:
                    if not self._validate_email(value):
                        errors.append(f"Invalid email format in {key}: {value}")

        return len(errors) == 0, errors

    def _validate_url(self, url: str) -> bool:
        """Validate URL format and safety"""
        try:
            parsed = urlparse(url)

            # Check basic URL structure
            if not parsed.scheme or not parsed.netloc:
                return False

            # Check allowed schemes
            if parsed.scheme.lower() not in ['http', 'https']:
                return False

            # Check for blocked domains
            if self.config.enable_ip_blacklist:
                domain = parsed.netloc.lower()
                for blocked in self.config.blocked_domains:
                    if blocked in domain:
                        return False

            # Check for suspicious patterns in URL
            for pattern in self.suspicious_patterns.values():
                if re.search(pattern, url, re.IGNORECASE):
                    return False

            return True

        except Exception:
            return False

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def check_rate_limit(self, identifier: str, limit: int = 100, window: int = 3600) -> bool:
        """Check if identifier is within rate limits"""
        if not self.config.enable_rate_limiting:
            return True

        current_time = time.time()

        # Get or create attempt history
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []

        attempts = self.failed_attempts[identifier]

        # Remove old attempts outside the window
        attempts[:] = [t for t in attempts if current_time - t < window]

        # Check if limit exceeded
        if len(attempts) >= limit:
            return False

        # Add current attempt
        attempts.append(current_time)
        return True

    def add_to_blacklist(self, ip: str) -> None:
        """Add IP to blacklist"""
        if self._validate_ip(ip):
            self.ip_blacklist.add(ip)
            logger.warning(f"Added IP {ip} to blacklist")

    def remove_from_blacklist(self, ip: str) -> None:
        """Remove IP from blacklist"""
        if ip in self.ip_blacklist:
            self.ip_blacklist.remove(ip)
            logger.info(f"Removed IP {ip} from blacklist")

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if not self.config.enable_ip_blacklist:
            return False

        return ip in self.ip_blacklist

    def add_to_whitelist(self, ip: str) -> None:
        """Add IP to whitelist"""
        if self._validate_ip(ip):
            self.ip_whitelist.add(ip)
            logger.info(f"Added IP {ip} to whitelist")

    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        if not self.config.enable_ip_whitelist:
            return False

        return ip in self.ip_whitelist

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def sanitize_payload(self, payload: str) -> str:
        """Sanitize payload for safe display"""
        if not payload:
            return ""

        # Remove or replace dangerous characters
        sanitized = payload.replace('\x00', '')  # Remove null bytes
        sanitized = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)  # Remove control characters

        return sanitized[:1000]  # Limit length

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data for storage"""
        # Simple encryption for demonstration
        # In production, use proper encryption libraries
        import base64

        timestamp = str(int(time.time()))
        combined = f"{timestamp}:{data}"

        # Simple base64 encoding (not secure encryption)
        return base64.b64encode(combined.encode()).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        # Simple decryption for demonstration
        import base64

        try:
            decoded = base64.b64decode(encrypted_data).decode()
            parts = decoded.split(':', 1)
            if len(parts) == 2:
                return parts[1]
        except Exception:
            pass

        return encrypted_data

    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          severity: str = 'MEDIUM') -> None:
        """Log security-related events"""
        logger.log(
            logging.ERROR if severity == 'HIGH' else logging.WARNING,
            f"Security Event [{event_type}]: {details}"
        )

    def _cleanup_expired_tokens(self) -> None:
        """Clean up expired CSRF tokens"""
        current_time = time.time()
        expired_tokens = []

        for token, timestamp in self.csrf_tokens.items():
            if current_time - timestamp > 900:  # 15 minutes
                expired_tokens.append(token)

        for token in expired_tokens:
            del self.csrf_tokens[token]

        # Schedule next cleanup
        self._cleanup_timer = threading.Timer(300, self._cleanup_expired_tokens)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            'csrf_enabled': self.config.enable_csrf,
            'rate_limiting_enabled': self.config.enable_rate_limiting,
            'input_validation_enabled': self.config.enable_input_validation,
            'ip_blacklist_enabled': self.config.enable_ip_blacklist,
            'ip_whitelist_enabled': self.config.enable_ip_whitelist,
            'blacklisted_ips_count': len(self.ip_blacklist),
            'whitelisted_ips_count': len(self.ip_whitelist),
            'active_csrf_tokens': len(self.csrf_tokens),
            'failed_attempts_tracked': len(self.failed_attempts)
        }

# Global security manager instance
security_manager = SecurityManager()
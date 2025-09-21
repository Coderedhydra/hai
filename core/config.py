#!/usr/bin/env python3
"""
Configuration Manager
===================

Centralized configuration management for the vulnerability scanner.
Handles environment variables, defaults, and runtime configuration.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ScannerConfig:
    """Scanner configuration settings"""
    # General settings
    debug: bool = False
    host: str = '0.0.0.0'
    port: int = 5000
    secret_key: str = 'dev-secret-key-change-in-production'

    # Database settings
    database_path: str = 'scanner_results.db'

    # LLM settings
    gemini_api_key: str = ''
    ollama_base_url: str = 'http://localhost:11434'
    default_model: str = 'llama2'

    # Scanning settings
    max_concurrent_scans: int = 5
    scan_timeout: int = 30
    max_url_depth: int = 3
    rate_limit_delay: float = 0.5

    # Security settings
    enable_csrf: bool = True
    session_timeout: int = 3600

    # Monitoring settings
    enable_monitoring: bool = True
    log_level: str = 'INFO'

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'debug': self.debug,
            'host': self.host,
            'port': self.port,
            'database_path': self.database_path,
            'max_concurrent_scans': self.max_concurrent_scans,
            'scan_timeout': self.scan_timeout,
            'max_url_depth': self.max_url_depth,
            'rate_limit_delay': self.rate_limit_delay,
            'enable_csrf': self.enable_csrf,
            'session_timeout': self.session_timeout,
            'enable_monitoring': self.enable_monitoring,
            'log_level': self.log_level
        }

class ConfigManager:
    """Centralized configuration management"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.environ.get('SCANNER_CONFIG', 'config.json')
        self.config = ScannerConfig()
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file and environment variables"""
        try:
            # Load from config file if exists
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    for key, value in file_config.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
                logger.info(f"Loaded configuration from {self.config_file}")

            # Override with environment variables
            env_mappings = {
                'DEBUG': ('debug', lambda x: x.lower() == 'true'),
                'HOST': ('host', str),
                'PORT': ('port', int),
                'SECRET_KEY': ('secret_key', str),
                'DATABASE_PATH': ('database_path', str),
                'GEMINI_API_KEY': ('gemini_api_key', str),
                'OLLAMA_BASE_URL': ('ollama_base_url', str),
                'DEFAULT_MODEL': ('default_model', str),
                'MAX_CONCURRENT_SCANS': ('max_concurrent_scans', int),
                'SCAN_TIMEOUT': ('scan_timeout', int),
                'MAX_URL_DEPTH': ('max_url_depth', int),
                'RATE_LIMIT_DELAY': ('rate_limit_delay', float),
                'ENABLE_CSRF': ('enable_csrf', lambda x: x.lower() == 'true'),
                'SESSION_TIMEOUT': ('session_timeout', int),
                'ENABLE_MONITORING': ('enable_monitoring', lambda x: x.lower() == 'true'),
                'LOG_LEVEL': ('log_level', str)
            }

            for env_var, (attr, converter) in env_mappings.items():
                if env_var in os.environ:
                    try:
                        value = converter(os.environ[env_var])
                        setattr(self.config, attr, value)
                        logger.info(f"Overrode {attr} from environment variable {env_var}")
                    except ValueError as e:
                        logger.warning(f"Invalid value for {env_var}: {e}")

        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")

    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)
            logger.info(f"Saved configuration to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return getattr(self.config, key, default)

    def set(self, key: str, value: Any) -> bool:
        """Set configuration value"""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            return True
        return False

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Validate required paths
        if not os.path.isabs(self.config.database_path):
            db_path = Path(self.config.database_path)
            if not db_path.parent.exists():
                errors.append(f"Database directory does not exist: {db_path.parent}")

        # Validate port range
        if not (1 <= self.config.port <= 65535):
            errors.append(f"Invalid port number: {self.config.port}")

        # Validate concurrent scans
        if self.config.max_concurrent_scans < 1:
            errors.append("max_concurrent_scans must be at least 1")

        return errors

# Global config instance
config = ConfigManager()

if __name__ == '__main__':
    # CLI for configuration management
    import argparse

    parser = argparse.ArgumentParser(description='Scanner Configuration Manager')
    parser.add_argument('--show', action='store_true', help='Show current configuration')
    parser.add_argument('--save', action='store_true', help='Save current configuration')
    parser.add_argument('--validate', action='store_true', help='Validate configuration')
    parser.add_argument('--reset', action='store_true', help='Reset to defaults')

    args = parser.parse_args()

    if args.show:
        print("Current Configuration:")
        for key, value in config.config.to_dict().items():
            print(f"  {key}: {value}")

    if args.validate:
        errors = config.validate()
        if errors:
            print("Configuration Errors:")
            for error in errors:
                print(f"  ❌ {error}")
            sys.exit(1)
        else:
            print("✅ Configuration is valid")

    if args.save:
        if config.save_config():
            print("✅ Configuration saved")
        else:
            print("❌ Failed to save configuration")
            sys.exit(1)

    if args.reset:
        config.config = ScannerConfig()
        if config.save_config():
            print("✅ Configuration reset to defaults")
        else:
            print("❌ Failed to reset configuration")
            sys.exit(1)
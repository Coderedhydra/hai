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
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Optional Flask imports
try:
    from flask import Flask, render_template, request, jsonify, session
    from flask_cors import CORS
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    FLASK_AVAILABLE = True
except ImportError as e:
    FLASK_AVAILABLE = False
    print(f"Flask not available - web interface will be disabled: {e}")

# Optional imports for LLM and web scraping
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("requests not available - HTTP operations will be limited")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("beautifulsoup4 not available - HTML parsing will be limited")

# Optional imports for LLM
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    print("Google Generative AI not available - Gemini API features will be limited")

# Set availability flags for optional extensions
if FLASK_AVAILABLE:
    try:
        CORS_AVAILABLE = True
    except:
        CORS_AVAILABLE = False

    try:
        LIMITER_AVAILABLE = True
    except:
        LIMITER_AVAILABLE = False
else:
    CORS_AVAILABLE = False
    LIMITER_AVAILABLE = False

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modular components
from core.scanner import VulnerabilityScanner
from core.database import DatabaseManager
from core.llm_manager import LLMManager
from core.config import ConfigManager, config
from core.security import SecurityManager
from core.monitoring import MonitoringManager
from core.payload_manager import PayloadManager

# Initialize Flask app if available
if FLASK_AVAILABLE:
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    # Initialize CORS if available
    if CORS_AVAILABLE:
        CORS(app)
        print("✅ CORS support enabled")
    else:
        print("⚠️ CORS support disabled")

    # Initialize rate limiter if available
    if LIMITER_AVAILABLE:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )
        print("✅ Rate limiting enabled")
    else:
        print("⚠️ Rate limiting disabled")
        limiter = None
else:
    print("⚠️ Flask not available - running in core-only mode")
    app = None
    limiter = None

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

# Initialize Flask routes if Flask is available
if FLASK_AVAILABLE and app:
    @app.route('/')
    def index():
        """Main web interface"""
        return render_template('index.html')

    @app.route('/api/config', methods=['GET', 'POST'])
    def handle_config():
        """Handle scanner configuration"""
        if request.method == 'GET':
            # Return current configuration
            try:
                models = llm_manager.list_models(only_available=False)
                return jsonify({
                    'target_url': session.get('target_url', ''),
                    'available_models': [
                        {
                            'name': m.name,
                            'provider': m.provider.value,
                            'is_available': m.is_available,
                            'capabilities': m.capabilities
                        }
                        for m in models
                    ],
                    'security_status': security_manager.get_security_status()
                })
            except Exception as e:
                logger.error(f"Error building config response: {e}")
                return jsonify({'error': 'Failed to build config'}), 500

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
        session['scan_session_id'] = scan_session_id

        # Ensure a stable client session id for CSRF
        if 'client_session_id' not in session:
            session['client_session_id'] = str(uuid.uuid4())

        # Generate CSRF token using client session id
        csrf_token = security_manager.generate_csrf_token(session['client_session_id'])

        logger.info(f"Configuration updated for target: {target_url}")
        return jsonify({
            'status': 'configured',
            'session_id': scan_session_id,
            'csrf_token': csrf_token
        })

    @app.route('/api/models', methods=['GET'])
    def get_available_models():
        """Get LLM models in deterministic order, including locally downloaded ones."""
        try:
            models = llm_manager.list_models(only_available=False)
            return jsonify({
                'models': [
                    {
                        'name': m.name,
                        'provider': m.provider.value,
                        'is_available': m.is_available,
                        'capabilities': m.capabilities
                    }
                    for m in models
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
            urls = scanner.discover_urls(target_url, max_depth=config.get('max_url_depth', 3), scan_session_id=scan_session_id)

            # Store discovered URLs in database
            for url in urls:
                try:
                    db_manager.save_scan_result({
                        'target_url': url,
                        'vulnerability_type': 'URL_DISCOVERY',
                        'payload': 'GET',
                        'response_code': 200,
                        'is_vulnerable': False,
                        'confidence_score': 1.0,
                        'severity': 'INFO'
                    }, scan_session_id)
                except Exception as e:
                    logger.warning(f"Failed persisting discovered url {url}: {e}")

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
        if not csrf_token or not security_manager.validate_csrf_token(csrf_token):
            return jsonify({'error': 'Invalid CSRF token'}), 403

        # Get scan configuration
        scan_types = data.get('scan_types', ['sql_injection', 'xss', 'lfi', 'command_injection', 'xxe', 'secrets', 'ai_agent'])
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
        if limiter:
            return jsonify({'error': 'Rate limit exceeded'}), 429
        else:
            # Fallback if limiter is not available
            return jsonify({'error': 'Too many requests'}), 429

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

    # Check if Flask is available
    if FLASK_AVAILABLE:
        # Start the web application
        logger.info(f"Starting scanner on {config.get('host')}:{config.get('port')}")
        app.run(
            host=config.get('host'),
            port=config.get('port'),
            debug=config.get('debug')
        )
    else:
        # Run in core-only mode
        logger.info("Flask not available - running in core-only mode")
        logger.info("Core scanner functionality is available via direct imports")
        logger.info("To enable web interface, install Flask: pip install flask flask-cors flask-limiter")

        # Keep the process running for testing
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Core-only mode stopped by user")
            

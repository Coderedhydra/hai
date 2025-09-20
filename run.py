#!/usr/bin/env python3
"""
LLM-Powered Vulnerability Scanner Launcher
==========================================

This script provides an easy way to start the vulnerability scanner with
proper environment setup and configuration validation.
"""

import os
import sys
import subprocess
import argparse
import webbrowser
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def check_dependencies():
    """Check if required dependencies are installed"""
    # Map pip package names to their import names
    required_packages = {
        'flask': 'flask',
        'requests': 'requests', 
        'beautifulsoup4': 'bs4',  # beautifulsoup4 imports as bs4
        'google-generativeai': 'google.generativeai',  # google-generativeai imports as google.generativeai
        'urllib3': 'urllib3'
    }
    
    missing_packages = []
    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✅ {pip_name}")
        except ImportError:
            print(f"❌ {pip_name}")
            missing_packages.append(pip_name)
    
    if missing_packages:
        print(f"\n❌ Missing {len(missing_packages)} required packages")
        print("\nInstall missing packages with:")
        print("   pip install " + " ".join(missing_packages))
        print("   # OR")
        print("   pip install -r requirements.txt")
        return False
    
    print("✅ All required dependencies are installed")
    return True

def check_ollama_availability():
    """Check if Ollama is available for local LLM support"""
    try:
        result = subprocess.run(['ollama', 'list'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            models = [line.split()[0] for line in result.stdout.strip().split('\n')[1:] 
                     if line.strip()]
            if models:
                print(f"✅ Ollama available with models: {', '.join(models)}")
                return True
            else:
                print("⚠️  Ollama available but no models installed")
                print("   Install a model with: ollama pull llama2")
        else:
            print("⚠️  Ollama installed but not running")
            print("   Start Ollama with: ollama serve")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("⚠️  Ollama not found (local LLM support unavailable)")
        print("   Install from: https://ollama.ai/")
    
    return False

def setup_database():
    """Initialize the database"""
    try:
        import sqlite3
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
        print("✅ Database initialized")
        return True
    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="LLM-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                    # Start with default settings
  python run.py --port 8080        # Start on custom port
  python run.py --no-browser       # Don't open browser automatically
  python run.py --debug            # Enable debug mode
        """
    )
    
    parser.add_argument('--port', '-p', type=int, default=5000,
                       help='Port to run the server on (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    parser.add_argument('--no-browser', action='store_true',
                       help='Don\'t open browser automatically')
    
    args = parser.parse_args()
    
    print("🔒 LLM-Powered Vulnerability Scanner")
    print("=" * 40)
    
    # Check system requirements
    check_python_version()
    
    if not check_dependencies():
        sys.exit(1)
    
    if not setup_database():
        sys.exit(1)
    
    check_ollama_availability()
    
    print("\n🚀 Starting vulnerability scanner...")
    print(f"   Server: http://{args.host}:{args.port}")
    print(f"   Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    
    # Open browser if requested
    if not args.no_browser:
        try:
            webbrowser.open(f'http://localhost:{args.port}')
            print("🌐 Opening browser...")
        except Exception:
            print("⚠️  Could not open browser automatically")
    
    print("\n📋 Usage Instructions:")
    print("1. Configure your target URL and LLM settings")
    print("2. Select vulnerability types to test")
    print("3. Click 'Discover URLs' to map the target")
    print("4. Start the comprehensive scan")
    print("5. Monitor results in real-time")
    print("\n⚠️  Remember: Only test applications you own or have permission to test!")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 40)
    
    # Set environment variables
    os.environ['FLASK_APP'] = 'app.py'
    if args.debug:
        os.environ['FLASK_DEBUG'] = '1'
    
    try:
        # Import and run the Flask app
        from app import app
        app.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n\n👋 Scanner stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
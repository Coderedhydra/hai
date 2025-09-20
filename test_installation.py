#!/usr/bin/env python3
"""
Test Script for LLM-Powered Vulnerability Scanner Installation
============================================================

This script tests if the vulnerability scanner is properly installed
and configured.
"""

import sys
import os
import sqlite3
from pathlib import Path

def test_python_version():
    """Test Python version"""
    if sys.version_info >= (3, 8):
        print("✅ Python version compatible")
        return True
    else:
        print("❌ Python version incompatible")
        return False

def test_dependencies():
    """Test if all required dependencies are available"""
    required_modules = [
        'flask',
        'requests', 
        'bs4',  # beautifulsoup4
        'google.generativeai',
        'urllib3'
    ]
    
    missing = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            missing.append(module)
    
    return len(missing) == 0

def test_database():
    """Test database connectivity and schema"""
    try:
        conn = sqlite3.connect('scanner_results.db')
        c = conn.cursor()
        
        # Test table creation
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
        
        # Test insert/select
        c.execute("INSERT INTO scan_results (timestamp, target_url, vulnerability_type) VALUES (?, ?, ?)",
                  ("test", "http://test.com", "test"))
        c.execute("SELECT COUNT(*) FROM scan_results WHERE target_url = ?", ("http://test.com",))
        count = c.fetchone()[0]
        
        # Clean up test data
        c.execute("DELETE FROM scan_results WHERE target_url = ?", ("http://test.com",))
        conn.commit()
        conn.close()
        
        if count > 0:
            print("✅ Database working")
            return True
        else:
            print("❌ Database insert/select failed")
            return False
            
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_flask_app():
    """Test if Flask app can be imported"""
    try:
        from app import app, VulnerabilityScanner
        print("✅ Flask app imports successfully")
        
        # Test scanner initialization
        scanner = VulnerabilityScanner()
        print("✅ VulnerabilityScanner initializes")
        return True
        
    except Exception as e:
        print(f"❌ Flask app import failed: {e}")
        return False

def test_file_structure():
    """Test if all required files exist"""
    required_files = [
        'app.py',
        'run.py',
        'requirements.txt',
        'templates/index.html',
        'static/css/style.css',
        'static/js/app.js'
    ]
    
    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            missing.append(file_path)
    
    return len(missing) == 0

def test_ollama_connection():
    """Test Ollama connection (optional)"""
    try:
        import subprocess
        result = subprocess.run(['ollama', 'list'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Ollama connection working")
            return True
        else:
            print("⚠️  Ollama not responding (optional)")
            return False
    except Exception:
        print("⚠️  Ollama not available (optional)")
        return False

def test_gemini_api_key():
    """Test if Gemini API key is configured"""
    # Check environment variables
    api_key = os.getenv('GEMINI_API_KEY')
    if api_key:
        print("✅ Gemini API key found in environment")
        return True
    
    # Check .env file
    env_file = Path('.env')
    if env_file.exists():
        content = env_file.read_text()
        if 'GEMINI_API_KEY=' in content and 'your-gemini-api-key-here' not in content:
            print("✅ Gemini API key configured in .env")
            return True
    
    print("⚠️  Gemini API key not configured (you'll need to set this up)")
    return False

def main():
    print("🔒 LLM-Powered Vulnerability Scanner Installation Test")
    print("=" * 60)
    
    tests = [
        ("Python Version", test_python_version),
        ("Dependencies", test_dependencies),
        ("File Structure", test_file_structure),
        ("Database", test_database),
        ("Flask App", test_flask_app),
        ("Gemini API Key", test_gemini_api_key),
        ("Ollama Connection", test_ollama_connection)
    ]
    
    passed = 0
    failed = 0
    warnings = 0
    
    for test_name, test_func in tests:
        print(f"\n🔍 Testing {test_name}...")
        try:
            result = test_func()
            if result:
                passed += 1
            else:
                if test_name in ["Gemini API Key", "Ollama Connection"]:
                    warnings += 1
                else:
                    failed += 1
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results:")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   ⚠️  Warnings: {warnings}")
    
    if failed == 0:
        print("\n🎉 Installation test successful!")
        print("\n📋 Next Steps:")
        if warnings > 0:
            print("1. Configure Gemini API key or set up Ollama for LLM support")
        print("2. Start the scanner: python run.py")
        print("3. Open http://localhost:5000 in your browser")
        print("4. Configure your target URL and start scanning!")
        
        return True
    else:
        print(f"\n❌ Installation test failed with {failed} errors")
        print("Please fix the issues above and run the test again.")
        return False

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n👋 Test cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with exception: {e}")
        sys.exit(1)
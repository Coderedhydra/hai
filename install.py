#!/usr/bin/env python3
"""
Installation Script for LLM-Powered Vulnerability Scanner
========================================================

This script helps set up the vulnerability scanner with all dependencies
and proper configuration.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def install_requirements():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def setup_environment():
    """Set up environment configuration"""
    env_template = Path('.env.template')
    env_file = Path('.env')
    
    if env_template.exists() and not env_file.exists():
        print("⚙️  Setting up environment configuration...")
        shutil.copy(env_template, env_file)
        print("✅ Created .env file from template")
        print("   Please edit .env file with your configuration")
        return True
    elif env_file.exists():
        print("✅ Environment file already exists")
        return True
    else:
        print("⚠️  No environment template found")
        return False

def check_ollama():
    """Check if Ollama is available"""
    try:
        result = subprocess.run(['ollama', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Ollama is installed")
            
            # Check if service is running
            result = subprocess.run(['ollama', 'list'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                models = [line.split()[0] for line in result.stdout.strip().split('\n')[1:] 
                         if line.strip()]
                if models:
                    print(f"✅ Available models: {', '.join(models)}")
                else:
                    print("⚠️  No models installed")
                    print("   Install a model with: ollama pull llama2")
            else:
                print("⚠️  Ollama service not running")
                print("   Start with: ollama serve")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("⚠️  Ollama not found")
        print("   Install from: https://ollama.ai/")
        print("   This is optional - you can use Gemini API instead")
    
    return False

def setup_database():
    """Initialize the scanner database"""
    print("🗄️  Setting up database...")
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

def create_desktop_shortcut():
    """Create desktop shortcut (Linux/macOS)"""
    try:
        if sys.platform.startswith('linux'):
            desktop_path = Path.home() / 'Desktop'
            if desktop_path.exists():
                shortcut_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Vulnerability Scanner
Comment=LLM-Powered Vulnerability Scanner
Exec=python3 {Path.cwd() / 'run.py'}
Icon=security
Terminal=true
Categories=Development;Security;
"""
                shortcut_file = desktop_path / 'vulnerability-scanner.desktop'
                shortcut_file.write_text(shortcut_content)
                shortcut_file.chmod(0o755)
                print("✅ Desktop shortcut created")
                return True
    except Exception as e:
        print(f"⚠️  Could not create desktop shortcut: {e}")
    
    return False

def main():
    print("🔒 LLM-Powered Vulnerability Scanner Installation")
    print("=" * 55)
    
    # Check system requirements
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_requirements():
        print("\n❌ Installation failed - could not install dependencies")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Setup database
    if not setup_database():
        print("\n❌ Installation failed - could not setup database")
        sys.exit(1)
    
    # Check optional components
    check_ollama()
    create_desktop_shortcut()
    
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Edit .env file with your configuration (optional)")
    print("2. Get a Gemini API key from: https://makersuite.google.com/app/apikey")
    print("3. Or install Ollama for local LLM support: https://ollama.ai/")
    print("4. Start the scanner with: python run.py")
    print("5. Open http://localhost:5000 in your browser")
    
    print("\n⚠️  Important Security Notes:")
    print("- Only test applications you own or have permission to test")
    print("- This tool is for authorized security testing only")
    print("- Follow responsible disclosure practices")
    print("- Be mindful of rate limits and server resources")
    
    print("\n🚀 Ready to start scanning!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Installation cancelled by user")
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)
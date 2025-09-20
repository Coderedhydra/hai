#!/usr/bin/env python3
"""
Quick Setup Script for LLM-Powered Vulnerability Scanner
======================================================

This script quickly installs the essential dependencies and starts the scanner.
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and return success status"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        if e.stdout:
            print(f"   Output: {e.stdout}")
        if e.stderr:
            print(f"   Error: {e.stderr}")
        return False

def main():
    print("🚀 Quick Setup for LLM-Powered Vulnerability Scanner")
    print("=" * 55)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    # Install essential packages
    essential_packages = [
        "Flask",
        "requests", 
        "beautifulsoup4",
        "google-generativeai"
    ]
    
    print("\n📦 Installing essential packages...")
    
    for package in essential_packages:
        cmd = f"{sys.executable} -m pip install --user {package}"
        if not run_command(cmd, f"Installing {package}"):
            # Try without --user flag
            cmd = f"{sys.executable} -m pip install {package}"
            if not run_command(cmd, f"Installing {package} (system-wide)"):
                print(f"⚠️  Failed to install {package}, continuing...")
    
    # Test imports
    print("\n🔍 Testing package imports...")
    
    test_imports = {
        'Flask': 'flask',
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'google-generativeai': 'google.generativeai'
    }
    
    all_working = True
    for package_name, import_name in test_imports.items():
        try:
            __import__(import_name)
            print(f"✅ {package_name} working")
        except ImportError:
            print(f"❌ {package_name} not working")
            all_working = False
    
    if not all_working:
        print("\n⚠️  Some packages failed to install. Try manual installation:")
        print("   pip install --user Flask requests beautifulsoup4 google-generativeai")
        print("   # OR")
        print("   sudo pip install Flask requests beautifulsoup4 google-generativeai")
        return False
    
    # Initialize database
    print("\n🗄️  Initializing database...")
    try:
        from app import init_db
        init_db()
        print("✅ Database initialized")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Get a Gemini API key from: https://makersuite.google.com/app/apikey")
    print("2. Start the scanner: python run.py")
    print("3. Open http://localhost:5000 in your browser")
    print("4. Configure your target URL and API key")
    print("5. Start scanning!")
    
    return True

if __name__ == '__main__':
    try:
        success = main()
        if success:
            print("\n🚀 Ready to start scanning!")
            user_input = input("\nWould you like to start the scanner now? (y/n): ")
            if user_input.lower().startswith('y'):
                print("\nStarting scanner...")
                os.system(f"{sys.executable} run.py")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n👋 Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
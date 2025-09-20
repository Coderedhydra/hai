#!/usr/bin/env python3
"""
Dependency Fix Script for LLM-Powered Vulnerability Scanner
=========================================================

This script fixes common dependency installation issues.
"""

import subprocess
import sys
import os

def install_package(package_name):
    """Install a single package using pip"""
    try:
        print(f"Installing {package_name}...")
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', package_name, '--user'
        ])
        print(f"✅ Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package_name}: {e}")
        return False

def test_import(pip_name, import_name):
    """Test if a package can be imported"""
    try:
        __import__(import_name)
        print(f"✅ {pip_name} is working")
        return True
    except ImportError:
        print(f"❌ {pip_name} not found")
        return False

def main():
    print("🔧 Fixing Dependencies for LLM-Powered Vulnerability Scanner")
    print("=" * 65)
    
    # Map of pip package names to import names
    packages = {
        'Flask': 'flask',
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'google-generativeai': 'google.generativeai',
        'urllib3': 'urllib3',
        'lxml': 'lxml'
    }
    
    print("🔍 Checking current package status...")
    missing_packages = []
    
    for pip_name, import_name in packages.items():
        if not test_import(pip_name, import_name):
            missing_packages.append(pip_name)
    
    if not missing_packages:
        print("\n🎉 All packages are already installed!")
        return True
    
    print(f"\n📦 Installing {len(missing_packages)} missing packages...")
    
    # Try installing missing packages one by one
    failed_packages = []
    for package in missing_packages:
        if not install_package(package):
            failed_packages.append(package)
    
    if failed_packages:
        print(f"\n❌ Failed to install: {', '.join(failed_packages)}")
        print("\nTry these manual commands:")
        for package in failed_packages:
            print(f"   pip install --user {package}")
        
        print("\nOr try with system pip:")
        for package in failed_packages:
            print(f"   sudo pip install {package}")
        
        return False
    
    print("\n🎉 All packages installed successfully!")
    
    # Verify installations
    print("\n✅ Verifying installations...")
    all_working = True
    for pip_name, import_name in packages.items():
        if not test_import(pip_name, import_name):
            all_working = False
    
    if all_working:
        print("\n🚀 All dependencies are working! You can now run:")
        print("   python run.py")
    else:
        print("\n⚠️  Some packages may need to be installed manually.")
        print("Try restarting your terminal and running the script again.")
    
    return all_working

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n👋 Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)
# Troubleshooting Guide

## Common Installation Issues

### 1. Missing Dependencies Error

**Problem**: Getting "Missing required packages" error even after running `pip install -r requirements.txt`

**Cause**: The script checks for import names which differ from pip package names.

**Solutions**:

#### Option A: Use the Quick Setup Script
```bash
python quick_setup.py
```

#### Option B: Install Packages Manually
```bash
# Install essential packages
pip install --user Flask requests beautifulsoup4 google-generativeai

# OR system-wide (may require sudo)
pip install Flask requests beautifulsoup4 google-generativeai
```

#### Option C: Use the Dependency Fix Script
```bash
python fix_dependencies.py
```

#### Option D: Install Minimal Requirements
```bash
pip install -r requirements-minimal.txt
```

### 2. Permission Issues

**Problem**: Permission denied when installing packages

**Solutions**:
```bash
# Install to user directory
pip install --user Flask requests beautifulsoup4 google-generativeai

# OR use sudo (Linux/Mac)
sudo pip install Flask requests beautifulsoup4 google-generativeai

# OR use pip3 explicitly
pip3 install --user Flask requests beautifulsoup4 google-generativeai
```

### 3. Python Version Issues

**Problem**: Script says Python version is incompatible

**Solution**: Ensure you're using Python 3.8+
```bash
python --version  # Should be 3.8+
python3 --version # Try python3 if python is old

# Use python3 explicitly if needed
python3 run.py
```

### 4. Import Errors After Installation

**Problem**: Packages installed but still getting import errors

**Solutions**:

#### Check Package Installation
```python
# Test in Python shell
python -c "import flask; import requests; import bs4; import google.generativeai; print('All packages working!')"
```

#### Restart Terminal
Close and reopen your terminal, then try again.

#### Check Installation Location
```bash
pip show Flask
pip show beautifulsoup4
pip show google-generativeai
```

#### Reinstall Problematic Packages
```bash
pip uninstall beautifulsoup4
pip install beautifulsoup4

pip uninstall google-generativeai
pip install google-generativeai
```

### 5. Google Generative AI Issues

**Problem**: `google-generativeai` package not installing or importing

**Solutions**:
```bash
# Try different installation methods
pip install google-generativeai
pip install --upgrade google-generativeai
pip install --user google-generativeai

# Check if it's installed
pip list | grep google-generativeai

# Test import
python -c "import google.generativeai; print('Google AI working!')"
```

### 6. BeautifulSoup4 Issues

**Problem**: `beautifulsoup4` not importing as `bs4`

**Solutions**:
```bash
# Reinstall beautifulsoup4
pip uninstall beautifulsoup4
pip install beautifulsoup4

# Install with lxml parser
pip install lxml

# Test import
python -c "from bs4 import BeautifulSoup; print('BeautifulSoup working!')"
```

## Quick Verification Commands

### Test All Dependencies
```bash
python -c "
import flask
import requests
import bs4
import google.generativeai
import urllib3
print('✅ All dependencies working!')
"
```

### Test Database
```bash
python -c "
import sqlite3
conn = sqlite3.connect('test.db')
conn.close()
print('✅ SQLite working!')
"
```

### Test Flask App
```bash
python -c "
from app import app
print('✅ Flask app imports successfully!')
"
```

## Manual Installation Steps

If automated scripts fail, follow these manual steps:

### 1. Create Virtual Environment (Recommended)
```bash
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/Mac
# OR
scanner_env\Scripts\activate     # Windows
```

### 2. Install Packages One by One
```bash
pip install Flask
pip install requests
pip install beautifulsoup4
pip install google-generativeai
pip install urllib3
pip install lxml
```

### 3. Verify Each Installation
```bash
python -c "import flask; print('Flask OK')"
python -c "import requests; print('Requests OK')"
python -c "import bs4; print('BeautifulSoup OK')"
python -c "import google.generativeai; print('Google AI OK')"
```

### 4. Test the Scanner
```bash
python test_installation.py
```

## Alternative Installation Methods

### Using pip3
```bash
pip3 install Flask requests beautifulsoup4 google-generativeai
python3 run.py
```

### Using conda
```bash
conda install flask requests beautifulsoup4
pip install google-generativeai  # Not available in conda
```

### Using system package manager (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3-flask python3-requests python3-bs4
pip install google-generativeai
```

## Getting Help

If you're still having issues:

1. **Check Python version**: `python --version`
2. **Check pip version**: `pip --version`
3. **Run diagnostics**: `python test_installation.py`
4. **Try quick setup**: `python quick_setup.py`
5. **Check error logs**: Look for specific error messages

## Common Error Messages and Solutions

### "No module named 'flask'"
```bash
pip install Flask
```

### "No module named 'bs4'"
```bash
pip install beautifulsoup4
```

### "No module named 'google.generativeai'"
```bash
pip install google-generativeai
```

### "Permission denied"
```bash
pip install --user [package_name]
```

### "Command not found: pip"
```bash
python -m pip install [package_name]
```

## Success Indicators

You'll know everything is working when:

1. `python run.py` shows all green checkmarks ✅
2. The web interface opens at http://localhost:5000
3. No error messages in the terminal
4. You can configure targets and start scans

## Still Need Help?

If none of these solutions work:

1. Create a fresh Python virtual environment
2. Use the minimal requirements: `pip install -r requirements-minimal.txt`
3. Try the quick setup script: `python quick_setup.py`
4. Check your Python and pip versions are up to date
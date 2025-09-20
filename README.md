# LLM-Powered Vulnerability Scanner

A comprehensive web vulnerability scanner that leverages Large Language Models (LLMs) to generate sophisticated attack payloads and intelligently test web applications for security vulnerabilities.

## Features

### 🤖 LLM-Powered Payload Generation
- **Gemini 2.0 Flash Integration**: Uses Google's Gemini 2.0 Flash model for intelligent payload generation
- **Ollama Support**: Local LLM support using Ollama for privacy-focused scanning
- **Adaptive Payloads**: Generates context-aware payloads based on target URLs and discovered patterns
- **Iterative Learning**: Continuously improves payload effectiveness based on scan results

### 🔍 Advanced Vulnerability Testing & Exploitation
- **SQL Injection with Data Extraction**: 
  - Database fingerprinting (MySQL, PostgreSQL, SQLite)
  - Database name and table enumeration
  - User credential extraction
  - Automatic data dumping from common tables
- **Local File Inclusion with File System Exploration**:
  - Sensitive file extraction (/etc/passwd, shadow, config files)
  - PHP wrapper exploitation
  - Credential harvesting from configuration files
  - Base64 encoded content decoding
- **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS detection
- **Command Injection**: OS command injection with both direct and blind detection
- **XXE Injection**: XML External Entity injection testing

### 🌐 Deep Web Crawling & Discovery
- **Comprehensive URL Discovery**: 
  - Recursive crawling with configurable depth (up to 3 levels)
  - Common endpoint testing (admin, api, config, backup paths)
  - JavaScript API endpoint extraction
  - Form parameter discovery and mapping
- **Smart Reconnaissance**:
  - Hidden directory and file discovery
  - API endpoint pattern recognition
  - Configuration file detection (.env, .git, composer.json)
  - Asset and resource mapping

### 🎯 Intelligent Exploitation Engine
- **Real Data Extraction**: Goes beyond detection to actually extract sensitive data
- **Credential Harvesting**: Automatically extracts usernames, passwords, and API keys
- **Database Enumeration**: Complete database structure mapping
- **File System Exploration**: Comprehensive file system traversal and content extraction
- **Severity-Based Classification**: CRITICAL, HIGH, MEDIUM, LOW severity levels

### 💻 Enhanced Web Interface
- **Real-Time Dashboard**: Live scan progress and results
- **Critical Alert System**: Red highlighting for confirmed data extraction
- **Data Visualization**: Extracted credentials, database content, and file contents
- **Severity Indicators**: Color-coded vulnerability classification
- **Interactive Results**: Expandable vulnerability details with extracted data
- **Export Capabilities**: Save scan results for reporting

## Installation

### Prerequisites
- Python 3.8+
- pip package manager
- (Optional) Ollama for local LLM support

### Quick Setup

1. **Clone or download the project files**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the web interface:**
   Open your browser and navigate to `http://localhost:5000`

## Configuration

### Gemini API Setup
1. Get your Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Enter the API key in the web interface configuration panel
3. Leave "Use Ollama" unchecked

### Ollama Setup (Local LLM)
1. Install Ollama from [https://ollama.ai/](https://ollama.ai/)
2. Pull a model: `ollama pull llama2`
3. Start Ollama service: `ollama serve`
4. In the web interface, check "Use Ollama" and select your model

## Usage

### Basic Scanning

1. **Configure the Scanner:**
   - Enter your target URL (e.g., `http://localhost:3000`)
   - Choose between Gemini API or Ollama
   - Configure your API key or local model

2. **Select Vulnerability Types:**
   - Toggle the switches for vulnerability types you want to test
   - All types are enabled by default

3. **Discover URLs:**
   - Click "Discover URLs" to automatically find internal endpoints
   - The scanner will crawl and map the target application

4. **Start Comprehensive Scan:**
   - Click "Start Comprehensive Scan"
   - Monitor progress in real-time
   - View results as they appear

### Advanced Features

#### Custom Payload Generation
The LLM integration allows for:
- Context-aware payload generation based on discovered URLs
- Adaptive payloads that learn from previous scan results
- Sophisticated encoding and bypass techniques
- Target-specific attack vectors

#### Iterative Testing
The scanner employs multiple testing strategies:
- Parameter fuzzing with different payload types
- Encoding variation testing (URL, HTML, Unicode, etc.)
- Time-based blind vulnerability detection
- Error message analysis for information disclosure

#### Smart URL Discovery
Advanced crawling capabilities:
- Recursive link following with configurable depth
- Form action URL extraction
- JavaScript-based endpoint discovery
- API endpoint pattern recognition

## Vulnerability Types

### SQL Injection
- **Union-based**: Data extraction through UNION queries
- **Boolean-based**: Blind SQL injection using boolean logic
- **Time-based**: Blind detection using database delay functions
- **Error-based**: Information extraction through error messages
- **Second-order**: Advanced injection in stored procedures

### Cross-Site Scripting (XSS)
- **Reflected**: Immediate payload reflection testing
- **Stored**: Persistent XSS detection
- **DOM-based**: Client-side XSS identification
- **Filter bypass**: Advanced encoding and obfuscation techniques

### Local File Inclusion (LFI)
- **Path traversal**: Directory traversal attacks
- **Wrapper exploitation**: PHP wrapper abuse
- **Log poisoning**: Log file inclusion attacks
- **Filter bypass**: Null byte and encoding bypasses

### Command Injection
- **Direct injection**: Immediate command execution
- **Blind injection**: Time-based detection methods
- **Output redirection**: Command output capture techniques
- **Bypass methods**: Filter evasion strategies

### XXE Injection
- **External entity**: File disclosure attacks
- **SSRF via XXE**: Server-side request forgery
- **Blind XXE**: Out-of-band detection methods
- **Parameter entity**: Advanced XXE techniques

## Security Considerations

### Responsible Usage
- Only test applications you own or have explicit permission to test
- Be mindful of the impact on target systems
- Follow responsible disclosure practices
- Respect rate limits and server resources

### Legal Compliance
- Ensure you have proper authorization before testing
- Follow local laws and regulations
- Document your testing activities
- Use the tool only for legitimate security testing

## Database Schema

The scanner stores results in SQLite with the following schema:

```sql
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    target_url TEXT,
    vulnerability_type TEXT,
    payload TEXT,
    response_code INTEGER,
    response_content TEXT,
    is_vulnerable BOOLEAN,
    confidence_score REAL
);
```

## API Endpoints

- `GET /` - Main web interface
- `POST /configure` - Configure scanner settings
- `POST /discover_urls` - Discover internal URLs
- `POST /scan` - Start vulnerability scan
- `GET /results` - Retrieve scan results
- `GET /status` - Get scanner status

## Troubleshooting

### Common Issues

**Gemini API Errors:**
- Verify your API key is correct
- Check API quota and billing status
- Ensure internet connectivity

**Ollama Connection Issues:**
- Verify Ollama service is running (`ollama serve`)
- Check if the selected model is available (`ollama list`)
- Ensure port 11434 is accessible

**Scan Failures:**
- Check target URL accessibility
- Verify network connectivity
- Review firewall and proxy settings

**Performance Issues:**
- Reduce scan scope for large applications
- Adjust timeout settings
- Monitor system resources

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## Disclaimer

This tool is designed for legitimate security testing and educational purposes. The developers are not responsible for any misuse of this tool. Always ensure you have proper authorization before testing any systems.

## Support

For questions, issues, or feature requests, please create an issue in the project repository or contact the development team.

---

**Happy Ethical Hacking! 🔒**
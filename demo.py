#!/usr/bin/env python3
"""
Demo Script for LLM-Powered Vulnerability Scanner
================================================

This script demonstrates how to use the vulnerability scanner programmatically
without the web interface.
"""

import sys
import time
from app import VulnerabilityScanner

def demo_scan():
    """Demonstrate the vulnerability scanner capabilities"""
    
    print("🔒 LLM-Powered Vulnerability Scanner Demo")
    print("=" * 50)
    
    # Initialize scanner
    scanner = VulnerabilityScanner()
    
    # Get target URL from user
    target_url = input("Enter target URL (e.g., http://localhost:3000): ").strip()
    if not target_url:
        print("❌ No target URL provided")
        return
    
    # Configure LLM
    print("\nLLM Configuration:")
    print("1. Use Gemini API (requires API key)")
    print("2. Use Ollama (local)")
    print("3. Skip LLM (use default payloads)")
    
    choice = input("Choose option (1-3): ").strip()
    
    if choice == "1":
        api_key = input("Enter Gemini API key: ").strip()
        if api_key:
            scanner.configure_llm(api_key=api_key, use_ollama=False)
            print("✅ Configured with Gemini API")
        else:
            print("⚠️  No API key provided, using default payloads")
    elif choice == "2":
        model = input("Enter Ollama model name (default: llama2): ").strip() or "llama2"
        scanner.configure_llm(ollama_model=model, use_ollama=True)
        print(f"✅ Configured with Ollama model: {model}")
    else:
        print("✅ Using default payloads")
    
    # Discover URLs
    print(f"\n🔍 Discovering URLs from {target_url}...")
    try:
        urls = scanner.discover_urls(target_url, max_depth=1)
        print(f"✅ Discovered {len(urls)} URLs:")
        for i, url in enumerate(urls[:10], 1):  # Show first 10 URLs
            print(f"   {i}. {url}")
        if len(urls) > 10:
            print(f"   ... and {len(urls) - 10} more")
    except Exception as e:
        print(f"❌ URL discovery failed: {e}")
        urls = [target_url]
    
    # Select vulnerability types
    print("\nVulnerability Types:")
    vuln_types = {
        '1': 'sql_injection',
        '2': 'xss',
        '3': 'lfi',
        '4': 'command_injection',
        '5': 'xxe'
    }
    
    for key, vuln_type in vuln_types.items():
        print(f"{key}. {vuln_type.replace('_', ' ').title()}")
    
    selected = input("Select types (comma-separated, e.g., 1,2,3): ").strip()
    if selected:
        scan_types = [vuln_types[num.strip()] for num in selected.split(',') 
                     if num.strip() in vuln_types]
    else:
        scan_types = list(vuln_types.values())
    
    print(f"✅ Selected: {', '.join(scan_types)}")
    
    # Run scan
    print(f"\n🚀 Starting vulnerability scan...")
    print("This may take several minutes depending on the number of URLs and vulnerability types.")
    
    start_time = time.time()
    results = []
    
    for url in urls[:5]:  # Limit to first 5 URLs for demo
        for scan_type in scan_types:
            print(f"   Testing {scan_type} on {url}")
            
            try:
                if scan_type == 'sql_injection':
                    test_results = scanner.test_sql_injection(url)
                elif scan_type == 'xss':
                    test_results = scanner.test_xss(url)
                elif scan_type == 'lfi':
                    test_results = scanner.test_lfi(url)
                elif scan_type == 'command_injection':
                    test_results = scanner.test_command_injection(url)
                elif scan_type == 'xxe':
                    test_results = scanner.test_xxe(url)
                else:
                    continue
                
                results.extend(test_results)
                
                # Show immediate results
                vulnerabilities = [r for r in test_results if r['is_vulnerable']]
                if vulnerabilities:
                    print(f"      ⚠️  Found {len(vulnerabilities)} potential vulnerabilities!")
                
            except Exception as e:
                print(f"      ❌ Error testing {scan_type}: {e}")
    
    # Display results
    elapsed_time = time.time() - start_time
    print(f"\n📊 Scan completed in {elapsed_time:.1f} seconds")
    print("=" * 50)
    
    vulnerabilities = [r for r in results if r['is_vulnerable']]
    safe_tests = [r for r in results if not r['is_vulnerable']]
    
    print(f"Total tests performed: {len(results)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    print(f"Safe endpoints: {len(safe_tests)}")
    
    if vulnerabilities:
        print("\n🚨 VULNERABILITIES FOUND:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{i}. {vuln['vulnerability_type']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Payload: {vuln['payload'][:100]}...")
            print(f"   Confidence: {vuln['confidence_score']*100:.1f}%")
            print(f"   Response Code: {vuln['response_code']}")
    else:
        print("\n✅ No vulnerabilities detected in the tested endpoints.")
    
    print(f"\n💾 Results saved to database: scanner_results.db")
    print("\nFor more detailed analysis, use the web interface:")
    print("   python run.py")

def show_database_stats():
    """Show statistics from previous scans"""
    try:
        import sqlite3
        conn = sqlite3.connect('scanner_results.db')
        c = conn.cursor()
        
        # Total scans
        c.execute("SELECT COUNT(*) FROM scan_results")
        total_tests = c.fetchone()[0]
        
        # Vulnerabilities found
        c.execute("SELECT COUNT(*) FROM scan_results WHERE is_vulnerable = 1")
        total_vulns = c.fetchone()[0]
        
        # By vulnerability type
        c.execute("""SELECT vulnerability_type, COUNT(*) 
                     FROM scan_results WHERE is_vulnerable = 1 
                     GROUP BY vulnerability_type""")
        vuln_by_type = c.fetchall()
        
        print("📈 Database Statistics:")
        print(f"   Total tests performed: {total_tests}")
        print(f"   Total vulnerabilities found: {total_vulns}")
        
        if vuln_by_type:
            print("   Vulnerabilities by type:")
            for vuln_type, count in vuln_by_type:
                print(f"     - {vuln_type}: {count}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Could not read database: {e}")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--stats':
        show_database_stats()
    else:
        try:
            demo_scan()
        except KeyboardInterrupt:
            print("\n\n👋 Demo stopped by user")
        except Exception as e:
            print(f"\n❌ Demo failed: {e}")
            sys.exit(1)
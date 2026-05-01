# Automated Vulnerability Scanner

A modular, Python-based automated vulnerability scanner designed for basic network and web application security testing.

## Features
- **Port Scanning**: Scans common ports to identify open services.
- **Web Crawling**: Extracts links and forms from the target website.
- **Security Headers Check**: Identifies missing essential HTTP security headers.
- **XSS Scanning**: Tests URL parameters and forms for Cross-Site Scripting vulnerabilities.
- **SQLi Scanning**: Tests URL parameters and forms for basic SQL Injection vulnerabilities.

## Installation

1. Make sure you have Python 3 installed.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the scanner using the `run.py` script:

```bash
python run.py --target http://example.com
```

### Options
- `--target` or `-t`: The target URL or IP address (e.g., `http://example.com` or `192.168.1.1`).
- `--ports` or `-p`: Comma-separated list of ports to scan (default: 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080).
- `--depth` or `-d`: Crawling depth for the web scanner (default: 2).
- `--output` or `-o`: Path to save the JSON report (e.g., `report.json`).

## Disclaimer
This tool is for educational purposes and authorized testing only. Do not use it against systems you do not own or have explicit permission to test.

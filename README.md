# CyberShield
### Vulnerability Scanner & Penetration Testing Framework

A full-stack cybersecurity tool built with Python and Flask featuring
real-time scanning, CVE lookup, pentest modules, and PDF report generation.

## Features
- Port scanning with Nmap service detection
- Live CVE lookup via NVD API
- Penetration testing: SQLi, XSS, directory traversal, header analysis
- Real-time WebSocket terminal output
- PDF and JSON report generation
- Login authentication with session management
- Rate limiting on all API endpoints
- Dark terminal web UI

## Installation

### Requirements
- Python 3.10+
- Nmap installed on system

### Setup
```bash
git clone https://github.com/yourusername/cybershield.git 

cd cybershield

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env

python run.py
```

### Docker
```bash
docker-compose up --build
```

### Default login
- Username: admin
- Password: cybershield123 (change in .env)

## Usage
1. Open http://localhost:5000
2. Log in with your credentials
3. Go to SCANNER — enter target IP or domain
4. Select port range and click RUN SCAN
5. View live output, results, and download PDF report
6. Go to PENTEST — enter target URL for web vulnerability testing

## Tech Stack
- Backend: Python, Flask, Flask-SocketIO
- Scanner: python-nmap, socket
- CVE Data: NVD API (NIST)
- Reports: fpdf2
- Auth: Flask sessions, SHA-256
- Frontend: Vanilla JS, WebSockets, CSS dark terminal theme

## Disclaimer
For authorized and educational use only.
Always obtain permission before scanning any target.

## License
MIT

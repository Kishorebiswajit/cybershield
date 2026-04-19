import sys
sys.path.insert(0, '.')

from app.scanner.port_scanner import scan_ports_basic, grab_banner
from app.scanner.vuln_engine import search_cves, calculate_risk_score
from app.scanner.pentest import test_headers
from app.scanner.report import generate_pdf_report, save_json_report

print("=" * 50)
print("CYBERSHIELD — MODULE TEST SUITE")
print("=" * 50)

print("\n[1] Testing port scanner...")
ports = scan_ports_basic("127.0.0.1", "1-1024")
print(f"    Open ports on localhost: {ports}")
assert isinstance(ports, list), "FAIL: port scanner"
print("    PASS")

print("\n[2] Testing CVE lookup...")
cves = search_cves("openssh", results_per_page=2)
assert isinstance(cves, list), "FAIL: cve lookup"
print(f"    Found {len(cves)} CVEs")
print("    PASS")

print("\n[3] Testing risk scoring...")
fake_vulns = [
    {"severity": "CRITICAL"},
    {"severity": "HIGH"},
    {"severity": "MEDIUM"}
]
risk = calculate_risk_score(fake_vulns)
assert risk["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
print(f"    Risk level: {risk['level']}")
print("    PASS")

print("\n[4] Testing header analysis...")
h = test_headers("http://localhost:5000")
assert isinstance(h, list)
print(f"    Found {len(h)} header issues")
print("    PASS")

print("\n[5] Testing report generation...")
fake_scan = {
    "target": "test_target",
    "timestamp": "2025-01-01 12:00:00",
    "open_ports": [22, 80],
    "nmap_results": [
        {"port": 22, "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "8.9"}
    ],
    "vulnerabilities": [
        {"cve_id": "CVE-2023-0001", "severity": "HIGH",
         "score": 7.5, "port": 22, "description": "Test"}
    ],
    "risk": {
        "level": "HIGH", "summary": "Test", "critical": 0,
        "high": 1, "medium": 0, "low": 0, "total_vulns": 1
    }
}
pdf = generate_pdf_report(fake_scan)
jsn = save_json_report(fake_scan)
assert pdf.endswith(".pdf")
assert jsn.endswith(".json")
print(f"    PDF: {pdf}")
print(f"    JSON: {jsn}")
print("    PASS")

print("\n" + "=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)

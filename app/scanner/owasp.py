import requests
import re
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Software Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF"
}

SECURITY_HEADERS = {
    "Content-Security-Policy":       {"severity": "HIGH",   "impact": "XSS and injection attacks"},
    "X-Frame-Options":               {"severity": "MEDIUM", "impact": "Clickjacking attacks"},
    "X-Content-Type-Options":        {"severity": "MEDIUM", "impact": "MIME type sniffing"},
    "Strict-Transport-Security":     {"severity": "HIGH",   "impact": "SSL stripping / MITM"},
    "Referrer-Policy":               {"severity": "LOW",    "impact": "Information leakage"},
    "Permissions-Policy":            {"severity": "LOW",    "impact": "Feature abuse"},
    "X-XSS-Protection":              {"severity": "MEDIUM", "impact": "Reflected XSS"},
    "Cross-Origin-Opener-Policy":    {"severity": "LOW",    "impact": "Cross-origin attacks"},
    "Cross-Origin-Resource-Policy":  {"severity": "LOW",    "impact": "Data leakage"},
    "Cache-Control":                 {"severity": "LOW",    "impact": "Sensitive data caching"},
}

OWASP_RISK_MATRIX = {
    "likelihood": {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
    "impact":     {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
}


def check_a01_broken_access(url, mode="quick"):
    findings = []
    admin_paths = [
        "/admin", "/admin/users", "/admin/config",
        "/api/admin", "/dashboard/admin", "/manage",
        "/wp-admin", "/administrator", "/superuser",
        "/api/v1/users", "/api/v1/admin", "/config",
        "/.env", "/.git/config", "/backup",
    ]
    if mode == "deep":
        admin_paths += [
            "/api/v2/admin", "/console", "/phpmyadmin",
            "/server-status", "/actuator", "/actuator/env",
            "/actuator/health", "/swagger-ui.html",
            "/api-docs", "/graphql", "/debug",
        ]
    for path in admin_paths:
        try:
            r = requests.get(urljoin(url, path), timeout=4,
                             verify=False, allow_redirects=False)
            if r.status_code == 200:
                findings.append({
                    "owasp": "A01", "category": OWASP_TOP10["A01"],
                    "severity": "CRITICAL", "path": path,
                    "status": r.status_code,
                    "detail": f"Sensitive path accessible: {path}",
                    "evidence": f"HTTP 200 — {len(r.text)} bytes returned"
                })
            elif r.status_code == 403:
                findings.append({
                    "owasp": "A01", "category": OWASP_TOP10["A01"],
                    "severity": "MEDIUM", "path": path,
                    "status": r.status_code,
                    "detail": f"Path exists but forbidden: {path}",
                    "evidence": "HTTP 403 — resource exists"
                })
        except Exception:
            pass
    return findings


def check_a02_crypto(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme == "http":
        findings.append({
            "owasp": "A02", "category": OWASP_TOP10["A02"],
            "severity": "HIGH",
            "detail": "Site uses HTTP — no encryption in transit",
            "evidence": f"URL scheme is http:// not https://"
        })
    try:
        r = requests.get(url, timeout=5, verify=False)
        cookies = r.cookies
        for cookie in cookies:
            if not cookie.secure:
                findings.append({
                    "owasp": "A02", "category": OWASP_TOP10["A02"],
                    "severity": "MEDIUM",
                    "detail": f"Cookie '{cookie.name}' missing Secure flag",
                    "evidence": f"Cookie set without Secure attribute"
                })
            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "owasp": "A02", "category": OWASP_TOP10["A02"],
                    "severity": "MEDIUM",
                    "detail": f"Cookie '{cookie.name}' missing HttpOnly flag",
                    "evidence": "Cookie accessible via JavaScript"
                })
    except Exception:
        pass
    return findings


def check_a03_injection(url, mode="quick"):
    findings = []
    sql_payloads = ["'", "\" OR \"1\"=\"1", "1; DROP TABLE--", "' OR SLEEP(3)--"]
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    test_params = {"id": "1", "q": "test", "search": "test", "input": "test"}

    if mode == "deep":
        sql_payloads += [
            "' UNION SELECT NULL--", "1' AND 1=1--",
            "'; EXEC xp_cmdshell('dir')--",
            "' OR 1=1 LIMIT 1--"
        ]
        xss_payloads += [
            "<svg onload=alert(1)>",
            "';alert(1);//",
            "\"><script>alert(1)</script>"
        ]

    sql_errors = [
        "sql syntax", "mysql_fetch", "syntax error",
        "ora-01756", "sqlite_error", "pg_query",
        "unclosed quotation", "odbc_exec"
    ]

    for param in test_params:
        for payload in sql_payloads:
            try:
                p = test_params.copy()
                p[param] = payload
                r = requests.get(url, params=p, timeout=4, verify=False)
                for err in sql_errors:
                    if err in r.text.lower():
                        findings.append({
                            "owasp": "A03", "category": OWASP_TOP10["A03"],
                            "severity": "CRITICAL",
                            "detail": f"SQL injection in param '{param}'",
                            "evidence": f"Error pattern '{err}' in response",
                            "payload": payload
                        })
                        break
            except Exception:
                pass

        for payload in xss_payloads[:2]:
            try:
                p = test_params.copy()
                p[param] = payload
                r = requests.get(url, params=p, timeout=4, verify=False)
                if payload in r.text:
                    findings.append({
                        "owasp": "A03", "category": OWASP_TOP10["A03"],
                        "severity": "HIGH",
                        "detail": f"Reflected XSS in param '{param}'",
                        "evidence": "Payload reflected unescaped in response",
                        "payload": payload
                    })
            except Exception:
                pass
    return findings


def check_a05_misconfiguration(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        if server:
            findings.append({
                "owasp": "A05", "category": OWASP_TOP10["A05"],
                "severity": "LOW",
                "detail": f"Server version disclosed: {server}",
                "evidence": f"Server: {server}"
            })
        if powered:
            findings.append({
                "owasp": "A05", "category": OWASP_TOP10["A05"],
                "severity": "LOW",
                "detail": f"Technology disclosed: {powered}",
                "evidence": f"X-Powered-By: {powered}"
            })

        error_urls = [urljoin(url, "/thisdoesnotexist_xyz")]
        for eu in error_urls:
            try:
                er = requests.get(eu, timeout=4, verify=False)
                if any(x in er.text.lower() for x in
                       ["traceback", "stack trace", "debug", "exception", "werkzeug"]):
                    findings.append({
                        "owasp": "A05", "category": OWASP_TOP10["A05"],
                        "severity": "HIGH",
                        "detail": "Debug/stack trace exposed in error pages",
                        "evidence": "Error page reveals internal stack trace"
                    })
            except Exception:
                pass
    except Exception:
        pass
    return findings


def check_a07_auth(url):
    findings = []
    login_paths = ["/login", "/signin", "/admin/login", "/user/login", "/auth"]
    weak_creds = [
        ("admin", "admin"), ("admin", "password"),
        ("admin", "123456"), ("root", "root"),
        ("test", "test"), ("admin", "admin123")
    ]

    for path in login_paths:
        login_url = urljoin(url, path)
        try:
            r = requests.get(login_url, timeout=4, verify=False)
            if r.status_code == 200:
                for user, pwd in weak_creds[:3]:
                    try:
                        pr = requests.post(
                            login_url,
                            data={"username": user, "password": pwd,
                                  "user": user, "pass": pwd},
                            timeout=4, verify=False, allow_redirects=True
                        )
                        if pr.status_code in [200, 302]:
                            if any(x in pr.text.lower() for x in
                                   ["dashboard", "logout", "welcome", "profile"]):
                                findings.append({
                                    "owasp": "A07", "category": OWASP_TOP10["A07"],
                                    "severity": "CRITICAL",
                                    "detail": f"Weak credentials work: {user}/{pwd}",
                                    "evidence": f"Login at {path} succeeded",
                                    "path": path
                                })
                    except Exception:
                        pass
        except Exception:
            pass
    return findings


def check_owasp_headers(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        for header, info in SECURITY_HEADERS.items():
            if header not in r.headers:
                findings.append({
                    "owasp": "A05", "category": "Security Headers",
                    "severity": info["severity"],
                    "detail": f"Missing header: {header}",
                    "evidence": f"Enables: {info['impact']}"
                })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings


def calculate_owasp_risk(findings):
    if not findings:
        return {"score": 0, "rating": "INFORMATIONAL",
                "likelihood": "LOW", "impact": "LOW",
                "summary": "No OWASP issues found"}

    sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    total = sum(sev_map.get(f.get("severity", "LOW"), 1) for f in findings)
    avg = total / len(findings)

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")

    if critical > 0 or avg >= 3.5:
        rating, likelihood, impact = "CRITICAL", "HIGH", "CRITICAL"
    elif high > 2 or avg >= 2.5:
        rating, likelihood, impact = "HIGH", "HIGH", "HIGH"
    elif avg >= 1.5:
        rating, likelihood, impact = "MEDIUM", "MEDIUM", "MEDIUM"
    else:
        rating, likelihood, impact = "LOW", "LOW", "LOW"

    by_category = {}
    for f in findings:
        cat = f.get("owasp", "OTHER")
        by_category[cat] = by_category.get(cat, 0) + 1

    return {
        "score": round(avg * 2.5, 1),
        "rating": rating,
        "likelihood": likelihood,
        "impact": impact,
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low": sum(1 for f in findings if f.get("severity") == "LOW"),
        "by_category": by_category,
        "summary": f"{len(findings)} OWASP issues — Risk: {rating}"
    }


def run_owasp_scan(url, mode="quick"):
    print(f"[*] Starting OWASP scan on {url} ({mode} mode)")
    all_findings = []

    print("[*] A01 — Broken Access Control...")
    all_findings += check_a01_broken_access(url, mode)

    print("[*] A02 — Cryptographic Failures...")
    all_findings += check_a02_crypto(url)

    print("[*] A03 — Injection...")
    all_findings += check_a03_injection(url, mode)

    print("[*] A05 — Security Misconfiguration...")
    all_findings += check_a05_misconfiguration(url)

    print("[*] A07 — Authentication Failures...")
    all_findings += check_a07_auth(url)

    print("[*] Security Headers check...")
    all_findings += check_owasp_headers(url)

    risk = calculate_owasp_risk(all_findings)
    print(f"[+] OWASP scan complete — {len(all_findings)} findings, Risk: {risk['rating']}")

    return {
        "target": url,
        "mode": mode,
        "findings": all_findings,
        "risk": risk
    }

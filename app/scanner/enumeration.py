import dns.resolver
import whois
import requests
import socket
from urllib.parse import urljoin
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
    "blog", "dev", "staging", "api", "admin", "portal",
    "vpn", "remote", "secure", "shop", "m", "app",
    "test", "beta", "cdn", "static", "media", "images",
    "support", "help", "docs", "git", "gitlab", "jenkins",
]

COMMON_DIRS = [
    "/admin", "/login", "/dashboard", "/api", "/api/v1",
    "/api/v2", "/backup", "/config", "/uploads", "/files",
    "/images", "/static", "/assets", "/css", "/js",
    "/.env", "/.git", "/robots.txt", "/sitemap.xml",
    "/wp-admin", "/wp-content", "/phpmyadmin", "/console",
    "/actuator", "/swagger", "/graphql", "/debug",
    "/server-status", "/info.php", "/test", "/tmp",
    "/old", "/archive", "/download", "/downloads",
]

TECH_SIGNATURES = {
    "WordPress":   {"header": "x-powered-by", "pattern": "wordpress",  "body": "wp-content"},
    "Drupal":      {"header": "",              "pattern": "",           "body": "drupal"},
    "Joomla":      {"header": "",              "pattern": "",           "body": "joomla"},
    "Laravel":     {"header": "x-powered-by", "pattern": "php",        "body": "laravel"},
    "Django":      {"header": "",              "pattern": "",           "body": "csrfmiddlewaretoken"},
    "Flask":       {"header": "server",        "pattern": "werkzeug",   "body": ""},
    "Express.js":  {"header": "x-powered-by", "pattern": "express",    "body": ""},
    "ASP.NET":     {"header": "x-powered-by", "pattern": "asp.net",    "body": ""},
    "PHP":         {"header": "x-powered-by", "pattern": "php",        "body": ""},
    "Nginx":       {"header": "server",        "pattern": "nginx",      "body": ""},
    "Apache":      {"header": "server",        "pattern": "apache",     "body": ""},
    "IIS":         {"header": "server",        "pattern": "iis",        "body": ""},
    "Cloudflare":  {"header": "server",        "pattern": "cloudflare", "body": ""},
    "React":       {"header": "",              "pattern": "",           "body": "react"},
    "Vue.js":      {"header": "",              "pattern": "",           "body": "vue"},
    "jQuery":      {"header": "",              "pattern": "",           "body": "jquery"},
    "Bootstrap":   {"header": "",              "pattern": "",           "body": "bootstrap"},
}


def dns_enumerate(domain):
    results = {
        "domain": domain,
        "subdomains": [],
        "records": {},
        "errors": []
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except Exception:
            pass

    print(f"[*] Brute-forcing {len(COMMON_SUBDOMAINS)} subdomains...")
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            results["subdomains"].append({
                "subdomain": fqdn,
                "ips": ips,
                "status": "LIVE"
            })
            print(f"[+] Found: {fqdn} -> {ips}")
        except Exception:
            pass

    return results


def whois_lookup(target):
    result = {
        "target": target,
        "domain_name": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "country": None,
        "org": None,
        "emails": [],
        "ip_info": {}
    }

    try:
        w = whois.whois(target)
        result["domain_name"] = str(w.domain_name) if w.domain_name else None
        result["registrar"] = str(w.registrar) if w.registrar else None
        result["country"] = str(w.country) if w.country else None
        result["org"] = str(w.org) if w.org else None

        if w.creation_date:
            d = w.creation_date
            result["creation_date"] = str(d[0] if isinstance(d, list) else d)
        if w.expiration_date:
            d = w.expiration_date
            result["expiration_date"] = str(d[0] if isinstance(d, list) else d)
        if w.name_servers:
            ns = w.name_servers
            result["name_servers"] = list(ns) if isinstance(ns, list) else [str(ns)]
        if w.emails:
            em = w.emails
            result["emails"] = list(em) if isinstance(em, list) else [str(em)]
    except Exception as e:
        result["error"] = str(e)

    try:
        ip = socket.gethostbyname(target)
        result["ip_info"]["resolved_ip"] = ip

        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if geo.status_code == 200:
            g = geo.json()
            result["ip_info"]["country"] = g.get("country_name")
            result["ip_info"]["city"] = g.get("city")
            result["ip_info"]["org"] = g.get("org")
            result["ip_info"]["isp"] = g.get("isp")
            result["ip_info"]["timezone"] = g.get("timezone")
            result["ip_info"]["latitude"] = g.get("latitude")
            result["ip_info"]["longitude"] = g.get("longitude")
    except Exception:
        pass

    return result


def fingerprint_tech(url):
    detected = []

    try:
        r = requests.get(url, timeout=6, verify=False)
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        body = r.text.lower()

        for tech, sig in TECH_SIGNATURES.items():
            matched = False
            if sig["header"] and sig["pattern"]:
                if sig["header"] in headers and sig["pattern"] in headers[sig["header"]]:
                    matched = True
            if sig["body"] and sig["body"] in body:
                matched = True
            if matched:
                detected.append({
                    "technology": tech,
                    "confidence": "HIGH" if sig["header"] and sig["header"] in headers else "MEDIUM",
                    "evidence": f"Detected via {'header' if sig['header'] in headers else 'body'}"
                })

        meta_tags = re.findall(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)["\']',
                               r.text, re.IGNORECASE)
        for m in meta_tags:
            detected.append({
                "technology": m.strip(),
                "confidence": "HIGH",
                "evidence": "Meta generator tag"
            })

        title_match = re.search(r'<title>([^<]+)</title>', r.text, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "N/A"

        return {
            "url": url,
            "status_code": r.status_code,
            "title": title,
            "server": r.headers.get("Server", "Unknown"),
            "content_type": r.headers.get("Content-Type", ""),
            "technologies": detected
        }
    except Exception as e:
        return {"url": url, "error": str(e), "technologies": []}


def dir_brute_force(base_url, wordlist=None, emit=None):
    paths = wordlist if wordlist else COMMON_DIRS
    found = []
    total = len(paths)

    if emit:
        emit('enum_log', {'msg': f'[*] Brute forcing {total} paths...', 'cls': 't-blue'})

    for i, path in enumerate(paths):
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403, 401]:
                entry = {
                    "path": path,
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.text),
                    "severity": "CRITICAL" if r.status_code == 200 and path in
                                ["/.env", "/.git", "/config", "/backup"]
                                else ("HIGH" if r.status_code == 200 else "LOW")
                }
                found.append(entry)
                if emit:
                    color = 't-red' if entry['severity'] == 'CRITICAL' else \
                            't-green' if r.status_code == 200 else 't-muted'
                    emit('enum_log', {
                        'msg': f'[{r.status_code}] {path} ({len(r.text)} bytes)',
                        'cls': color
                    })

        except Exception:
            pass

        if emit and i % 10 == 0:
            pct = int((i / total) * 100)
            emit('enum_progress', {'value': pct})

    if emit:
        emit('enum_progress', {'value': 100})
        emit('enum_log', {'msg': f'[+] Dir scan complete — {len(found)} paths found', 'cls': 't-green'})

    return found


def run_enumeration(target, url=None, emit=None):
    results = {
        "target": target,
        "whois": {},
        "dns": {},
        "technologies": {},
        "directories": []
    }

    if emit:
        emit('enum_log', {'msg': f'[*] Starting enumeration on {target}', 'cls': 't-blue'})

    emit and emit('enum_log', {'msg': '[*] Running Whois lookup...', 'cls': 't-blue'})
    results["whois"] = whois_lookup(target)

    emit and emit('enum_log', {'msg': '[*] Running DNS enumeration...', 'cls': 't-blue'})
    results["dns"] = dns_enumerate(target)

    if url:
        emit and emit('enum_log', {'msg': '[*] Fingerprinting technologies...', 'cls': 't-blue'})
        results["technologies"] = fingerprint_tech(url)

        emit and emit('enum_log', {'msg': '[*] Running directory brute force...', 'cls': 't-blue'})
        results["directories"] = dir_brute_force(url, emit=emit)

    emit and emit('enum_log', {'msg': '[+] Enumeration complete', 'cls': 't-green'})
    emit and emit('enum_complete', results)

    return results


import re

import requests
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_SCORES = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NONE": 1
}


def search_cves(keyword, results_per_page=5):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page
    }

    try:
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            severity = "UNKNOWN"
            score = 0.0
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", 0.0)
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore", 0.0)
                if score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            cves.append({
                "cve_id": cve_id,
                "description": description[:300],
                "severity": severity,
                "score": score
            })

        return cves

    except requests.exceptions.RequestException as e:
        return [{"error": str(e)}]


def analyze_service_vulns(nmap_results):
    all_vulns = []

    for service in nmap_results:
        if "error" in service:
            continue

        product = service.get("product", "")
        version = service.get("version", "")
        service_name = service.get("service", "")

        keyword = product if product else service_name
        if not keyword:
            continue

        if version:
            keyword = f"{keyword} {version}"

        print(f"[*] Looking up CVEs for: {keyword}")
        cves = search_cves(keyword, results_per_page=3)

        for cve in cves:
            if "error" not in cve:
                cve["port"] = service.get("port")
                cve["service"] = service_name
                cve["product"] = product
                cve["version"] = version
                all_vulns.append(cve)

    return all_vulns


def calculate_risk_score(vulns):
    if not vulns:
        return {"score": 0, "level": "SAFE", "summary": "No vulnerabilities found"}

    total = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    for v in vulns:
        sev = v.get("severity", "LOW")
        total += SEVERITY_SCORES.get(sev, 1)
        if sev == "CRITICAL":
            critical += 1
        elif sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        else:
            low += 1

    avg = total / len(vulns)

    if critical > 0 or avg >= 4.5:
        level = "CRITICAL"
    elif high > 2 or avg >= 3.5:
        level = "HIGH"
    elif medium > 3 or avg >= 2.5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": round(avg, 2),
        "level": level,
        "total_vulns": len(vulns),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "summary": f"{len(vulns)} vulnerabilities found — Risk level: {level}"
    }

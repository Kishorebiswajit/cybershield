from flask import Blueprint, render_template, request, jsonify
from app.scanner import run_full_scan, analyze_service_vulns, calculate_risk_score
from app.scanner import run_pentest

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan')
def scan():
    return render_template('scan.html')

@main.route('/pentest')
def pentest():
    return render_template('pentest.html')

@main.route('/results')
def results():
    return render_template('results.html')

@main.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target = data.get('target', '')
    port_range = data.get('port_range', '1-1024')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    results = run_full_scan(target, port_range)
    vulns = analyze_service_vulns(results.get("nmap_results", []))
    risk = calculate_risk_score(vulns)
    results["vulnerabilities"] = vulns
    results["risk"] = risk
    return jsonify(results)

@main.route('/api/pentest', methods=['POST'])
def api_pentest():
    data = request.get_json()
    target_url = data.get('url', '')
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400
    results = run_pentest(target_url)
    return jsonify(results)

@main.route('/api/cve', methods=['POST'])
def api_cve():
    data = request.get_json()
    keyword = data.get('keyword', '')
    if not keyword:
        return jsonify({"error": "No keyword provided"}), 400
    from app.scanner import search_cves
    cves = search_cves(keyword)
    return jsonify({"results": cves})

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
from app import socketio
from app.scanner import run_full_scan, analyze_service_vulns, calculate_risk_score
from app.scanner import run_pentest
import threading

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

@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target', '')
    port_range = data.get('port_range', '1-1024')

    if not target:
        emit('scan_log', {'msg': '[!] No target provided', 'cls': 't-red'})
        return

    def do_scan():
        try:
            results = run_full_scan(target, port_range, emit=emit)
            vulns = analyze_service_vulns(results.get("nmap_results", []))
            risk = calculate_risk_score(vulns)
            results["vulnerabilities"] = vulns
            results["risk"] = risk

            emit('scan_log', {'msg': f'[+] Found {len(vulns)} vulnerabilities', 'cls': 't-red' if vulns else 't-green'})
            emit('scan_log', {'msg': f'[+] Risk level: {risk["level"]}', 'cls': 't-yellow'})
            emit('scan_progress', {'value': 100})
            emit('scan_complete', results)
        except Exception as e:
            emit('scan_log', {'msg': f'[!] Scan error: {str(e)}', 'cls': 't-red'})
            emit('scan_complete', {'error': str(e)})

    t = threading.Thread(target=do_scan)
    t.daemon = True
    t.start()

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

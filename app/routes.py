from flask import Blueprint, render_template, request, jsonify, send_file
from flask_socketio import emit
from app import socketio, limiter
from app.scanner import run_full_scan, analyze_service_vulns, calculate_risk_score
from app.scanner import run_pentest
from app.scanner import generate_pdf_report, save_json_report, list_reports
from app.auth import login_required
import threading

main = Blueprint('main', __name__)

@main.route('/')
@login_required
def index():
    return render_template('index.html')

@main.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

@main.route('/pentest')
@login_required
def pentest():
    return render_template('pentest.html')

@main.route('/results')
@login_required
def results():
    reports = list_reports()
    return render_template('results.html', reports=reports)

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

            json_file = save_json_report(results)
            emit('scan_log', {'msg': f'[+] JSON report saved: {json_file}', 'cls': 't-muted'})
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
@login_required
@limiter.limit("10 per minute")
def api_pentest():
    data = request.get_json()
    target_url = data.get('url', '')
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400
    results = run_pentest(target_url)
    return jsonify(results)

@main.route('/api/report/pdf', methods=['POST'])
@login_required
def api_pdf_report():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No scan data provided"}), 400
    try:
        filename = generate_pdf_report(data)
        return send_file(filename, as_attachment=True,
                         download_name=filename.split("/")[-1],
                         mimetype='application/pdf')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/report/json', methods=['POST'])
@login_required
def api_json_report():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No scan data provided"}), 400
    try:
        filename = save_json_report(data)
        return send_file(filename, as_attachment=True,
                         download_name=filename.split("/")[-1],
                         mimetype='application/json')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/api/reports', methods=['GET'])
@login_required
def api_list_reports():
    return jsonify(list_reports())

@main.route('/api/cve', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def api_cve():
    data = request.get_json()
    keyword = data.get('keyword', '')
    if not keyword:
        return jsonify({"error": "No keyword provided"}), 400
    from app.scanner import search_cves
    cves = search_cves(keyword)
    return jsonify({"results": cves})

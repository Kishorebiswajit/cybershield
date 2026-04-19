from flask import Blueprint, render_template, request, jsonify
from app.scanner import run_full_scan

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan')
def scan():
    return render_template('scan.html')

@main.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target = data.get('target', '')
    port_range = data.get('port_range', '1-1024')

    if not target:
        return jsonify({"error": "No target provided"}), 400

    results = run_full_scan(target, port_range)
    return jsonify(results)

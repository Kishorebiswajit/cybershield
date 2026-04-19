from flask_mail import Mail, Message
from flask import current_app

mail = Mail()


def send_critical_alert(scan_data, critical_vulns):
    recipient = current_app.config.get("ALERT_RECIPIENT", "")
    if not recipient:
        print("[!] No alert recipient configured")
        return False

    target = scan_data.get("target", "Unknown")
    timestamp = scan_data.get("timestamp", "")
    count = len(critical_vulns)

    subject = f"[CYBERSHIELD] CRITICAL Alert - {count} Critical Vuln(s) on {target}"

    body = f"""
CYBERSHIELD SECURITY ALERT
===========================

CRITICAL vulnerabilities detected during scan.

Target    : {target}
Scan Time : {timestamp}
Critical  : {count} vulnerability/vulnerabilities found

CRITICAL VULNERABILITIES
------------------------
"""

    for v in critical_vulns:
        body += f"""
CVE ID    : {v.get('cve_id', 'N/A')}
Port      : {v.get('port', 'N/A')}
Score     : {v.get('score', 'N/A')}
Service   : {v.get('service', 'N/A')}
Details   : {v.get('description', 'N/A')[:200]}
---
"""

    body += f"""

RISK SUMMARY
------------
Risk Level : {scan_data.get('risk', {}).get('level', 'N/A')}
Total Vulns: {scan_data.get('risk', {}).get('total_vulns', 0)}

--
This is an automated alert from CyberShield.
For authorized use only.
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: monospace; background: #0a0e17; color: #c0c8d8; padding: 20px; }}
  .header {{ background: #ff3333; color: #fff; padding: 16px 20px; border-radius: 6px; margin-bottom: 20px; }}
  .header h1 {{ margin: 0; font-size: 18px; letter-spacing: 2px; }}
  .header p {{ margin: 6px 0 0; font-size: 13px; opacity: 0.9; }}
  .meta {{ background: #0f1623; border: 1px solid #1e2d47; border-radius: 6px; padding: 16px; margin-bottom: 20px; }}
  .meta table {{ width: 100%; border-collapse: collapse; }}
  .meta td {{ padding: 6px 0; font-size: 13px; }}
  .meta td:first-child {{ color: #00bfff; width: 120px; }}
  .vuln-card {{ background: #1a0000; border: 1px solid #ff3333; border-radius: 6px; padding: 16px; margin-bottom: 12px; }}
  .vuln-title {{ color: #ff3333; font-size: 14px; font-weight: bold; margin-bottom: 10px; }}
  .vuln-row {{ display: flex; gap: 12px; font-size: 12px; margin: 4px 0; }}
  .vuln-key {{ color: #00bfff; width: 80px; }}
  .footer {{ margin-top: 24px; color: #4a5568; font-size: 11px; text-align: center; }}
  .badge {{ display: inline-block; background: #3d0000; color: #ff3333;
            border: 1px solid #ff3333; padding: 2px 10px; border-radius: 3px;
            font-size: 11px; letter-spacing: 1px; }}
</style>
</head>
<body>
<div class="header">
  <h1>CYBERSHIELD - CRITICAL SECURITY ALERT</h1>
  <p>{count} critical vulnerability/vulnerabilities detected on <strong>{target}</strong></p>
</div>

<div class="meta">
  <table>
    <tr><td>Target</td><td>{target}</td></tr>
    <tr><td>Scan Time</td><td>{timestamp}</td></tr>
    <tr><td>Risk Level</td><td><span class="badge">CRITICAL</span></td></tr>
    <tr><td>Total Vulns</td><td>{scan_data.get('risk', {}).get('total_vulns', 0)}</td></tr>
  </table>
</div>

<h3 style="color:#ff3333;letter-spacing:2px;font-size:13px;">// CRITICAL FINDINGS</h3>
"""

    for v in critical_vulns:
        html_body += f"""
<div class="vuln-card">
  <div class="vuln-title">{v.get('cve_id', 'N/A')} — Score: {v.get('score', 'N/A')}</div>
  <div class="vuln-row"><span class="vuln-key">Port</span><span>{v.get('port', 'N/A')}</span></div>
  <div class="vuln-row"><span class="vuln-key">Service</span><span>{v.get('service', 'N/A')}</span></div>
  <div class="vuln-row"><span class="vuln-key">Details</span><span>{v.get('description', 'N/A')[:200]}</span></div>
</div>
"""

    html_body += """
<div class="footer">
  Automated alert from CyberShield &nbsp;|&nbsp; Authorized use only
</div>
</body>
</html>
"""

    try:
        msg = Message(
            subject=subject,
            recipients=[recipient],
            body=body,
            html=html_body
        )
        mail.send(msg)
        print(f"[+] Critical alert email sent to {recipient}")
        return True
    except Exception as e:
        print(f"[!] Failed to send alert email: {e}")
        return False


def check_and_alert(scan_data):
    vulns = scan_data.get("vulnerabilities", [])
    critical_vulns = [v for v in vulns if v.get("severity", "").upper() == "CRITICAL"]

    if critical_vulns:
        print(f"[!] {len(critical_vulns)} CRITICAL vulnerabilities found — sending alert...")
        send_critical_alert(scan_data, critical_vulns)
    else:
        print("[*] No critical vulnerabilities — no alert needed")

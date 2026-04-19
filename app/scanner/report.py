import json
import os
from datetime import datetime
from fpdf import FPDF

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def save_json_report(scan_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan_data.get("target", "unknown").replace(".", "_")
    filename = f"{REPORTS_DIR}/scan_{target}_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(scan_data, f, indent=2)

    return filename


def generate_pdf_report(scan_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan_data.get("target", "unknown").replace(".", "_")
    filename = f"{REPORTS_DIR}/report_{target}_{timestamp}.pdf"

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_fill_color(10, 14, 23)
    pdf.rect(0, 0, 210, 297, 'F')

    pdf.set_font("Courier", "B", 22)
    pdf.set_text_color(0, 255, 65)
    pdf.cell(0, 12, "CYBERSHIELD", ln=True, align="C")

    pdf.set_font("Courier", "", 10)
    pdf.set_text_color(0, 191, 255)
    pdf.cell(0, 8, "Vulnerability Scanner & Penetration Testing Framework", ln=True, align="C")

    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(74, 85, 104)
    pdf.cell(0, 6, "For authorized use only", ln=True, align="C")
    pdf.ln(6)

    pdf.set_draw_color(30, 45, 71)
    pdf.set_line_width(0.5)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(6)

    def section_title(title):
        pdf.set_font("Courier", "B", 11)
        pdf.set_text_color(0, 255, 65)
        pdf.cell(0, 8, f"// {title.upper()}", ln=True)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)

    def key_val(key, val, color=(192, 200, 216)):
        pdf.set_font("Courier", "B", 9)
        pdf.set_text_color(0, 191, 255)
        pdf.cell(50, 6, key + ":", ln=False)
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, str(val), ln=True)

    section_title("Scan Summary")
    key_val("Target", scan_data.get("target", "N/A"))
    key_val("Scan Time", scan_data.get("timestamp", "N/A"))
    key_val("Open Ports", str(len(scan_data.get("open_ports", []))))
    key_val("Ports Found", ", ".join(map(str, scan_data.get("open_ports", []))) or "None")

    risk = scan_data.get("risk", {})
    risk_level = risk.get("level", "N/A")
    risk_colors = {
        "CRITICAL": (255, 51, 51),
        "HIGH": (255, 140, 0),
        "MEDIUM": (255, 215, 0),
        "LOW": (0, 255, 65),
        "SAFE": (0, 255, 65)
    }
    key_val("Risk Level", risk_level, color=risk_colors.get(risk_level, (192, 200, 216)))
    key_val("Total Vulns", str(risk.get("total_vulns", 0)))
    pdf.ln(4)

    nmap_results = scan_data.get("nmap_results", [])
    if nmap_results:
        section_title("Detected Services")
        pdf.set_font("Courier", "B", 8)
        pdf.set_text_color(0, 191, 255)
        pdf.cell(20, 6, "PORT", ln=False)
        pdf.cell(30, 6, "STATE", ln=False)
        pdf.cell(40, 6, "SERVICE", ln=False)
        pdf.cell(50, 6, "PRODUCT", ln=False)
        pdf.cell(0, 6, "VERSION", ln=True)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(1)

        for svc in nmap_results:
            if "error" in svc:
                continue
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(0, 255, 65)
            pdf.cell(20, 5, str(svc.get("port", "")), ln=False)
            pdf.set_text_color(192, 200, 216)
            pdf.cell(30, 5, svc.get("state", ""), ln=False)
            pdf.cell(40, 5, svc.get("service", ""), ln=False)
            pdf.cell(50, 5, svc.get("product", "")[:20], ln=False)
            pdf.cell(0, 5, svc.get("version", "")[:20], ln=True)
        pdf.ln(4)

    vulns = scan_data.get("vulnerabilities", [])
    if vulns:
        section_title("Vulnerabilities Found")
        sev_colors = {
            "CRITICAL": (255, 51, 51),
            "HIGH": (255, 140, 0),
            "MEDIUM": (255, 215, 0),
            "LOW": (0, 255, 65)
        }

        for v in vulns:
            sev = v.get("severity", "LOW").upper()
            color = sev_colors.get(sev, (192, 200, 216))

            pdf.set_font("Courier", "B", 9)
            pdf.set_text_color(*color)
            pdf.cell(0, 6, f"[{sev}] {v.get('cve_id', 'N/A')} - Score: {v.get('score', 0)}  |  Port: {v.get('port', 'N/A')}", ln=True)

            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(192, 200, 216)
            desc = v.get("description", "")[:200]
            pdf.multi_cell(0, 5, desc)
            pdf.ln(2)
        pdf.ln(2)

    section_title("Risk Summary")
    key_val("Critical", str(risk.get("critical", 0)), (255, 51, 51))
    key_val("High", str(risk.get("high", 0)), (255, 140, 0))
    key_val("Medium", str(risk.get("medium", 0)), (255, 215, 0))
    key_val("Low", str(risk.get("low", 0)), (0, 255, 65))
    key_val("Overall Risk", risk.get("level", "N/A"), risk_colors.get(risk_level, (192, 200, 216)))
    pdf.ln(4)

    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(74, 85, 104)
    pdf.cell(0, 6, f"Generated by CyberShield  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Ethical use only", ln=True, align="C")

    pdf.output(filename)
    return filename


def list_reports():
    reports = []
    if not os.path.exists(REPORTS_DIR):
        return reports
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        full_path = os.path.join(REPORTS_DIR, f)
        reports.append({
            "filename": f,
            "path": full_path,
            "size": os.path.getsize(full_path),
            "created": datetime.fromtimestamp(
                os.path.getctime(full_path)
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "pdf" if f.endswith(".pdf") else "json"
        })
    return reports

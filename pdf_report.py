from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
import os

def generate_pdf_report(result):
    """Generate a professional PDF report with all findings.
    
    Args:
        result: A ScanResult dataclass instance
    """
    os.makedirs("reports", exist_ok=True)

    safe_target = result.target.replace("https://", "").replace("http://", "").replace("/", "")
    filename = f"reports/report_{safe_target}.pdf"

    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    
    # Colors
    c_critical = colors.HexColor("#ff4444")
    c_high = colors.HexColor("#ff8c00")
    c_medium = colors.HexColor("#ffd700")
    c_low = colors.HexColor("#00ff88")
    c_info = colors.HexColor("#2196f3") # Blue for info
    
    def get_color(severity):
        if severity == "Critical": return c_critical
        if severity == "High": return c_high
        if severity == "Medium": return c_medium
        if severity == "Info": return c_info
        return c_low

    y = height - 50

    # Title
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, y, "Vulnerability Scan Report")
    y -= 30

    # Meta
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Target: {result.target} ({result.ip})")
    y -= 20
    c.drawString(50, y, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 40
    
    # Executive Summary (Count risks)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for p_data in result.ports.values():
        counts[p_data["risk"]["severity"]] += 1
        
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Executive Summary")
    y -= 20
    
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Total Open Ports: {len(result.ports)}")
    y -= 20
    
    x_offset = 50
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        c.setFillColor(get_color(sev))
        c.drawString(x_offset, y, f"{sev}: {counts[sev]}")
        x_offset += 85
        
    c.setFillColor(colors.black)
    y -= 40

    # DNS Info
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "DNS Reconnaissance")
    y -= 20
    c.setFont("Helvetica", 11)
    if result.dns_info.get("reverse_dns"):
        c.drawString(50, y, f"Reverse DNS: {result.dns_info['reverse_dns']}")
        y -= 20
    if result.dns_info.get("aliases"):
        c.drawString(50, y, f"Aliases: {', '.join(result.dns_info['aliases'])}")
        y -= 30

    # Open Ports & Vulnerabilities
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Open Ports & Vulnerability Assessment")
    y -= 20
    
    for port, p_data in result.ports.items():
        if y < 100:  # New page if near bottom
             c.showPage()
             c.setFillColor(colors.black)
             y = height - 50
             
        sev = p_data["risk"]["severity"]
        c.setFillColor(get_color(sev))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"[{sev}] Port {port} -> {p_data['service']}")
        c.setFillColor(colors.black)
        
        y -= 15
        if p_data["banner"]:
             c.setFont("Helvetica-Oblique", 10)
             c.drawString(70, y, f"Banner: {p_data['banner']}")
             y -= 15
             
        c.setFont("Helvetica", 10)
        
        # Text wrap trick
        rec_text = p_data['risk']['recommendation']
        c.drawString(70, y, f"Rec: {rec_text[:80]}")
        if len(rec_text) > 80:
             y -= 15
             c.drawString(70, y, f"     {rec_text[80:]}")
             
        y -= 25

    # Headers and SSL
    if y < 200:
        c.showPage()
        y = height - 50
        
    if result.headers:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "HTTP Security Headers")
        y -= 20
        c.setFont("Helvetica", 12)
        c.drawString(50, y, f"Security Grade: {result.headers.get('grade', 'N/A')}")
        y -= 20
        c.setFont("Helvetica", 10)
        for missing in result.headers.get('missing', []):
             c.setFillColor(c_high)
             c.drawString(60, y, f"Missing: {missing['header']}")
             c.setFillColor(colors.black)
             y -= 15
        y -= 20

    if result.ssl:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "SSL/TLS Certificate")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Issuer: {result.ssl.get('issuer')}")
        y -= 15
        c.drawString(60, y, f"Valid Until: {result.ssl.get('valid_to')} ({result.ssl.get('days_until_expiry')} days)")
        
    c.save()
    return filename

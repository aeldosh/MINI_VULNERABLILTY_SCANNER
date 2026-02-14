from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import os

def generate_pdf_report(target, open_ports):
    os.makedirs("reports", exist_ok=True)

    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "")
    filename = f"reports/report_{safe_target}.pdf"

    c = canvas.Canvas(filename, pagesize=A4)
    text = c.beginText(40, 800)

    text.setFont("Helvetica-Bold", 16)
    text.textLine("Mini Vulnerability Scanner Report")
    text.textLine("")

    text.setFont("Helvetica", 12)
    text.textLine(f"Target: {target}")
    text.textLine(f"Date: {datetime.now()}")
    text.textLine("")

    text.textLine("Open Ports:")
    if open_ports:
        for port in open_ports:
            text.textLine(f"- Port {port}")
    else:
        text.textLine("No open ports found")

    text.textLine("")
    text.textLine("Security Recommendations:")
    text.textLine("- Close unused ports")
    text.textLine("- Use firewall rules")
    text.textLine("- Monitor exposed services")

    c.drawText(text)
    c.save()

    return filename

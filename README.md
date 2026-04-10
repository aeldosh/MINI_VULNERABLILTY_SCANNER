# 🛡️ Advanced Vulnerability Scanner

![Python versions](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)

An automated, multi-threaded vulnerability assessment scanner built in Python. Designed as a professional utility for footprinting, enumeration, and risk assessment of target infrastructure.

## ✨ Features

- **Concurrent Port Scanning:** Utilizes `ThreadPoolExecutor` to rapidly scan target endpoints.
- **Service Banner Grabbing:** Interrogates open sockets to extract exact web server and software version banners.
- **Risk Assessment Engine:** Analyzes active services, classifying risks (Critical, High, Medium, Low) and providing actionable remediation paths.
- **SSL/TLS Certificate Analysis:** Automatically extracts and validates x509 network certificates (Issuer, Subject, Validity duration).
- **HTTP Security Header Auditing:** Interrogates target web interfaces for strict security headers (HSTS, CSP, X-Frame-Options) and generates a security grade.
- **DNS Reconnaissance:** Fetches reverse DNS footprinting and network aliases automatically.
- **Advanced GUI Dashboard:** Comprehensive tabbed interface built with Tkinter, featuring live real-time terminal output, colored security severity tags, and target statistics.
- **Automated PDF Reporting:** Leverages the `reportlab` library to generate executive-ready PDF summaries listing DNS footprint, grouped port exposures, and security grading.

## 🏗️ Architecture

The scanner is completely modularized for scalability:
- `gui.py` - Main entrypoint triggering the scanner threads and managing the Tkinter notebook layout.
- `scanner.py` - Orchestrator module combining network findings into a structured `ScanResult` dataclass.
- `banner_grabber.py` / `port_scanner.py` / `ssl_checker.py` / `header_analyzer.py` / `dns_recon.py` - Decoupled vulnerability interrogation engines.
- `vuln_assessor.py` - Security ruleset evaluating the output of engine scans.

## 🚀 How to Run

1. Clone the repository and install the dependencies:
```bash
pip install -r requirements.txt
```

2. Execute the user interface application:
```bash
python gui.py
```

3. Enter a target (e.g. `scanme.nmap.org`) and hit **Start Scan**. Results will be synchronously exported to the `/reports/` directory.

## ⚠️ Disclaimer

This tool is strictly developed for educational purposes, authorized security research, and personal portfolio demonstration. You may only use this tool against targets you explicitly own or have documented consent to test.

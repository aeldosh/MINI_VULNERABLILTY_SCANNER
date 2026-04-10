import socket
from dataclasses import dataclass
from port_scanner import scan_ports
from service_detector import detect_services
from banner_grabber import grab_banner
from vuln_assessor import assess_port_risk
from header_analyzer import analyze_headers
from ssl_checker import check_ssl
from dns_recon import perform_recon

@dataclass
class ScanResult:
    target: str
    ip: str
    dns_info: dict
    ports: dict  # {port: {"service": str, "banner": str, "risk": dict}}
    headers: dict
    ssl: dict

def resolve_target(target):
    """Resolve hostname to IP address with error handling."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None

def run_scan(target, progress_callback=None):
    # 1. DNS Recon
    if progress_callback: progress_callback(5, 100)
    dns_info = perform_recon(target)
    ip = dns_info.get("ip") or resolve_target(target)
    
    # Scan well-known ports (1-1024) plus common high ports
    high_ports = [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    ports_to_scan = list(range(1, 1025)) + high_ports

    # 2. Port Scan
    def p_callback(completed, total):
        # map 10-60% portion to port scanning
        if progress_callback:
            pct = 10 + int((completed / total) * 50)
            progress_callback(pct, 100)

    open_ports = scan_ports(target, ports_to_scan, progress_callback=p_callback)
    
    # 3. Service Detection
    services_detected = detect_services(target, open_ports)
    
    if progress_callback: progress_callback(65, 100)
    
    ports_data = {}
    
    # 4. Banner Grabbing & Vuln Assessment
    for idx, port in enumerate(open_ports):
        service_name = services_detected.get(port, "Unknown")
        banner = grab_banner(target, port)
        risk = assess_port_risk(port, service_name, banner)
        
        ports_data[port] = {
            "service": service_name,
            "banner": banner,
            "risk": risk
        }
        
        if progress_callback:
            pct = 65 + int(((idx + 1) / len(open_ports)) * 20)
            progress_callback(pct, 100)

    # 5. Header Analysis (if 80, 443, 8080, 8443 open)
    headers_info = {}
    http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
    if http_ports:
         headers_info = analyze_headers(target, http_ports[-1]) # analyze highest http port

    if progress_callback: progress_callback(90, 100)

    # 6. SSL Check (if 443 or 8443 open)
    ssl_info = {}
    ssl_ports = [p for p in open_ports if p in [443, 8443]]
    if ssl_ports:
         ssl_info = check_ssl(target, ssl_ports[-1])

    if progress_callback: progress_callback(95, 100)
         
    return ScanResult(
        target=target,
        ip=ip,
        dns_info=dns_info,
        ports=ports_data,
        headers=headers_info,
        ssl=ssl_info
    )

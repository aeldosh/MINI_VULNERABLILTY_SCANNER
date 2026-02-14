from port_scanner import scan_ports
from service_detector import detect_services

def run_scan(target):
    ports = range(20, 1025)
    open_ports = scan_ports(target, ports)
    services = detect_services(target, open_ports)
    return services

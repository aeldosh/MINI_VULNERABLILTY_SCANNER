COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
}

def detect_services(target, open_ports):
    services = {}
    for port in open_ports:
        services[port] = COMMON_SERVICES.get(port, "Unknown Service")
    return services

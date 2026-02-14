import socket
from concurrent.futures import ThreadPoolExecutor

def check_port(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.3)
        sock.connect((target, port))
        sock.close()
        return port
    except:
        return None

def scan_ports(target, ports):
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: check_port(target, p), ports)

    for result in results:
        if result:
            open_ports.append(result)

    return open_ports

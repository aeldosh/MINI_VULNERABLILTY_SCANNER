import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((target, port))
        sock.close()
        return port
    except (socket.error, OSError):
        return None

def scan_ports(target, ports, progress_callback=None):
    open_ports = []
    port_list = list(ports)
    total = len(port_list)
    completed = 0

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_port, target, p): p for p in port_list}

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

            completed += 1
            if progress_callback and completed % 50 == 0:
                progress_callback(completed, total)

    # Final progress update
    if progress_callback:
        progress_callback(total, total)

    open_ports.sort()
    return open_ports

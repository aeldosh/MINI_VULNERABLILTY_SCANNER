import socket

def grab_banner(target, port, timeout=1.0):
    """
    Attempts to connect to a port and retrieve the service banner.
    Returns the banner string or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # For some services like HTTP, we need to send a request to get a banner
        if port in [80, 8080, 443, 8443]:
            # Simple HTTP GET request
            request = b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
            if port in [443, 8443]:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)
            sock.sendall(request)
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Clean up the banner (take first line or first 50 chars)
        if banner:
            lines = banner.split('\n')
            if port in [80, 8080, 443, 8443]:
                # Extract Server header if present
                for line in lines:
                    if line.lower().startswith('server:'):
                        return line.strip()
                return lines[0][:50].strip()
            return lines[0][:50].strip()
            
    except (socket.error, socket.timeout, UnicodeDecodeError):
        pass
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except:
            pass
            
    return None

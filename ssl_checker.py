import ssl
import socket
from datetime import datetime

def check_ssl(target, port=443, timeout=3.0):
    """
    Retrieves and analyzes the SSL/TLS certificate for a given target.
    Returns details including issuer, expiry, and validity status.
    """
    result = {
        "issuer": "Unknown",
        "subject": "Unknown",
        "valid_from": None,
        "valid_to": None,
        "days_until_expiry": 0,
        "is_valid": False,
        "error": None
    }
    
    try:
        # First attempt: Try with verification to get the full dictionary
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_dict = ssock.getpeercert()
                result['is_valid'] = True
    except ssl.SSLCertVerificationError as e:
        # Second attempt: Bypass verification but at least we know it's invalid
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_dict = ssock.getpeercert() # Will be empty ({}) but binary cert is available
                result['is_valid'] = False
                result['error'] = "Certificate verification failed (e.g., self-signed)"
    except Exception as e:
        result['error'] = str(e)
        return result

    if cert_dict:
        # Extract Issuer
        for item in cert_dict.get('issuer', []):
            for k, v in item:
                if k == 'organizationName' or k == 'commonName':
                    result['issuer'] = v

        # Extract Subject
        for item in cert_dict.get('subject', []):
            for k, v in item:
                if k == 'commonName':
                    result['subject'] = v

        # Dates
        not_before = cert_dict.get('notBefore')
        not_after = cert_dict.get('notAfter')

        if not_before and not_after:
            d1 = ssl.cert_time_to_seconds(not_before)
            d2 = ssl.cert_time_to_seconds(not_after)

            dt_before = datetime.utcfromtimestamp(d1)
            dt_after = datetime.utcfromtimestamp(d2)

            result['valid_from'] = dt_before.strftime('%Y-%m-%d')
            result['valid_to'] = dt_after.strftime('%Y-%m-%d')

            now = datetime.utcnow()
            days_left = (dt_after - now).days
            result['days_until_expiry'] = days_left

            if days_left <= 0:
                 result['is_valid'] = False
        
    return result

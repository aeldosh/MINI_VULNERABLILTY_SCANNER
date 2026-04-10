import urllib.request
import urllib.error
import ssl

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS - site is vulnerable to downgrade attacks.",
    "X-Content-Type-Options": "Missing MIME sniffing protection.",
    "X-Frame-Options": "Missing clickjacking protection.",
    "Content-Security-Policy": "Missing CSP - vulnerable to XSS and data injection.",
}

def analyze_headers(target, port=443):
    """
    Checks HTTP/HTTPS endpoints for standard security headers.
    Returns a grade and a list of missing headers with warnings.
    """
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{target}:{port}/"
    
    results = {
        "present": [],
        "missing": [],
        "grade": "F"
    }
    
    try:
        # Ignore SSL errors for testing
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
            headers = response.headers
            
            for header, warning in SECURITY_HEADERS.items():
                if header in headers or header.lower() in headers:
                    results["present"].append(header)
                else:
                    results["missing"].append({
                        "header": header,
                        "warning": warning
                    })
                    
    except Exception as e:
        results["error"] = str(e)
        return results

    # Determine grade
    present_count = len(results["present"])
    total_count = len(SECURITY_HEADERS)
    
    if present_count == total_count:
        results["grade"] = "A+"
    elif present_count >= total_count - 1:
        results["grade"] = "A"
    elif present_count >= total_count - 2:
        results["grade"] = "B"
    elif present_count > 0:
        results["grade"] = "C"
    else:
        results["grade"] = "F"
        
    return results

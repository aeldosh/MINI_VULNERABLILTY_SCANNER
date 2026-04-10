def assess_port_risk(port, service_name, banner=None):
    """
    Classifies the risk of an open port/service.
    Returns a dict with: 'severity' (Critical/High/Medium/Low) and 'recommendation'.
    """
    severity = "Low"
    recommendation = "Standard open port."
    
    # Critical Risk
    if port in [21, 23]:
        severity = "Critical"
        recommendation = f"{service_name} transmits data in plaintext. Use secure alternatives like SFTP or SSH."
    elif port in [135, 137, 138, 139, 445]:
        severity = "High"
        recommendation = "Windows file sharing/RPC ports should not be exposed to the internet. Restrict with firewall."
    elif port in [3389, 5900]:
        severity = "High"
        recommendation = f"Remote desktop ({service_name}) exposed. Use a VPN or restrict IP access."
    elif port in [1433, 1521, 3306, 5432, 27017, 6379]:
        severity = "High"
        recommendation = f"Database port ({service_name}) is exposed. Ensure strong authentication and restrict IP access."
    # Medium Risk
    elif port in [80, 8080]:
        severity = "Medium"
        recommendation = "Unencrypted HTTP traffic. Ensure a redirect to HTTPS (443) is in place."
    elif port in [25, 110, 143]:
        severity = "Medium"
        recommendation = f"Unencrypted email traffic ({service_name}). Use SSL/TLS variants (465, 993, 995)."
    # Low Risk
    elif port in [22, 443, 8443, 465, 993, 995, 53]:
        severity = "Low"
        recommendation = f"{service_name} is generally secure. Ensure software is up to date and weak ciphers are disabled."
    else:
        severity = "Info"
        recommendation = f"Unknown or non-standard service ({service_name}). Monitor if unexpected."
        
    # Check banner for outdated versions (simple keyword matching)
    if banner and severity != "Critical":
        banner_lower = banner.lower()
        if "apache/2.2" in banner_lower or "nginx/1.14" in banner_lower or "openssh 6" in banner_lower:
             if severity == "Low" or severity == "Info":
                 severity = "Medium"
             recommendation += " Potentially outdated service version detected in banner."

    return {
        "severity": severity,
        "recommendation": recommendation
    }

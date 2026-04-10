import socket

def perform_recon(target):
    """
    Performs basic DNS reconnaissance.
    Returns dict with resolved IP, aliases, and reverse DNS name.
    """
    results = {
        "ip": None,
        "aliases": [],
        "reverse_dns": None,
        "error": None
    }
    
    try:
        # Get IP and aliases
        name, aliaslist, addresslist = socket.gethostbyname_ex(target)
        
        if addresslist:
            results["ip"] = addresslist[0]
            if len(addresslist) > 1:
                results["aliases"].extend(addresslist[1:])
        
        if name != target and name not in results["aliases"]:
            results["aliases"].append(name)
            
        for alias in aliaslist:
             if alias not in results["aliases"]:
                 results["aliases"].append(alias)
                 
        # Reverse DNS lookup
        if results["ip"]:
            try:
                host_info = socket.gethostbyaddr(results["ip"])
                results["reverse_dns"] = host_info[0]
            except socket.herror:
                results["reverse_dns"] = "Not found"
                
    except socket.gaierror as e:
        results["error"] = str(e)
    
    return results

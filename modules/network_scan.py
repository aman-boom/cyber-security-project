import nmap

def scan_ports(ip):
    try:
        print("Scanning:", ip)

        # Force Nmap path (Windows)
        scanner = nmap.PortScanner(
            nmap_search_path=(
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe"
            )
        )

        # FAST SCAN (IMPORTANT)
        scanner.scan(ip, arguments='-F -T4')

        results = []

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():

                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']

                    results.append({
                        "port": port,
                        "service": service,
                        "state": state
                    })

        if not results:
            return [{"port": "-", "service": "No open ports found", "state": "filtered"}]

        return results

    except Exception as e:
        return [{"port": "Error", "service": str(e), "state": "failed"}]
import socket
import nmap
import concurrent.futures
from datetime import datetime

def scan_ports_basic(target, port_range="1-1024"):
    open_ports = []
    start_port, end_port = map(int, port_range.split("-"))

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_port, range(start_port, end_port + 1))

    open_ports = [p for p in results if p is not None]
    return sorted(open_ports)


def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner
    except:
        return "No banner"


def nmap_scan(target, port_range="1-1024"):
    scanner = nmap.PortScanner()
    results = []

    try:
        scanner.scan(target, port_range, arguments="-sV -T4")

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    info = scanner[host][proto][port]
                    results.append({
                        "port": port,
                        "state": info["state"],
                        "service": info["name"],
                        "version": info.get("version", ""),
                        "product": info.get("product", ""),
                    })
    except Exception as e:
        results.append({"error": str(e)})

    return results


def run_full_scan(target, port_range="1-1024"):
    scan_data = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "nmap_results": [],
        "banners": {}
    }

    print(f"[*] Starting scan on {target}...")
    open_ports = scan_ports_basic(target, port_range)
    scan_data["open_ports"] = open_ports
    print(f"[+] Open ports found: {open_ports}")

    for port in open_ports[:10]:
        banner = grab_banner(target, port)
        scan_data["banners"][port] = banner
        print(f"[+] Port {port} banner: {banner[:60]}")

    print("[*] Running Nmap service detection...")
    scan_data["nmap_results"] = nmap_scan(target, port_range)

    return scan_data

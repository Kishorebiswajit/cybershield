import socket
import nmap
import concurrent.futures
from datetime import datetime


def scan_ports_basic(target, port_range="1-1024", emit=None):
    """Fast port scanning with optimized timeouts and thread pool"""
    open_ports = []
    start_port, end_port = map(int, port_range.split("-"))
    total = end_port - start_port + 1

    if emit:
        emit('scan_log', {'msg': f'[*] Scanning {total} ports on {target}...', 'cls': 't-blue'})

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)  # OPTIMIZED: Reduced from 1s to 0.3s
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None

    # OPTIMIZED: Reduced max_workers from 100 to 50 for better performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_port, range(start_port, end_port + 1))

    open_ports = sorted([p for p in results if p is not None])

    if emit:
        if open_ports:
            emit('scan_log', {'msg': f'[+] Open ports: {open_ports}', 'cls': 't-green'})
        else:
            emit('scan_log', {'msg': '[*] No open ports found', 'cls': 't-muted'})
        emit('scan_progress', {'value': 40})

    return open_ports


def grab_banner(target, port):
    """Grab service banners with optimized timeout"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)  # OPTIMIZED: Reduced from 2s to 0.8s
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100]  # OPTIMIZED: Limit banner length
    except:
        return "No banner"


def nmap_scan(target, port_range="1-1024", emit=None):
    """Run Nmap with faster timing template"""
    scanner = nmap.PortScanner()
    results = []

    if emit:
        emit('scan_log', {'msg': '[*] Running Nmap service detection...', 'cls': 't-blue'})

    try:
        # OPTIMIZED: Changed from -sV -T4 to -sV -T5 for faster scanning
        # T5 = Insane timing (fastest), T4 = Aggressive
        scanner.scan(target, port_range, arguments="-sV -T5 --max-retries 1")
        
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():
                    info = scanner[host][proto][port]
                    entry = {
                        "port": port,
                        "state": info["state"],
                        "service": info["name"],
                        "version": info.get("version", "")[:50],  # OPTIMIZED: Limit version string
                        "product": info.get("product", "")[:50],  # OPTIMIZED: Limit product string
                    }
                    results.append(entry)
                    if emit:
                        emit('scan_log', {
                            'msg': f'[+] Port {port}/tcp — {info["name"]} {info.get("product","")} {info.get("version","")}',
                            'cls': 't-green'
                        })
    except Exception as e:
        if emit:
            emit('scan_log', {'msg': f'[!] Nmap error: {e}', 'cls': 't-red'})
        results.append({"error": str(e)})

    if emit:
        emit('scan_progress', {'value': 75})

    return results


def run_full_scan(target, port_range="1-1024", emit=None):
    """Execute full scan with optimized workflow"""
    scan_data = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "nmap_results": [],
        "banners": {}
    }

    if emit:
        emit('scan_log', {'msg': f'[*] CyberShield scan started on {target}', 'cls': 't-blue'})
        emit('scan_progress', {'value': 5})

    open_ports = scan_ports_basic(target, port_range, emit=emit)
    scan_data["open_ports"] = open_ports

    if emit:
        emit('scan_log', {'msg': '[*] Grabbing service banners...', 'cls': 't-blue'})

    # OPTIMIZED: Only grab banners for top 5 ports instead of 10
    for port in open_ports[:5]:
        banner = grab_banner(target, port)
        scan_data["banners"][port] = banner
        if emit and banner != "No banner":
            emit('scan_log', {'msg': f'[+] Port {port} — {banner[:80]}', 'cls': 't-muted'})

    scan_data["nmap_results"] = nmap_scan(target, port_range, emit=emit)

    if emit:
        emit('scan_log', {'msg': '[*] Scan complete. Analyzing vulnerabilities...', 'cls': 't-blue'})
        emit('scan_progress', {'value': 90})

    return scan_data

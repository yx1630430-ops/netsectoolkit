import socket
import ipaddress
from typing import Optional, List, Tuple

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def get_host_status(host: str, timeout: float = 2.0) -> bool:
    try:
        if not is_valid_ip(host):
            host = socket.gethostbyname(host)
        
        import subprocess
        if subprocess.os.name == 'nt':
            param = '-n'
        else:
            param = '-c'
        
        command = ['ping', param, '1', '-W', str(int(timeout)), host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def resolve_hostname(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except:
        return None

def parse_port_range(port_range: str) -> List[int]:
    ports = []
    
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
    except ValueError:
        raise ValueError(f"Invalid port range: {port_range}")
    
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Port {port} is out of range (1-65535)")
    
    return ports

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except:
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            8080: "http-proxy", 8443: "https-alt"
        }
        return service_map.get(port, "unknown")

def calculate_subnet(ip: str, mask: str) -> Tuple[str, str, str]:
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return str(network.network_address), str(network.broadcast_address), str(network.netmask)
    except:
        return "", "", ""
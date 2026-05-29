import socket
import threading
import time
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, conf
from scapy.layers.inet import traceroute

from ..utils.logger import Logger
from ..utils.network import get_host_status, is_valid_ip

class NetworkScanner:
    def __init__(self, timeout: float = 2.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.logger = Logger("NetworkScanner")
        self.results = {}
        conf.verb = 0
    
    def ping_scan(self, target: str) -> bool:
        try:
            if not is_valid_ip(target):
                target = socket.gethostbyname(target)
            
            packet = IP(dst=target)/ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response:
                self.logger.info(f"Host {target} is alive")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Ping scan failed for {target}: {str(e)}")
            return False
    
    def tcp_port_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        results = {}
        
        def scan_port(port: int) -> Tuple[int, str]:
            try:
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    return port, "filtered"
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x12:
                        rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                        sr(rst_packet, timeout=self.timeout, verbose=0)
                        return port, "open"
                    elif response[TCP].flags == 0x14:
                        return port, "closed"
                return port, "unknown"
            except Exception as e:
                self.logger.error(f"Port scan error on {target}:{port}: {str(e)}")
                return port, "error"
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                port, status = future.result()
                results[port] = status
        
        self.results[f"{target}_tcp"] = results
        return results
    
    def udp_port_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        results = {}
        
        def scan_port(port: int) -> Tuple[int, str]:
            try:
                packet = IP(dst=target)/UDP(dport=port)
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    return port, "open|filtered"
                elif response.haslayer(ICMP):
                    if response[ICMP].type == 3 and response[ICMP].code == 3:
                        return port, "closed"
                    elif response[ICMP].type == 3 and response[ICMP].code in [1, 2, 9, 10, 13]:
                        return port, "filtered"
                return port, "unknown"
            except Exception as e:
                self.logger.error(f"UDP scan error on {target}:{port}: {str(e)}")
                return port, "error"
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                port, status = future.result()
                results[port] = status
        
        self.results[f"{target}_udp"] = results
        return results
    
    def syn_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        results = {}
        
        def scan_port(port: int) -> Tuple[int, str]:
            try:
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    return port, "filtered"
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x12:
                        return port, "open"
                    elif response[TCP].flags == 0x14:
                        return port, "closed"
                return port, "unknown"
            except Exception as e:
                self.logger.error(f"SYN scan error on {target}:{port}: {str(e)}")
                return port, "error"
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                port, status = future.result()
                results[port] = status
        
        self.results[f"{target}_syn"] = results
        return results
    
    def service_detection(self, target: str, port: int) -> Optional[str]:
        try:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                    sr(rst_packet, timeout=self.timeout, verbose=0)
                    
                    service_map = {
                        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
                        53: "dns", 80: "http", 110: "pop3", 143: "imap",
                        443: "https", 993: "imaps", 995: "pop3s",
                        3306: "mysql", 3389: "rdp", 5432: "postgresql",
                        8080: "http-proxy", 8443: "https-alt"
                    }
                    return service_map.get(port, "unknown")
            return None
        except Exception as e:
            self.logger.error(f"Service detection failed on {target}:{port}: {str(e)}")
            return None
    
    def host_discovery(self, network: str) -> List[str]:
        alive_hosts = []
        
        try:
            base_ip = ".".join(network.split(".")[:3])
            
            def check_host(ip: str) -> Optional[str]:
                if self.ping_scan(ip):
                    return ip
                return None
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(check_host, f"{base_ip}.{i}"): i 
                    for i in range(1, 255)
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        alive_hosts.append(result)
            
            self.logger.info(f"Found {len(alive_hosts)} alive hosts in {network}")
            return sorted(alive_hosts, key=lambda x: int(x.split(".")[-1]))
        except Exception as e:
            self.logger.error(f"Host discovery failed for {network}: {str(e)}")
            return []
    
    def traceroute_scan(self, target: str, max_hops: int = 30) -> List[Dict]:
        try:
            result, _ = traceroute(target, maxttl=max_hops, verbose=0)
            
            hops = []
            for snd, rcv in result:
                hop = {
                    "ttl": snd.ttl,
                    "ip": rcv.src if rcv else "*",
                    "rtt": (rcv.time - snd.sent_time) * 1000 if rcv else None
                }
                hops.append(hop)
            
            return hops
        except Exception as e:
            self.logger.error(f"Traceroute failed to {target}: {str(e)}")
            return []
    
    def get_results(self) -> Dict:
        return self.results
    
    def clear_results(self):
        self.results = {}
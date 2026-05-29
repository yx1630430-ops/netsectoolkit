import socket
import ssl
import json
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from scapy.all import IP, TCP, UDP, DNS, sr1, sr, conf
from scapy.layers.http import HTTP, HTTPRequest

from ..utils.logger import Logger
from .scanner import NetworkScanner

class VulnerabilityDetector:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.logger = Logger("VulnerabilityDetector")
        self.scanner = NetworkScanner(timeout=timeout)
        self.vulnerabilities = []
        conf.verb = 0
        
        self.common_vulns = {
            21: self._check_ftp_vulns,
            22: self._check_ssh_vulns,
            23: self._check_telnet_vulns,
            25: self._check_smtp_vulns,
            80: self._check_http_vulns,
            443: self._check_https_vulns,
            445: self._check_smb_vulns,
            3306: self._check_mysql_vulns,
            3389: self._check_rdp_vulns,
            5432: self._check_postgresql_vulns,
            8080: self._check_http_vulns,
            8443: self._check_https_vulns
        }
    
    def scan_host(self, target: str, ports: Optional[List[int]] = None) -> List[Dict]:
        if ports is None:
            ports = list(self.common_vulns.keys())
        
        self.logger.info(f"Starting vulnerability scan on {target}")
        
        open_ports = self.scanner.tcp_port_scan(target, ports)
        open_ports_list = [port for port, status in open_ports.items() if status == "open"]
        
        vulnerabilities = []
        
        for port in open_ports_list:
            if port in self.common_vulns:
                vulns = self.common_vulns[port](target, port)
                vulnerabilities.extend(vulns)
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    def _check_ftp_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if 'vsftpd' in banner.lower() and '2.3.4' in banner:
                vulns.append({
                    "type": "backdoor",
                    "severity": "critical",
                    "port": port,
                    "service": "ftp",
                    "description": "vsftpd 2.3.4 backdoor vulnerability",
                    "cve": "CVE-2011-2523"
                })
            
            if 'anonymous' in banner.lower() or 'ftp' in banner.lower():
                vulns.append({
                    "type": "misconfiguration",
                    "severity": "medium",
                    "port": port,
                    "service": "ftp",
                    "description": "Anonymous FTP access may be enabled"
                })
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"FTP check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_ssh_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if 'SSH-1' in banner:
                vulns.append({
                    "type": "outdated_protocol",
                    "severity": "high",
                    "port": port,
                    "service": "ssh",
                    "description": "SSH protocol version 1 is enabled (insecure)"
                })
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"SSH check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_telnet_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        vulns.append({
            "type": "insecure_protocol",
            "severity": "high",
            "port": port,
            "service": "telnet",
            "description": "Telnet transmits data in cleartext"
        })
        
        return vulns
    
    def _check_smtp_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"EHLO test\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if 'STARTTLS' not in response:
                vulns.append({
                    "type": "missing_encryption",
                    "severity": "medium",
                    "port": port,
                    "service": "smtp",
                    "description": "SMTP server does not support STARTTLS"
                })
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"SMTP check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_http_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            headers = response.split('\r\n')
            server_header = None
            for header in headers:
                if header.lower().startswith('server:'):
                    server_header = header.split(':', 1)[1].strip()
                    break
            
            if server_header:
                vulns.append({
                    "type": "information_disclosure",
                    "severity": "low",
                    "port": port,
                    "service": "http",
                    "description": f"Server header reveals: {server_header}"
                })
            
            if 'X-Frame-Options' not in response:
                vulns.append({
                    "type": "missing_header",
                    "severity": "low",
                    "port": port,
                    "service": "http",
                    "description": "Missing X-Frame-Options header (clickjacking)"
                })
            
            if 'X-Content-Type-Options' not in response:
                vulns.append({
                    "type": "missing_header",
                    "severity": "low",
                    "port": port,
                    "service": "http",
                    "description": "Missing X-Content-Type-Options header"
                })
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"HTTP check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_https_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    if version in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulns.append({
                            "type": "outdated_protocol",
                            "severity": "high",
                            "port": port,
                            "service": "https",
                            "description": f"Server supports outdated TLS version: {version}"
                        })
                    
                    if cipher and cipher[1] < 128:
                        vulns.append({
                            "type": "weak_encryption",
                            "severity": "medium",
                            "port": port,
                            "service": "https",
                            "description": f"Weak cipher suite: {cipher[0]} ({cipher[1]} bits)"
                        })
        except Exception as e:
            self.logger.debug(f"HTTPS check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_smb_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        vulns.append({
            "type": "potential_vulnerability",
            "severity": "medium",
            "port": port,
            "service": "smb",
            "description": "SMB service detected - check for EternalBlue and other SMB vulnerabilities"
        })
        
        return vulns
    
    def _check_mysql_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024)
            
            if b'5.5' in banner or b'5.6' in banner or b'5.7' in banner:
                vulns.append({
                    "type": "outdated_software",
                    "severity": "medium",
                    "port": port,
                    "service": "mysql",
                    "description": "MySQL version may be outdated"
                })
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"MySQL check failed on {target}:{port}: {str(e)}")
        
        return vulns
    
    def _check_rdp_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        vulns.append({
            "type": "potential_vulnerability",
            "severity": "medium",
            "port": port,
            "service": "rdp",
            "description": "RDP service detected - check for BlueKeep and other RDP vulnerabilities"
        })
        
        return vulns
    
    def _check_postgresql_vulns(self, target: str, port: int) -> List[Dict]:
        vulns = []
        
        vulns.append({
            "type": "information",
            "severity": "info",
            "port": port,
            "service": "postgresql",
            "description": "PostgreSQL service detected"
        })
        
        return vulns
    
    def check_common_credentials(self, target: str, port: int, service: str) -> List[Dict]:
        vulns = []
        
        common_creds = {
            "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
            "ssh": [("root", "root"), ("admin", "admin"), ("user", "user")],
            "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
            "postgresql": [("postgres", "postgres"), ("admin", "admin")]
        }
        
        if service not in common_creds:
            return vulns
        
        for username, password in common_creds[service]:
            if self._try_credentials(target, port, service, username, password):
                vulns.append({
                    "type": "weak_credentials",
                    "severity": "critical",
                    "port": port,
                    "service": service,
                    "description": f"Weak credentials found: {username}:{password}"
                })
        
        return vulns
    
    def _try_credentials(self, target: str, port: int, service: str, 
                        username: str, password: str) -> bool:
        try:
            if service == "ftp":
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=self.timeout)
                ftp.login(username, password)
                ftp.quit()
                return True
        except:
            pass
        
        return False
    
    def generate_report(self, target: str) -> Dict:
        report = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": sum(1 for v in self.vulnerabilities if v["severity"] == "critical"),
                "high": sum(1 for v in self.vulnerabilities if v["severity"] == "high"),
                "medium": sum(1 for v in self.vulnerabilities if v["severity"] == "medium"),
                "low": sum(1 for v in self.vulnerabilities if v["severity"] == "low"),
                "info": sum(1 for v in self.vulnerabilities if v["severity"] == "info")
            }
        }
        
        return report
    
    def export_report(self, target: str, output_file: str, format: str = "json"):
        report = self.generate_report(target)
        
        try:
            if format == "json":
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            elif format == "text":
                with open(output_file, 'w') as f:
                    f.write(f"Vulnerability Scan Report for {target}\n")
                    f.write(f"Scan Time: {report['scan_time']}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    f.write("Summary:\n")
                    f.write(f"  Total vulnerabilities: {report['summary']['total']}\n")
                    f.write(f"  Critical: {report['summary']['critical']}\n")
                    f.write(f"  High: {report['summary']['high']}\n")
                    f.write(f"  Medium: {report['summary']['medium']}\n")
                    f.write(f"  Low: {report['summary']['low']}\n")
                    f.write(f"  Info: {report['summary']['info']}\n\n")
                    
                    f.write("Detailed Findings:\n")
                    for i, vuln in enumerate(report['vulnerabilities'], 1):
                        f.write(f"\n{i}. [{vuln['severity'].upper()}] {vuln['description']}\n")
                        f.write(f"   Port: {vuln['port']} | Service: {vuln['service']}\n")
                        if 'cve' in vuln:
                            f.write(f"   CVE: {vuln['cve']}\n")
            
            self.logger.info(f"Report exported to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to export report: {str(e)}")
    
    def clear_vulnerabilities(self):
        self.vulnerabilities = []
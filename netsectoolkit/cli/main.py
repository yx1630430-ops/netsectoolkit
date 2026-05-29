import argparse
import sys
from typing import List, Optional

from ..core.scanner import NetworkScanner
from ..core.analyzer import TrafficAnalyzer
from ..core.detector import VulnerabilityDetector
from ..utils.config import Config
from ..utils.logger import Logger
from ..utils.network import parse_port_range, is_valid_ip, is_valid_cidr

class NetSecToolkitCLI:
    def __init__(self):
        self.config = Config()
        self.logger = Logger("NetSecToolkit", log_file=self.config.get("logging.file"))
        self.scanner = NetworkScanner(
            timeout=self.config.get("scanner.timeout"),
            max_threads=self.config.get("scanner.max_threads")
        )
        self.analyzer = TrafficAnalyzer()
        self.detector = VulnerabilityDetector(timeout=self.config.get("detector.timeout"))
    
    def create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="NetSecToolkit - Network Security Toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  netsectoolkit scan 192.168.1.1
  netsectoolkit scan 192.168.1.0/24 --type host
  netsectoolkit scan 192.168.1.1 --ports 80,443,8080
  netsectoolkit sniff --interface eth0 --count 100
  netsectoolkit analyze capture.pcap
  netsectoolkit vuln 192.168.1.1
  netsectoolkit vuln 192.168.1.1 --export report.json
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        scan_parser = subparsers.add_parser("scan", help="Network scanning")
        scan_parser.add_argument("target", help="Target IP, hostname, or network (CIDR)")
        scan_parser.add_argument("--type", choices=["port", "host", "syn", "udp"], 
                               default="port", help="Scan type")
        scan_parser.add_argument("--ports", help="Port range (e.g., 80,443 or 1-1024)")
        scan_parser.add_argument("--timeout", type=float, help="Scan timeout")
        scan_parser.add_argument("--threads", type=int, help="Max threads")
        scan_parser.add_argument("--output", help="Output file")
        
        sniff_parser = subparsers.add_parser("sniff", help="Packet capture")
        sniff_parser.add_argument("--interface", "-i", help="Network interface")
        sniff_parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets")
        sniff_parser.add_argument("--timeout", "-t", type=int, help="Capture timeout")
        sniff_parser.add_argument("--filter", "-f", help="BPF filter")
        sniff_parser.add_argument("--output", "-o", help="Output pcap file")
        
        analyze_parser = subparsers.add_parser("analyze", help="Traffic analysis")
        analyze_parser.add_argument("pcap_file", help="PCAP file to analyze")
        analyze_parser.add_argument("--output", help="Output file")
        
        vuln_parser = subparsers.add_parser("vuln", help="Vulnerability detection")
        vuln_parser.add_argument("target", help="Target IP or hostname")
        vuln_parser.add_argument("--ports", help="Port range")
        vuln_parser.add_argument("--export", help="Export report file")
        vuln_parser.add_argument("--format", choices=["json", "text"], 
                               default="json", help="Export format")
        
        return parser
    
    def run(self, args: Optional[List[str]] = None):
        parser = self.create_parser()
        
        if args is None:
            args = sys.argv[1:]
        
        if not args:
            parser.print_help()
            return
        
        parsed_args = parser.parse_args(args)
        
        try:
            if parsed_args.command == "scan":
                self._handle_scan(parsed_args)
            elif parsed_args.command == "sniff":
                self._handle_sniff(parsed_args)
            elif parsed_args.command == "analyze":
                self._handle_analyze(parsed_args)
            elif parsed_args.command == "vuln":
                self._handle_vuln(parsed_args)
            else:
                parser.print_help()
        except KeyboardInterrupt:
            self.logger.info("\nOperation cancelled by user")
        except Exception as e:
            self.logger.error(f"Error: {str(e)}")
    
    def _handle_scan(self, args):
        target = args.target
        scan_type = args.type
        
        if args.timeout:
            self.scanner.timeout = args.timeout
        if args.threads:
            self.scanner.max_threads = args.threads
        
        if is_valid_cidr(target):
            self.logger.info(f"Starting host discovery on {target}")
            alive_hosts = self.scanner.host_discovery(target)
            print(f"\nAlive hosts in {target}:")
            for host in alive_hosts:
                print(f"  {host}")
            return
        
        if not is_valid_ip(target):
            import socket
            try:
                target = socket.gethostbyname(target)
            except:
                self.logger.error(f"Cannot resolve hostname: {target}")
                return
        
        if args.ports:
            ports = parse_port_range(args.ports)
        else:
            ports = self.config.get("scanner.default_ports")
        
        if scan_type == "port":
            self.logger.info(f"Starting TCP port scan on {target}")
            results = self.scanner.tcp_port_scan(target, ports)
        elif scan_type == "syn":
            self.logger.info(f"Starting SYN scan on {target}")
            results = self.scanner.syn_scan(target, ports)
        elif scan_type == "udp":
            self.logger.info(f"Starting UDP scan on {target}")
            results = self.scanner.udp_port_scan(target, ports)
        elif scan_type == "host":
            self.logger.info(f"Starting host discovery on {target}")
            is_alive = self.scanner.ping_scan(target)
            print(f"\nHost {target} is {'alive' if is_alive else 'down'}")
            return
        
        print(f"\nScan results for {target}:")
        print("-" * 40)
        open_ports = []
        for port, status in sorted(results.items()):
            if status == "open":
                open_ports.append(port)
                service = self.scanner.service_detection(target, port)
                print(f"  {port}/tcp  open  {service or 'unknown'}")
        
        if not open_ports:
            print("  No open ports found")
        
        if args.output:
            self._save_results(args.output, results)
    
    def _handle_sniff(self, args):
        self.logger.info("Starting packet capture")
        
        def packet_callback(packet):
            print(f"Captured: {packet.summary()}")
        
        self.analyzer.start_capture(
            interface=args.interface,
            count=args.count,
            timeout=args.timeout,
            filter_expr=args.filter,
            callback=packet_callback
        )
        
        if args.count > 0:
            import time
            while self.analyzer.is_capturing:
                time.sleep(0.1)
        else:
            print("Press Ctrl+C to stop capture...")
            try:
                import time
                while self.analyzer.is_capturing:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.analyzer.stop_capture()
        
        if args.output:
            self.analyzer.export_packets(args.output)
            print(f"\nPackets exported to {args.output}")
        
        stats = self.analyzer.get_statistics()
        print(f"\nCapture Statistics:")
        print(f"  Total packets: {stats['total_packets']}")
        print(f"  Protocols: {stats['protocol_distribution']}")
    
    def _handle_analyze(self, args):
        self.logger.info(f"Analyzing {args.pcap_file}")
        
        stats = self.analyzer.analyze_pcap(args.pcap_file)
        
        if not stats:
            self.logger.error("Failed to analyze pcap file")
            return
        
        print(f"\nAnalysis Results for {args.pcap_file}:")
        print("-" * 50)
        print(f"Total packets: {stats['total_packets']}")
        print(f"Capture duration: {stats['capture_duration']:.2f} seconds")
        
        print("\nProtocol Distribution:")
        for protocol, count in stats['protocol_distribution'].items():
            print(f"  {protocol}: {count}")
        
        print("\nTop Talkers:")
        for talker in self.analyzer.get_top_talkers(5):
            print(f"  {talker['ip']}: sent={talker['sent']}, received={talker['received']}")
        
        print("\nTop Ports:")
        for port_info in self.analyzer.get_top_ports(5):
            print(f"  Port {port_info['port']}: {port_info['count']} packets")
        
        anomalies = self.analyzer.detect_anomalies()
        if anomalies:
            print("\nAnomalies Detected:")
            for anomaly in anomalies:
                print(f"  [{anomaly['type']}] {anomaly['description']}")
        
        if args.output:
            self._save_results(args.output, stats)
    
    def _handle_vuln(self, args):
        target = args.target
        
        if not is_valid_ip(target):
            import socket
            try:
                target = socket.gethostbyname(target)
            except:
                self.logger.error(f"Cannot resolve hostname: {target}")
                return
        
        ports = None
        if args.ports:
            ports = parse_port_range(args.ports)
        
        self.logger.info(f"Starting vulnerability scan on {target}")
        vulnerabilities = self.detector.scan_host(target, ports)
        
        report = self.detector.generate_report(target)
        
        print(f"\nVulnerability Scan Report for {target}")
        print("=" * 60)
        print(f"Scan time: {report['scan_time']}")
        print(f"\nSummary:")
        print(f"  Total vulnerabilities: {report['summary']['total']}")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High: {report['summary']['high']}")
        print(f"  Medium: {report['summary']['medium']}")
        print(f"  Low: {report['summary']['low']}")
        print(f"  Info: {report['summary']['info']}")
        
        if vulnerabilities:
            print(f"\nDetailed Findings:")
            print("-" * 60)
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. [{vuln['severity'].upper()}] {vuln['description']}")
                print(f"   Port: {vuln['port']} | Service: {vuln['service']}")
                if 'cve' in vuln:
                    print(f"   CVE: {vuln['cve']}")
        
        if args.export:
            self.detector.export_report(target, args.export, args.format)
            print(f"\nReport exported to {args.export}")
    
    def _save_results(self, filename: str, results: dict):
        try:
            import json
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")

def main():
    cli = NetSecToolkitCLI()
    cli.run()

if __name__ == "__main__":
    main()
import time
import threading
from typing import List, Dict, Optional, Callable
from collections import defaultdict

from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, DNS
from scapy.packet import Packet

from ..utils.logger import Logger

class TrafficAnalyzer:
    def __init__(self):
        self.logger = Logger("TrafficAnalyzer")
        self.captured_packets = []
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"sent": 0, "received": 0})
        self.port_stats = defaultdict(int)
        self.is_capturing = False
        self.capture_thread = None
        self.packet_callback = None
    
    def start_capture(self, interface: Optional[str] = None, count: int = 0, 
                     timeout: Optional[int] = None, filter_expr: Optional[str] = None,
                     callback: Optional[Callable] = None):
        if self.is_capturing:
            self.logger.warning("Capture is already running")
            return
        
        self.is_capturing = True
        self.packet_callback = callback
        
        def capture_packets():
            try:
                self.logger.info(f"Starting packet capture on {interface or 'default interface'}")
                sniff(
                    iface=interface,
                    count=count,
                    timeout=timeout,
                    filter=filter_expr,
                    prn=self._process_packet,
                    store=False
                )
            except Exception as e:
                self.logger.error(f"Capture error: {str(e)}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Packet capture stopped")
    
    def _process_packet(self, packet: Packet):
        self.captured_packets.append(packet)
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_stats[src_ip]["sent"] += 1
            self.ip_stats[dst_ip]["received"] += 1
        
        if TCP in packet:
            self.protocol_stats["TCP"] += 1
            self.port_stats[packet[TCP].dport] += 1
        elif UDP in packet:
            self.protocol_stats["UDP"] += 1
            self.port_stats[packet[UDP].dport] += 1
        elif ICMP in packet:
            self.protocol_stats["ICMP"] += 1
        elif DNS in packet:
            self.protocol_stats["DNS"] += 1
        else:
            self.protocol_stats["Other"] += 1
        
        if self.packet_callback:
            self.packet_callback(packet)
    
    def analyze_pcap(self, pcap_file: str) -> Dict:
        try:
            packets = rdpcap(pcap_file)
            self.captured_packets.extend(packets)
            
            for packet in packets:
                self._process_packet(packet)
            
            return self.get_statistics()
        except Exception as e:
            self.logger.error(f"Failed to analyze pcap file: {str(e)}")
            return {}
    
    def get_statistics(self) -> Dict:
        return {
            "total_packets": len(self.captured_packets),
            "protocol_distribution": dict(self.protocol_stats),
            "ip_statistics": dict(self.ip_stats),
            "port_statistics": dict(self.port_stats),
            "capture_duration": self._calculate_duration()
        }
    
    def _calculate_duration(self) -> float:
        if len(self.captured_packets) < 2:
            return 0.0
        first_time = self.captured_packets[0].time
        last_time = self.captured_packets[-1].time
        return float(last_time - first_time)
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        return dict(self.protocol_stats)
    
    def get_top_talkers(self, top_n: int = 10) -> List[Dict]:
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]["sent"] + x[1]["received"],
            reverse=True
        )[:top_n]
        
        return [{"ip": ip, "sent": stats["sent"], "received": stats["received"]} 
                for ip, stats in sorted_ips]
    
    def get_top_ports(self, top_n: int = 10) -> List[Dict]:
        sorted_ports = sorted(
            self.port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        return [{"port": port, "count": count} for port, count in sorted_ports]
    
    def filter_packets(self, filter_func: Callable[[Packet], bool]) -> List[Packet]:
        return [p for p in self.captured_packets if filter_func(p)]
    
    def get_tcp_streams(self) -> Dict[str, List[Packet]]:
        streams = defaultdict(list)
        
        for packet in self.captured_packets:
            if TCP in packet and IP in packet:
                stream_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
                streams[stream_id].append(packet)
        
        return dict(streams)
    
    def get_dns_queries(self) -> List[Dict]:
        dns_queries = []
        
        for packet in self.captured_packets:
            if DNS in packet and packet[DNS].qr == 0:
                query = {
                    "time": float(packet.time),
                    "src": packet[IP].src if IP in packet else None,
                    "query": packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                    "type": packet[DNS].qd.qtype if packet[DNS].qd else None
                }
                dns_queries.append(query)
        
        return dns_queries
    
    def detect_anomalies(self) -> List[Dict]:
        anomalies = []
        
        for ip, stats in self.ip_stats.items():
            if stats["sent"] > 1000:
                anomalies.append({
                    "type": "high_traffic",
                    "ip": ip,
                    "sent": stats["sent"],
                    "description": f"High outbound traffic from {ip}"
                })
        
        for port, count in self.port_stats.items():
            if count > 500:
                anomalies.append({
                    "type": "port_scan",
                    "port": port,
                    "count": count,
                    "description": f"High activity on port {port}"
                })
        
        return anomalies
    
    def export_packets(self, output_file: str, packets: Optional[List[Packet]] = None):
        try:
            packets_to_export = packets or self.captured_packets
            wrpcap(output_file, packets_to_export)
            self.logger.info(f"Exported {len(packets_to_export)} packets to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to export packets: {str(e)}")
    
    def clear_data(self):
        self.captured_packets.clear()
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.port_stats.clear()
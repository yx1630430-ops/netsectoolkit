# NetSecToolkit - Network Security Toolkit

A comprehensive network security toolkit based on Scapy for network scanning, traffic analysis, and vulnerability detection.

## Features

### 1. Network Scanner
- TCP/UDP port scanning
- SYN scanning
- Host discovery
- Service detection
- Traceroute

### 2. Traffic Analyzer
- Real-time packet capture
- Protocol distribution analysis
- Top talkers identification
- DNS query extraction
- Anomaly detection

### 3. Vulnerability Detector
- Common vulnerability scanning
- Service-specific checks
- SSL/TLS analysis
- Report generation

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install from source
```bash
git clone https://github.com/yourusername/netsectoolkit.git
cd netsectoolkit
pip install -e .
```

### Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

#### Network Scanning
```bash
# Scan single host
netsectoolkit scan 192.168.1.1

# Scan with specific ports
netsectoolkit scan 192.168.1.1 --ports 80,443,8080

# Scan port range
netsectoolkit scan 192.168.1.1 --ports 1-1024

# Host discovery
netsectoolkit scan 192.168.1.0/24 --type host

# SYN scan
netsectoolkit scan 192.168.1.1 --type syn

# UDP scan
netsectoolkit scan 192.168.1.1 --type udp
```

#### Packet Capture
```bash
# Capture 100 packets
netsectoolkit sniff --count 100

# Capture on specific interface
netsectoolkit sniff --interface eth0 --count 100

# Capture with filter
netsectoolkit sniff --filter "tcp port 80" --count 50

# Save to file
netsectoolkit sniff --count 100 --output capture.pcap
```

#### Traffic Analysis
```bash
# Analyze pcap file
netsectoolkit analyze capture.pcap

# Save analysis results
netsectoolkit analyze capture.pcap --output results.json
```

#### Vulnerability Detection
```bash
# Scan for vulnerabilities
netsectoolkit vuln 192.168.1.1

# Scan specific ports
netsectoolkit vuln 192.168.1.1 --ports 21,22,80,443

# Export report
netsectoolkit vuln 192.168.1.1 --export report.json

# Export as text
netsectoolkit vuln 192.168.1.1 --export report.txt --format text
```

### Python API

```python
from netsectoolkit import NetworkScanner, TrafficAnalyzer, VulnerabilityDetector

# Network scanning
scanner = NetworkScanner()
results = scanner.tcp_port_scan("192.168.1.1", [22, 80, 443])
print(results)

# Traffic analysis
analyzer = TrafficAnalyzer()
analyzer.start_capture(count=100)
stats = analyzer.get_statistics()
print(stats)

# Vulnerability detection
detector = VulnerabilityDetector()
vulns = detector.scan_host("192.168.1.1")
report = detector.generate_report("192.168.1.1")
print(report)
```

## Configuration

The toolkit uses a configuration file located at `~/.netsectoolkit/config.json`.

Default configuration:
```json
{
  "scanner": {
    "timeout": 2.0,
    "max_threads": 100,
    "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
  },
  "analyzer": {
    "capture_timeout": 60,
    "max_packets": 10000,
    "default_interface": null
  },
  "detector": {
    "timeout": 3.0,
    "check_credentials": true,
    "export_format": "json"
  },
  "logging": {
    "level": "INFO",
    "file": null,
    "console": true
  }
}
```

## Project Structure

```
netsectoolkit/
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── scanner.py          # Network scanning module
│   ├── analyzer.py         # Traffic analysis module
│   └── detector.py         # Vulnerability detection module
├── utils/
│   ├── __init__.py
│   ├── logger.py           # Logging utilities
│   ├── network.py          # Network utility functions
│   └── config.py           # Configuration management
└── cli/
    ├── __init__.py
    └── main.py             # Command line interface
```

## Testing

Run tests with pytest:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=netsectoolkit tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) - The Python-based interactive packet manipulation program
- [Python](https://www.python.org/) - The programming language used

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning or testing any network or system. Unauthorized scanning is illegal and unethical.
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from netsectoolkit.core.scanner import NetworkScanner

class TestNetworkScanner:
    def setup_method(self):
        self.scanner = NetworkScanner(timeout=1.0, max_threads=10)
    
    def test_init(self):
        assert self.scanner.timeout == 1.0
        assert self.scanner.max_threads == 10
        assert self.scanner.results == {}
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_ping_scan_success(self, mock_sr1):
        mock_response = MagicMock()
        mock_sr1.return_value = mock_response
        
        result = self.scanner.ping_scan("192.168.1.1")
        assert result is True
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_ping_scan_failure(self, mock_sr1):
        mock_sr1.return_value = None
        
        result = self.scanner.ping_scan("192.168.1.1")
        assert result is False
    
    @patch('netsectoolkit.core.scanner.sr')
    @patch('netsectoolkit.core.scanner.sr1')
    def test_tcp_port_scan_open(self, mock_sr1, mock_sr):
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        
        tcp_layer = MagicMock()
        tcp_layer.flags = 0x12
        mock_response.__getitem__ = MagicMock(return_value=tcp_layer)
        mock_sr1.return_value = mock_response
        mock_sr.return_value = (None, None)
        
        results = self.scanner.tcp_port_scan("192.168.1.1", [80])
        assert 80 in results
        assert results[80] == "open"
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_tcp_port_scan_closed(self, mock_sr1):
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        
        tcp_layer = MagicMock()
        tcp_layer.flags = 0x14
        mock_response.__getitem__ = MagicMock(return_value=tcp_layer)
        mock_sr1.return_value = mock_response
        
        results = self.scanner.tcp_port_scan("192.168.1.1", [80])
        assert 80 in results
        assert results[80] == "closed"
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_tcp_port_scan_filtered(self, mock_sr1):
        mock_sr1.return_value = None
        
        results = self.scanner.tcp_port_scan("192.168.1.1", [80])
        assert 80 in results
        assert results[80] == "filtered"
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_udp_port_scan_open_filtered(self, mock_sr1):
        mock_sr1.return_value = None
        
        results = self.scanner.udp_port_scan("192.168.1.1", [53])
        assert 53 in results
        assert results[53] == "open|filtered"
    
    @patch('netsectoolkit.core.scanner.sr1')
    def test_syn_scan_open(self, mock_sr1):
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        
        tcp_layer = MagicMock()
        tcp_layer.flags = 0x12
        mock_response.__getitem__ = MagicMock(return_value=tcp_layer)
        mock_sr1.return_value = mock_response
        
        results = self.scanner.syn_scan("192.168.1.1", [443])
        assert 443 in results
        assert results[443] == "open"
    
    def test_get_results(self):
        self.scanner.results = {"test": "data"}
        results = self.scanner.get_results()
        assert results == {"test": "data"}
    
    def test_clear_results(self):
        self.scanner.results = {"test": "data"}
        self.scanner.clear_results()
        assert self.scanner.results == {}
    
    def test_service_detection_known_ports(self):
        service = self.scanner.service_detection("192.168.1.1", 80)
        assert service == "http" or service is None
    
    def test_results_storage(self):
        self.scanner.results["192.168.1.1_tcp"] = {80: "open", 443: "closed"}
        assert "192.168.1.1_tcp" in self.scanner.get_results()
        assert self.scanner.get_results()["192.168.1.1_tcp"][80] == "open"
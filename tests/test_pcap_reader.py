import os
import pytest
from scapy.all import IP, TCP, UDP, Ether, wrpcap
from ingestion.pcap_reader import PCAPIngestor

@pytest.fixture
def dummy_pcap(tmp_path):
    pcap_file = tmp_path / "test_capture.pcap"
    
    # Generate some harmless dummy packets for testing
    pkts = [
        Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80),
        Ether()/IP(src="192.168.1.2", dst="192.168.1.1")/TCP(sport=80, dport=1234),
        Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/UDP(sport=4321, dport=53)
    ]
    
    # Set explicit timestamps to verify preservation
    pkts[0].time = 1000.0
    pkts[1].time = 1001.0
    pkts[2].time = 1002.5
    
    wrpcap(str(pcap_file), pkts)
    return str(pcap_file)

def test_pcap_reader_invalid_file():
    with pytest.raises(FileNotFoundError):
        PCAPIngestor("nonexistent_file.pcap")
        
def test_pcap_reader_invalid_path_type(tmp_path):
    with pytest.raises(ValueError, match="Path is not a file"):
        PCAPIngestor(str(tmp_path))

def test_pcap_reader_iterates_packets(dummy_pcap):
    ingestor = PCAPIngestor(dummy_pcap)
    events = list(ingestor)
    
    assert len(events) == 3
    
    # Verify first packet (TCP)
    assert events[0].src_ip == "192.168.1.1"
    assert events[0].dst_ip == "192.168.1.2"
    assert events[0].protocol == "TCP"
    assert events[0].timestamp == 1000.0
    assert events[0].src_port == 1234
    assert events[0].dst_port == 80
    assert events[0].length > 0
    
    # Verify third packet (UDP)
    assert events[2].src_ip == "10.0.0.1"
    assert events[2].dst_ip == "8.8.8.8"
    assert events[2].protocol == "UDP"
    assert events[2].src_port == 4321
    assert events[2].dst_port == 53
    assert events[2].timestamp == 1002.5

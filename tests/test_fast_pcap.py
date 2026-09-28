import pytest
from ingestion.pcap_reader import PCAPIngestor
from ingestion.fast_pcap import FastPCAPIngestor

def test_fast_pcap_vs_scapy(tmp_path):
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    
    # Create a tiny PCAP fixture
    pcap_file = str(tmp_path / "test.pcap")
    pkts = [
        Ether()/IP(src="192.168.1.1", dst="10.0.0.1")/TCP(sport=1234, dport=80, flags="S"),
        Ether()/IP(src="10.0.0.1", dst="192.168.1.1")/TCP(sport=80, dport=1234, flags="SA")
    ]
    scapy.wrpcap(pcap_file, pkts)
    
    # Run Scapy
    scapy_events = list(PCAPIngestor(pcap_file))
    # Run Fast (dpkt)
    fast_events = list(FastPCAPIngestor(pcap_file))
    
    assert len(scapy_events) == len(fast_events) == 2
    for s_ev, f_ev in zip(scapy_events, fast_events):
        assert abs(s_ev.timestamp - f_ev.timestamp) < 0.001
        assert s_ev.length == f_ev.length
        assert s_ev.src_ip == f_ev.src_ip
        assert s_ev.dst_ip == f_ev.dst_ip
        assert s_ev.src_port == f_ev.src_port
        assert s_ev.dst_port == f_ev.dst_port
        assert s_ev.protocol == f_ev.protocol
        assert s_ev.is_syn == f_ev.is_syn
        assert s_ev.is_ack == f_ev.is_ack

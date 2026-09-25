import pytest
from processing.features import FeatureExtractor
from processing.window import WindowSnapshot
from processing.flow import FlowState

def test_extract_features_empty():
    extractor = FeatureExtractor()
    snapshot = WindowSnapshot(window_start=0.0, window_end=5.0)
    features = extractor.extract_features(snapshot)
    assert len(features) == 0

def test_extract_features_flow_level():
    extractor = FeatureExtractor()
    
    flow1 = FlowState(
        flow_id="192.168.1.1:1000-10.0.0.1:80-TCP",
        src_ip="192.168.1.1", dst_ip="10.0.0.1",
        src_port=1000, dst_port=80, protocol="TCP",
        first_seen=1.0, last_seen=2.0,
        packet_count=3, byte_count=300,
        fwd_packet_count=2, rev_packet_count=1,
        fwd_byte_count=200, rev_byte_count=100
    )
    
    snapshot = WindowSnapshot(
        window_start=0.0, window_end=5.0,
        total_packets=3, total_bytes=300, flow_count=1,
        flows={flow1.flow_id: flow1}
    )
    
    features = extractor.extract_features(snapshot)
    assert len(features) == 1
    
    vec = features[flow1.flow_id]
    
    # Assert flow level computations
    assert vec["flow_duration"] == 1.0  # 2.0 - 1.0
    assert vec["fwd_packet_count"] == 2.0
    assert vec["rev_packet_count"] == 1.0
    assert vec["fwd_bytes_per_sec"] == 200.0  # 200 / 1.0
    assert vec["rev_bytes_per_sec"] == 100.0
    assert vec["byte_ratio"] == pytest.approx(2.0, 0.01) # 200 / 100
    assert vec["is_unidirectional"] == 0.0
    
    # Assert context enrichment
    assert vec["src_ip_flow_count"] == 1.0
    assert vec["src_ip_unique_dst_ips"] == 1.0
    assert vec["src_ip_unique_dst_ports"] == 1.0
    assert vec["is_tcp"] == 1.0
    assert vec["is_udp"] == 0.0

def test_extract_features_port_scan_context():
    extractor = FeatureExtractor()
    
    # Simulate a port scan: One source IP hitting multiple ports
    flows = {}
    for port in range(80, 85):
        flow_id = f"10.0.0.5:5555-192.168.1.100:{port}-TCP"
        flows[flow_id] = FlowState(
            flow_id=flow_id,
            src_ip="10.0.0.5", dst_ip="192.168.1.100",
            src_port=5555, dst_port=port, protocol="TCP",
            first_seen=1.0, last_seen=1.0,  # instantaneous
            packet_count=1, byte_count=64,
            fwd_packet_count=1, rev_packet_count=0,
            fwd_byte_count=64, rev_byte_count=0
        )
        
    snapshot = WindowSnapshot(
        window_start=0.0, window_end=5.0,
        total_packets=5, total_bytes=320, flow_count=5,
        flows=flows
    )
    
    features = extractor.extract_features(snapshot)
    assert len(features) == 5
    
    # Check that context enrichment caught the scan
    for vec in features.values():
        assert vec["src_ip_flow_count"] == 5.0
        assert vec["src_ip_unique_dst_ips"] == 1.0
        assert vec["src_ip_unique_dst_ports"] == 5.0
        assert vec["fwd_bytes_per_sec"] == 0.0 # Duration is 0, so rate is 0.0
        assert vec["byte_ratio"] == 10000.0 # rev_bytes is 0, capped at 10000.0
        assert vec["is_unidirectional"] == 1.0

def test_zero_duration_behavior():
    extractor = FeatureExtractor()
    flow1 = FlowState(
        flow_id="10.0.0.1:100-10.0.0.2:200-TCP",
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=100, dst_port=200, protocol="TCP",
        first_seen=5.0, last_seen=5.0,  # Zero duration
        packet_count=2, byte_count=150,
        fwd_packet_count=2, rev_packet_count=0,
        fwd_byte_count=150, rev_byte_count=0
    )
    snapshot = WindowSnapshot(
        window_start=0.0, window_end=5.0,
        total_packets=2, total_bytes=150, flow_count=1,
        flows={flow1.flow_id: flow1}
    )
    
    features = extractor.extract_features(snapshot)
    vec = features[flow1.flow_id]
    
    # Assert zero-duration logic
    assert vec["flow_duration"] == 0.0
    assert vec["fwd_bytes_per_sec"] == 0.0
    assert vec["rev_bytes_per_sec"] == 0.0
    assert vec["fwd_pkts_per_sec"] == 0.0
    assert vec["rev_pkts_per_sec"] == 0.0
    
    # Assert zero reverse bytes logic
    assert vec["byte_ratio"] == 10000.0
    assert vec["is_unidirectional"] == 1.0

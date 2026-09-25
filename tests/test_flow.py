import pytest
from processing.flow import FlowProcessor, FlowState
from ingestion.packet_event import PacketEvent

def test_flow_creation():
    processor = FlowProcessor()
    
    packet = PacketEvent(
        timestamp=1.0,
        length=100,
        raw_packet=None,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP"
    )
    
    flow = processor.process_packet(packet)
    assert flow is not None
    assert flow.flow_id == "192.168.1.1:12345-10.0.0.1:80-TCP"
    assert flow.src_ip == "192.168.1.1"
    assert flow.dst_ip == "10.0.0.1"
    assert flow.packet_count == 1
    assert flow.byte_count == 100
    assert flow.fwd_packet_count == 1
    assert flow.rev_packet_count == 0
    assert flow.fwd_byte_count == 100
    assert flow.rev_byte_count == 0
    assert flow.first_seen == 1.0
    assert flow.last_seen == 1.0
    assert flow.duration == 0.0

def test_bidirectional_flow():
    processor = FlowProcessor()
    
    # Forward packet
    p1 = PacketEvent(timestamp=1.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1000, dst_port=80, protocol="TCP")
    
    # Reverse packet
    p2 = PacketEvent(timestamp=2.5, length=250, raw_packet=None, src_ip="B", dst_ip="A", src_port=80, dst_port=1000, protocol="TCP")
    
    # Another forward packet
    p3 = PacketEvent(timestamp=3.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=1000, dst_port=80, protocol="TCP")
    
    f1 = processor.process_packet(p1)
    f2 = processor.process_packet(p2)
    f3 = processor.process_packet(p3)
    
    assert f1 is f2 is f3  # Should be the exact same object reference
    
    assert f3.packet_count == 3
    assert f3.byte_count == 400
    
    assert f3.fwd_packet_count == 2
    assert f3.rev_packet_count == 1
    
    assert f3.fwd_byte_count == 150
    assert f3.rev_byte_count == 250
    
    assert f3.first_seen == 1.0
    assert f3.last_seen == 3.0
    assert f3.duration == 2.0
    
    # Invariant checks
    assert f3.packet_count == f3.fwd_packet_count + f3.rev_packet_count
    assert f3.byte_count == f3.fwd_byte_count + f3.rev_byte_count
    assert f3.duration == f3.last_seen - f3.first_seen

def test_multiple_independent_flows():
    processor = FlowProcessor()
    
    # Flow 1: UDP
    processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=123, dst_port=456, protocol="UDP"))
    
    # Flow 2: TCP
    processor.process_packet(PacketEvent(timestamp=2.0, length=100, raw_packet=None, src_ip="C", dst_ip="D", src_port=111, dst_port=222, protocol="TCP"))
    
    # Flow 1 reversed
    processor.process_packet(PacketEvent(timestamp=3.0, length=60, raw_packet=None, src_ip="B", dst_ip="A", src_port=456, dst_port=123, protocol="UDP"))
    
    assert len(processor.flows) == 2
    
    # Find flow 1
    flow1 = next(f for f in processor.flows.values() if f.protocol == "UDP")
    assert flow1.packet_count == 2
    assert flow1.byte_count == 110
    
    # Find flow 2
    flow2 = next(f for f in processor.flows.values() if f.protocol == "TCP")
    assert flow2.packet_count == 1
    assert flow2.byte_count == 100

def test_malformed_incomplete_packets():
    processor = FlowProcessor()
    
    # Missing protocol
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=123, dst_port=456, protocol=None))
    assert f is None
    
    # Missing IP
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip=None, dst_ip="B", src_port=123, dst_port=456, protocol="TCP"))
    assert f is None
    
    # Unsupported protocol (e.g. ICMP)
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=123, dst_port=456, protocol="ICMP"))
    assert f is None
    
    # Missing src_port
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=None, dst_port=456, protocol="TCP"))
    assert f is None
    
    # Missing dst_port
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=123, dst_port=None, protocol="TCP"))
    assert f is None

    # Missing both ports
    f = processor.process_packet(PacketEvent(timestamp=1.0, length=50, raw_packet=None, src_ip="A", dst_ip="B", src_port=None, dst_port=None, protocol="TCP"))
    assert f is None
    
    assert len(processor.flows) == 0

def test_out_of_order_timestamps():
    processor = FlowProcessor()
    
    # Send later packet first
    processor.process_packet(PacketEvent(timestamp=5.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1000, dst_port=80, protocol="TCP"))
    
    # Send earlier packet second
    flow = processor.process_packet(PacketEvent(timestamp=2.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1000, dst_port=80, protocol="TCP"))
    
    assert flow.first_seen == 2.0
    assert flow.last_seen == 5.0
    assert flow.duration == 3.0

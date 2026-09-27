import pytest
from ingestion.packet_event import PacketEvent

def test_packet_event_initialization():
    event = PacketEvent(
        timestamp=1000.0,
        length=64,
        raw_packet=None,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP"
    )

    assert event.timestamp == 1000.0
    assert event.length == 64
    assert event.src_ip == "192.168.1.1"
    assert event.dst_ip == "10.0.0.1"
    assert event.src_port == 12345
    assert event.dst_port == 80
    assert event.protocol == "TCP"

def test_packet_event_optional_fields():
    event = PacketEvent(
        timestamp=2000.0,
        length=128,
        raw_packet=None
    )

    assert event.timestamp == 2000.0
    assert event.length == 128
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.src_port is None
    assert event.dst_port is None
    assert event.protocol is None

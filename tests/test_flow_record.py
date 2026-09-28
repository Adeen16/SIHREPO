import pytest
from processing.flow import FlowRecord

def test_flow_record_schema():
    # Assert we can instantiate a FlowRecord
    record = FlowRecord(
        flow_id="192.168.1.1:1234-8.8.8.8:53-UDP",
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=1234,
        dst_port=53,
        protocol="UDP",
        first_seen=1000.0,
        last_seen=1001.0,
        packet_count=2,
        byte_count=120,
        fwd_packet_count=1,
        rev_packet_count=1,
        fwd_byte_count=60,
        rev_byte_count=60
    )
    
    assert record.flow_id == "192.168.1.1:1234-8.8.8.8:53-UDP"
    assert record.src_ip == "192.168.1.1"
    assert record.protocol == "UDP"
    assert record.fwd_packet_count == 1
    assert record.syn_count == 0  # Default value

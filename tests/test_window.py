import pytest
from processing.window import SlidingWindowManager, WindowSnapshot
from ingestion.packet_event import PacketEvent

def test_window_manager_initialization():
    manager = SlidingWindowManager(window_seconds=10.0, slide_seconds=2.0)
    assert manager.window_seconds == 10.0
    assert manager.slide_seconds == 2.0
    
    with pytest.raises(ValueError):
        SlidingWindowManager(window_seconds=0, slide_seconds=1.0)
        
    with pytest.raises(ValueError):
        SlidingWindowManager(window_seconds=10.0, slide_seconds=-1.0)

def test_window_snapshot_empty():
    manager = SlidingWindowManager(window_seconds=5.0, slide_seconds=1.0)
    snapshot = manager.get_current_snapshot()
    
    assert snapshot.total_packets == 0
    assert snapshot.total_bytes == 0
    assert snapshot.flow_count == 0
    assert len(snapshot.flows) == 0

def test_sliding_window_aggregation_and_emission():
    # 5-second window sliding every 1 second
    manager = SlidingWindowManager(window_seconds=5.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=10.0, length=100, raw_packet=None, src_ip="192.168.1.1", dst_ip="10.0.0.1", src_port=1000, dst_port=80, protocol="TCP")
    p2 = PacketEvent(timestamp=10.5, length=200, raw_packet=None, src_ip="10.0.0.1", dst_ip="192.168.1.1", src_port=80, dst_port=1000, protocol="TCP")
    p3 = PacketEvent(timestamp=11.2, length=150, raw_packet=None, src_ip="192.168.1.2", dst_ip="10.0.0.1", src_port=2000, dst_port=80, protocol="TCP")
    
    # Packet 1 at 10.0 -> sets initial emitted window end to 10.0
    snapshots = manager.add_packet(p1)
    assert len(snapshots) == 0
    
    # Packet 2 at 10.5 -> no full 1s slide past 10.0 yet
    snapshots = manager.add_packet(p2)
    assert len(snapshots) == 0
    
    # Packet 3 at 11.2 -> crosses 11.0 (slide boundary)
    snapshots = manager.add_packet(p3)
    assert len(snapshots) == 1
    
    snap = snapshots[0]
    assert snap.window_start == 6.0
    assert snap.window_end == 11.0
    assert snap.total_packets == 2  # p1 (10.0) and p2 (10.5) fall within [6.0, 11.0]
    assert snap.total_bytes == 300
    assert snap.flow_count == 1
    
    # On-demand snapshot at current time (11.2) includes all 3 packets
    curr_snap = manager.get_current_snapshot()
    assert curr_snap.total_packets == 3
    assert curr_snap.total_bytes == 450
    assert curr_snap.flow_count == 2

def test_buffer_eviction():
    # 3-second window horizon
    manager = SlidingWindowManager(window_seconds=3.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=1.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP")
    p2 = PacketEvent(timestamp=5.0, length=200, raw_packet=None, src_ip="C", dst_ip="D", src_port=3, dst_port=4, protocol="TCP")
    
    manager.add_packet(p1)
    manager.add_packet(p2)  # Timestamp jumps to 5.0 -> cutoff is 5.0 - 3.0 = 2.0
    
    snapshot = manager.get_current_snapshot()
    assert snapshot.window_start == 2.0
    assert snapshot.window_end == 5.0
    assert snapshot.total_packets == 1  # Only p2 remains in buffer
    assert snapshot.total_bytes == 200
    assert snapshot.flow_count == 1

def test_monotonic_timestamps():
    manager = SlidingWindowManager(window_seconds=5.0, slide_seconds=1.0)
    manager.add_packet(PacketEvent(timestamp=10.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP"))
    
    with pytest.raises(ValueError, match="Out-of-order packet timestamp"):
        manager.add_packet(PacketEvent(timestamp=9.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP"))

def test_boundary_conditions():
    manager = SlidingWindowManager(window_seconds=5.0, slide_seconds=1.0)
    # Window is [start, end] i.e. start <= timestamp <= end
    p1 = PacketEvent(timestamp=10.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP")
    p2 = PacketEvent(timestamp=15.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP")
    
    manager.add_packet(p1)
    manager.add_packet(p2)
    
    # Snapshot for [10.0, 15.0]. p1 at 10.0 is included, p2 at 15.0 is also included.
    snap = manager.get_current_snapshot(end_timestamp=15.0)
    assert snap.total_packets == 2
    assert snap.window_start == 10.0
    assert snap.window_end == 15.0

def test_large_timestamp_jump():
    # 5-second window sliding every 1 second
    manager = SlidingWindowManager(window_seconds=5.0, slide_seconds=1.0)
    
    p1 = PacketEvent(timestamp=10.0, length=100, raw_packet=None, src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol="TCP")
    # p2 arrives 100 seconds later! This should cause many windows to be emitted, or just the necessary ones.
    # Actually, the sliding window logic will emit empty windows for every slide step if it processes them linearly.
    p2 = PacketEvent(timestamp=110.0, length=200, raw_packet=None, src_ip="C", dst_ip="D", src_port=3, dst_port=4, protocol="TCP")
    
    snapshots_p1 = manager.add_packet(p1)
    assert len(snapshots_p1) == 0
    
    # Adding p2 at 110.0 crosses exactly 100 slide boundaries (from 11.0 to 110.0)
    snapshots_p2 = manager.add_packet(p2)
    
    assert len(snapshots_p2) > 0
    
    # Check the first emitted window
    first_snap = snapshots_p2[0]
    assert first_snap.window_end == 11.0
    assert first_snap.window_start == 6.0
    # p1 at 10.0 is included in [6.0, 11.0]
    assert first_snap.total_packets == 1
    
    # Check the last emitted window
    last_snap = snapshots_p2[-1]
    assert last_snap.window_end == 110.0
    assert last_snap.window_start == 105.0
    # p2 at 110.0 is included in [105.0, 110.0]
    assert last_snap.total_packets == 1
    
    # Check get_current_snapshot() behaves correctly
    curr_snap = manager.get_current_snapshot()
    assert curr_snap.window_end == 110.0
    assert curr_snap.window_start == 105.0
    assert curr_snap.total_packets == 1
    
    # Check buffer contents after eviction
    # Only p2 (timestamp=110.0) should remain. p1 (timestamp=10.0) must be evicted.
    # This proves we don't accidentally preserve unbounded historical packets.
    assert len(manager._buffer) == 1
    assert manager._buffer[0].timestamp == 110.0

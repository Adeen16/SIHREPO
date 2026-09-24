from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque
from collections import deque
from ingestion.packet_event import PacketEvent
from processing.flow import FlowProcessor, FlowState

@dataclass
class WindowSnapshot:
    """
    Snapshot of network activity and flow states within a time window [window_start, window_end].
    """
    window_start: float
    window_end: float
    total_packets: int = 0
    total_bytes: int = 0
    flow_count: int = 0
    flows: Dict[str, FlowState] = field(default_factory=dict)

class SlidingWindowManager:
    """
    Manages time-based sliding windows driven strictly by packet timestamps.
    Maintains a bounded packet buffer and generates WindowSnapshot instances as time advances.
    """
    def __init__(self, window_seconds: float = 10.0, slide_seconds: float = 1.0):
        if window_seconds <= 0 or slide_seconds <= 0:
            raise ValueError("window_seconds and slide_seconds must be positive numbers")
            
        self.window_seconds: float = window_seconds
        self.slide_seconds: float = slide_seconds
        
        # Bounded buffer of raw PacketEvent objects within the max window horizon
        self._buffer: Deque[PacketEvent] = deque()
        
        # Timestamp tracking
        self.latest_timestamp: Optional[float] = None
        self._last_emitted_window_end: Optional[float] = None

    def add_packet(self, packet: PacketEvent) -> List[WindowSnapshot]:
        """
        Adds a PacketEvent to the sliding window buffer.
        Evicts packets older than (latest_timestamp - window_seconds) and returns completed WindowSnapshots.
        """
        if not packet or packet.timestamp is None:
            return []
            
        self._buffer.append(packet)
        
        # Advance current time tracker
        if self.latest_timestamp is None or packet.timestamp > self.latest_timestamp:
            self.latest_timestamp = packet.timestamp
            
        # Evict packets older than window horizon
        cutoff = self.latest_timestamp - self.window_seconds
        while self._buffer and self._buffer[0].timestamp < cutoff:
            self._buffer.popleft()
            
        # Check if slide intervals have elapsed and emit snapshots
        emitted_snapshots: List[WindowSnapshot] = []
        if self._last_emitted_window_end is None:
            self._last_emitted_window_end = packet.timestamp
            
        while self.latest_timestamp >= self._last_emitted_window_end + self.slide_seconds:
            win_end = self._last_emitted_window_end + self.slide_seconds
            win_start = win_end - self.window_seconds
            
            snapshot = self._compute_snapshot(win_start, win_end)
            emitted_snapshots.append(snapshot)
            self._last_emitted_window_end = win_end
            
        return emitted_snapshots

    def get_current_snapshot(self, end_timestamp: Optional[float] = None) -> WindowSnapshot:
        """
        Computes an on-demand snapshot for [end_time - window_seconds, end_time].
        Uses self.latest_timestamp if end_timestamp is not specified.
        """
        end_time = end_timestamp if end_timestamp is not None else (self.latest_timestamp or 0.0)
        start_time = max(0.0, end_time - self.window_seconds)
        return self._compute_snapshot(start_time, end_time)

    def _compute_snapshot(self, start_time: float, end_time: float) -> WindowSnapshot:
        """
        Helper method to aggregate packets into flow states within the range [start_time, end_time].
        """
        processor = FlowProcessor()
        total_packets = 0
        total_bytes = 0
        
        for packet in self._buffer:
            if start_time <= packet.timestamp <= end_time:
                flow = processor.process_packet(packet)
                if flow:
                    total_packets += 1
                    total_bytes += packet.length
                    
        return WindowSnapshot(
            window_start=start_time,
            window_end=end_time,
            total_packets=total_packets,
            total_bytes=total_bytes,
            flow_count=len(processor.flows),
            flows={flow.flow_id: flow for flow in processor.flows.values()}
        )

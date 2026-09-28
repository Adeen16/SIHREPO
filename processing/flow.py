from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from ingestion.packet_event import PacketEvent

@dataclass
class FlowRecord:
    """Canonical schema for a flow, produced by both PCAP and CSV/binetflow adapters."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int
    byte_count: int
    fwd_packet_count: int
    rev_packet_count: int
    fwd_byte_count: int
    rev_byte_count: int
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0
    psh_count: int = 0
    fwd_iat_mean: float = 0.0
    fwd_iat_std: float = 0.0
    rev_iat_mean: float = 0.0
    rev_iat_std: float = 0.0

@dataclass
class FlowState:
    """
    State representation of a unidirectional or bidirectional network flow.
    Directionality is based on the first observed packet for the flow canonical key.
    """
    flow_id: str
    
    # Original initiator of the flow
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Timestamps
    first_seen: float
    last_seen: float
    
    # Aggregated stats
    packet_count: int = 0
    byte_count: int = 0
    
    # Directional stats
    fwd_packet_count: int = 0
    rev_packet_count: int = 0
    fwd_byte_count: int = 0
    rev_byte_count: int = 0
    
    @property
    def duration(self) -> float:
        """Returns the duration of the flow in seconds."""
        return self.last_seen - self.first_seen

    # --- Extended Stage 3 fields -------------------------------------------
    # TCP flag counters (always 0 for UDP)
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0
    psh_count: int = 0

    # Inter-arrival time lists — populated lazily to bound memory
    # Capped at _IAT_CAP entries per direction to avoid unbounded growth.
    _IAT_CAP: int = field(default=500, init=False, repr=False)
    fwd_iat_list: List[float] = field(default_factory=list)   # fwd IATs
    rev_iat_list: List[float] = field(default_factory=list)   # rev IATs

    # Last packet timestamp per direction (for IAT calculation)
    _last_fwd_ts: Optional[float] = field(default=None, init=False, repr=False)
    _last_rev_ts: Optional[float] = field(default=None, init=False, repr=False)

    @property
    def fwd_iat_mean(self) -> float:
        if not self.fwd_iat_list:
            return 0.0
        return sum(self.fwd_iat_list) / len(self.fwd_iat_list)

    @property
    def fwd_iat_std(self) -> float:
        n = len(self.fwd_iat_list)
        if n < 2:
            return 0.0
        mean = self.fwd_iat_mean
        return (sum((x - mean) ** 2 for x in self.fwd_iat_list) / (n - 1)) ** 0.5

    @property
    def rev_iat_mean(self) -> float:
        if not self.rev_iat_list:
            return 0.0
        return sum(self.rev_iat_list) / len(self.rev_iat_list)

    @property
    def rev_iat_std(self) -> float:
        n = len(self.rev_iat_list)
        if n < 2:
            return 0.0
        mean = self.rev_iat_mean
        return (sum((x - mean) ** 2 for x in self.rev_iat_list) / (n - 1)) ** 0.5

    @property
    def pkt_size_mean(self) -> float:
        total = self.fwd_packet_count + self.rev_packet_count
        if total == 0:
            return 0.0
        return (self.fwd_byte_count + self.rev_byte_count) / total

class FlowProcessor:
    """
    Stateful processor that incrementally consumes PacketEvents and updates FlowStates.
    """
    def __init__(self):
        # Maps bidirectional canonical key to FlowState
        self.flows: Dict[Tuple, FlowState] = {}
        
    def _canonicalize(self, packet: PacketEvent) -> Tuple:
        """
        Create a bidirectional canonical key for the flow.
        Sorts the endpoints so that packets in both directions hash to the same tuple.
        """
        ip1, ip2 = packet.src_ip, packet.dst_ip
        port1, port2 = packet.src_port, packet.dst_port
        proto = packet.protocol
        
        # Sort based on IP, then port to ensure both directions hash to same key
        if (ip1, port1) < (ip2, port2):
            return (ip1, port1, ip2, port2, proto)
        else:
            return (ip2, port2, ip1, port1, proto)

    def process_packet(self, packet: PacketEvent) -> Optional[FlowState]:
        """
        Process a single packet and update/create the corresponding FlowState.
        Returns the updated FlowState if it was successfully matched/created.
        Returns None if the packet is unsupported or malformed.
        """
        if not packet.src_ip or not packet.dst_ip or not packet.protocol:
            return None
            
        if packet.protocol not in ('TCP', 'UDP'):
            # Current requirements say support TCP and UDP initially
            return None
            
        key = self._canonicalize(packet)
        
        if key not in self.flows:
            # First time seeing this flow, direction of this packet is forward
            flow_id = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
            new_flow = FlowState(
                flow_id=flow_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                packet_count=1,
                byte_count=packet.length,
                fwd_packet_count=1,
                fwd_byte_count=packet.length,
                rev_packet_count=0,
                rev_byte_count=0
            )
            # Initialize fwd IAT tracking with the first packet's timestamp
            new_flow._last_fwd_ts = packet.timestamp
            # Count TCP flags from the first packet
            if packet.is_syn:
                new_flow.syn_count += 1
            if packet.is_fin:
                new_flow.fin_count += 1
            if packet.is_rst:
                new_flow.rst_count += 1
            if packet.is_ack:
                new_flow.ack_count += 1
            if packet.is_psh:
                new_flow.psh_count += 1
            self.flows[key] = new_flow
            return new_flow
            
        flow = self.flows[key]
        
        # Update overall stats
        flow.packet_count += 1
        flow.byte_count += packet.length
        
        # Update timestamps
        if packet.timestamp < flow.first_seen:
            flow.first_seen = packet.timestamp
        if packet.timestamp > flow.last_seen:
            flow.last_seen = packet.timestamp
            
        # Determine direction relative to the initiator
        # The initiator is whoever was seen first (stored in src_ip/src_port)
        is_forward = (packet.src_ip == flow.src_ip and packet.src_port == flow.src_port)
        if is_forward:
            # IAT
            if flow._last_fwd_ts is not None and len(flow.fwd_iat_list) < flow._IAT_CAP:
                flow.fwd_iat_list.append(packet.timestamp - flow._last_fwd_ts)
            flow._last_fwd_ts = packet.timestamp
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += packet.length
        else:
            # IAT
            if flow._last_rev_ts is not None and len(flow.rev_iat_list) < flow._IAT_CAP:
                flow.rev_iat_list.append(packet.timestamp - flow._last_rev_ts)
            flow._last_rev_ts = packet.timestamp
            flow.rev_packet_count += 1
            flow.rev_byte_count += packet.length

        # TCP flag counters
        if packet.is_syn:
            flow.syn_count += 1
        if packet.is_fin:
            flow.fin_count += 1
        if packet.is_rst:
            flow.rst_count += 1
        if packet.is_ack:
            flow.ack_count += 1
        if packet.is_psh:
            flow.psh_count += 1
            
        return flow

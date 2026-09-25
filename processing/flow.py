from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from ingestion.packet_event import PacketEvent

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
        if packet.src_ip is None or packet.dst_ip is None or packet.protocol is None:
            return None
            
        if packet.src_port is None or packet.dst_port is None:
            return None
            
        if packet.protocol not in ('TCP', 'UDP'):
            # Current requirements say support TCP and UDP initially
            return None
            
        key = self._canonicalize(packet)
        
        if key not in self.flows:
            # First time seeing this flow, direction of this packet is forward
            flow_id = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
            self.flows[key] = FlowState(
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
            return self.flows[key]
            
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
        if packet.src_ip == flow.src_ip and packet.src_port == flow.src_port:
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += packet.length
        else:
            flow.rev_packet_count += 1
            flow.rev_byte_count += packet.length
            
        return flow

from dataclasses import dataclass
from typing import Optional, Any

@dataclass
class PacketEvent:
    """
    Internal representation of a packet event.
    Designed to preserve metadata required for future flow construction and feature engineering.
    """
    timestamp: float
    length: int
    raw_packet: Any  # Reference to the Scapy packet object
    
    # Basic IP Metadata
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    
    # Basic Transport Metadata
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

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

    # TCP flag fields (set by pcap_reader if TCP layer present; None for non-TCP)
    tcp_flags: Optional[int] = None   # raw TCP flags bitmask
    is_syn: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_ack: bool = False
    is_psh: bool = False

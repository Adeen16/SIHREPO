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
    
    # DNS Metadata
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[int] = None
    dns_response_code: Optional[int] = None
    
    # TLS Metadata
    tls_version: Optional[int] = None
    tls_is_client_hello: bool = False
    tls_sni: Optional[str] = None
    tls_cipher_suites_count: Optional[int] = None
    tls_extensions_count: Optional[int] = None
